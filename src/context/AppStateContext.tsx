import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import questionsData from '../data/questions.json';
import { Question, RawQuestion } from '../types/questions';
import { computeScore, ScoreResult } from '../utils/scoring';
import { mapRisks, RiskMappingResult } from '../utils/recommendations';
import { DomainScanResult } from '../utils/domainChecks';
import { runAllScanners } from '../utils/scanners';
import { DomainScanAggregate } from '../types/domainScan';
import { ExecutedScannerResult } from '../types/domainScan';
import { APP_CONFIG } from '../config/appConfig';
import * as amplitude from '@amplitude/analytics-browser';
import { trackEvent, trackImport } from '../utils/analytics';
import { scannerCache } from '../utils/scannerCache';
import { validateImportJSON } from '../utils/importValidation';
import { useTranslatedQuestions } from '../utils/questionTranslation';
import { migrateAnswers, needsMigration } from '../utils/answerMigration';
import { useTranslation } from 'react-i18next';

interface AppStateContextValue {
  questions: Question[];
  answers: Record<string, string>;
  setAnswer: (id: string, value: string) => void;
  resetAnswers: () => void;
  resetAll: () => void;
  score: ScoreResult;
  risks: string[];
  bestPractices: string[];
  domainScan?: DomainScanResult;
  // New aggregated scanner state
  domainScanAggregate?: DomainScanAggregate;
  scannerProgress: ExecutedScannerResult[];
  runScanners: (domain: string) => Promise<void>;
  exportJSON: () => string;
  importJSON: (json: string) => { success: boolean; error?: string };
}

export type { AppStateContextValue };

const AppStateContext = createContext<AppStateContextValue | undefined>(undefined);

const ANSWERS_KEY = 'risk_answers_v2';
const DOMAIN_KEY = 'risk_domain_scan_v2';
const DOMAIN_AGG_KEY = 'risk_domain_scan_agg_v2';

const loadStored = <T,>(key: string): T | undefined => {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) as T : undefined;
  } catch {
    return undefined;
  }
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const persist = (key: string, value: any) => {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // TODO: handle storage errors
  }
};

export const AppStateProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { t, i18n } = useTranslation('questions');

  // Store raw questions data
  const rawQuestions = useMemo(() => {
    return (questionsData as { questions: RawQuestion[] }).questions;
  }, []);

  // Translate questions using i18n
  const questions = useTranslatedQuestions(rawQuestions);

  const [answers, setAnswers] = useState<Record<string, string>>(() => {
    return loadStored<Record<string, string>>(ANSWERS_KEY) || {};
  });

  const [migrationDone, setMigrationDone] = useState(false);

  // Perform migration after i18n is ready
  useEffect(() => {
    if (migrationDone || !i18n.isInitialized) return;

    const stored = answers;

    // Check if migration is needed
    if (Object.keys(stored).length > 0 && needsMigration(stored)) {
      const migrationResult = migrateAnswers(stored, rawQuestions, t);

      // Save migrated answers back to localStorage
      if (migrationResult.migratedCount > 0) {
        setAnswers(migrationResult.answers);
        persist(ANSWERS_KEY, migrationResult.answers);

        // Track migration for analytics
        trackEvent('answers_migrated', {
          migrated_count: migrationResult.migratedCount,
          unmatched_count: migrationResult.unmatchedCount
        });
      }
    }

    setMigrationDone(true);
  }, [i18n.isInitialized, migrationDone, answers, rawQuestions, t]);
  const [domainScanAggregate, setDomainScanAggregate] = useState<DomainScanAggregate | undefined>(
    () => loadStored<DomainScanAggregate>(DOMAIN_AGG_KEY)
  );
  const [scannerProgress, setScannerProgress] = useState<ExecutedScannerResult[]>([]);

  useEffect(() => {
    if (APP_CONFIG.amplitudeApiKey) {
      amplitude.init(
        APP_CONFIG.amplitudeApiKey,
        undefined,
        {
          autocapture: true,
          cookieOptions: { secure: true, upgrade: true },
          defaultTracking: true
        },
      );
    }
  }, []);

  const setAnswer = (id: string, value: string) => {
    setAnswers((prev) => {
      const updated = { ...prev, [id]: value };
      persist(ANSWERS_KEY, updated);
      trackEvent('answer_set', { question_id: id, value });
      return updated;
    });
  };

  const resetAnswers = () => {
    setAnswers({});
    localStorage.removeItem(ANSWERS_KEY);
    trackEvent('answers_reset');
  };

  const resetAll = () => {
    setAnswers({});
    setDomainScanAggregate(undefined);
    setScannerProgress([]);
    localStorage.removeItem(ANSWERS_KEY);
    localStorage.removeItem(DOMAIN_KEY);
    localStorage.removeItem(DOMAIN_AGG_KEY);
    trackEvent('reset_all');
  };

  const score = useMemo(() => computeScore(answers, questions), [answers, questions]);
  const { risks, bestPractices }: RiskMappingResult = useMemo(() => mapRisks(answers, questions), [answers, questions]);

  const runScanners = async (domain: string) => {
    // Check cache first
    const cached = scannerCache.get<DomainScanAggregate>(domain);
    if (cached) {
      setDomainScanAggregate(cached);
      setScannerProgress(cached.scanners);
      trackEvent('domain_scanned_cached', { domain: cached.domain });
      return;
    }

    // Check rate limit
    const rateCheck = scannerCache.checkRateLimit();
    if (!rateCheck.allowed) {
      throw new Error(`Rate limit exceeded. Please wait ${rateCheck.retryAfter} seconds before scanning again.`);
    }

    setScannerProgress([]);
    const agg = await runAllScanners(domain, (partial) => {
      setScannerProgress(partial);
    });

    setDomainScanAggregate(agg);
    persist(DOMAIN_AGG_KEY, agg);

    // Cache the result
    scannerCache.set(domain, agg);

    trackEvent('domain_scanned_modular', { domain: agg.domain, issues_count: agg.issues.length });
  };

  const exportJSON = () => JSON.stringify({
    version: 2,
    answers,
    risks,
    bestPractices,
    domainScanAggregate
  }, null, 2);

  const importJSON = (json: string): { success: boolean; error?: string } => {
    // Validate JSON structure and complexity first
    const validation = validateImportJSON(json);
    if (!validation.isValid) {
      trackImport('json', false, { error: validation.error });
      return { success: false, error: validation.error };
    }

    try {
      const obj = JSON.parse(json);

      // Detect version: missing version = v1, explicit version 1 = v1, version 2 = v2
      const dataVersion = obj.version ?? 1; // Default to v1 if no version specified

      let answersImported = false;

      // Validate and import answers
      if (obj.answers && typeof obj.answers === 'object' && !Array.isArray(obj.answers)) {
        let answersToImport = obj.answers;

        // For v1 data (no version or version=1), ALWAYS migrate regardless of what needsMigration says
        // because v1 format uses text-based answers that must be converted to option IDs
        const shouldMigrate = dataVersion === 1;

        // Migrate v1 data to v2 format
        if (shouldMigrate) {

          const migrationResult = migrateAnswers(answersToImport, rawQuestions, t);
          answersToImport = migrationResult.answers;

          // Track migration during import
          trackEvent('imported_answers_migrated', {
            from_version: dataVersion,
            migrated_count: migrationResult.migratedCount,
            unmatched_count: migrationResult.unmatchedCount
          });
        }

        setAnswers(answersToImport);
        persist(ANSWERS_KEY, answersToImport);
        answersImported = Object.keys(answersToImport).length > 0;
      }

      // Validate and import domain scan aggregate
      if (
        obj.domainScanAggregate &&
        typeof obj.domainScanAggregate === 'object' &&
        !Array.isArray(obj.domainScanAggregate)
      ) {
        setDomainScanAggregate(obj.domainScanAggregate);
        persist(DOMAIN_AGG_KEY, obj.domainScanAggregate);
      }

      trackImport('json', true);

      // Return success with warning if no answers were actually imported
      if (!answersImported && !obj.domainScanAggregate) {
        return { success: false, error: 'No valid data found to import' };
      }

      return { success: true };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to parse JSON';
      trackImport('json', false, { error: errorMessage });
      return { success: false, error: errorMessage };
    }
  };

  return (
    <AppStateContext.Provider
      value={{
        questions,
        answers,
        setAnswer,
        resetAnswers,
        resetAll,
        score,
        risks,
        bestPractices,
        domainScanAggregate,
        scannerProgress,
        runScanners,
        exportJSON,
        importJSON
      }}
    >
      {children}
    </AppStateContext.Provider>
  );
};

export const useAppState = () => {
  const ctx = useContext(AppStateContext);
  if (!ctx) throw new Error('useAppState must be used within an AppStateProvider');
  return ctx;
};
