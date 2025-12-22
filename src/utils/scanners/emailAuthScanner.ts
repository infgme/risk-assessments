// Email Auth scanner: SPF / DMARC / DKIM with detailed policy validation.

import i18next from 'i18next';
import { DomainScanner, ExecutedScannerResult, ScannerInterpretation, SeverityLevel } from '../../types/domainScan';
import { fetchDNS, extractSPF, fetchDMARC, checkDKIM } from '../domainChecks';
import { getDkimSelectors } from '../dkimSelectorsService';

export const emailAuthScanner: DomainScanner = {
  id: 'emailAuth',
  label: 'emailAuth.label',
  description: 'emailAuth.description',
  timeout: 10000, // 10 seconds - multiple DNS lookups
  dataSource: {
    name: 'Google Public DNS',
    url: 'https://dns.google',
  },
  run: async (domain) => {
    const txtRec = await fetchDNS(domain, 'TXT');
    const txtRecords = txtRec?.data || [];
    const spf = extractSPF(txtRecords);
    const dmarc = await fetchDMARC(domain);

    // Get custom DKIM selectors from localStorage if available
    const customSelectors = getDkimSelectors(domain);
    const dkimSelectorsFound = await checkDKIM(domain, customSelectors.length > 0 ? customSelectors : undefined);

    const issues: string[] = [];
    const warnings: string[] = [];

    // SPF Validation
    if (!spf) {
      issues.push(i18next.t('emailAuth.issues.noSPF', { ns: 'scanners' }));
    } else {
      // Check SPF policy strength
      if (spf.includes('~all')) {
        // Soft fail is actually recommended with DMARC - no warning needed
        // With DMARC, ~all and -all have the same security properties
      } else if (spf.includes('-all')) {
        // Hard fail can cause deliverability issues with forwarded email
        if (dmarc && (dmarc.toLowerCase().includes('p=quarantine') || dmarc.toLowerCase().includes('p=reject'))) {
          warnings.push(i18next.t('emailAuth.issues.spfHardFailWithDMARC', { ns: 'scanners' }));
        } else {
          // Hard fail without DMARC enforcement is actually weaker security
          warnings.push(i18next.t('emailAuth.issues.spfHardFailNoDMARC', { ns: 'scanners' }));
        }
      } else if (spf.includes('+all')) {
        issues.push(i18next.t('emailAuth.issues.spfAllowAll', { ns: 'scanners' }));
      } else if (spf.includes('?all')) {
        warnings.push(i18next.t('emailAuth.issues.spfNeutral', { ns: 'scanners' }));
      } else if (!spf.includes('all')) {
        warnings.push(i18next.t('emailAuth.issues.spfMissingAll', { ns: 'scanners' }));
      }
      // Check for too many DNS lookups (SPF limit is 10)
      const includeCount = (spf.match(/include:/g) || []).length;
      const redirectCount = (spf.match(/redirect=/g) || []).length;
      const lookupCount = includeCount + redirectCount;
      if (lookupCount > 10) {
        issues.push(i18next.t('emailAuth.issues.spfLookupLimit', { ns: 'scanners', count: lookupCount }));
      } else if (lookupCount > 8) {
        warnings.push(i18next.t('emailAuth.issues.spfLookupWarning', { ns: 'scanners', count: lookupCount }));
      }
    }

    // DMARC Validation
    if (!dmarc) {
      issues.push(i18next.t('emailAuth.issues.noDMARC', { ns: 'scanners' }));
    } else {
      const dmarcLower = dmarc.toLowerCase();

      // Check DMARC policy
      if (dmarcLower.includes('p=none')) {
        warnings.push(i18next.t('emailAuth.issues.dmarcNone', { ns: 'scanners' }));
      } else if (dmarcLower.includes('p=quarantine')) {
        // Quarantine is good, but reject is better
        warnings.push(i18next.t('emailAuth.issues.dmarcQuarantine', { ns: 'scanners' }));
      } else if (dmarcLower.includes('p=reject')) {
        // Perfect! No warning needed
      } else {
        warnings.push(i18next.t('emailAuth.issues.dmarcNoPolicyDefined', { ns: 'scanners' }));
      }

      // Check for subdomain policy
      if (!dmarcLower.includes('sp=')) {
        warnings.push(i18next.t('emailAuth.issues.dmarcNoSubdomain', { ns: 'scanners' }));
      }

      // Check for reporting
      const hasRua = dmarcLower.includes('rua=');
      const hasRuf = dmarcLower.includes('ruf=');
      if (!hasRua && !hasRuf) {
        warnings.push(i18next.t('emailAuth.issues.dmarcNoReporting', { ns: 'scanners' }));
      }

      // Check percentage
      if (dmarcLower.includes('pct=') && !dmarcLower.includes('pct=100')) {
        const pctMatch = dmarcLower.match(/pct=(\d+)/);
        const pct = pctMatch ? pctMatch[1] : 'unknown';
        warnings.push(i18next.t('emailAuth.issues.dmarcPercentage', { ns: 'scanners', pct }));
      }
    }

    // DKIM Validation
    if (dkimSelectorsFound.length === 0) {
      issues.push(i18next.t('emailAuth.issues.noDKIM', { ns: 'scanners' }));
      warnings.push(i18next.t('emailAuth.issues.dkimNote', { ns: 'scanners' }));
      warnings.push(i18next.t('emailAuth.issues.dkimVerify', { ns: 'scanners' }));
    }

    // Aggregate assessment
    const hasSpf = !!spf;
    const hasDmarc = !!dmarc;
    const hasDkim = dkimSelectorsFound.length > 0;
    const dmarcEnforced = dmarc && (dmarc.toLowerCase().includes('p=quarantine') ||
                                     dmarc.toLowerCase().includes('p=reject'));

    // Build aggregate message
    let aggregateMessage = '';
    if (hasSpf && hasDmarc && hasDkim && dmarcEnforced) {
      aggregateMessage = i18next.t('emailAuth.aggregate.fullAuth', { ns: 'scanners' });
    } else if (hasSpf && hasDmarc && hasDkim) {
      aggregateMessage = i18next.t('emailAuth.aggregate.noEnforcement', { ns: 'scanners' });
    } else if (hasSpf || hasDmarc || hasDkim) {
      const missing = [];
      if (!hasSpf) missing.push('SPF');
      if (!hasDmarc) missing.push('DMARC');
      if (!hasDkim) missing.push('DKIM');
      aggregateMessage = i18next.t('emailAuth.aggregate.partial', { ns: 'scanners', missing: missing.join(', ') });
    } else {
      aggregateMessage = i18next.t('emailAuth.aggregate.none', { ns: 'scanners' });
    }

    // Combine issues and warnings
    const allIssues = [...issues, ...warnings];

    const data = {
      spf,
      dmarc,
      dkimSelectorsFound,
      aggregateMessage,
      hasSpf,
      hasDmarc,
      hasDkim,
      dmarcEnforced
    };

    const summary = aggregateMessage;

    return {
      data,
      summary,
      issues: allIssues
    };
  }
};

// Interpretation function for Email Auth scanner results
export const interpretEmailAuthResult = (
  scanner: ExecutedScannerResult,
  issueCount: number
): ScannerInterpretation => {
  const data = scanner.data as {
    hasSpf?: boolean;
    hasDmarc?: boolean;
    hasDkim?: boolean;
    dmarcEnforced?: boolean;
    aggregateMessage?: string;
  };

  // Use the aggregate message from the scanner for consistent messaging
  const message = data?.aggregateMessage ||
    (issueCount === 0 ? 'Email authentication configured' : 'Email authentication issues detected');

  // Determine severity based on what's configured
  let severity: SeverityLevel;
  if (data?.hasSpf && data?.hasDmarc && data?.hasDkim && data?.dmarcEnforced) {
    severity = 'success';
  } else if (data?.hasSpf && data?.hasDmarc && data?.hasDkim) {
    severity = 'warning'; // Has all three but DMARC not enforcing
  } else if ((data?.hasSpf || data?.hasDmarc || data?.hasDkim)) {
    severity = 'warning'; // Partial configuration
  } else {
    severity = 'critical'; // Nothing configured
  }

  // Build recommendation based on what's missing/weak
  let recommendation = '';
  if (data?.hasSpf && data?.hasDmarc && data?.hasDkim && data?.dmarcEnforced) {
    recommendation = i18next.t('emailAuth.interpretation.excellent.recommendation', { ns: 'scanners' });
  } else {
    const missing = [];
    if (!data?.hasSpf) missing.push('SPF');
    if (!data?.hasDmarc) missing.push('DMARC');
    if (!data?.hasDkim) missing.push('DKIM');

    if (missing.length > 0) {
      recommendation = i18next.t('emailAuth.interpretation.partial.recommendation', {
        ns: 'scanners',
        missing: missing.join(', ')
      });
    } else if (data?.hasDmarc && !data?.dmarcEnforced) {
      recommendation = i18next.t('emailAuth.interpretation.upgradePolicy.recommendation', { ns: 'scanners' });
    } else {
      recommendation = i18next.t('emailAuth.interpretation.configured.recommendation', {
        ns: 'scanners',
        missing: ''
      });
    }
  }

  return {
    severity,
    message,
    recommendation
  };
};
