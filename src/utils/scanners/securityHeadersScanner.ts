// Security Headers scanner: Fetches and parses results from securityheaders.com

import { DomainScanner, ExecutedScannerResult, ScannerInterpretation } from '../../types/domainScan';

export const securityHeadersScanner: DomainScanner = {
  id: 'securityHeaders',
  label: 'Security Headers',
  description: 'Analyzes HTTP security headers using securityheaders.com',
  timeout: 15000, // 15 seconds - external service
  dataSource: {
    name: 'securityheaders.com',
    url: 'https://securityheaders.com',
  },
  run: async (domain) => {
    const issues: string[] = [];
    const warnings: string[] = [];

    try {
      // Build the securityheaders.com URL
      const testUrl = `https://securityheaders.com/?q=${encodeURIComponent(domain)}&hide=on&followRedirects=on`;

      // Build the CORS proxy URL
      // We use corsproxy.io to proxy requests that we can't make directly from the browser. Normally, we would not use
      // a commercial proxy service for production code. However, since all of these data are publicly available, we are
      // using this service for convenience in this open source project. If you are forking this code for your own use,
      // consider hosting your own CORS proxy or making server-side requests instead.
      const proxyUrl = new URL('https://corsproxy.io/');
      proxyUrl.searchParams.set('url', testUrl);

      const response = await fetch(proxyUrl);
      if (!response.ok) {
        throw new Error(`securityheaders.com returned ${response.status}: ${response.statusText}`);
      }

      const html = await response.text();

      // Parse the grade from the HTML
      // The grade appears in a div with class "score" containing a div with class "score_*" and a span
      // Example: <div class="score"><div class="score_yellow"><span>B</span></div></div>
      const gradeMatch = html.match(
        /<div\s+class="score">\s*<div\s+class="score_[^"]*">\s*<span>([A-F][+-]?)<\/span>/i
      );
      const grade = gradeMatch ? gradeMatch[1] : null;

      // Parse the score from the HTML
      // The score appears in the reportTitle div
      // Example: <div class="reportTitle">...Score: 85...</div>
      const scoreMatch = html.match(/Score:\s*(\d+)/i);
      const score = scoreMatch ? parseInt(scoreMatch[1], 10) : null;

      // Parse missing headers from the "Missing Headers" section
      // Missing headers appear in a reportSection with reportTitle "Missing Headers"
      // Example: <th class="tableLabel table_red">Permissions-Policy</th>
      const missingHeadersSection = html.match(
        /<div class="reportTitle">Missing Headers<\/div>[\s\S]*?<div class="reportBody">([\s\S]*?)<\/div>\s*<\/div>/i
      );
      const missingHeaders: string[] = [];
      if (missingHeadersSection) {
        const headerMatches = missingHeadersSection[1].matchAll(
          /<th\s+class="tableLabel table_red">([^<]+)<\/th>/gi
        );
        for (const match of headerMatches) {
          const headerName = match[1].trim();
          if (headerName && !missingHeaders.includes(headerName)) {
            missingHeaders.push(headerName);
            issues.push(`Missing security header: ${headerName}`);
          }
        }
      }

      // Parse warnings from the "Warnings" section
      // Warnings appear in a reportSection with reportTitle "Warnings"
      // Example: <th class="tableLabel table_orange">Site is using HTTP</th>
      const warningsSection = html.match(
        /<div class="reportTitle">Warnings<\/div>[\s\S]*?<div class="reportBody">([\s\S]*?)<\/div>\s*<\/div>/i
      );
      if (warningsSection) {
        const warningMatches = warningsSection[1].matchAll(
          /<th\s+class="tableLabel table_orange">([^<]+)<\/th>/gi
        );
        for (const match of warningMatches) {
          const warningText = match[1].trim();
          if (warningText) {
            warnings.push(warningText);
          }
        }
      }

      // Parse present headers (if needed for data)
      // These would be in a different section, similar pattern
      const presentHeaders: string[] = [];
      // Note: We may not need to parse present headers if the grade/score is sufficient

      // Build summary
      let summary = '';
      if (grade) {
        summary = `Grade: ${grade}`;
        if (score !== null) {
          summary += ` (${score}/100)`;
        }
      } else if (score !== null) {
        summary = `Score: ${score}/100`;
      } else {
        summary = 'Security headers analyzed';
      }

      const data = {
        status: 'available',
        grade,
        score,
        testUrl,
        missingHeaders,
        presentHeaders,
      };

      const allIssues = [...issues, ...warnings];

      return {
        data,
        summary,
        issues: allIssues.length > 0 ? allIssues : undefined,
      };

    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';

      // If we can't reach the service, provide a fallback
      const testUrl = `https://securityheaders.com/?q=${encodeURIComponent(domain)}&hide=on&followRedirects=on`;

      return {
        data: {
          status: 'unavailable',
          error: errorMessage,
          testUrl
        },
        summary: 'Security headers check unavailable',
        issues: [`Could not retrieve security headers analysis: ${errorMessage}`]
      };
    }
  }
};

// Interpretation function for Security Headers scanner results
export const interpretSecurityHeadersResult = (
  scanner: ExecutedScannerResult,
  issueCount: number
): ScannerInterpretation => {
  const data = scanner.data as { status?: string; grade?: string; score?: number; testUrl?: string };
  if (data?.status === 'unavailable') {
    return {
      severity: 'info',
      message: 'Headers check unavailable',
      recommendation: data.testUrl
        ? `Visit ${data.testUrl} for a comprehensive security headers analysis.`
        : 'Visit securityheaders.com for a full analysis.'
    };
  }

  // Grade-based interpretation
  const grade = data?.grade || 'Unknown';
  const gradeMap: Record<string, { severity: 'success' | 'info' | 'warning' | 'critical'; message: string }> = {
    'A+': { severity: 'success', message: 'Excellent security headers (A+)' },
    'A': { severity: 'success', message: 'Great security headers (A)' },
    'B': { severity: 'info', message: 'Good security headers (B)' },
    'C': { severity: 'warning', message: 'Moderate security headers (C)' },
    'D': { severity: 'warning', message: 'Weak security headers (D)' },
    'E': { severity: 'critical', message: 'Poor security headers (E)' },
    'F': { severity: 'critical', message: 'Failed security headers (F)' },
  };

  const gradeInfo = gradeMap[grade] || {
    severity: 'info' as const,
    message: `Security headers analyzed (${grade})`
  };

  let recommendation = '';
  if (['A+', 'A'].includes(grade)) {
    recommendation = 'Your site has excellent security headers protecting against common web vulnerabilities. ';
  } else if (['B', 'C'].includes(grade)) {
    recommendation = 'Consider strengthening your security headers. ';
  } else if (['D', 'E', 'F'].includes(grade)) {
    recommendation = 'Your security headers need immediate attention. ';
  }

  if (issueCount > 0) {
    recommendation += `Missing ${issueCount} critical header(s). `;
  }

  return {
    severity: gradeInfo.severity,
    message: gradeInfo.message,
    recommendation: recommendation || 'Visit securityheaders.com for detailed analysis.'
  };
};
