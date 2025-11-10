// SSL Labs scanner: TLS/SSL configuration analysis using SSLLabs API
// Note: This scanner uses polling since SSL Labs processes scans asynchronously

import { DomainScanner, ExecutedScannerResult, ScannerInterpretation, SeverityLevel } from '../../types/domainScan';

export const sslLabsScanner: DomainScanner = {
  id: 'sslLabs',
  label: 'SSL/TLS Configuration',
  description: 'Analyzes SSL/TLS configuration using Qualys SSL Labs (may take several minutes)',
  timeout: 600000, // 10 minutes - SSL Labs can take a while with polling
  dataSource: {
    name: 'Qualys SSL Labs',
    url: 'https://www.ssllabs.com/ssltest/',
  },
  run: async (domain) => {
    const warnings: string[] = [];
    const issues: string[] = [];

    // Type definitions for SSL Labs API responses
    interface SSLLabsProtocol {
      name: string;
      version: string;
    }

    interface SSLLabsCertChain {
      issues?: number;
    }

    interface SSLLabsEndpointDetails {
      protocols?: SSLLabsProtocol[];
      vulnBeast?: boolean;
      poodle?: boolean;
      heartbleed?: boolean;
      freak?: boolean;
      logjam?: boolean;
      drownVulnerable?: boolean;
      certChains?: SSLLabsCertChain[];
      forwardSecrecy?: number;
      hstsPolicy?: {
        status: string;
        maxAge?: number;
      };
    }

    interface SSLLabsEndpoint {
      ipAddress: string;
      grade?: string;
      statusMessage?: string;
      hasWarnings?: boolean;
      isExceptional?: boolean;
      details?: SSLLabsEndpointDetails;
    }

    interface SSLLabsResult {
      status: string;
      statusMessage?: string;
      endpoints?: SSLLabsEndpoint[];
    }

    // Helper function to fetch analysis status
    const fetchAnalysis = async (fromCache: boolean = true, startNew: boolean = false) => {
      // Build the SSL Labs API URL
      const sslLabsUrl = new URL('https://api.ssllabs.com/api/v3/analyze');
      sslLabsUrl.searchParams.append('host', domain);
      sslLabsUrl.searchParams.append('fromCache', fromCache ? 'on' : 'off');
      sslLabsUrl.searchParams.append('all', 'done');
      if (startNew) {
        sslLabsUrl.searchParams.append('startNew', 'on');
      }

      // Build the CORS proxy URL with key first, then url parameter
      // We use corsproxy.io to proxy requests that we can't make directly from the browser. Normally, we would not use
      // a commercial proxy service for production code. However, since all of these data are publicly available, we are
      // using this service for convenience in this open source project. If you are forking this code for your own use,
      // consider hosting your own CORS proxy or making server-side requests instead.
      const proxyUrl = new URL('https://corsproxy.io/');
      // TODO: Currently, the API documentation for CORS Proxy says a key is required from a non-localhost domain.
      // However, when the key is provided, their API returns a 403 error with a bad URL, which suggests they are
      // parsing the querystring incorrectly. For now, we will omit the key to allow things to work, but we expect that
      // the API will be fixed in the future and this key will be required again.
      // proxyUrl.searchParams.set('key', '54aed9d2');
      proxyUrl.searchParams.set('url', sslLabsUrl.toString());

      const response = await fetch(proxyUrl);
      if (!response.ok) {
        throw new Error(`SSL Labs API returned ${response.status}: ${response.statusText}`);
      }

      return await response.json() as SSLLabsResult;
    };

    try {
      // First, try to get cached results
      let result: SSLLabsResult = await fetchAnalysis(true, false);

      // If no cached results or scan in progress, we may need to poll
      const maxPolls = 20; // Maximum 20 polls (10 minutes at 30 second intervals)
      const pollInterval = 30000; // 30 seconds
      let pollCount = 0;

      while (result.status !== 'READY' && result.status !== 'ERROR' && pollCount < maxPolls) {
        // If status is DNS, IN_PROGRESS, wait and poll again
        if (result.status === 'DNS' || result.status === 'IN_PROGRESS') {
          await new Promise((resolve) => setTimeout(resolve, pollInterval));
          result = await fetchAnalysis(true, false);
          pollCount++;
        } else {
          // For other statuses, break
          break;
        }
      }

      // Handle different result statuses
      if (result.status === 'ERROR') {
        return {
          data: { status: result.status, statusMessage: result.statusMessage },
          summary: `SSL Labs scan error: ${result.statusMessage || 'Unknown error'}`,
          issues: [`SSL Labs could not scan this domain: ${result.statusMessage || 'Unknown error'}`]
        };
      }

      if (result.status !== 'READY') {
        return {
          data: { status: result.status },
          summary: `SSL Labs scan still in progress (status: ${result.status})`,
          issues: ['Scan timed out or is still processing. Try again later or visit ssllabs.com for full results.']
        };
      }

      // Process READY results
      const endpoints = result.endpoints || [];

      if (endpoints.length === 0) {
        return {
          data: { status: result.status, endpoints: [] },
          summary: 'No SSL/TLS endpoints found',
          issues: ['No HTTPS endpoints detected for this domain']
        };
      }

      // Analyze each endpoint
      const grades: string[] = [];
      let lowestGradeValue = 100;
      const gradeMap: Record<string, number> = {
        'A+': 100, 'A': 95, 'A-': 90, 'B': 80, 'C': 70, 'D': 60, 'E': 50, 'F': 40, 'T': 30, 'M': 20
      };

      endpoints.forEach((endpoint: SSLLabsEndpoint) => {
        if (endpoint.grade) {
          grades.push(endpoint.grade);
          const gradeValue = gradeMap[endpoint.grade] || 0;
          lowestGradeValue = Math.min(lowestGradeValue, gradeValue);
        }

        // Check for specific issues
        if (endpoint.statusMessage && endpoint.statusMessage !== 'Ready') {
          warnings.push(`Endpoint ${endpoint.ipAddress}: ${endpoint.statusMessage}`);
        }

        // Analyze protocol support
        if (endpoint.details) {
          const details = endpoint.details;

          // Check for outdated protocols
          if (details.protocols) {
            const hasSSLv2 = details.protocols.some((p: SSLLabsProtocol) =>
              p.name === 'SSL' && p.version === '2.0');
            const hasSSLv3 = details.protocols.some((p: SSLLabsProtocol) =>
              p.name === 'SSL' && p.version === '3.0');
            const hasTLS10 = details.protocols.some((p: SSLLabsProtocol) =>
              p.name === 'TLS' && p.version === '1.0');
            const hasTLS11 = details.protocols.some((p: SSLLabsProtocol) =>
              p.name === 'TLS' && p.version === '1.1');

            if (hasSSLv2 || hasSSLv3) {
              issues.push(`Endpoint ${endpoint.ipAddress}: Supports deprecated SSL protocols (SSLv2/SSLv3)`);
            }
            if (hasTLS10 || hasTLS11) {
              warnings.push(`Endpoint ${endpoint.ipAddress}: Supports outdated TLS 1.0/1.1 protocols`);
            }
          }

          // Check for vulnerabilities
          if (details.vulnBeast) {
            warnings.push(`Endpoint ${endpoint.ipAddress}: Vulnerable to BEAST attack`);
          }
          if (details.poodle) {
            issues.push(`Endpoint ${endpoint.ipAddress}: Vulnerable to POODLE attack`);
          }
          if (details.heartbleed) {
            issues.push(`Endpoint ${endpoint.ipAddress}: Vulnerable to Heartbleed`);
          }
          if (details.freak) {
            issues.push(`Endpoint ${endpoint.ipAddress}: Vulnerable to FREAK attack`);
          }
          if (details.logjam) {
            warnings.push(`Endpoint ${endpoint.ipAddress}: Vulnerable to Logjam attack`);
          }
          if (details.drownVulnerable) {
            issues.push(`Endpoint ${endpoint.ipAddress}: Vulnerable to DROWN attack`);
          }

          // Check certificate issues
          if (details.certChains) {
            details.certChains.forEach((chain: SSLLabsCertChain, idx: number) => {
              if (chain.issues) {
                if (chain.issues & 1) {
                  warnings.push(`Endpoint ${endpoint.ipAddress}: Certificate chain ${idx + 1} has issues`);
                }
              }
            });
          }

          // Check for forward secrecy
          if (details.forwardSecrecy === 0) {
            warnings.push(`Endpoint ${endpoint.ipAddress}: Does not support forward secrecy`);
          } else if (details.forwardSecrecy === 1) {
            warnings.push(`Endpoint ${endpoint.ipAddress}: Forward secrecy with some browsers only`);
          }

          // Check for HSTS
          if (!details.hstsPolicy || details.hstsPolicy.status === 'absent') {
            warnings.push(`Endpoint ${endpoint.ipAddress}: HSTS not configured`);
          } else if (details.hstsPolicy.status === 'present' &&
                     details.hstsPolicy.maxAge &&
                     details.hstsPolicy.maxAge < 15768000) {
            warnings.push(`Endpoint ${endpoint.ipAddress}: HSTS max-age is too short (should be 6+ months)`);
          }
        }
      });

      // Build summary
      const uniqueGrades = [...new Set(grades)].sort((a, b) => a.localeCompare(b));
      const gradeText = uniqueGrades.length > 0 ? uniqueGrades.join(', ') : 'No grade';
      const allIssues = [...issues, ...warnings];

      let summary = `${endpoints.length} endpoint(s) scanned`;
      if (uniqueGrades.length > 0) {
        summary += `, grade(s): ${gradeText}`;
      }

      // Add data for UI
      const data = {
        status: result.status,
        endpoints: endpoints.map((ep: SSLLabsEndpoint) => ({
          ipAddress: ep.ipAddress,
          grade: ep.grade,
          hasWarnings: ep.hasWarnings,
          isExceptional: ep.isExceptional,
        })),
        grades: uniqueGrades,
        lowestGrade: uniqueGrades[uniqueGrades.length - 1] || null,
        testUrl: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(domain)}`,
      };

      return {
        data,
        summary,
        issues: allIssues
      };

    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      return {
        data: { error: errorMessage },
        summary: 'SSL Labs scan failed',
        issues: [`Failed to scan SSL/TLS configuration: ${errorMessage}`]
      };
    }
  }
};

// Interpretation function for SSL Labs scanner results
export const interpretSslLabsResult = (
  scanner: ExecutedScannerResult,
  issueCount: number
): ScannerInterpretation => {
  const data = scanner.data as {
    status?: string;
    grades?: string[];
    lowestGrade?: string;
    endpoints?: unknown[];
    testUrl?: string;
    error?: string;
  };

  if (data?.status === 'ERROR') {
    return {
      severity: 'error',
      message: 'SSL Labs could not scan this domain',
      recommendation: 'The domain may not support HTTPS or SSL Labs cannot reach it. ' +
        'Verify the domain is accessible.'
    };
  }

  if (data?.status !== 'READY') {
    return {
      severity: 'info',
      message: 'SSL Labs scan in progress',
      recommendation: data?.testUrl
        ? `Visit ${data.testUrl} to see the scan progress and full results.`
        : 'Try scanning again in a few minutes for complete results.'
    };
  }

  const lowestGrade = data?.lowestGrade;
  const gradeMap: Record<string, { severity: SeverityLevel; message: string }> = {
    'A+': { severity: 'success', message: 'Excellent SSL/TLS configuration (A+)' },
    'A': { severity: 'success', message: 'Excellent SSL/TLS configuration (A)' },
    'A-': { severity: 'success', message: 'Good SSL/TLS configuration (A-)' },
    'B': { severity: 'warning', message: 'Acceptable SSL/TLS configuration (B)' },
    'C': { severity: 'warning', message: 'Mediocre SSL/TLS configuration (C)' },
    'D': { severity: 'critical', message: 'Weak SSL/TLS configuration (D)' },
    'E': { severity: 'critical', message: 'Poor SSL/TLS configuration (E)' },
    'F': { severity: 'critical', message: 'Failed SSL/TLS configuration (F)' },
    'T': { severity: 'critical', message: 'Certificate trust issues (T)' },
    'M': { severity: 'critical', message: 'Certificate name mismatch (M)' }
  };

  const gradeInfo = (lowestGrade && gradeMap[lowestGrade]) || {
    severity: 'info' as SeverityLevel,
    message: 'SSL/TLS configuration analyzed'
  };

  let recommendation = '';
  if (lowestGrade && ['A+', 'A', 'A-'].includes(lowestGrade)) {
    recommendation = 'Your SSL/TLS configuration follows security best practices. ';
  } else if (lowestGrade && ['B', 'C'].includes(lowestGrade)) {
    recommendation = 'Your SSL/TLS configuration could be improved. Consider upgrading cipher suites, ' +
      'disabling older protocols, and enabling HSTS. ';
  } else if (lowestGrade && ['D', 'E', 'F', 'T', 'M'].includes(lowestGrade)) {
    recommendation = 'Your SSL/TLS configuration has serious issues that need immediate attention. ' +
      'Update your TLS configuration, disable weak ciphers and outdated protocols. ';
  }

  if (issueCount > 0) {
    recommendation += `${issueCount} specific issue(s) detected - review them below. `;
  }

  if (data?.testUrl) {
    recommendation += 'View the complete SSL Labs report for detailed recommendations.';
  }

  return {
    severity: gradeInfo.severity,
    message: gradeInfo.message,
    recommendation: recommendation || 'SSL/TLS configuration analyzed. Review any issues detected.'
  };
};
