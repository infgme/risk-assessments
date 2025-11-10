// Certificate enumeration scanner using crt.sh with security analysis

import { DomainScanner, ExecutedScannerResult, ScannerInterpretation, SeverityLevel } from '../../types/domainScan';
import { fetchCertificates } from '../domainChecks';

export const certificateScanner: DomainScanner = {
  id: 'certificates',
  label: 'SSL/TLS Certificates',
  description: 'Analyzes SSL certificates from public certificate transparency logs',
  timeout: 15000, // 15 seconds - external API call
  dataSource: {
    name: 'crt.sh',
    url: 'https://crt.sh',
  },
  run: async (domain) => {
    const certificates = await fetchCertificates(domain);

    if (!certificates || certificates.length === 0) {
      return {
        data: { certificates: [], certCount: 0 },
        summary: 'No certificates found in transparency logs',
        issues: ['No SSL certificates found - if you use HTTPS, this might indicate a very new certificate']
      };
    }

    const issues: string[] = [];
    const warnings: string[] = [];
    const now = new Date();

    // Parse and analyze certificates
    interface CertInfo {
      commonName: string;
      issuer: string;
      notBefore: Date;
      notAfter: Date;
      isExpired: boolean;
      daysUntilExpiry: number;
      id: number;
    }

    const parsedCerts: CertInfo[] = certificates.map((cert) => {
      const notBefore = new Date(cert.not_before);
      const notAfter = new Date(cert.not_after);
      const daysUntilExpiry = Math.floor((notAfter.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

      return {
        commonName: cert.common_name || cert.name_value || 'Unknown',
        issuer: cert.issuer_name || 'Unknown',
        notBefore,
        notAfter,
        isExpired: notAfter < now,
        daysUntilExpiry,
        id: cert.id
      };
    });

    // Get unique, non-expired certificates (most recent per common name)
    const certsByName = new Map<string, CertInfo>();
    parsedCerts
      .filter((cert) => !cert.isExpired)
      .sort((a, b) => b.notBefore.getTime() - a.notBefore.getTime()) // Most recent first
      .forEach((cert) => {
        if (!certsByName.has(cert.commonName)) {
          certsByName.set(cert.commonName, cert);
        }
      });

    const activeCerts = Array.from(certsByName.values());
    const expiredCerts = parsedCerts.filter((cert) => cert.isExpired);

    // Analysis 1: Check for expiring certificates
    const expiringIn30Days = activeCerts.filter((cert) => cert.daysUntilExpiry <= 30 && cert.daysUntilExpiry > 0);
    const expiringIn7Days = activeCerts.filter((cert) => cert.daysUntilExpiry <= 7 && cert.daysUntilExpiry > 0);

    if (expiringIn7Days.length > 0) {
      expiringIn7Days.forEach((cert) => {
        issues.push(
          `Certificate for ${cert.commonName} expires in ${cert.daysUntilExpiry} day(s) - renew immediately!`
        );
      });
    } else if (expiringIn30Days.length > 0) {
      expiringIn30Days.forEach((cert) => {
        warnings.push(
          `Certificate for ${cert.commonName} expires in ${cert.daysUntilExpiry} days - plan renewal soon`
        );
      });
    }

    // Analysis 2: Check certificate issuers (identify Let's Encrypt, self-signed, etc.)
    const selfSignedCerts = activeCerts.filter((cert) =>
      cert.issuer.toLowerCase().includes('self-signed') ||
      cert.commonName === cert.issuer
    );

    if (selfSignedCerts.length > 0) {
      issues.push(
        `${selfSignedCerts.length} self-signed certificate(s) detected - not trusted by browsers`
      );
    }

    // Analysis 3: Check for wildcard certificates
    const wildcardCerts = activeCerts.filter((cert) => cert.commonName.startsWith('*.'));
    if (wildcardCerts.length > 0) {
      warnings.push(
        `${wildcardCerts.length} wildcard certificate(s) found - ensure proper security controls`
      );
    }

    // Analysis 4: Detect unusual number of active certificates
    if (activeCerts.length > 10) {
      warnings.push(
        `High number of active certificates (${activeCerts.length}) - review for unnecessary or duplicate certs`
      );
    }

    // Analysis 5: Check for recent expired certificates (potential renewal issues)
    const recentlyExpired = expiredCerts.filter((cert) => {
      const daysSinceExpiry = Math.floor((now.getTime() - cert.notAfter.getTime()) / (1000 * 60 * 60 * 24));
      return daysSinceExpiry <= 30;
    });

    // Only warn about recently expired certs that don't have an active replacement
    const expiredWithoutReplacement = recentlyExpired.filter((expired) => {
      // Check if there's an active cert for the same common name
      return !activeCerts.some((active) => active.commonName === expired.commonName);
    });

    if (expiredWithoutReplacement.length > 0) {
      const certNames = expiredWithoutReplacement.map((cert) => cert.commonName).join(', ');
      warnings.push(
        `${expiredWithoutReplacement.length} certificate(s) expired recently without replacement: ${certNames}`
      );
    }

    // Analysis 6: Check issuer diversity (too many different CAs might indicate issues)
    const uniqueIssuers = new Set(activeCerts.map((cert) => cert.issuer));
    if (uniqueIssuers.size > 3) {
      warnings.push(
        `Certificates from ${uniqueIssuers.size} different issuers - consider standardizing on fewer CAs`
      );
    }

    // Build summary
    const allIssues = [...issues, ...warnings];
    let summary = `Found ${certificates.length} total certificates`;
    if (activeCerts.length > 0) {
      summary += `, ${activeCerts.length} currently active`;
    }
    if (expiredCerts.length > 0) {
      summary += `, ${expiredCerts.length} expired`;
    }

    // Add data for UI display
    const data = {
      certificates,
      certCount: certificates.length,
      activeCertCount: activeCerts.length,
      expiredCertCount: expiredCerts.length,
      activeCerts: activeCerts.slice(0, 10), // Limit for display
      expiringIn30Days: expiringIn30Days.length,
      expiringIn7Days: expiringIn7Days.length,
      wildcardCount: wildcardCerts.length,
      uniqueIssuers: Array.from(uniqueIssuers).slice(0, 5), // Top 5 issuers
      expiredWithoutReplacement: expiredWithoutReplacement.map((cert) => cert.commonName),
    };

    return {
      data,
      summary,
      issues: allIssues
    };
  }
};

// Interpretation function for Certificate scanner results
export const interpretCertificateResult = (
  scanner: ExecutedScannerResult,
  issueCount: number
): ScannerInterpretation => {
  const data = scanner.data as {
    certCount?: number;
    activeCertCount?: number;
    expiredCertCount?: number;
    expiringIn7Days?: number;
    expiringIn30Days?: number;
  };

  const certCount = data?.certCount || 0;
  const activeCertCount = data?.activeCertCount || 0;
  const expiringIn7Days = data?.expiringIn7Days || 0;
  const expiringIn30Days = data?.expiringIn30Days || 0;

  // Determine severity based on certificate status
  let severity: SeverityLevel;
  let message: string;
  let recommendation: string;

  if (certCount === 0) {
    severity = 'info';
    message = 'No certificates found';
    recommendation = 'No SSL certificates found in public certificate transparency logs. ' +
      'If you use HTTPS, this might indicate a very new certificate or the certificate is not yet logged.';
  } else if (expiringIn7Days > 0) {
    severity = 'critical';
    message = `${expiringIn7Days} certificate(s) expiring within 7 days!`;
    recommendation = 'Renew expiring certificates immediately to avoid service disruption. ' +
      'Consider setting up automated renewal (e.g., using Let\'s Encrypt with auto-renewal).';
  } else if (expiringIn30Days > 0) {
    severity = 'warning';
    message = `${expiringIn30Days} certificate(s) expiring within 30 days`;
    recommendation = 'Plan to renew certificates soon to avoid last-minute issues. ' +
      'Set up monitoring alerts for certificate expiration.';
  } else if (issueCount > 0) {
    severity = 'warning';
    message = `${activeCertCount} active certificate(s), ${issueCount} issue(s) detected`;
    recommendation = 'Review the certificate issues below. Consider cleaning up expired certificates ' +
      'and standardizing on a single Certificate Authority.';
  } else {
    severity = 'success';
    message = `${activeCertCount} valid certificate(s) found`;
    recommendation = activeCertCount > 50
      ? 'Large number of certificates found. Regularly review and remove unnecessary certificates.'
      : 'Certificate transparency logs show your domain has valid SSL certificates with no immediate issues.';
  }

  return {
    severity,
    message,
    recommendation
  };
};
