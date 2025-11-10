// DNS Scanner: collects common record types and validates configuration.

import { DomainScanner, ExecutedScannerResult, ScannerInterpretation } from '../../types/domainScan';
import { fetchDNS } from '../domainChecks';

export const dnsScanner: DomainScanner = {
  id: 'dns',
  label: 'DNS Records',
  description: 'Retrieves A, AAAA, MX, TXT, CNAME records and validates configuration',
  timeout: 5000, // 5 seconds - DNS should be fast
  dataSource: {
    name: 'Google Public DNS',
    url: 'https://dns.google',
  },
  run: async (domain) => {
    const types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME'];
    const records = [] as { type: string; data: string[] }[];
    for (const t of types) {
      const r = await fetchDNS(domain, t);
      if (r) records.push(r);
    }

    // Validate DNS configuration and detect issues
    const issues: string[] = [];
    const aRecords = records.find((r) => r.type === 'A')?.data || [];
    const aaaaRecords = records.find((r) => r.type === 'AAAA')?.data || [];
    const mxRecords = records.find((r) => r.type === 'MX')?.data || [];
    const cnameRecords = records.find((r) => r.type === 'CNAME')?.data || [];
    const txtRecords = records.find((r) => r.type === 'TXT')?.data || [];

    // Critical: No A or AAAA records means the domain won't resolve
    if (aRecords.length === 0 && aaaaRecords.length === 0 && cnameRecords.length === 0) {
      issues.push('No A, AAAA, or CNAME records found - domain may not be accessible via web browser');
    }

    // Check for reserved/private IP addresses in A records
    const reservedIPs = ['127.', '0.0.0.0', '10.', '172.16.', '192.168.', '169.254.'];
    aRecords.forEach((ip) => {
      if (reservedIPs.some((reserved) => ip.startsWith(reserved))) {
        issues.push(`A record contains reserved/private IP: ${ip} - should be a public IP`);
      }
    });

    // CNAME conflicts: CNAME cannot coexist with other record types at the same name
    if (cnameRecords.length > 0) {
      if (aRecords.length > 0 || aaaaRecords.length > 0 || mxRecords.length > 0) {
        issues.push('CNAME conflict detected - CNAME records cannot coexist with A, AAAA, or MX records');
      }
      if (cnameRecords.length > 1) {
        issues.push('Multiple CNAME records found - only one CNAME record should exist per name');
      }
    }

    // Excessive A records might indicate misconfiguration or compromise
    if (aRecords.length > 10) {
      issues.push(`Unusually high number of A records (${aRecords.length}) - verify this is intentional`);
    }

    // No MX records means email won't work for this domain
    if (mxRecords.length === 0) {
      issues.push('No MX records found - email delivery to this domain will fail');
    }

    // Check for overly long TXT records (SPF/DKIM often have this issue)
    txtRecords.forEach((txt) => {
      if (txt.length > 255) {
        // Note: DNS can split these, but it's a common misconfiguration point
        issues.push('TXT record exceeds 255 characters - may cause issues with some DNS resolvers');
      }
    });

    // Check if MX records point to IP addresses (should be hostnames)
    mxRecords.forEach((mx) => {
      // MX format is "priority hostname" e.g., "10 mail.example.com."
      const parts = mx.split(' ');
      const hostname = parts[1] || parts[0];
      // Simple IP detection (contains only digits and dots)
      if (/^\d+\.\d+\.\d+\.\d+\.?$/.test(hostname)) {
        issues.push(`MX record points to IP address (${hostname}) - should point to a hostname`);
      }
    });

    // Build summary with record counts
    const recordCounts = records.map((r) => `${r.type}:${r.data.length}`).join(', ');
    const summary = records.length > 0
      ? `Found ${recordCounts}`
      : 'No DNS records found';

    return {
      data: { records },
      summary,
      issues,
    };
  }
};

// Interpretation function for DNS scanner results
export const interpretDnsResult = (
  scanner: ExecutedScannerResult,
  issueCount: number
): ScannerInterpretation => {
  if (issueCount === 0) {
    return {
      severity: 'success',
      message: 'DNS records retrieved successfully',
      recommendation: 'Your domain\'s DNS configuration is accessible and responding normally.'
    };
  } else if (issueCount <= 2) {
    return {
      severity: 'warning',
      message: 'DNS configuration has warnings',
      recommendation: 'Review the DNS issues detected. These may indicate misconfigurations that could affect ' +
        'website accessibility or email delivery.'
    };
  } else {
    return {
      severity: 'critical',
      message: 'DNS configuration has critical issues',
      recommendation: 'Multiple DNS problems detected. These issues may prevent your domain from functioning ' +
        'correctly. Review and fix DNS records immediately.'
    };
  }
};
