// Email Auth scanner: SPF / DMARC / DKIM with detailed policy validation.

import { DomainScanner, ExecutedScannerResult, ScannerInterpretation, SeverityLevel } from '../../types/domainScan';
import { fetchDNS, extractSPF, fetchDMARC, checkDKIM } from '../domainChecks';

export const emailAuthScanner: DomainScanner = {
  id: 'emailAuth',
  label: 'Email Authentication',
  description: 'Validates SPF, DMARC, and DKIM configuration for email security',
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
    const dkimSelectorsFound = await checkDKIM(domain);

    const issues: string[] = [];
    const warnings: string[] = [];

    // SPF Validation
    if (!spf) {
      issues.push('No SPF record found - your domain is vulnerable to email spoofing');
    } else {
      // Check SPF policy strength
      if (spf.includes('~all')) {
        // Soft fail is actually recommended with DMARC - no warning needed
        // With DMARC, ~all and -all have the same security properties
      } else if (spf.includes('-all')) {
        // Hard fail can cause deliverability issues with forwarded email
        if (dmarc && (dmarc.toLowerCase().includes('p=quarantine') || dmarc.toLowerCase().includes('p=reject'))) {
          warnings.push(
            'SPF uses hard fail (-all) which can cause deliverability issues with forwarded emails. ' +
            'Since you have DMARC enforcement, consider using soft fail (~all) instead - it provides ' +
            'the same security but better deliverability. ' +
            'See https://www.mailhardener.com/blog/why-mailhardener-recommends-spf-softfail-over-fail'
          );
        } else {
          // Hard fail without DMARC enforcement is actually weaker security
          warnings.push(
            'SPF uses hard fail (-all). For best security AND deliverability, combine soft fail (~all) ' +
            'with DMARC enforcement (p=quarantine or p=reject)'
          );
        }
      } else if (spf.includes('+all')) {
        issues.push('SPF allows all senders (+all) - this provides no protection against spoofing');
      } else if (spf.includes('?all')) {
        warnings.push('SPF uses neutral policy (?all) - consider using ~all with DMARC for protection');
      } else if (!spf.includes('all')) {
        warnings.push('SPF record missing "all" mechanism - add ~all to the end of your SPF record');
      }
      // Check for too many DNS lookups (SPF limit is 10)
      const includeCount = (spf.match(/include:/g) || []).length;
      const redirectCount = (spf.match(/redirect=/g) || []).length;
      const lookupCount = includeCount + redirectCount;
      if (lookupCount > 10) {
        issues.push(`SPF exceeds 10 DNS lookup limit (${lookupCount} found) - will cause validation failures`);
      } else if (lookupCount > 8) {
        warnings.push(`SPF has ${lookupCount} DNS lookups - limit is 10, you're close to the maximum`);
      }
    }

    // DMARC Validation
    if (!dmarc) {
      issues.push('No DMARC record found - email spoofing protection is incomplete');
    } else {
      const dmarcLower = dmarc.toLowerCase();

      // Check DMARC policy
      if (dmarcLower.includes('p=none')) {
        warnings.push('DMARC policy is "none" - monitoring only, no enforcement against spoofed emails');
      } else if (dmarcLower.includes('p=quarantine')) {
        // Quarantine is good, but reject is better
        warnings.push('DMARC policy is "quarantine" - consider upgrading to "reject" for maximum protection');
      } else if (dmarcLower.includes('p=reject')) {
        // Perfect! No warning needed
      } else {
        warnings.push('DMARC policy not clearly defined - ensure p=quarantine or p=reject is set');
      }

      // Check for subdomain policy
      if (!dmarcLower.includes('sp=')) {
        warnings.push('DMARC missing subdomain policy (sp=) - subdomains may not be protected');
      }

      // Check for reporting
      const hasRua = dmarcLower.includes('rua=');
      const hasRuf = dmarcLower.includes('ruf=');
      if (!hasRua && !hasRuf) {
        warnings.push('DMARC has no reporting emails (rua/ruf) - you won\'t receive abuse reports');
      }

      // Check percentage
      if (dmarcLower.includes('pct=') && !dmarcLower.includes('pct=100')) {
        const pctMatch = dmarcLower.match(/pct=(\d+)/);
        const pct = pctMatch ? pctMatch[1] : 'unknown';
        warnings.push(`DMARC applies to only ${pct}% of emails - consider increasing to pct=100`);
      }
    }

    // DKIM Validation
    if (dkimSelectorsFound.length === 0) {
      issues.push('No DKIM selectors detected - emails cannot be cryptographically verified');
      warnings.push(
        'Note: Checked ~40 common DKIM selectors used by major email providers. ' +
        'Custom/random selectors cannot be discovered via DNS queries alone.'
      );
      warnings.push(
        'To verify DKIM is configured, try: ' +
        '1) Check your email provider\'s documentation for your selector name, ' +
        '2) Use EasyDMARC\'s free DKIM Lookup tool (https://easydmarc.com/tools/dkim-lookup) to auto-detect, or ' +
        '3) Inspect email headers from sent emails for the DKIM-Signature "s=" parameter'
      );
    } else {
      warnings.push(
        `Found DKIM selector(s): ${dkimSelectorsFound.join(', ')}. ` +
        'Additional selectors may exist but cannot be automatically discovered.'
      );
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
      aggregateMessage = '✓ Email authentication fully configured with enforcement';
    } else if (hasSpf && hasDmarc && hasDkim) {
      aggregateMessage = '⚠ Email authentication configured but DMARC not enforcing (p=none)';
    } else if (hasSpf || hasDmarc || hasDkim) {
      const missing = [];
      if (!hasSpf) missing.push('SPF');
      if (!hasDmarc) missing.push('DMARC');
      if (!hasDkim) missing.push('DKIM');
      aggregateMessage = `⚠ Partial email authentication - missing: ${missing.join(', ')}`;
    } else {
      aggregateMessage = '✗ No email authentication configured - domain is vulnerable to spoofing';
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
    recommendation =
      'Excellent! Your domain has complete email authentication protecting against spoofing and phishing.';
  } else {
    const missing = [];
    if (!data?.hasSpf) missing.push('SPF');
    if (!data?.hasDmarc) missing.push('DMARC');
    if (!data?.hasDkim) missing.push('DKIM');

    if (missing.length > 0) {
      recommendation = `Configure ${missing.join(', ')} to protect your domain from email spoofing. `;
    }

    if (data?.hasDmarc && !data?.dmarcEnforced) {
      recommendation += 'Upgrade your DMARC policy from p=none to p=quarantine or p=reject for enforcement. ';
    }

    recommendation += 'Review the issues below for specific configuration improvements.';
  }

  return {
    severity,
    message,
    recommendation
  };
};
