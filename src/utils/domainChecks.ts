// Client-side domain assessment utilities relying on public APIs.
// NOTE: Some checks (full SSL chain, security headers via direct fetch) are limited by CORS in a static site.

export interface DNSRecordResult {
  type: string;
  data: string[];
}

export interface DomainScanResult {
  domain: string;
  timestamp: string;
  dns: DNSRecordResult[];
  spf?: string;
  dmarc?: string;
  dkimSelectorsFound: string[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  certificates?: any[]; // Raw crt.sh JSON rows
  issues: string[]; // Derived issue strings
}

export const fetchDNS = async (domain: string, rrtype: string): Promise<DNSRecordResult | null> => {
  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${rrtype}`);
    if (!res.ok) return null;
    const json = await res.json();
    if (!json.Answer) return { type: rrtype, data: [] };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = json.Answer.map((a: any) => a.data).filter((d: string) => !!d);
    return { type: rrtype, data };
  } catch {
    return null;
  }
};

export const fetchTXT = async (domain: string): Promise<string[]> => {
  const rec = await fetchDNS(domain, 'TXT');
  return rec?.data || [];
};

export const extractSPF = (txtRecords: string[]): string | undefined => {
  return txtRecords.find((r) => r.toLowerCase().startsWith('v=spf1'));
};

export const fetchDMARC = async (domain: string): Promise<string | undefined> => {
  const name = `_dmarc.${domain}`;
  const txt = await fetchTXT(name);
  return txt.find((t) => t.toLowerCase().includes('v=dmarc'));
};

export const checkDKIM = async (domain: string, customSelectors?: string[]): Promise<string[]> => {
  // If custom selectors are provided, use only those
  // Otherwise, fall back to common DKIM selectors used by major email providers
  const defaultSelectors = [
    // Generic/Common
    'default', 'dkim', 'mail', 'email', 'smtp',

    // Google Workspace / Gmail
    'google', 'googlemail',

    // Microsoft 365 / Office 365
    'selector1', 'selector2',

    // Common patterns
    'k1', 'k2', 'k3', 's1', 's2', 's3',
    'key1', 'key2', 'key3',
    'dkim1', 'dkim2', 'dkim3',

    // Marketing platforms
    'mailgun', 'sendgrid', 'mandrill', 'sparkpost',
    'mta', 'mta1', 'mta2',
    'pm', 'pm1', 'pm2', // Postmark
    'em', 'em1', 'em2', // Email service providers

    // Other common patterns
    'mx', 'mx1', 'mx2',
    'smtpapi', 'api',
    'marketing', 'transactional',
  ];

  const selectors = customSelectors && customSelectors.length > 0 ? customSelectors : defaultSelectors;

  const found: string[] = [];

  // Check all selectors in parallel for better performance
  const checks = selectors.map(async (sel) => {
    const name = `${sel}._domainkey.${domain}`;
    const txt = await fetchTXT(name);
    // Valid DKIM records contain either v=DKIM1 or p= with actual key data (not just "p=" or "p= ")
    if (txt.some((t) => {
      if (t.includes('v=DKIM1')) return true;
      // Check for p= with actual content (not empty or whitespace only)
      const pMatch = t.match(/p=([^;\s]+)/);
      return pMatch && pMatch[1] && pMatch[1].length > 0;
    })) {
      return sel;
    }
    return null;
  });

  const results = await Promise.all(checks);
  found.push(...results.filter((r): r is string => r !== null));

  return found;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const fetchCertificates = async (domain: string): Promise<any[] | undefined> => {
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`);
    if (!res.ok) return undefined;
    return await res.json();
  } catch {
    return undefined;
  }
};

export const deriveIssues = (scan: Partial<DomainScanResult>): string[] => {
  const issues: string[] = [];
  if (scan.spf === undefined) issues.push('Missing SPF record');
  if (scan.dmarc === undefined) issues.push('Missing DMARC record');
  if ((scan.dkimSelectorsFound || []).length === 0) issues.push('No DKIM selectors detected (heuristic)');
  return issues;
};
