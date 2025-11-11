import { describe, it, expect, vi, beforeEach } from 'vitest';
import { emailAuthScanner, interpretEmailAuthResult } from './emailAuthScanner';
import * as domainChecks from '../domainChecks';

// Mock domainChecks module
vi.mock('../domainChecks', () => ({
  fetchDNS: vi.fn(),
  extractSPF: vi.fn(),
  fetchDMARC: vi.fn(),
  checkDKIM: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('emailAuthScanner', () => {
  it('should have correct scanner metadata', () => {
    expect(emailAuthScanner.id).toBe('emailAuth');
    expect(emailAuthScanner.label).toBe('Email Authentication');
    expect(emailAuthScanner.description).toBeDefined();
    expect(emailAuthScanner.timeout).toBe(10000);
    expect(emailAuthScanner.dataSource).toBeDefined();
  });

  it('should detect missing SPF record', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: [] });
    mockExtractSPF.mockReturnValue(null);
    mockFetchDMARC.mockResolvedValue(null);
    mockCheckDKIM.mockResolvedValue([]);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues).toContain('No SPF record found - your domain is vulnerable to email spoofing');
  });

  it('should NOT warn about SPF soft fail (~all) as it is recommended', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=reject; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    // Should NOT have any warnings about upgrading ~all to -all
    const spfWarnings = result.issues?.filter((issue) => issue.includes('soft fail') && issue.includes('hard fail'));
    expect(spfWarnings?.length || 0).toBe(0);
  });

  it('should warn about SPF hard fail (-all) when DMARC is enforced', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 -all'] });
    mockExtractSPF.mockReturnValue('v=spf1 -all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) =>
      issue.includes('hard fail (-all)') &&
      issue.includes('deliverability issues') &&
      issue.includes('soft fail (~all)')
    )).toBe(true);
  });

  it('should warn about SPF hard fail (-all) when DMARC is NOT enforced', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 -all'] });
    mockExtractSPF.mockReturnValue('v=spf1 -all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=none; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) =>
      issue.includes('hard fail (-all)') &&
      issue.includes('soft fail (~all)') &&
      issue.includes('DMARC enforcement')
    )).toBe(true);
  });

  it('should detect SPF +all policy', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 +all'] });
    mockExtractSPF.mockReturnValue('v=spf1 +all');
    mockFetchDMARC.mockResolvedValue(null);
    mockCheckDKIM.mockResolvedValue([]);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues).toContain('SPF allows all senders (+all) - this provides no protection against spoofing');
  });

  it('should detect SPF neutral policy (?all)', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ?all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ?all');
    mockFetchDMARC.mockResolvedValue(null);
    mockCheckDKIM.mockResolvedValue([]);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) =>
      issue.includes('neutral policy (?all)') && issue.includes('~all')
    )).toBe(true);
  });

  it('should detect missing "all" mechanism in SPF', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 include:_spf.example.com'] });
    mockExtractSPF.mockReturnValue('v=spf1 include:_spf.example.com');
    mockFetchDMARC.mockResolvedValue(null);
    mockCheckDKIM.mockResolvedValue([]);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('missing "all" mechanism'))).toBe(true);
  });

  it('should detect SPF exceeding 10 DNS lookup limit', async () => {
    const spfWithManyIncludes = 'v=spf1 ' + 'include:domain.com '.repeat(11) + '~all';
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: [spfWithManyIncludes] });
    mockExtractSPF.mockReturnValue(spfWithManyIncludes);
    mockFetchDMARC.mockResolvedValue(null);
    mockCheckDKIM.mockResolvedValue([]);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('exceeds 10 DNS lookup limit'))).toBe(true);
  });

  it('should warn about SPF approaching 10 DNS lookup limit', async () => {
    const spfWith9Includes = 'v=spf1 ' + 'include:domain.com '.repeat(9) + '~all';
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: [spfWith9Includes] });
    mockExtractSPF.mockReturnValue(spfWith9Includes);
    mockFetchDMARC.mockResolvedValue(null);
    mockCheckDKIM.mockResolvedValue([]);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('close to the maximum'))).toBe(true);
  });

  it('should detect missing DMARC record', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue(null);
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues).toContain('No DMARC record found - email spoofing protection is incomplete');
  });

  it('should warn about DMARC p=none policy', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=none; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('p=none') && issue.includes('monitoring only'))).toBe(false); // It's a warning, not an issue
    expect(
      result.issues?.some((issue) => issue.toLowerCase().includes('none') && issue.includes('monitoring'))
    ).toBe(true);
  });

  it('should warn about DMARC p=quarantine suggesting upgrade to reject', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('quarantine') && issue.includes('reject'))).toBe(true);
  });

  it('should NOT warn about DMARC p=reject policy', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=reject; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    // Should not have any warnings about DMARC policy
    const dmarcPolicyWarnings = result.issues?.filter((issue) =>
      issue.toLowerCase().includes('dmarc policy') && issue.toLowerCase().includes('p=reject')
    );
    expect(dmarcPolicyWarnings?.length || 0).toBe(0);
  });

  it('should warn about missing DMARC subdomain policy', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=reject; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('subdomain policy (sp=)'))).toBe(true);
  });

  it('should warn about missing DMARC reporting emails', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=reject');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('no reporting emails (rua/ruf)'))).toBe(true);
  });

  it('should warn about DMARC percentage less than 100', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('pct=100'))).toBe(true);
  });

  it('should detect missing DKIM selectors', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=reject; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue([]);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues).toContain('No DKIM selectors detected - emails cannot be cryptographically verified');
  });

  it('should include helpful DKIM discovery suggestions when none found', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=reject; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue([]);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('~40 common DKIM selectors'))).toBe(true);
    expect(result.issues?.some((issue) => issue.includes('EasyDMARC'))).toBe(true);
  });

  it('should list found DKIM selectors', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=reject; rua=mailto:dmarc@example.com');
    mockCheckDKIM.mockResolvedValue(['google', 'selector1']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('google, selector1'))).toBe(true);
  });

  it('should provide success summary for fully configured email auth', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue('v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com; pct=100');
    mockCheckDKIM.mockResolvedValue(['google']);

    const result = await emailAuthScanner.run('example.com');

    expect(result.summary).toContain('fully configured');
    const data = result.data as { hasSpf: boolean; hasDmarc: boolean; hasDkim: boolean; dmarcEnforced: boolean };
    expect(data.hasSpf).toBe(true);
    expect(data.hasDmarc).toBe(true);
    expect(data.hasDkim).toBe(true);
    expect(data.dmarcEnforced).toBe(true);
  });

  it('should provide warning summary for partial configuration', async () => {
    const mockExtractSPF = domainChecks.extractSPF as ReturnType<typeof vi.fn>;
    const mockFetchDMARC = domainChecks.fetchDMARC as ReturnType<typeof vi.fn>;
    const mockCheckDKIM = domainChecks.checkDKIM as ReturnType<typeof vi.fn>;
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;

    mockFetchDNS.mockResolvedValue({ type: 'TXT', data: ['v=spf1 ~all'] });
    mockExtractSPF.mockReturnValue('v=spf1 ~all');
    mockFetchDMARC.mockResolvedValue(null);
    mockCheckDKIM.mockResolvedValue([]);

    const result = await emailAuthScanner.run('example.com');

    expect(result.summary).toContain('Partial email authentication');
    expect(result.summary).toContain('DMARC');
    expect(result.summary).toContain('DKIM');
  });
});

describe('interpretEmailAuthResult', () => {
  const createMockScanner = (data: {
    hasSpf?: boolean;
    hasDmarc?: boolean;
    hasDkim?: boolean;
    dmarcEnforced?: boolean;
  }) => ({
    id: 'emailAuth',
    label: 'Email Authentication',
    status: 'complete' as const,
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    data,
    issues: [],
  });

  it('should return success severity for fully configured email auth', () => {
    const scanner = createMockScanner({
      hasSpf: true,
      hasDmarc: true,
      hasDkim: true,
      dmarcEnforced: true,
    });

    const interpretation = interpretEmailAuthResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.message).toMatch(/email authentication/i);
    expect(interpretation.recommendation).toContain('Excellent');
  });

  it('should return warning severity for configured but not enforced', () => {
    const scanner = createMockScanner({
      hasSpf: true,
      hasDmarc: true,
      hasDkim: true,
      dmarcEnforced: false,
    });

    const interpretation = interpretEmailAuthResult(scanner, 1);

    expect(interpretation.severity).toBe('warning');
    expect(interpretation.recommendation).toContain('p=none');
  });

  it('should return warning severity for partial configuration', () => {
    const scanner = createMockScanner({
      hasSpf: true,
      hasDmarc: false,
      hasDkim: false,
      dmarcEnforced: false,
    });

    const interpretation = interpretEmailAuthResult(scanner, 2);

    expect(interpretation.severity).toBe('warning');
    expect(interpretation.recommendation).toContain('DMARC');
    expect(interpretation.recommendation).toContain('DKIM');
  });

  it('should return critical severity for no configuration', () => {
    const scanner = createMockScanner({
      hasSpf: false,
      hasDmarc: false,
      hasDkim: false,
      dmarcEnforced: false,
    });

    const interpretation = interpretEmailAuthResult(scanner, 3);

    expect(interpretation.severity).toBe('critical');
  });

  it('should build recommendation for missing components', () => {
    const scanner = createMockScanner({
      hasSpf: true,
      hasDmarc: false,
      hasDkim: true,
      dmarcEnforced: false,
    });

    const interpretation = interpretEmailAuthResult(scanner, 1);

    expect(interpretation.recommendation).toContain('DMARC');
    expect(interpretation.recommendation).not.toContain('SPF');
    expect(interpretation.recommendation).not.toContain('DKIM');
  });
});
