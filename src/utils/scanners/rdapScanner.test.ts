import { describe, it, expect, vi, beforeEach } from 'vitest';
import { rdapScanner, interpretRdapResult } from './rdapScanner';

// Mock fetch globally
global.fetch = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
});

describe('rdapScanner', () => {
  it('should have correct scanner metadata', () => {
    expect(rdapScanner.id).toBe('rdap');
    expect(rdapScanner.label).toBe('Domain Registration (RDAP)');
    expect(rdapScanner.description).toBeDefined();
    expect(rdapScanner.timeout).toBe(10000);
    expect(rdapScanner.dataSource).toBeDefined();
  });

  it('should handle invalid domain format', async () => {
    const result = await rdapScanner.run('invalid');

    expect(result.summary).toBe('Invalid domain');
    expect(result.issues).toContain('Domain must have at least a name and TLD (e.g., example.com)');
  });

  it('should handle successful RDAP lookup', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    // Mock bootstrap response
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        services: [[['com'], ['https://rdap.example.com/']]],
      }),
    });

    // Mock RDAP domain response
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        ldhName: 'example.com',
        status: ['active'],
        nameservers: [{ ldhName: 'ns1.example.com' }, { ldhName: 'ns2.example.com' }],
        secureDNS: { delegationSigned: true },
        events: [
          { eventAction: 'expiration', eventDate: '2026-01-01T00:00:00Z' },
          { eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' },
        ],
      }),
    });

    const result = await rdapScanner.run('example.com');

    expect(result.summary).toContain('example.com');
    expect(result.summary).toContain('active');
    const data = result.data as { dnssecEnabled: boolean; nameservers: string[] };
    expect(data.dnssecEnabled).toBe(true);
    expect(data.nameservers).toHaveLength(2);
  });

  it('should detect domain expiring soon', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;
    const twentyFiveDaysFromNow = new Date(Date.now() + 25 * 24 * 60 * 60 * 1000).toISOString();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        services: [[['com'], ['https://rdap.example.com/']]],
      }),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        ldhName: 'example.com',
        status: ['active'],
        nameservers: [{ ldhName: 'ns1.example.com' }],
        events: [{ eventAction: 'expiration', eventDate: twentyFiveDaysFromNow }],
      }),
    });

    const result = await rdapScanner.run('example.com');

    // Check for expiration warning (between 20-30 days)
    expect(result.issues?.some((issue) => issue.includes('expires in') && issue.includes('day'))).toBe(true);
  });

  it('should detect expired domain', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;
    const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        services: [[['com'], ['https://rdap.example.com/']]],
      }),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        ldhName: 'example.com',
        status: ['active'],
        nameservers: [{ ldhName: 'ns1.example.com' }],
        events: [{ eventAction: 'expiration', eventDate: tenDaysAgo }],
      }),
    });

    const result = await rdapScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('expired'))).toBe(true);
  });

  it('should warn about disabled DNSSEC', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        services: [[['com'], ['https://rdap.example.com/']]],
      }),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        ldhName: 'example.com',
        status: ['active'],
        nameservers: [{ ldhName: 'ns1.example.com' }, { ldhName: 'ns2.example.com' }],
        secureDNS: { delegationSigned: false },
        events: [{ eventAction: 'expiration', eventDate: '2026-01-01T00:00:00Z' }],
      }),
    });

    const result = await rdapScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('DNSSEC is not enabled'))).toBe(true);
  });

  it('should detect problematic domain statuses', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        services: [[['com'], ['https://rdap.example.com/']]],
      }),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        ldhName: 'example.com',
        status: ['clientHold', 'active'],
        nameservers: [{ ldhName: 'ns1.example.com' }],
        events: [{ eventAction: 'expiration', eventDate: '2026-01-01T00:00:00Z' }],
      }),
    });

    const result = await rdapScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('problematic status'))).toBe(true);
  });

  it('should warn about insufficient nameservers', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        services: [[['com'], ['https://rdap.example.com/']]],
      }),
    });

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        ldhName: 'example.com',
        status: ['active'],
        nameservers: [{ ldhName: 'ns1.example.com' }],
        events: [{ eventAction: 'expiration', eventDate: '2026-01-01T00:00:00Z' }],
      }),
    });

    const result = await rdapScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('Only one nameserver'))).toBe(true);
  });

  it('should handle TLD without RDAP support', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        services: [[['com'], ['https://rdap.example.com/']]],
      }),
    });

    const result = await rdapScanner.run('example.unknown');

    expect(result.summary).toBe('RDAP not available for this TLD');
    expect(result.issues?.some((issue) => issue.includes('No RDAP service available'))).toBe(true);
  });

  it('should handle failed bootstrap lookup', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    const result = await rdapScanner.run('example.com');

    expect(result.summary).toBe('RDAP lookup failed');
    expect(result.issues?.some((issue) => issue.includes('Failed to retrieve RDAP'))).toBe(true);
  });

  it('should handle domain not found in RDAP', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        services: [[['com'], ['https://rdap.example.com/']]],
      }),
    });

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
    });

    const result = await rdapScanner.run('example.com');

    expect(result.summary).toBe('RDAP lookup failed');
    expect(result.data).toHaveProperty('error');
  });
});

describe('interpretRdapResult', () => {
  const createMockScanner = (data: unknown, issues: string[] = []) => ({
    id: 'rdap',
    label: 'Domain Registration (RDAP)',
    status: 'complete' as const,
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    data,
    issues,
  });

  it('should handle RDAP lookup errors gracefully', () => {
    const scanner = createMockScanner({ error: 'Domain not found' }, ['Failed to retrieve RDAP information']);
    const interpretation = interpretRdapResult(scanner, 1);

    expect(interpretation.severity).toBe('info');
    expect(interpretation.message).toContain('incomplete');
  });

  it('should return critical severity for expired domains', () => {
    const scanner = createMockScanner(
      { status: ['active'] },
      ['Domain expired 10 days ago']
    );
    const interpretation = interpretRdapResult(scanner, 1);

    expect(interpretation.severity).toBe('critical');
    expect(interpretation.recommendation).toContain('immediately');
  });

  it('should return warning severity for expiring domains', () => {
    const scanner = createMockScanner(
      { status: ['active'] },
      ['Domain expires in 20 days - renew soon!']
    );
    const interpretation = interpretRdapResult(scanner, 1);

    expect(interpretation.severity).toBe('warning');
    expect(interpretation.message).toContain('needs attention');
  });

  it('should return success severity for healthy domains with DNSSEC', () => {
    const scanner = createMockScanner({ dnssecEnabled: true }, []);
    const interpretation = interpretRdapResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.recommendation).toContain('DNSSEC');
  });

  it('should recommend DNSSEC when not enabled', () => {
    const scanner = createMockScanner({ dnssecEnabled: false }, []);
    const interpretation = interpretRdapResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.recommendation).toContain('Consider enabling DNSSEC');
  });
});
