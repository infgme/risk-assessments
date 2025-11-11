import { describe, it, expect, vi, beforeEach } from 'vitest';
import { certificateScanner, interpretCertificateResult } from './certificateScanner';
import * as domainChecks from '../domainChecks';

// Mock domainChecks module
vi.mock('../domainChecks', () => ({
  fetchCertificates: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('certificateScanner', () => {
  it('should have correct scanner metadata', () => {
    expect(certificateScanner.id).toBe('certificates');
    expect(certificateScanner.label).toBe('SSL/TLS Certificates');
    expect(certificateScanner.description).toBeDefined();
    expect(certificateScanner.timeout).toBe(15000);
    expect(certificateScanner.dataSource).toBeDefined();
  });

  it('should handle no certificates found', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    mockFetchCertificates.mockResolvedValue([]);

    const result = await certificateScanner.run('example.com');

    expect(result.summary).toBe('No certificates found in transparency logs');
    expect(result.issues).toContain(
      'No SSL certificates found - if you use HTTPS, this might indicate a very new certificate'
    );
  });

  it('should detect certificates expiring within 7 days', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const fiveDaysFromNow = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString();

    mockFetchCertificates.mockResolvedValue([
      {
        id: 1,
        common_name: 'example.com',
        name_value: 'example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2024-01-01T00:00:00Z',
        not_after: fiveDaysFromNow,
      },
    ]);

    const result = await certificateScanner.run('example.com');

    // Check for expiring soon warning with "immediately"
    expect(
      result.issues?.some((issue) =>
        issue.includes('expires in') && issue.includes('day') && issue.includes('immediately')
      )
    ).toBe(true);
  });

  it('should detect certificates expiring within 30 days', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const twentyDaysFromNow = new Date(Date.now() + 20 * 24 * 60 * 60 * 1000).toISOString();

    mockFetchCertificates.mockResolvedValue([
      {
        id: 1,
        common_name: 'example.com',
        name_value: 'example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2024-01-01T00:00:00Z',
        not_after: twentyDaysFromNow,
      },
    ]);

    const result = await certificateScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('expires in 20 day') && issue.includes('renewal soon'))).toBe(
      true
    );
  });

  it('should detect self-signed certificates', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    mockFetchCertificates.mockResolvedValue([
      {
        id: 1,
        common_name: 'example.com',
        name_value: 'example.com',
        issuer_name: 'example.com', // Same as common_name indicates self-signed
        not_before: '2024-01-01T00:00:00Z',
        not_after: futureDate,
      },
    ]);

    const result = await certificateScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('self-signed'))).toBe(true);
  });

  it('should detect wildcard certificates', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    mockFetchCertificates.mockResolvedValue([
      {
        id: 1,
        common_name: '*.example.com',
        name_value: '*.example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2024-01-01T00:00:00Z',
        not_after: futureDate,
      },
    ]);

    const result = await certificateScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('wildcard certificate'))).toBe(true);
  });

  it('should warn about high number of active certificates', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    const manyCerts = Array.from({ length: 15 }, (_, i) => ({
      id: i,
      common_name: `subdomain${i}.example.com`,
      name_value: `subdomain${i}.example.com`,
      issuer_name: 'Let\'s Encrypt',
      not_before: '2024-01-01T00:00:00Z',
      not_after: futureDate,
    }));

    mockFetchCertificates.mockResolvedValue(manyCerts);

    const result = await certificateScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('High number of active certificates'))).toBe(true);
  });

  it('should detect recently expired certificates without replacement', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const recentlyExpired = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    mockFetchCertificates.mockResolvedValue([
      {
        id: 1,
        common_name: 'old.example.com',
        name_value: 'old.example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2023-01-01T00:00:00Z',
        not_after: recentlyExpired,
      },
      {
        id: 2,
        common_name: 'current.example.com',
        name_value: 'current.example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2024-01-01T00:00:00Z',
        not_after: futureDate,
      },
    ]);

    const result = await certificateScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('expired recently without replacement'))).toBe(true);
    expect(result.issues?.some((issue) => issue.includes('old.example.com'))).toBe(true);
  });

  it('should NOT warn about expired certificates that have active replacements', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const recentlyExpired = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    mockFetchCertificates.mockResolvedValue([
      {
        id: 1,
        common_name: 'example.com',
        name_value: 'example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2023-01-01T00:00:00Z',
        not_after: recentlyExpired,
      },
      {
        id: 2,
        common_name: 'example.com',
        name_value: 'example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2024-01-01T00:00:00Z',
        not_after: futureDate,
      },
    ]);

    const result = await certificateScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('expired recently without replacement'))).toBe(false);
  });

  it('should warn about certificates from many different issuers', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    const issuers = ['Let\'s Encrypt', 'DigiCert', 'Comodo', 'GeoTrust', 'GlobalSign'];
    const certs = issuers.map((issuer, i) => ({
      id: i,
      common_name: `subdomain${i}.example.com`,
      name_value: `subdomain${i}.example.com`,
      issuer_name: issuer,
      not_before: '2024-01-01T00:00:00Z',
      not_after: futureDate,
    }));

    mockFetchCertificates.mockResolvedValue(certs);

    const result = await certificateScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('different issuers'))).toBe(true);
  });

  it('should build proper summary with certificate counts', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
    const expired = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();

    mockFetchCertificates.mockResolvedValue([
      {
        id: 1,
        common_name: 'example.com',
        name_value: 'example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2024-01-01T00:00:00Z',
        not_after: futureDate,
      },
      {
        id: 2,
        common_name: 'old.example.com',
        name_value: 'old.example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2022-01-01T00:00:00Z',
        not_after: expired,
      },
    ]);

    const result = await certificateScanner.run('example.com');

    expect(result.summary).toContain('2 total certificates');
    expect(result.summary).toContain('1 currently active');
    expect(result.summary).toContain('1 expired');
  });

  it('should deduplicate certificates by common name keeping most recent', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
    const oldDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    mockFetchCertificates.mockResolvedValue([
      {
        id: 1,
        common_name: 'example.com',
        name_value: 'example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2024-01-01T00:00:00Z', // Older cert
        not_after: oldDate,
      },
      {
        id: 2,
        common_name: 'example.com',
        name_value: 'example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2024-06-01T00:00:00Z', // Newer cert
        not_after: futureDate,
      },
    ]);

    const result = await certificateScanner.run('example.com');
    const data = result.data as { activeCertCount: number };

    // Should only count 1 active cert (the newer one)
    expect(data.activeCertCount).toBe(1);
  });

  it('should include detailed data for UI display', async () => {
    const mockFetchCertificates = domainChecks.fetchCertificates as ReturnType<typeof vi.fn>;
    const futureDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    mockFetchCertificates.mockResolvedValue([
      {
        id: 1,
        common_name: 'example.com',
        name_value: 'example.com',
        issuer_name: 'Let\'s Encrypt',
        not_before: '2024-01-01T00:00:00Z',
        not_after: futureDate,
      },
    ]);

    const result = await certificateScanner.run('example.com');
    const data = result.data as {
      certCount: number;
      activeCertCount: number;
      expiredCertCount: number;
      uniqueIssuers: string[];
    };

    expect(data.certCount).toBe(1);
    expect(data.activeCertCount).toBe(1);
    expect(data.expiredCertCount).toBe(0);
    expect(data.uniqueIssuers).toContain('Let\'s Encrypt');
  });
});

describe('interpretCertificateResult', () => {
  const createMockScanner = (data: {
    certCount?: number;
    activeCertCount?: number;
    expiredCertCount?: number;
    expiringIn7Days?: number;
    expiringIn30Days?: number;
  }, issueCount: number = 0) => ({
    id: 'certificates',
    label: 'SSL/TLS Certificates',
    status: 'complete' as const,
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    data,
    issues: Array(issueCount).fill('test issue'),
  });

  it('should return info severity for no certificates', () => {
    const scanner = createMockScanner({ certCount: 0 });
    const interpretation = interpretCertificateResult(scanner, 0);

    expect(interpretation.severity).toBe('info');
    expect(interpretation.message).toContain('No certificates found');
  });

  it('should return critical severity for certificates expiring in 7 days', () => {
    const scanner = createMockScanner({
      certCount: 5,
      activeCertCount: 3,
      expiringIn7Days: 2,
    });
    const interpretation = interpretCertificateResult(scanner, 2);

    expect(interpretation.severity).toBe('critical');
    expect(interpretation.message).toContain('expiring within 7 days');
    expect(interpretation.recommendation).toContain('immediately');
  });

  it('should return warning severity for certificates expiring in 30 days', () => {
    const scanner = createMockScanner({
      certCount: 5,
      activeCertCount: 3,
      expiringIn30Days: 2,
    });
    const interpretation = interpretCertificateResult(scanner, 2);

    expect(interpretation.severity).toBe('warning');
    expect(interpretation.message).toContain('expiring within 30 days');
  });

  it('should return warning severity for other issues', () => {
    const scanner = createMockScanner(
      {
        certCount: 5,
        activeCertCount: 3,
      },
      3
    );
    const interpretation = interpretCertificateResult(scanner, 3);

    expect(interpretation.severity).toBe('warning');
    expect(interpretation.message).toContain('issue(s) detected');
  });

  it('should return success severity for valid certificates with no issues', () => {
    const scanner = createMockScanner({
      certCount: 5,
      activeCertCount: 3,
    });
    const interpretation = interpretCertificateResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.message).toContain('valid certificate(s) found');
  });

  it('should provide special recommendation for large numbers of certificates', () => {
    const scanner = createMockScanner({
      certCount: 100,
      activeCertCount: 60,
    });
    const interpretation = interpretCertificateResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.recommendation).toContain('Large number');
  });
});
