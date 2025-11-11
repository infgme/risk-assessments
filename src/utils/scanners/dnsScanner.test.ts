import { describe, it, expect, vi, beforeEach } from 'vitest';
import { dnsScanner, interpretDnsResult } from './dnsScanner';
import * as domainChecks from '../domainChecks';

// Mock domainChecks module
vi.mock('../domainChecks', () => ({
  fetchDNS: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('dnsScanner', () => {
  it('should have correct scanner metadata', () => {
    expect(dnsScanner.id).toBe('dns');
    expect(dnsScanner.label).toBe('DNS Records');
    expect(dnsScanner.description).toBeDefined();
    expect(dnsScanner.timeout).toBe(5000);
    expect(dnsScanner.dataSource).toBeDefined();
  });

  it('should retrieve DNS records successfully', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: ['93.184.216.34'] };
      if (type === 'MX') return { type: 'MX', data: ['10 mail.example.com.'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');

    expect(result.data).toBeDefined();
    expect((result.data as { records: unknown[] }).records).toBeDefined();
    expect(result.summary).toBeDefined();
    expect(Array.isArray(result.issues)).toBe(true);
  });

  it('should detect missing A/AAAA/CNAME records', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'MX') return { type: 'MX', data: ['10 mail.example.com.'] };
      if (type === 'TXT') return { type: 'TXT', data: ['v=spf1 ~all'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');

    expect(result.issues).toContain(
      'No A, AAAA, or CNAME records found - domain may not be accessible via web browser'
    );
  });

  it('should detect reserved/private IP addresses', async () => {
    const testCases = [
      '127.0.0.1',
      '10.0.0.1',
      '192.168.1.1',
      '169.254.1.1',
      '0.0.0.0',
    ];

    for (const ip of testCases) {
      const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
      mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
        if (type === 'A') return { type: 'A', data: [ip] };
        return null;
      });

      const result = await dnsScanner.run('example.com');
      expect(result.issues?.some((issue) => issue.includes('reserved/private IP'))).toBe(true);
      expect(result.issues?.some((issue) => issue.includes(ip))).toBe(true);
    }
  });

  it('should not flag public IP addresses as reserved', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: ['93.184.216.34'] };
      if (type === 'MX') return { type: 'MX', data: ['10 mail.example.com.'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues?.some((issue) => issue.includes('reserved/private IP'))).toBe(false);
  });

  it('should detect CNAME conflicts with A records', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: ['93.184.216.34'] };
      if (type === 'CNAME') return { type: 'CNAME', data: ['target.example.com.'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues).toContain(
      'CNAME conflict detected - CNAME records cannot coexist with A, AAAA, or MX records'
    );
  });

  it('should detect CNAME conflicts with AAAA records', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'AAAA') return { type: 'AAAA', data: ['2606:2800:220:1:248:1893:25c8:1946'] };
      if (type === 'CNAME') return { type: 'CNAME', data: ['target.example.com.'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues).toContain(
      'CNAME conflict detected - CNAME records cannot coexist with A, AAAA, or MX records'
    );
  });

  it('should detect CNAME conflicts with MX records', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'MX') return { type: 'MX', data: ['10 mail.example.com.'] };
      if (type === 'CNAME') return { type: 'CNAME', data: ['target.example.com.'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues).toContain(
      'CNAME conflict detected - CNAME records cannot coexist with A, AAAA, or MX records'
    );
  });

  it('should detect multiple CNAME records', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'CNAME')
        return {
          type: 'CNAME',
          data: ['target1.example.com.', 'target2.example.com.'],
        };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues).toContain('Multiple CNAME records found - only one CNAME record should exist per name');
  });

  it('should detect excessive A records', async () => {
    const manyIPs = Array.from({ length: 15 }, (_, i) => `93.184.216.${i}`);
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: manyIPs };
      if (type === 'MX') return { type: 'MX', data: ['10 mail.example.com.'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues?.some((issue) => issue.includes('Unusually high number of A records'))).toBe(true);
  });

  it('should detect missing MX records', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: ['93.184.216.34'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues).toContain('No MX records found - email delivery to this domain will fail');
  });

  it('should detect TXT records exceeding 255 characters', async () => {
    const longTxt = 'v=spf1 ' + 'include:example.com '.repeat(20); // Creates a very long TXT record
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: ['93.184.216.34'] };
      if (type === 'MX') return { type: 'MX', data: ['10 mail.example.com.'] };
      if (type === 'TXT') return { type: 'TXT', data: [longTxt] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues?.some((issue) => issue.includes('TXT record exceeds 255 characters'))).toBe(true);
  });

  it('should detect MX records pointing to IP addresses', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: ['93.184.216.34'] };
      if (type === 'MX') return { type: 'MX', data: ['10 192.0.2.1'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues?.some((issue) => issue.includes('MX record points to IP address'))).toBe(true);
  });

  it('should accept valid MX records with hostnames', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: ['93.184.216.34'] };
      if (type === 'MX') return { type: 'MX', data: ['10 mail.example.com.'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.issues?.some((issue) => issue.includes('MX record points to IP address'))).toBe(false);
  });

  it('should build summary with record counts', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: ['93.184.216.34'] };
      if (type === 'MX') return { type: 'MX', data: ['10 mail.example.com.'] };
      if (type === 'TXT') return { type: 'TXT', data: ['v=spf1 ~all'] };
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.summary).toContain('Found');
    expect(result.summary).toMatch(/A:\d+/);
  });

  it('should handle no DNS records found', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockResolvedValue(null);

    const result = await dnsScanner.run('example.com');
    expect(result.summary).toBe('No DNS records found');
    expect(result.issues?.length || 0).toBeGreaterThan(0);
  });

  it('should handle partial DNS data gracefully', async () => {
    const mockFetchDNS = domainChecks.fetchDNS as ReturnType<typeof vi.fn>;
    mockFetchDNS.mockImplementation(async (domain: string, type: string) => {
      if (type === 'A') return { type: 'A', data: ['93.184.216.34'] };
      // Other record types return null
      return null;
    });

    const result = await dnsScanner.run('example.com');
    expect(result.data).toBeDefined();
    expect(result.issues).toContain('No MX records found - email delivery to this domain will fail');
  });
});

describe('interpretDnsResult', () => {
  const createMockScanner = (issueCount: number) => ({
    id: 'dns',
    label: 'DNS Records',
    status: 'complete' as const,
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    data: { records: [] },
    issues: Array(issueCount).fill('test issue'),
  });

  it('should return success severity for no issues', () => {
    const scanner = createMockScanner(0);
    const interpretation = interpretDnsResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.message).toContain('successfully');
  });

  it('should return warning severity for 1-2 issues', () => {
    const scanner1 = createMockScanner(1);
    const interpretation1 = interpretDnsResult(scanner1, 1);
    expect(interpretation1.severity).toBe('warning');
    expect(interpretation1.message).toContain('warnings');

    const scanner2 = createMockScanner(2);
    const interpretation2 = interpretDnsResult(scanner2, 2);
    expect(interpretation2.severity).toBe('warning');
  });

  it('should return critical severity for 3+ issues', () => {
    const scanner = createMockScanner(3);
    const interpretation = interpretDnsResult(scanner, 3);

    expect(interpretation.severity).toBe('critical');
    expect(interpretation.message).toContain('critical');
  });

  it('should provide appropriate recommendations', () => {
    const scannerSuccess = createMockScanner(0);
    const interpSuccess = interpretDnsResult(scannerSuccess, 0);
    expect(interpSuccess.recommendation).toBeDefined();

    const scannerWarning = createMockScanner(1);
    const interpWarning = interpretDnsResult(scannerWarning, 1);
    expect(interpWarning.recommendation).toContain('Review');

    const scannerCritical = createMockScanner(5);
    const interpCritical = interpretDnsResult(scannerCritical, 5);
    expect(interpCritical.recommendation).toContain('immediately');
  });
});
