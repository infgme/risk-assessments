import { describe, it, expect, vi, beforeEach } from 'vitest';
import { sslLabsScanner, interpretSslLabsResult } from './sslLabsScanner';

// Mock fetch globally
global.fetch = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
});

describe('sslLabsScanner', () => {
  it('should have correct scanner metadata', () => {
    expect(sslLabsScanner.id).toBe('sslLabs');
    expect(sslLabsScanner.label).toBe('SSL/TLS Configuration');
    expect(sslLabsScanner.description).toBeDefined();
    expect(sslLabsScanner.timeout).toBe(600000); // 10 minutes
    expect(sslLabsScanner.dataSource).toBeDefined();
  });

  it('should handle cached READY results', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'READY',
        endpoints: [
          {
            ipAddress: '93.184.216.34',
            grade: 'A',
            details: {
              protocols: [
                { name: 'TLS', version: '1.2' },
                { name: 'TLS', version: '1.3' },
              ],
            },
          },
        ],
      }),
    });

    const result = await sslLabsScanner.run('example.com');

    expect(result.summary).toContain('1 endpoint(s) scanned');
    expect(result.summary).toContain('A');
  });

  it('should handle no endpoints found', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'READY',
        endpoints: [],
      }),
    });

    const result = await sslLabsScanner.run('example.com');

    expect(result.summary).toBe('No SSL/TLS endpoints found');
    expect(result.issues).toContain('No HTTPS endpoints detected for this domain');
  });

  it('should detect SSL protocol vulnerabilities', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'READY',
        endpoints: [
          {
            ipAddress: '93.184.216.34',
            grade: 'F',
            details: {
              protocols: [
                { name: 'SSL', version: '3.0' },
                { name: 'TLS', version: '1.2' },
              ],
            },
          },
        ],
      }),
    });

    const result = await sslLabsScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('deprecated SSL protocols'))).toBe(true);
  });

  it('should detect outdated TLS versions', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'READY',
        endpoints: [
          {
            ipAddress: '93.184.216.34',
            grade: 'B',
            details: {
              protocols: [
                { name: 'TLS', version: '1.0' },
                { name: 'TLS', version: '1.2' },
              ],
            },
          },
        ],
      }),
    });

    const result = await sslLabsScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('outdated TLS 1.0'))).toBe(true);
  });

  it('should detect known vulnerabilities', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'READY',
        endpoints: [
          {
            ipAddress: '93.184.216.34',
            grade: 'F',
            details: {
              protocols: [{ name: 'TLS', version: '1.2' }],
              heartbleed: true,
              poodle: true,
            },
          },
        ],
      }),
    });

    const result = await sslLabsScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('Heartbleed'))).toBe(true);
    expect(result.issues?.some((issue) => issue.includes('POODLE'))).toBe(true);
  });

  it('should warn about missing HSTS', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'READY',
        endpoints: [
          {
            ipAddress: '93.184.216.34',
            grade: 'A',
            details: {
              protocols: [{ name: 'TLS', version: '1.2' }],
              hstsPolicy: { status: 'absent' },
            },
          },
        ],
      }),
    });

    const result = await sslLabsScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('HSTS not configured'))).toBe(true);
  });

  it('should warn about short HSTS max-age', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'READY',
        endpoints: [
          {
            ipAddress: '93.184.216.34',
            grade: 'A',
            details: {
              protocols: [{ name: 'TLS', version: '1.2' }],
              hstsPolicy: { status: 'present', maxAge: 86400 }, // 1 day, should be 6+ months
            },
          },
        ],
      }),
    });

    const result = await sslLabsScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('HSTS max-age is too short'))).toBe(true);
  });

  it('should handle ERROR status', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'ERROR',
        statusMessage: 'Unable to connect to server',
      }),
    });

    const result = await sslLabsScanner.run('example.com');

    expect(result.summary).toContain('SSL Labs scan error');
    expect(result.issues?.some((issue) => issue.includes('could not scan'))).toBe(true);
  });

  it('should handle fetch errors', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockRejectedValueOnce(new Error('Network error'));

    const result = await sslLabsScanner.run('example.com');

    expect(result.summary).toBe('SSL Labs scan failed');
    expect(result.issues?.some((issue) => issue.includes('Failed to scan'))).toBe(true);
  });

  it('should include test URL in data', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        status: 'READY',
        endpoints: [
          {
            ipAddress: '93.184.216.34',
            grade: 'A',
          },
        ],
      }),
    });

    const result = await sslLabsScanner.run('example.com');
    const data = result.data as { testUrl: string };

    expect(data.testUrl).toContain('ssllabs.com/ssltest');
    expect(data.testUrl).toContain('example.com');
  });
});

describe('interpretSslLabsResult', () => {
  const createMockScanner = (data: unknown, issues: string[] = []) => ({
    id: 'sslLabs',
    label: 'SSL/TLS Configuration',
    status: 'complete' as const,
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    data,
    issues,
  });

  it('should return success severity for A+ grade', () => {
    const scanner = createMockScanner({ status: 'READY', lowestGrade: 'A+', grades: ['A+'] });
    const interpretation = interpretSslLabsResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.message).toContain('A+');
  });

  it('should return success severity for A grade', () => {
    const scanner = createMockScanner({ status: 'READY', lowestGrade: 'A', grades: ['A'] });
    const interpretation = interpretSslLabsResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.message).toContain('A');
  });

  it('should return warning severity for B grade', () => {
    const scanner = createMockScanner({ status: 'READY', lowestGrade: 'B', grades: ['B'] });
    const interpretation = interpretSslLabsResult(scanner, 1);

    expect(interpretation.severity).toBe('warning');
    expect(interpretation.message).toContain('B');
  });

  it('should return critical severity for F grade', () => {
    const scanner = createMockScanner({ status: 'READY', lowestGrade: 'F', grades: ['F'] });
    const interpretation = interpretSslLabsResult(scanner, 3);

    expect(interpretation.severity).toBe('critical');
    expect(interpretation.message).toContain('F');
    expect(interpretation.recommendation).toContain('serious issues');
  });

  it('should handle ERROR status', () => {
    const scanner = createMockScanner({ status: 'ERROR' });
    const interpretation = interpretSslLabsResult(scanner, 0);

    expect(interpretation.severity).toBe('error');
    expect(interpretation.message).toContain('could not scan');
  });

  it('should handle in-progress scans', () => {
    const scanner = createMockScanner({ status: 'IN_PROGRESS' });
    const interpretation = interpretSslLabsResult(scanner, 0);

    expect(interpretation.severity).toBe('info');
    expect(interpretation.message).toContain('in progress');
  });

  it('should include test URL link in recommendation', () => {
    const scanner = createMockScanner({
      status: 'READY',
      lowestGrade: 'B',
      testUrl: 'https://www.ssllabs.com/ssltest/analyze.html?d=example.com',
    });
    const interpretation = interpretSslLabsResult(scanner, 1);

    expect(interpretation.recommendation).toContain('SSL Labs report');
  });
});
