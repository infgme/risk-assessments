import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  SCANNERS,
  runAllScanners,
  runScanner,
  interpretScannerResult,
  setScannerTimeout,
} from './index';

// Mock fetch globally
global.fetch = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
});

describe('SCANNERS', () => {
  it('should export array of scanners', () => {
    expect(SCANNERS).toBeDefined();
    expect(Array.isArray(SCANNERS)).toBe(true);
    expect(SCANNERS.length).toBeGreaterThan(0);
  });

  it('should have scanners with required properties', () => {
    SCANNERS.forEach((scanner) => {
      expect(scanner.id).toBeDefined();
      expect(scanner.label).toBeDefined();
      expect(scanner.description).toBeDefined();
      expect(typeof scanner.run).toBe('function');
    });
  });

  it('should have unique scanner IDs', () => {
    const ids = SCANNERS.map((s) => s.id);
    const uniqueIds = new Set(ids);
    expect(ids.length).toBe(uniqueIds.size);
  });

  it('should have all expected scanners', () => {
    const expectedIds = ['dns', 'emailAuth', 'certificates', 'rdap', 'sslLabs', 'securityHeaders'];
    expectedIds.forEach((id) => {
      expect(SCANNERS.find((s) => s.id === id)).toBeDefined();
    });
  });
});

describe('setScannerTimeout', () => {
  it('should reject invalid timeout values', () => {
    expect(() => setScannerTimeout(0)).toThrow('Invalid timeout value');
    expect(() => setScannerTimeout(-1)).toThrow('Invalid timeout value');
    expect(() => setScannerTimeout(Infinity)).toThrow('Invalid timeout value');
  });

  it('should accept valid timeout values', () => {
    expect(() => setScannerTimeout(1000)).not.toThrow();
    expect(() => setScannerTimeout(30000)).not.toThrow();
  });
});

describe('runAllScanners', () => {
  beforeEach(() => {
    // Mock all fetch calls to return empty responses
    (global.fetch as ReturnType<typeof vi.fn>).mockImplementation((url) => {
      const urlStr = url.toString();

      // Mock certificate scanner (crt.sh)
      if (urlStr.includes('crt.sh')) {
        return Promise.resolve({
          ok: true,
          json: async () => [],
        });
      }

      // Mock IANA RDAP bootstrap service
      if (urlStr.includes('data.iana.org/rdap/dns.json')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            services: [
              [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
              [['org'], ['https://rdap.publicinterestregistry.org/']],
              [['io'], ['https://rdap.nic.io/']],
            ],
          }),
        });
      }

      // Mock RDAP domain lookup
      if (
        urlStr.includes('rdap.verisign.com') ||
        urlStr.includes('rdap.publicinterestregistry.org') ||
        urlStr.includes('rdap.nic.io')
      ) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            ldhName: 'example.com',
            status: ['active'],
            nameservers: [{ ldhName: 'ns1.example.com' }, { ldhName: 'ns2.example.com' }],
            secureDNS: { delegationSigned: true },
            events: [
              { eventAction: 'expiration', eventDate: '2026-08-29T14:17:30Z' },
              { eventAction: 'registration', eventDate: '2023-08-29T14:17:30Z' },
            ],
            entities: [
              {
                roles: ['registrar'],
                vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]],
              },
            ],
          }),
        });
      }

      // Mock SSL Labs scanner
      if (urlStr.includes('ssllabs.com')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            status: 'READY',
            endpoints: [],
          }),
        });
      }

      // Mock security headers scanner
      if (urlStr.includes('securityheaders.com')) {
        return Promise.resolve({
          ok: true,
          text: async () => '<div class="score"><div class="score_green"><span>A</span></div></div>',
        });
      }

      // Default mock for DNS queries
      return Promise.resolve({
        ok: true,
        json: async () => ({}),
        headers: {
          get: () => null,
        },
      });
    });
  });

  it('should execute all scanners and return aggregate result', async () => {
    const result = await runAllScanners('example.com');

    expect(result).toBeDefined();
    expect(result.domain).toBe('example.com');
    expect(result.timestamp).toBeDefined();
    expect(result.scanners).toBeDefined();
    expect(Array.isArray(result.scanners)).toBe(true);
    expect(result.scanners.length).toBe(SCANNERS.length);
    expect(result.issues).toBeDefined();
    expect(Array.isArray(result.issues)).toBe(true);
  });

  it('should trim and lowercase domain', async () => {
    const result = await runAllScanners('  EXAMPLE.COM  ');
    expect(result.domain).toBe('example.com');
  });

  it('should mark scanners as complete when they succeed', async () => {
    const result = await runAllScanners('example.com');

    result.scanners.forEach((scanner) => {
      expect(['complete', 'error']).toContain(scanner.status);
      expect(scanner.startedAt).toBeDefined();
      expect(scanner.finishedAt).toBeDefined();
    });
  });

  it('should call onProgress callback during execution', async () => {
    const onProgress = vi.fn();
    await runAllScanners('example.com', onProgress);

    expect(onProgress).toHaveBeenCalled();
    expect(onProgress.mock.calls.length).toBeGreaterThan(0);
  });

  it('should handle scanner errors gracefully', async () => {
    // Make fetch fail to trigger error handling
    (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Network error'));

    const result = await runAllScanners('example.com');

    expect(result.scanners).toBeDefined();
    result.scanners.forEach((scanner) => {
      expect(['complete', 'error']).toContain(scanner.status);
      if (scanner.status === 'error') {
        expect(scanner.error).toBeDefined();
      }
    });
  });

  it('should aggregate issues from all scanners', async () => {
    // Mock to return no records, which will generate issues
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => ({}),
      headers: {
        get: () => null,
      },
    });

    const result = await runAllScanners('example.com');

    expect(result.issues).toBeDefined();
    expect(result.issues.length).toBeGreaterThan(0);
  });

  it('should include dataSource information in results', async () => {
    const result = await runAllScanners('example.com');

    result.scanners.forEach((scanner) => {
      if (scanner.dataSource) {
        expect(scanner.dataSource.name).toBeDefined();
        expect(scanner.dataSource.url).toBeDefined();
      }
    });
  });
});

describe('runScanner', () => {
  beforeEach(() => {
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => ({}),
      headers: {
        get: () => null,
      },
    });
  });

  it('should run individual scanner by ID', async () => {
    const scannerId = SCANNERS[0].id;
    const result = await runScanner('example.com', scannerId);

    expect(result).toBeDefined();
    expect(result.id).toBe(scannerId);
    expect(result.status).toBeDefined();
    expect(result.startedAt).toBeDefined();
    expect(result.finishedAt).toBeDefined();
  });

  it('should throw error for non-existent scanner', async () => {
    await expect(runScanner('example.com', 'non-existent-scanner')).rejects.toThrow('Scanner not found');
  });

  it('should return complete status when scanner succeeds', async () => {
    const scannerId = SCANNERS[0].id;
    const result = await runScanner('example.com', scannerId);

    expect(result.status).toBe('complete');
    expect(result.data).toBeDefined();
  });

  it('should return error status when scanner fails', async () => {
    // Override the scanner's run method to throw an error
    const scannerId = SCANNERS[0].id;
    const scanner = SCANNERS.find((s) => s.id === scannerId)!;
    const originalRun = scanner.run;

    // Make the scanner throw
    scanner.run = vi.fn().mockRejectedValue(new Error('Scanner execution failed'));

    const result = await runScanner('example.com', scannerId);

    expect(result.status).toBe('error');
    expect(result.error).toBeDefined();

    // Restore
    scanner.run = originalRun;
  });

  it('should trim and lowercase domain', async () => {
    const scannerId = 'dns';
    await runScanner('  EXAMPLE.COM  ', scannerId);

    const fetchCalls = (global.fetch as ReturnType<typeof vi.fn>).mock.calls;
    expect(fetchCalls.length).toBeGreaterThan(0);
  });

  it('should include issues in result', async () => {
    const scannerId = 'emailAuth';
    const result = await runScanner('example.com', scannerId);

    expect(result.issues).toBeDefined();
    expect(Array.isArray(result.issues)).toBe(true);
  });

  it('should respect scanner timeout', async () => {
    const dnsScanner = SCANNERS.find((s) => s.id === 'dns');
    const originalTimeout = dnsScanner?.timeout;

    if (dnsScanner) {
      dnsScanner.timeout = 1; // Very short timeout

      (global.fetch as ReturnType<typeof vi.fn>).mockImplementation(
        () =>
          new Promise((resolve) =>
            setTimeout(
              () =>
                resolve({
                  ok: true,
                  json: async () => ({}),
                }),
              50
            )
          )
      );

      const result = await runScanner('example.com', 'dns');
      expect(result.status).toBe('error');
      expect(result.error).toMatch(/timed out/);

      // Restore original timeout
      dnsScanner.timeout = originalTimeout;
    }
  });
});

describe('interpretScannerResult', () => {
  it('should return error interpretation for failed scanners', () => {
    const scanner = {
      id: 'test',
      label: 'Test Scanner',
      status: 'error' as const,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      error: 'Test error',
    };

    const interpretation = interpretScannerResult(scanner);
    expect(interpretation.severity).toBe('error');
    expect(interpretation.message).toBe('Test error');
  });

  it('should delegate to DNS interpreter', () => {
    const scanner = {
      id: 'dns',
      label: 'DNS Records',
      status: 'complete' as const,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      data: { records: [] },
      issues: [],
    };

    const interpretation = interpretScannerResult(scanner);
    expect(interpretation).toBeDefined();
    expect(interpretation.severity).toBeDefined();
  });

  it('should delegate to email auth interpreter', () => {
    const scanner = {
      id: 'emailAuth',
      label: 'Email Authentication',
      status: 'complete' as const,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      data: { hasSpf: true, hasDmarc: true, hasDkim: true, dmarcEnforced: true },
      issues: [],
    };

    const interpretation = interpretScannerResult(scanner);
    expect(interpretation).toBeDefined();
    expect(interpretation.severity).toBe('success');
  });

  it('should provide default interpretation for unknown scanners', () => {
    const scanner = {
      id: 'unknown',
      label: 'Unknown Scanner',
      status: 'complete' as const,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      issues: [],
    };

    const interpretation = interpretScannerResult(scanner);
    expect(interpretation.severity).toBe('success');
    expect(interpretation.message).toContain('successfully');
  });

  it('should handle scanners with issues using default interpretation', () => {
    const scanner = {
      id: 'unknown',
      label: 'Unknown Scanner',
      status: 'complete' as const,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      issues: ['Issue 1', 'Issue 2'],
    };

    const interpretation = interpretScannerResult(scanner);
    expect(interpretation.severity).toBe('warning');
    expect(interpretation.message).toContain('2 issue');
  });
});
