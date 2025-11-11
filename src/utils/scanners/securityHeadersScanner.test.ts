import { describe, it, expect, vi, beforeEach } from 'vitest';
import { securityHeadersScanner, interpretSecurityHeadersResult } from './securityHeadersScanner';

// Mock fetch globally
global.fetch = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
});

describe('securityHeadersScanner', () => {
  it('should have correct scanner metadata', () => {
    expect(securityHeadersScanner.id).toBe('securityHeaders');
    expect(securityHeadersScanner.label).toBe('Security Headers');
    expect(securityHeadersScanner.description).toBeDefined();
    expect(securityHeadersScanner.timeout).toBe(15000);
    expect(securityHeadersScanner.dataSource).toBeDefined();
  });

  it('should parse grade from HTML', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    const mockHTML = `
      <div class="score">
        <div class="score_green">
          <span>A</span>
        </div>
      </div>
      <div class="reportTitle">Score: 90</div>
    `;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => mockHTML,
    });

    const result = await securityHeadersScanner.run('example.com');

    expect(result.summary).toContain('Grade: A');
    expect(result.summary).toContain('90/100');
  });

  it('should parse missing headers', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    const mockHTML = `
      <div class="score">
        <div class="score_red">
          <span>F</span>
        </div>
      </div>
      <div class="reportSection">
        <div class="reportTitle">Missing Headers</div>
        <div class="reportBody">
          <table>
            <tr>
              <th class="tableLabel table_red">Content-Security-Policy</th>
            </tr>
            <tr>
              <th class="tableLabel table_red">Strict-Transport-Security</th>
            </tr>
          </table>
        </div>
      </div>
    `;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => mockHTML,
    });

    const result = await securityHeadersScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('Content-Security-Policy'))).toBe(true);
    expect(result.issues?.some((issue) => issue.includes('Strict-Transport-Security'))).toBe(true);
  });

  it('should parse warnings', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    const mockHTML = `
      <div class="score">
        <div class="score_orange">
          <span>C</span>
        </div>
      </div>
      <div class="reportSection">
        <div class="reportTitle">Warnings</div>
        <div class="reportBody">
          <table>
            <tr>
              <th class="tableLabel table_orange">X-Frame-Options header deprecated</th>
            </tr>
          </table>
        </div>
      </div>
    `;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => mockHTML,
    });

    const result = await securityHeadersScanner.run('example.com');

    expect(result.issues?.some((issue) => issue.includes('X-Frame-Options header deprecated'))).toBe(true);
  });

  it('should handle grades with modifiers (A+)', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    const mockHTML = `
      <div class="score">
        <div class="score_green">
          <span>A+</span>
        </div>
      </div>
      <div class="reportTitle">Score: 100</div>
    `;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => mockHTML,
    });

    const result = await securityHeadersScanner.run('example.com');

    expect(result.summary).toContain('Grade: A+');
  });

  it('should handle no grade found', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    const mockHTML = '<html><body>No score available</body></html>';

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => mockHTML,
    });

    const result = await securityHeadersScanner.run('example.com');

    expect(result.summary).toBe('Security headers analyzed');
  });

  it('should handle fetch errors gracefully', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockRejectedValueOnce(new Error('Network error'));

    const result = await securityHeadersScanner.run('example.com');

    expect(result.summary).toBe('Security headers check unavailable');
    expect(result.issues?.some((issue) => issue.includes('Could not retrieve'))).toBe(true);
    const data = result.data as { status: string; testUrl: string };
    expect(data.status).toBe('unavailable');
    expect(data.testUrl).toContain('securityheaders.com');
  });

  it('should handle HTTP error responses', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    });

    const result = await securityHeadersScanner.run('example.com');

    expect(result.summary).toBe('Security headers check unavailable');
    expect(result.issues?.some((issue) => issue.includes('Could not retrieve'))).toBe(true);
  });

  it('should include test URL in data', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    const mockHTML = `
      <div class="score">
        <div class="score_green">
          <span>A</span>
        </div>
      </div>
    `;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => mockHTML,
    });

    const result = await securityHeadersScanner.run('example.com');
    const data = result.data as { testUrl: string };

    expect(data.testUrl).toContain('securityheaders.com');
    expect(data.testUrl).toContain('example.com');
  });

  it('should not duplicate missing headers', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    const mockHTML = `
      <div class="score">
        <div class="score_red">
          <span>F</span>
        </div>
      </div>
      <div class="reportSection">
        <div class="reportTitle">Missing Headers</div>
        <div class="reportBody">
          <table>
            <tr>
              <th class="tableLabel table_red">X-Frame-Options</th>
            </tr>
            <tr>
              <th class="tableLabel table_red">X-Frame-Options</th>
            </tr>
          </table>
        </div>
      </div>
    `;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => mockHTML,
    });

    const result = await securityHeadersScanner.run('example.com');

    const xFrameIssues = result.issues?.filter((issue) => issue.includes('X-Frame-Options'));
    expect(xFrameIssues?.length).toBe(1);
  });

  it('should parse score without grade', async () => {
    const mockFetch = global.fetch as ReturnType<typeof vi.fn>;

    const mockHTML = '<div class="reportTitle">Score: 75</div>';

    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: async () => mockHTML,
    });

    const result = await securityHeadersScanner.run('example.com');

    expect(result.summary).toContain('75/100');
  });
});

describe('interpretSecurityHeadersResult', () => {
  const createMockScanner = (data: unknown, issues: string[] = []) => ({
    id: 'securityHeaders',
    label: 'Security Headers',
    status: 'complete' as const,
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    data,
    issues,
  });

  it('should return info severity for unavailable status', () => {
    const scanner = createMockScanner({
      status: 'unavailable',
      testUrl: 'https://securityheaders.com/?q=example.com',
    });
    const interpretation = interpretSecurityHeadersResult(scanner, 0);

    expect(interpretation.severity).toBe('info');
    expect(interpretation.message).toContain('unavailable');
    expect(interpretation.recommendation).toContain('securityheaders.com');
  });

  it('should return success severity for A+ grade', () => {
    const scanner = createMockScanner({ status: 'available', grade: 'A+', score: 100 });
    const interpretation = interpretSecurityHeadersResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.message).toContain('A+');
    expect(interpretation.recommendation).toContain('excellent');
  });

  it('should return success severity for A grade', () => {
    const scanner = createMockScanner({ status: 'available', grade: 'A', score: 95 });
    const interpretation = interpretSecurityHeadersResult(scanner, 0);

    expect(interpretation.severity).toBe('success');
    expect(interpretation.message).toContain('A');
  });

  it('should return info severity for B grade', () => {
    const scanner = createMockScanner({ status: 'available', grade: 'B', score: 80 });
    const interpretation = interpretSecurityHeadersResult(scanner, 1);

    expect(interpretation.severity).toBe('info');
    expect(interpretation.message).toContain('B');
  });

  it('should return warning severity for C grade', () => {
    const scanner = createMockScanner({ status: 'available', grade: 'C', score: 70 });
    const interpretation = interpretSecurityHeadersResult(scanner, 2);

    expect(interpretation.severity).toBe('warning');
    expect(interpretation.message).toContain('C');
  });

  it('should return warning severity for D grade', () => {
    const scanner = createMockScanner({ status: 'available', grade: 'D', score: 60 });
    const interpretation = interpretSecurityHeadersResult(scanner, 3);

    expect(interpretation.severity).toBe('warning');
    expect(interpretation.message).toContain('D');
  });

  it('should return critical severity for E grade', () => {
    const scanner = createMockScanner({ status: 'available', grade: 'E', score: 40 });
    const interpretation = interpretSecurityHeadersResult(scanner, 4);

    expect(interpretation.severity).toBe('critical');
    expect(interpretation.message).toContain('E');
  });

  it('should return critical severity for F grade', () => {
    const scanner = createMockScanner({ status: 'available', grade: 'F', score: 0 });
    const interpretation = interpretSecurityHeadersResult(scanner, 5);

    expect(interpretation.severity).toBe('critical');
    expect(interpretation.message).toContain('F');
    expect(interpretation.recommendation).toContain('immediate attention');
  });

  it('should mention missing headers count in recommendation', () => {
    const scanner = createMockScanner(
      { status: 'available', grade: 'C', score: 70 },
      ['Missing header 1', 'Missing header 2', 'Missing header 3']
    );
    const interpretation = interpretSecurityHeadersResult(scanner, 3);

    expect(interpretation.recommendation).toContain('Missing 3');
  });

  it('should handle unknown grade', () => {
    const scanner = createMockScanner({ status: 'available', grade: 'Unknown' });
    const interpretation = interpretSecurityHeadersResult(scanner, 0);

    expect(interpretation.severity).toBe('info');
    expect(interpretation.message).toContain('Unknown');
  });
});
