# Domain Scanner Framework

This directory contains the modular domain scanner framework that powers the risk assessment tool. Each scanner is independent and can be added, modified, or removed without affecting others.

## Architecture

The scanner framework consists of:

- **`index.ts`** - Main entry point that exports `SCANNERS`, `runAllScanners()`, `runScanner()`, and `interpretScannerResult()`
- **Individual scanner files** - Each scanner (DNS, Email Auth, Certificates, etc.) in its own file
- **Type definitions** - Shared types in `src/types/domainScan.ts`
- **Helper utilities** - Domain checking functions in `src/utils/domainChecks.ts`

## Available Scanners

| Scanner | File | Description | Timeout |
|---------|------|-------------|---------|
| DNS Records | `dnsScanner.ts` | Retrieves A, AAAA, MX, TXT, CNAME records | 5s |
| Email Authentication | `emailAuthScanner.ts` | Validates SPF, DMARC, and DKIM | 10s |
| SSL/TLS Certificates | `certificateScanner.ts` | Analyzes certificates from crt.sh | 15s |
| Domain Registration | `rdapScanner.ts` | Retrieves RDAP/WHOIS data | 10s |
| SSL/TLS Configuration | `sslLabsScanner.ts` | Deep TLS analysis via SSL Labs | 10m |
| Security Headers | `securityHeadersScanner.ts` | Checks HTTP security headers | 15s |

## How to Add a New Scanner

Adding a new scanner is straightforward and follows these steps:

### 1. Create Your Scanner File

Create a new file in `src/utils/scanners/` named after your scanner (e.g., `myNewScanner.ts`):

```typescript
import { DomainScanner, ExecutedScannerResult, ScannerInterpretation } from '../../types/domainScan';

export const myNewScanner: DomainScanner = {
  id: 'myNewScanner',  // Unique ID (camelCase)
  label: 'My New Scanner',  // Display name
  description: 'What this scanner checks',
  timeout: 10000,  // Timeout in milliseconds
  dataSource: {
    name: 'Data Source Name',
    url: 'https://datasource.com',
  },
  run: async (domain: string) => {
    // Your scanner logic here
    const issues: string[] = [];

    try {
      // Perform checks...
      // Add issues as you find them

      return {
        data: {
          // Any structured data you want to return
        },
        summary: 'Brief summary of results',
        issues: issues.length > 0 ? issues : undefined
      };
    } catch (err) {
      return {
        data: { error: err instanceof Error ? err.message : 'Unknown error' },
        summary: 'Scanner failed',
        issues: ['Error message here']
      };
    }
  }
};

// Interpretation function for your scanner
export const interpretMyNewScannerResult = (
  scanner: ExecutedScannerResult,
  issueCount: number
): ScannerInterpretation => {
  // Determine severity based on your criteria
  const severity = issueCount === 0 ? 'success' :
                   issueCount <= 2 ? 'warning' : 'critical';

  return {
    severity,
    message: 'Result message',
    recommendation: 'What users should do'
  };
};
```

### 2. Register Your Scanner

Update `src/utils/scanners/index.ts`:

```typescript
// Add import at the top
import { myNewScanner } from './myNewScanner';
import { interpretMyNewScannerResult } from './myNewScanner';

// Add to SCANNERS array
export const SCANNERS: DomainScanner[] = [
  dnsScanner,
  emailAuthScanner,
  certificateScanner,
  rdapScanner,
  sslLabsScanner,
  securityHeadersScanner,
  myNewScanner,  // Add here
];

// Add case in interpretScannerResult switch
export const interpretScannerResult = (scanner: ExecutedScannerResult): ScannerInterpretation => {
  // ... existing code ...

  switch (scanner.id) {
    // ... existing cases ...
    case 'myNewScanner':
      return interpretMyNewScannerResult(scanner, issueCount);
    // ...
  }
};
```

### 3. Create Tests for Your Scanner

Create `src/utils/scanners/myNewScanner.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { myNewScanner, interpretMyNewScannerResult } from './myNewScanner';

// Mock fetch globally
global.fetch = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
});

describe('My New Scanner', () => {
  it('should perform basic check', async () => {
    // Mock your API calls
    (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => ({ /* mock data */ }),
    });

    const result = await myNewScanner.run('example.com');

    expect(result).toBeDefined();
    expect(result.summary).toBeDefined();
  });

  it('should detect issues', async () => {
    // Test issue detection
    // ...
  });

  it('should handle errors gracefully', async () => {
    // Test error handling
    // ...
  });
});

describe('My New Scanner Interpretation', () => {
  it('returns success severity for no issues', () => {
    const result = {
      id: 'myNewScanner',
      label: 'My New Scanner',
      status: 'complete' as const,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      data: {},
      issues: [],
    };

    const interp = interpretMyNewScannerResult(result, 0);
    expect(interp.severity).toBe('success');
  });
});
```

### 4. Run Tests

```bash
# Run just your scanner's tests
npm test -- myNewScanner.test.ts

# Run all tests to ensure nothing broke
npm test
```

## Scanner Structure

### Required Properties

Each scanner must implement the `DomainScanner` interface:

```typescript
interface DomainScanner {
  id: string;              // Unique identifier (camelCase)
  label: string;           // Human-readable name
  description: string;     // What the scanner does
  timeout?: number;        // Optional timeout (ms), default 30s
  dataSource: {            // Where data comes from
    name: string;
    url: string;
  };
  run: (domain: string) => Promise<BaseScannerResult>;
  deriveIssues?: (result: BaseScannerResult, domain: string) => string[];
}
```

### Return Value

The `run()` function must return:

```typescript
interface BaseScannerResult {
  data: unknown;           // Structured data for UI
  summary: string;         // Brief text summary
  issues?: string[];       // Array of issue messages
}
```

### Best Practices

1. **Timeout appropriately** - Set realistic timeouts based on expected API response times
2. **Handle errors gracefully** - Always catch and return structured errors
3. **Provide actionable issues** - Issue messages should be clear and actionable
4. **Include data sources** - Credit the data source for transparency
5. **Write comprehensive tests** - Test success cases, error cases, and edge cases
6. **Keep scanners independent** - Don't rely on other scanners' results
7. **Use helper functions** - Leverage `src/utils/domainChecks.ts` for common operations

## Interpretation Functions

Each scanner should export an interpretation function that translates results into user-facing guidance:

```typescript
export const interpretMyResult = (
  scanner: ExecutedScannerResult,
  issueCount: number
): ScannerInterpretation => {
  return {
    severity: 'success' | 'info' | 'warning' | 'critical' | 'error',
    message: 'Short status message',
    recommendation: 'Detailed guidance for the user'
  };
};
```

### Severity Levels

- **success** - Everything is good
- **info** - Informational, no action needed
- **warning** - Issues that should be addressed
- **critical** - Serious issues requiring immediate attention
- **error** - Scanner failed to execute

## Helper Utilities

Common domain checking functions are available in `src/utils/domainChecks.ts`:

```typescript
import { fetchDNS, extractSPF, fetchDMARC, checkDKIM, fetchCertificates } from '../domainChecks';

// Fetch DNS records
const aRecords = await fetchDNS('example.com', 'A');

// Extract SPF from TXT records
const spf = extractSPF(txtRecords);

// Fetch DMARC record
const dmarc = await fetchDMARC('example.com');

// Check for DKIM selectors
const dkimSelectors = await checkDKIM('example.com');

// Fetch certificates from crt.sh
const certificates = await fetchCertificates('example.com');
```

## Running Scanners

### Run All Scanners

```typescript
import { runAllScanners } from './scanners';

const results = await runAllScanners('example.com', (progress) => {
  console.log('Progress:', progress);
});
```

### Run Individual Scanner

```typescript
import { runScanner } from './scanners';

const result = await runScanner('example.com', 'dns');
```

### Interpret Results

```typescript
import { interpretScannerResult } from './scanners';

const interpretation = interpretScannerResult(result);
console.log(interpretation.message);
console.log(interpretation.recommendation);
```

## Testing Strategy

Each scanner should have comprehensive tests covering:

1. **Success cases** - Scanner completes successfully
2. **Issue detection** - Scanner identifies problems correctly
3. **Error handling** - Scanner handles API failures gracefully
4. **Edge cases** - Unusual inputs, timeouts, malformed data
5. **Interpretation** - Severity levels are assigned correctly

See existing scanner tests for examples and patterns to follow.

## Contributing

When adding or modifying scanners:

1. Follow the established patterns in existing scanners
2. Write tests for all new functionality
3. Update this README if adding new concepts
4. Ensure all tests pass before submitting
5. Keep scanner logic focused and single-purpose

## Questions?

For questions about the scanner framework, see the main project README or review existing scanner implementations as examples.
