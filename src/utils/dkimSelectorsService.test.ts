import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  getDkimSelectors,
  saveDkimSelectors,
  deleteDkimSelectors,
  type DkimSelectorsData
} from './dkimSelectorsService';

// Mock localStorage
const localStorageMock = (() => {
  let store: { [key: string]: string } = {};

  return {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    key: vi.fn((index: number) => {
      const keys = Object.keys(store);
      return keys[index] || null;
    }),
    get length() {
      return Object.keys(store).length;
    },
  };
})();

Object.defineProperty(global, 'localStorage', {
  value: localStorageMock,
  writable: true,
});

describe('dkimSelectorsService', () => {
  beforeEach(() => {
    localStorageMock.clear();
    vi.clearAllMocks();
  });

  describe('getDkimSelectors', () => {
    it('should return empty array when no selectors stored', () => {
      const result = getDkimSelectors('example.com');
      expect(result).toEqual([]);
    });

    it('should return stored selectors for a domain', () => {
      const data: DkimSelectorsData = {
        domain: 'example.com',
        selectors: ['google', 'selector1'],
        updatedAt: new Date().toISOString(),
      };
      localStorageMock.setItem('dkim_selectors_example.com', JSON.stringify(data));

      const result = getDkimSelectors('example.com');
      expect(result).toEqual(['google', 'selector1']);
    });

    it('should return empty array for empty domain', () => {
      const result = getDkimSelectors('');
      expect(result).toEqual([]);
    });

    it('should handle corrupted JSON data gracefully', () => {
      localStorageMock.setItem('dkim_selectors_example.com', 'invalid json');

      const result = getDkimSelectors('example.com');
      expect(result).toEqual([]);
    });

    it('should handle invalid data structure gracefully', () => {
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      localStorageMock.setItem('dkim_selectors_example.com', JSON.stringify({
        domain: 'example.com',
        selectors: 'not-an-array', // Invalid: should be array
        updatedAt: new Date().toISOString(),
      }));

      const result = getDkimSelectors('example.com');
      expect(result).toEqual([]);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Invalid DKIM selectors data structure')
      );

      consoleWarnSpy.mockRestore();
    });

    it('should handle localStorage unavailable gracefully', () => {
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const originalGetItem = localStorageMock.getItem;

      localStorageMock.getItem = vi.fn(() => {
        throw new Error('localStorage is not available');
      });

      const result = getDkimSelectors('example.com');
      expect(result).toEqual([]);
      expect(consoleWarnSpy).toHaveBeenCalled();

      localStorageMock.getItem = originalGetItem;
      consoleWarnSpy.mockRestore();
    });
  });

  describe('saveDkimSelectors', () => {
    it('should save selectors successfully', () => {
      const result = saveDkimSelectors('example.com', ['google', 'selector1']);

      expect(result).toBe(true);
      expect(localStorageMock.setItem).toHaveBeenCalled();

      const stored = localStorageMock.getItem('dkim_selectors_example.com');
      const data = JSON.parse(stored!);

      expect(data.domain).toBe('example.com');
      expect(data.selectors).toEqual(['google', 'selector1']);
      expect(data.updatedAt).toBeDefined();
    });

    it('should save empty selectors array', () => {
      const result = saveDkimSelectors('example.com', []);

      expect(result).toBe(true);

      const stored = localStorageMock.getItem('dkim_selectors_example.com');
      const data = JSON.parse(stored!);

      expect(data.selectors).toEqual([]);
    });

    it('should return false for empty domain', () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const result = saveDkimSelectors('', ['google']);

      expect(result).toBe(false);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to save DKIM selectors'),
        expect.stringContaining('Domain is required')
      );

      consoleErrorSpy.mockRestore();
    });

    it('should return false for non-array selectors', () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = saveDkimSelectors('example.com', 'not-an-array' as any);

      expect(result).toBe(false);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to save DKIM selectors'),
        expect.stringContaining('Selectors must be an array')
      );

      consoleErrorSpy.mockRestore();
    });

    it('should handle quota exceeded error', () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const originalSetItem = localStorageMock.setItem;

      localStorageMock.setItem = vi.fn(() => {
        const error = new Error('QuotaExceededError');
        error.name = 'QuotaExceededError';
        throw error;
      });

      const result = saveDkimSelectors('example.com', ['google']);

      expect(result).toBe(false);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to save DKIM selectors'),
        expect.any(String)
      );
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('LocalStorage quota exceeded')
      );

      localStorageMock.setItem = originalSetItem;
      consoleErrorSpy.mockRestore();
    });

    it('should update existing selectors', () => {
      saveDkimSelectors('example.com', ['google']);
      saveDkimSelectors('example.com', ['selector1', 'selector2']);

      const result = getDkimSelectors('example.com');
      expect(result).toEqual(['selector1', 'selector2']);
    });
  });

  describe('deleteDkimSelectors', () => {
    it('should delete selectors successfully', () => {
      saveDkimSelectors('example.com', ['google']);

      const result = deleteDkimSelectors('example.com');

      expect(result).toBe(true);
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('dkim_selectors_example.com');

      const retrieved = getDkimSelectors('example.com');
      expect(retrieved).toEqual([]);
    });

    it('should return true even if domain does not exist', () => {
      const result = deleteDkimSelectors('nonexistent.com');
      expect(result).toBe(true);
    });

    it('should return false for empty domain', () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const result = deleteDkimSelectors('');

      expect(result).toBe(false);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to delete DKIM selectors'),
        expect.stringContaining('Domain is required')
      );

      consoleErrorSpy.mockRestore();
    });

    it('should handle localStorage errors', () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const originalRemoveItem = localStorageMock.removeItem;

      localStorageMock.removeItem = vi.fn(() => {
        throw new Error('localStorage error');
      });

      const result = deleteDkimSelectors('example.com');

      expect(result).toBe(false);
      expect(consoleErrorSpy).toHaveBeenCalled();

      localStorageMock.removeItem = originalRemoveItem;
      consoleErrorSpy.mockRestore();
    });
  });

  describe('integration tests', () => {
    it('should handle complete lifecycle of selectors', () => {
      // Save selectors for multiple domains
      expect(saveDkimSelectors('domain1.com', ['sel1', 'sel2'])).toBe(true);
      expect(saveDkimSelectors('domain2.com', ['sel3'])).toBe(true);

      // Get individual selectors
      expect(getDkimSelectors('domain1.com')).toEqual(['sel1', 'sel2']);
      expect(getDkimSelectors('domain2.com')).toEqual(['sel3']);

      // Update selectors for one domain
      expect(saveDkimSelectors('domain1.com', ['sel4'])).toBe(true);
      expect(getDkimSelectors('domain1.com')).toEqual(['sel4']);

      // Delete selectors for one domain
      expect(deleteDkimSelectors('domain1.com')).toBe(true);
      expect(getDkimSelectors('domain1.com')).toEqual([]);

      // Other domain should still exist
      expect(getDkimSelectors('domain2.com')).toEqual(['sel3']);
    });

    it('should maintain data integrity across operations', () => {
      const selectors = ['google', 'selector1', 'selector2'];

      saveDkimSelectors('example.com', selectors);

      const retrieved = getDkimSelectors('example.com');
      expect(retrieved).toEqual(selectors);

      // Verify stored data structure
      const stored = localStorageMock.getItem('dkim_selectors_example.com');
      const data = JSON.parse(stored!);

      expect(data.domain).toBe('example.com');
      expect(data.selectors).toEqual(selectors);
      expect(data.updatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/); // ISO date format
    });
  });
});
