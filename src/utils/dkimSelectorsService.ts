const STORAGE_KEY_PREFIX = 'dkim_selectors_';

export interface DkimSelectorsData {
  domain: string;
  selectors: string[];
  updatedAt: string;
}

/**
 * Get DKIM selectors for a specific domain from LocalStorage
 */
export const getDkimSelectors = (domain: string): string[] => {
  try {
    if (!domain) {
      return [];
    }

    const key = `${STORAGE_KEY_PREFIX}${domain}`;
    const stored = localStorage.getItem(key);
    if (!stored) return [];

    const data: DkimSelectorsData = JSON.parse(stored);

    // Validate data structure
    if (!data.selectors || !Array.isArray(data.selectors)) {
      // eslint-disable-next-line no-console
      console.warn(`Invalid DKIM selectors data structure for domain: ${domain}`);
      return [];
    }

    return data.selectors;
  } catch (error) {
    // Silent fail for read operations - just return empty array
    // This is expected behavior when localStorage is unavailable or data is corrupted
    if (error instanceof Error && error.message.includes('localStorage')) {
      // eslint-disable-next-line no-console
      console.warn('LocalStorage unavailable for reading DKIM selectors');
    }
    return [];
  }
};

/**
 * Save DKIM selectors for a specific domain to LocalStorage
 */
export const saveDkimSelectors = (domain: string, selectors: string[]): boolean => {
  try {
    if (!domain) {
      throw new Error('Domain is required to save DKIM selectors');
    }

    if (!Array.isArray(selectors)) {
      throw new Error('Selectors must be an array');
    }

    const key = `${STORAGE_KEY_PREFIX}${domain}`;
    const data: DkimSelectorsData = {
      domain,
      selectors,
      updatedAt: new Date().toISOString(),
    };
    localStorage.setItem(key, JSON.stringify(data));
    return true;
  } catch (error) {
    // Report errors for write operations as these affect user functionality
    if (error instanceof Error) {
      // eslint-disable-next-line no-console
      console.error(`Failed to save DKIM selectors for ${domain}:`, error.message);

      // Check for quota exceeded error
      if (error.name === 'QuotaExceededError') {
        // eslint-disable-next-line no-console
        console.error('LocalStorage quota exceeded. Consider clearing old data.');
      }
    }
    return false;
  }
};

/**
 * Delete DKIM selectors for a specific domain from LocalStorage
 */
export const deleteDkimSelectors = (domain: string): boolean => {
  try {
    if (!domain) {
      throw new Error('Domain is required to delete DKIM selectors');
    }

    const key = `${STORAGE_KEY_PREFIX}${domain}`;
    localStorage.removeItem(key);
    return true;
  } catch (error) {
    // Report errors for delete operations as user initiated
    if (error instanceof Error) {
      // eslint-disable-next-line no-console
      console.error(`Failed to delete DKIM selectors for ${domain}:`, error.message);
    }
    return false;
  }
};
