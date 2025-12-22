import React, { useState, useEffect } from 'react';
import './DkimSelectorsModal.css';

interface DkimSelectorsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (selectors: string[]) => void;
  domain: string;
  existingSelectors?: string[];
}

const DkimSelectorsModal: React.FC<DkimSelectorsModalProps> = ({
  isOpen,
  onClose,
  onSave,
  domain,
  existingSelectors = [],
}) => {
  const [selectors, setSelectors] = useState<string[]>(existingSelectors);
  const [newSelector, setNewSelector] = useState('');
  const [emailSource, setEmailSource] = useState('');
  const [showEmailInput, setShowEmailInput] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});

  useEffect(() => {
    setSelectors(existingSelectors);
  }, [existingSelectors]);

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleEscape);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose]);

  const validateSelector = (selector: string): string | null => {
    const pattern = /^[a-z0-9-]+$/i;
    if (!selector) return 'Selector cannot be empty';
    if (selector.length > 63) return 'Selector must be 63 characters or less';
    if (!pattern.test(selector)) return 'Selector can only contain letters, numbers, and hyphens';
    return null;
  };

  const handleAddSelector = () => {
    const trimmed = newSelector.trim();
    const error = validateSelector(trimmed);
    if (error) {
      setErrors({ selector: error });
      return;
    }

    if (selectors.includes(trimmed)) {
      setErrors({ selector: 'Selector already added' });
      return;
    }

    setSelectors([...selectors, trimmed]);
    setNewSelector('');
    setErrors({});
  };

  const handleRemoveSelector = (selectorToRemove: string) => {
    setSelectors(selectors.filter((s) => s !== selectorToRemove));
  };

  const extractSelectorsFromEmail = () => {
    const selectorMatches = emailSource.matchAll(/s=([a-z0-9-]+)/gi);
    const extracted = [...new Set([...selectorMatches].map((match) => match[1]))];

    if (extracted.length === 0) {
      setErrors({ email: 'No DKIM selectors found in email source' });
      return;
    }

    const newSelectors = [...selectors];
    extracted.forEach((selector) => {
      if (!newSelectors.includes(selector)) {
        newSelectors.push(selector);
      }
    });

    setSelectors(newSelectors);
    setEmailSource('');
    setShowEmailInput(false);
    setErrors({});
  };

  const handleSave = () => {
    if (selectors.length === 0) {
      setErrors({ general: 'Please add at least one selector' });
      return;
    }
    onSave(selectors);
    onClose();
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleAddSelector();
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="dkim-modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="dkim-modal-title"
    >
      <div className="dkim-modal">
        <div className="dkim-modal-header">
          <h2 id="dkim-modal-title">Manage DKIM Selectors</h2>
          <button
            className="dkim-modal-close"
            onClick={onClose}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="dkim-modal-body">
          <div className="dkim-info-banner">
            <svg
              className="dkim-info-icon"
              viewBox="0 0 24 24"
              fill="currentColor"
              aria-hidden="true"
            >
              <path
                d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2z
                m0-4h-2V7h2v6z"
              />
            </svg>
            <p>
              DKIM selectors vary by email provider. Add known selectors or extract them from an email.
              Domain: <strong>{domain}</strong>
            </p>
          </div>

          {errors.general && <div className="dkim-error">{errors.general}</div>}

          {selectors.length > 0 && (
            <div className="dkim-selectors-section">
              <h4>Current Selectors ({selectors.length})</h4>
              <ul className="dkim-selectors-list">
                {selectors.map((selector) => (
                  <li key={selector} className="dkim-selector-item">
                    <span className="dkim-selector-name">{selector}</span>
                    <button
                      className="dkim-remove-btn"
                      data-testId={`remove-selector-${selector}`}
                      onClick={() => handleRemoveSelector(selector)}
                      aria-label={`Remove ${selector}`}
                    >
                      <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                        <path
                          d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59
                          19 19 17.59 13.41 12z"
                        />
                      </svg>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {!showEmailInput && (
            <div className="dkim-add-section">
              <h4>Add Selector Manually</h4>
              <div className="dkim-input-group">
                <input
                  type="text"
                  value={newSelector}
                  onChange={(e) => setNewSelector(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="e.g., default, google, k1"
                  className={errors.selector ? 'error' : ''}
                />
                <button className="dkim-add-btn" onClick={handleAddSelector}>
                  Add
                </button>
              </div>
              {errors.selector && <div className="dkim-error-text">{errors.selector}</div>}
            </div>
          )}

          <div className="dkim-toggle-section">
            <button
              className="dkim-toggle-btn"
              onClick={() => setShowEmailInput(!showEmailInput)}
            >
              <svg
                className="dkim-btn-icon"
                viewBox="0 0 24 24"
                fill="currentColor"
                aria-hidden="true"
              >
                <path
                  d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2
                  16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"
                />
              </svg>
              {showEmailInput ? 'Hide Email Source' : 'Extract from Email Source'}
            </button>
          </div>

          {showEmailInput && (
            <div className="dkim-email-section">
              <h4>Extract from Email Source</h4>
              <p className="dkim-help-text">
                To get email source: Open an email → More options → Show original / View source
              </p>
              <textarea
                value={emailSource}
                onChange={(e) => setEmailSource(e.target.value)}
                placeholder="Paste email headers or full email source here..."
                rows={10}
                className={errors.email ? 'error' : ''}
              />
              {errors.email && <div className="dkim-error-text">{errors.email}</div>}
              <button className="dkim-extract-btn" onClick={extractSelectorsFromEmail}>
                <svg
                  className="dkim-btn-icon"
                  viewBox="0 0 24 24"
                  fill="currentColor"
                  aria-hidden="true"
                >
                  <path
                    d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3
                    9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6
                    0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"
                  />
                </svg>
                Extract Selectors
              </button>
            </div>
          )}
        </div>

        <div className="dkim-modal-footer">
          <button className="dkim-cancel-btn" onClick={onClose}>
            Cancel
          </button>
          <button className="dkim-save-btn" onClick={handleSave}>
            Save Selectors
          </button>
        </div>
      </div>
    </div>
  );
};

export default DkimSelectorsModal;
