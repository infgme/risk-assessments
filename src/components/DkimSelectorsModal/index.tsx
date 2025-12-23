import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';

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
  const { t } = useTranslation('common');

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
    // DNS label rules: must start and end with alphanumeric, hyphens only in middle
    const pattern = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i;
    if (!selector) return t('dkimModal.errors.selectorEmpty');
    if (selector.length > 63) return t('dkimModal.errors.selectorTooLong');
    if (!pattern.test(selector)) {
      return t('dkimModal.errors.selectorInvalid');
    }
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
      setErrors({ selector: t('dkimModal.errors.selectorDuplicate') });
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
    if (!emailSource.trim()) {
      setErrors({ email: t('dkimModal.errors.emailSourceEmpty') });
      return;
    }

    // Match DKIM-Signature headers specifically and extract the s= parameter
    // This regex looks for DKIM-Signature: followed by any content containing s=value
    const dkimHeaderPattern = /DKIM-Signature:[^]*?(?=DKIM-Signature:|$)/gi;
    const dkimHeaders = emailSource.match(dkimHeaderPattern) || [];

    const extracted: string[] = [];
    dkimHeaders.forEach((header) => {
      // Within each DKIM-Signature header, extract the selector value after s=
      // Match s= preceded by start-of-string, semicolon, or whitespace, and followed by selector chars
      const selectorMatch = header.match(/(?:^|[;\s])s=([a-z0-9-]+)(?=[;\s]|$)/i);
      if (selectorMatch && selectorMatch[1]) {
        extracted.push(selectorMatch[1]);
      }
    });

    // Remove duplicates
    const uniqueSelectors = [...new Set(extracted)];

    if (uniqueSelectors.length === 0) {
      setErrors({ email: t('dkimModal.errors.noSelectorsFound') });
      return;
    }

    const newSelectors = [...selectors];
    uniqueSelectors.forEach((selector) => {
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
      setErrors({ general: t('dkimModal.errors.noSelectors') });
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
      className='dkim-modal-overlay'
      role='dialog'
      aria-modal='true'
      aria-labelledby='dkim-modal-title'
    >
      <div className='dkim-modal'>
        <div className='dkim-modal-header'>
          <h2 id='dkim-modal-title'>{t('dkimModal.title')}</h2>
          <button
            className='dkim-modal-close'
            onClick={onClose}
            aria-label='Close'
          >
            ×
          </button>
        </div>

        <div className='dkim-modal-body'>
          <div className='dkim-info-banner'>
            <svg
              className='dkim-info-icon'
              viewBox='0 0 24 24'
              fill='currentColor'
              aria-hidden='true'
            >
              <path
                d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z'
              />
            </svg>
            <p>
              {t('dkimModal.infoBanner.description')}{' '}
              {t('dkimModal.infoBanner.domain')}:{' '}
              <strong>{domain}</strong>
            </p>
          </div>

          {errors.general && <div className='dkim-error'>{errors.general}</div>}

          {selectors.length > 0 && (
            <div className='dkim-selectors-section'>
              <h4>{t('dkimModal.currentSelectors', { count: selectors.length })}</h4>
              <ul className='dkim-selectors-list'>
                {selectors.map((selector) => (
                  <li key={selector} className='dkim-selector-item'>
                    <span className='dkim-selector-name'>{selector}</span>
                    <button
                      className="dkim-remove-btn"
                      data-testid={`remove-selector-${selector}`}
                      onClick={() => handleRemoveSelector(selector)}
                      aria-label={`${t('dkimModal.removeSelector', { selector })}`}
                    >
                      <svg viewBox='0 0 24 24' fill='currentColor' aria-hidden='true'>
                        <path
                          // eslint-disable-next-line max-len
                          d='M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z'
                        />
                      </svg>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {!showEmailInput && (
            <div className='dkim-add-section'>
              <h4>{t('dkimModal.addManually')}</h4>
              <div className='dkim-input-group'>
                <input
                  type='text'
                  value={newSelector}
                  onChange={(e) => setNewSelector(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder={t('dkimModal.selectorPlaceholder')}
                  aria-label={t('dkimModal.selectorPlaceholder')}
                  className={errors.selector ? 'error' : ''}
                />
                <button className='dkim-add-btn' onClick={handleAddSelector}>
                  {t('dkimModal.addButton')}
                </button>
              </div>
              {errors.selector && <div className='dkim-error-text'>{errors.selector}</div>}
            </div>
          )}

          <div className='dkim-toggle-section'>
            <button
              className='dkim-toggle-btn'
              onClick={() => setShowEmailInput(!showEmailInput)}
            >
              <svg
                className='dkim-btn-icon'
                viewBox='0 0 24 24'
                fill='currentColor'
                aria-hidden='true'
              >
                <path
                  // eslint-disable-next-line max-len
                  d='M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z'
                />
              </svg>
              {showEmailInput ? t('dkimModal.hideEmailSource') : t('dkimModal.extractFromEmail')}
            </button>
          </div>

          {showEmailInput && (
            <div className='dkim-email-section'>
              <h4>{t('dkimModal.extractFromEmail')}</h4>
              <p className='dkim-help-text'>
                {t('dkimModal.extractHelp')}
              </p>
              <textarea
                value={emailSource}
                onChange={(e) => setEmailSource(e.target.value)}
                placeholder={t('dkimModal.emailSourcePlaceholder')}
                rows={10}
                className={errors.email ? 'error' : ''}
              />
              {errors.email && <div className='dkim-error-text'>{errors.email}</div>}
              <button className='dkim-extract-btn' onClick={extractSelectorsFromEmail}>
                <svg
                  className='dkim-btn-icon'
                  viewBox='0 0 24 24'
                  fill='currentColor'
                  aria-hidden='true'
                >
                  <path
                    // eslint-disable-next-line max-len
                    d='M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z'
                  />
                </svg>
                {t('dkimModal.extractButton')}
              </button>
            </div>
          )}
        </div>

        <div className='dkim-modal-footer'>
          <button className='dkim-cancel-btn' onClick={onClose}>
            {t('buttons.cancel')}
          </button>
          <button className='dkim-save-btn' onClick={handleSave}>
            {t('dkimModal.saveButton')}
          </button>
        </div>
      </div>
    </div>
  );
};

export default DkimSelectorsModal;
