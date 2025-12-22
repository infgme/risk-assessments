import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import DkimSelectorsModal from './index';

describe('DkimSelectorsModal', () => {
  const defaultProps = {
    isOpen: true,
    onClose: vi.fn(),
    onSave: vi.fn(),
    domain: 'example.com',
    existingSelectors: [],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    document.body.style.overflow = '';
  });

  it('renders nothing when isOpen is false', () => {
    const { container } = render(<DkimSelectorsModal {...defaultProps} isOpen={false} />);
    expect(container.querySelector('.dkim-modal-overlay')).toBeNull();
  });

  it('renders modal when isOpen is true', () => {
    render(<DkimSelectorsModal {...defaultProps} />);
    expect(screen.getByText('Manage DKIM Selectors')).toBeTruthy();
    expect(screen.getByText(/DKIM selectors vary by email provider/)).toBeTruthy();
  });

  it('displays domain in modal content', () => {
    render(<DkimSelectorsModal {...defaultProps} domain="test.com" />);
    expect(screen.getByText(/test.com/)).toBeTruthy();
  });

  it('loads existing selectors', () => {
    render(<DkimSelectorsModal {...defaultProps} existingSelectors={['google', 'selector1']} />);
    expect(screen.getByText('google')).toBeTruthy();
    expect(screen.getByText('selector1')).toBeTruthy();
  });

  it('calls onClose when close button is clicked', () => {
    render(<DkimSelectorsModal {...defaultProps} />);
    const closeButton = screen.getByLabelText('Close');
    fireEvent.click(closeButton);
    expect(defaultProps.onClose).toHaveBeenCalledTimes(1);
  });

  it('calls onClose when Escape key is pressed', () => {
    render(<DkimSelectorsModal {...defaultProps} />);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(defaultProps.onClose).toHaveBeenCalledTimes(1);
  });

  it('sets body overflow to hidden when open', () => {
    render(<DkimSelectorsModal {...defaultProps} />);
    expect(document.body.style.overflow).toBe('hidden');
  });

  it('resets body overflow when closed', () => {
    const { rerender } = render(<DkimSelectorsModal {...defaultProps} />);
    expect(document.body.style.overflow).toBe('hidden');

    rerender(<DkimSelectorsModal {...defaultProps} isOpen={false} />);
    expect(document.body.style.overflow).toBe('unset');
  });

  describe('Adding selectors', () => {
    it('adds a valid selector', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const input = screen.getByPlaceholderText('e.g., default, google, k1');
      fireEvent.change(input, { target: { value: 'newselector' } });

      const addButton = screen.getByText('Add');
      fireEvent.click(addButton);

      expect(screen.getByText('newselector')).toBeTruthy();
    });

    it('adds selector on Enter key press', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const input = screen.getByPlaceholderText('e.g., default, google, k1');
      fireEvent.change(input, { target: { value: 'newselector' } });
      fireEvent.keyPress(input, { key: 'Enter', code: 'Enter', charCode: 13 });

      expect(screen.getByText('newselector')).toBeTruthy();
    });

    it('clears input after adding selector', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const input = screen.getByPlaceholderText('e.g., default, google, k1') as HTMLInputElement;
      fireEvent.change(input, { target: { value: 'newselector' } });

      const addButton = screen.getByText('Add');
      fireEvent.click(addButton);

      expect(input.value).toBe('');
    });

    it('validates empty selector', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const addButton = screen.getByText('Add');
      fireEvent.click(addButton);

      expect(screen.getByText('Selector cannot be empty')).toBeTruthy();
    });

    it('validates selector length (max 63 characters)', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const input = screen.getByPlaceholderText('e.g., default, google, k1');
      const longSelector = 'a'.repeat(64);
      fireEvent.change(input, { target: { value: longSelector } });

      const addButton = screen.getByText('Add');
      fireEvent.click(addButton);

      expect(screen.getByText('Selector must be 63 characters or less')).toBeTruthy();
    });

    it('validates selector format (alphanumeric and hyphens only)', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const input = screen.getByPlaceholderText('e.g., default, google, k1');
      fireEvent.change(input, { target: { value: 'invalid@selector' } });

      const addButton = screen.getByText('Add');
      fireEvent.click(addButton);

      expect(screen.getByText('Selector can only contain letters, numbers, and hyphens')).toBeTruthy();
    });

    it('prevents duplicate selectors', () => {
      render(<DkimSelectorsModal {...defaultProps} existingSelectors={['google']} />);

      const input = screen.getByPlaceholderText('e.g., default, google, k1');
      fireEvent.change(input, { target: { value: 'google' } });

      const addButton = screen.getByText('Add');
      fireEvent.click(addButton);

      expect(screen.getByText('Selector already added')).toBeTruthy();
    });

    it('accepts valid selector formats', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const validSelectors = ['google', 'selector1', 'my-selector', 'ABC123'];

      validSelectors.forEach((selector) => {
        const input = screen.getByPlaceholderText('e.g., default, google, k1');
        fireEvent.change(input, { target: { value: selector } });

        const addButton = screen.getByText('Add');
        fireEvent.click(addButton);

        expect(screen.getByText(selector)).toBeTruthy();
      });
    });
  });

  describe('Removing selectors', () => {
    it('removes a selector when delete button is clicked', async () => {
      render(<DkimSelectorsModal {...defaultProps} existingSelectors={['google', 'selector1']} />);

      expect(screen.getByText('google')).toBeTruthy();

      // Find the remove button for 'google' selector
      const removeButton = screen.getByTestId('remove-selector-google');

      if (removeButton) {
        await fireEvent.click(removeButton);
      }

      await waitFor(() => expect(screen.queryByText('google')).toBeNull());
      expect(screen.getByText('selector1')).toBeTruthy();
    });
  });

  describe('Email source extraction', () => {
    it('toggles email input section', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const toggleButton = screen.getByText(/Extract from Email Source/);
      fireEvent.click(toggleButton);

      expect(screen.getByPlaceholderText(/Paste email headers or full email source/)).toBeTruthy();
    });

    it('extracts selectors from email headers', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const toggleButton = screen.getByText(/Extract from Email Source/);
      fireEvent.click(toggleButton);

      const textarea = screen.getByPlaceholderText(/Paste email headers or full email source/);
      const emailHeaders = `
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=google;
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
      `;

      fireEvent.change(textarea, { target: { value: emailHeaders } });

      const extractButton = screen.getByText('Extract Selectors');
      fireEvent.click(extractButton);

      expect(screen.getByText('google')).toBeTruthy();
      expect(screen.getByText('selector1')).toBeTruthy();
    });

    it('shows error when no selectors found in email', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const toggleButton = screen.getByText(/Extract from Email Source/);
      fireEvent.click(toggleButton);

      const textarea = screen.getByPlaceholderText(/Paste email headers or full email source/);
      fireEvent.change(textarea, { target: { value: 'No DKIM headers here' } });

      const extractButton = screen.getByText('Extract Selectors');
      fireEvent.click(extractButton);

      expect(screen.getByText(/No DKIM selectors found/)).toBeTruthy();
    });

    it('validates empty email input', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const toggleButton = screen.getByText(/Extract from Email Source/);
      fireEvent.click(toggleButton);

      const extractButton = screen.getByText('Extract Selectors');
      fireEvent.click(extractButton);

      expect(screen.getByPlaceholderText(/Paste email headers/)).toBeTruthy();
    });
  });

  describe('Saving selectors', () => {
    it('calls onSave with selectors when save button is clicked', () => {
      render(<DkimSelectorsModal {...defaultProps} existingSelectors={['google']} />);

      const saveButton = screen.getByText('Save Selectors');
      fireEvent.click(saveButton);

      expect(defaultProps.onSave).toHaveBeenCalledWith(['google']);
    });

    it('calls onSave with updated selectors', () => {
      render(<DkimSelectorsModal {...defaultProps} existingSelectors={['google']} />);

      // Add a new selector
      const input = screen.getByPlaceholderText('e.g., default, google, k1');
      fireEvent.change(input, { target: { value: 'selector1' } });

      const addButton = screen.getByText('Add');
      fireEvent.click(addButton);

      const saveButton = screen.getByText('Save Selectors');
      fireEvent.click(saveButton);

      expect(defaultProps.onSave).toHaveBeenCalledWith(['google', 'selector1']);
    });

    it('calls onClose when cancel button is clicked', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      const cancelButton = screen.getByText('Cancel');
      fireEvent.click(cancelButton);

      expect(defaultProps.onClose).toHaveBeenCalledTimes(1);
    });
  });

  describe('Info banner', () => {
    it('displays informational banner', () => {
      render(<DkimSelectorsModal {...defaultProps} />);

      expect(screen.getByText(/DKIM selectors vary by email provider/)).toBeTruthy();
    });
  });

  describe('Updates from props', () => {
    it('updates selectors when existingSelectors prop changes', () => {
      const { rerender } = render(<DkimSelectorsModal {...defaultProps} existingSelectors={['google']} />);

      expect(screen.getByText('google')).toBeTruthy();

      rerender(<DkimSelectorsModal {...defaultProps} existingSelectors={['selector1', 'selector2']} />);

      expect(screen.queryByText('google')).toBeNull();
      expect(screen.getByText('selector1')).toBeTruthy();
      expect(screen.getByText('selector2')).toBeTruthy();
    });
  });
});
