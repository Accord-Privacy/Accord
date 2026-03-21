import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the markdown module BEFORE importing MessagePreview
vi.mock('../markdown', () => ({
  renderMessageMarkdown: vi.fn((text: string) => {
    // More realistic mock - return empty for whitespace-only, otherwise wrap in p tag
    const trimmed = text.trim();
    return trimmed ? `<p>${trimmed}</p>` : '';
  }),
}));

import { MessagePreview } from '../components/MessagePreview';
import { renderMessageMarkdown } from '../markdown';

describe('MessagePreview', () => {
  const mockOnClose = vi.fn();

  beforeEach(() => {
    mockOnClose.mockClear();
    vi.clearAllMocks();
  });

  it('returns null when visible is false', () => {
    const { container } = render(
      <MessagePreview
        text="Some text"
        visible={false}
        onClose={mockOnClose}
      />
    );

    expect(container.firstChild).toBeNull();
    expect(screen.queryByText('Preview')).not.toBeInTheDocument();
  });

  it('returns null when text is empty', () => {
    const { container } = render(
      <MessagePreview
        text=""
        visible={true}
        onClose={mockOnClose}
      />
    );

    expect(container.firstChild).toBeNull();
  });

  it('returns null when text contains only spaces', () => {
    const { container } = render(
      <MessagePreview
        text="     "
        visible={true}
        onClose={mockOnClose}
      />
    );

    // Component checks text.trim() before rendering
    expect(container.firstChild).toBeNull();
  });

  it('renders preview panel when visible with text', () => {
    render(
      <MessagePreview
        text="Hello world"
        visible={true}
        onClose={mockOnClose}
      />
    );

    expect(screen.getByText('Preview')).toBeInTheDocument();
    expect(screen.getByText('×')).toBeInTheDocument();
  });

  it('calls renderMessageMarkdown with text and currentUsername', () => {
    render(
      <MessagePreview
        text="Test message"
        currentUsername="testuser"
        visible={true}
        onClose={mockOnClose}
      />
    );

    expect(renderMessageMarkdown).toHaveBeenCalledWith('Test message', 'testuser');
  });

  it('calls renderMessageMarkdown without username when not provided', () => {
    render(
      <MessagePreview
        text="Test message"
        visible={true}
        onClose={mockOnClose}
      />
    );

    expect(renderMessageMarkdown).toHaveBeenCalledWith('Test message', undefined);
  });

  it('close button calls onClose when clicked', () => {
    render(
      <MessagePreview
        text="Test content"
        visible={true}
        onClose={mockOnClose}
      />
    );

    const closeButton = screen.getByRole('button', { name: /close preview/i });
    closeButton.click();

    expect(mockOnClose).toHaveBeenCalledTimes(1);
  });

  it('has correct aria-label on close button', () => {
    render(
      <MessagePreview
        text="Test content"
        visible={true}
        onClose={mockOnClose}
      />
    );

    const closeButton = screen.getByRole('button');
    expect(closeButton).toHaveAttribute('aria-label', 'Close preview');
  });

  it('close button has title attribute with keyboard shortcut', () => {
    render(
      <MessagePreview
        text="Test content"
        visible={true}
        onClose={mockOnClose}
      />
    );

    const closeButton = screen.getByRole('button');
    expect(closeButton).toHaveAttribute('title', 'Close preview (Ctrl+Shift+P)');
  });

  it('renders markdown HTML in preview body', () => {
    const { container } = render(
      <MessagePreview
        text="**Bold text**"
        visible={true}
        onClose={mockOnClose}
      />
    );

    const previewBody = container.querySelector('.message-preview-body');
    expect(previewBody).toBeInTheDocument();
    expect(previewBody).toHaveClass('message-content');
  });

  it('uses dangerouslySetInnerHTML to render markdown', () => {
    vi.mocked(renderMessageMarkdown).mockReturnValue('<strong>Rendered HTML</strong>');

    const { container } = render(
      <MessagePreview
        text="**Bold**"
        visible={true}
        onClose={mockOnClose}
      />
    );

    const previewBody = container.querySelector('.message-preview-body');
    expect(previewBody?.innerHTML).toBe('<strong>Rendered HTML</strong>');
  });

  it('has correct CSS classes on panel elements', () => {
    const { container } = render(
      <MessagePreview
        text="Content"
        visible={true}
        onClose={mockOnClose}
      />
    );

    expect(container.querySelector('.message-preview-panel')).toBeInTheDocument();
    expect(container.querySelector('.message-preview-header')).toBeInTheDocument();
    expect(container.querySelector('.message-preview-title')).toBeInTheDocument();
    expect(container.querySelector('.message-preview-close')).toBeInTheDocument();
    expect(container.querySelector('.message-preview-body')).toBeInTheDocument();
  });

  it('only calls renderMessageMarkdown when text changes', () => {
    const { rerender } = render(
      <MessagePreview
        text="Initial text"
        visible={true}
        onClose={mockOnClose}
      />
    );

    expect(renderMessageMarkdown).toHaveBeenCalledTimes(1);

    // Rerender with same text
    rerender(
      <MessagePreview
        text="Initial text"
        visible={true}
        onClose={mockOnClose}
      />
    );

    // Should still be 1 due to useMemo
    expect(renderMessageMarkdown).toHaveBeenCalledTimes(1);

    // Rerender with different text
    rerender(
      <MessagePreview
        text="New text"
        visible={true}
        onClose={mockOnClose}
      />
    );

    // Should now be 2
    expect(renderMessageMarkdown).toHaveBeenCalledTimes(2);
  });
});
