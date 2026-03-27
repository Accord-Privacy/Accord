import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MessagePreview } from '../components/MessagePreview';
import * as markdownModule from '../markdown';

vi.mock('../markdown', () => ({
  renderMessageMarkdown: vi.fn((text: string, _username?: string) => `<p>${text}</p>`),
}));

describe('MessagePreview', () => {
  const mockOnClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders preview panel when visible and has text', () => {
    render(<MessagePreview text="Hello" visible={true} onClose={mockOnClose} />);
    expect(screen.getByText('Preview')).toBeInTheDocument();
  });

  it('renders null when not visible', () => {
    const { container } = render(<MessagePreview text="Hello" visible={false} onClose={mockOnClose} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders null when text is empty', () => {
    const { container } = render(<MessagePreview text="" visible={true} onClose={mockOnClose} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders null when text is only whitespace', () => {
    const { container } = render(<MessagePreview text="   " visible={true} onClose={mockOnClose} />);
    expect(container.firstChild).toBeNull();
  });

  it('displays close button with × symbol', () => {
    render(<MessagePreview text="Hello" visible={true} onClose={mockOnClose} />);
    expect(screen.getByText('×')).toBeInTheDocument();
  });

  it('calls onClose when close button is clicked', () => {
    render(<MessagePreview text="Hello" visible={true} onClose={mockOnClose} />);
    const closeButton = screen.getByRole('button', { name: /close preview/i });
    fireEvent.click(closeButton);
    expect(mockOnClose).toHaveBeenCalledTimes(1);
  });

  it('close button has correct title attribute', () => {
    render(<MessagePreview text="Hello" visible={true} onClose={mockOnClose} />);
    const closeButton = screen.getByRole('button', { name: /close preview/i });
    expect(closeButton).toHaveAttribute('title', 'Close preview (Ctrl+Shift+P)');
  });

  it('renders markdown content using dangerouslySetInnerHTML', () => {
    const { container } = render(<MessagePreview text="**bold**" visible={true} onClose={mockOnClose} />);
    const body = container.querySelector('.message-preview-body');
    expect(body).toBeInTheDocument();
    expect(body?.innerHTML).toBe('<p>**bold**</p>');
  });

  it('applies correct CSS classes to elements', () => {
    const { container } = render(<MessagePreview text="Test" visible={true} onClose={mockOnClose} />);
    expect(container.querySelector('.message-preview-panel')).toBeInTheDocument();
    expect(container.querySelector('.message-preview-header')).toBeInTheDocument();
    expect(container.querySelector('.message-preview-title')).toBeInTheDocument();
    expect(container.querySelector('.message-preview-close')).toBeInTheDocument();
    expect(container.querySelector('.message-preview-body')).toBeInTheDocument();
  });

  it('message body has message-content class for styling', () => {
    const { container } = render(<MessagePreview text="Test" visible={true} onClose={mockOnClose} />);
    const body = container.querySelector('.message-preview-body');
    expect(body).toHaveClass('message-content');
  });

  it('passes currentUsername to renderMessageMarkdown', () => {
    render(<MessagePreview text="Hello @user" currentUsername="testuser" visible={true} onClose={mockOnClose} />);
    expect(markdownModule.renderMessageMarkdown).toHaveBeenCalledWith('Hello @user', 'testuser');
  });

  it('works without currentUsername prop', () => {
    render(<MessagePreview text="Hello" visible={true} onClose={mockOnClose} />);
    expect(markdownModule.renderMessageMarkdown).toHaveBeenCalledWith('Hello', undefined);
  });

  it('memoizes rendered HTML based on text and currentUsername', () => {
    const { rerender } = render(<MessagePreview text="Hello" currentUsername="user1" visible={true} onClose={mockOnClose} />);

    // Same props, should not re-render
    rerender(<MessagePreview text="Hello" currentUsername="user1" visible={true} onClose={mockOnClose} />);
    expect(markdownModule.renderMessageMarkdown).toHaveBeenCalledTimes(1);
  });

  it('re-renders when text changes', () => {
    const { rerender } = render(<MessagePreview text="Hello" visible={true} onClose={mockOnClose} />);
    rerender(<MessagePreview text="World" visible={true} onClose={mockOnClose} />);
    expect(markdownModule.renderMessageMarkdown).toHaveBeenCalledTimes(2);
  });

  it('re-renders when currentUsername changes', () => {
    const { rerender } = render(<MessagePreview text="Hello" currentUsername="user1" visible={true} onClose={mockOnClose} />);
    rerender(<MessagePreview text="Hello" currentUsername="user2" visible={true} onClose={mockOnClose} />);
    expect(markdownModule.renderMessageMarkdown).toHaveBeenCalledTimes(2);
  });
});
