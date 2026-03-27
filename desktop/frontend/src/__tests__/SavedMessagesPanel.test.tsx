import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { SavedMessagesPanel } from '../components/SavedMessagesPanel';
import type { SavedMessage } from '../hooks/useBookmarks';

vi.mock('../components/Icon', () => ({
  Icon: ({ name, size }: { name: string; size?: number }) => (
    <span data-icon={name} data-size={size}>{name}</span>
  ),
}));

const mockBookmark: SavedMessage = {
  id: 'msg-1',
  content: 'This is a saved message',
  channelId: 'ch-1',
  channelName: 'general',
  author: 'Alice',
  timestamp: 1700000000000,
  savedAt: 1700000001000,
};

describe('SavedMessagesPanel', () => {
  const mockOnRemove = vi.fn();
  const mockOnJumpTo = vi.fn();
  const mockOnClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the panel with header', () => {
    render(
      <SavedMessagesPanel
        bookmarks={[]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    expect(screen.getByText('Saved Messages')).toBeInTheDocument();
  });

  it('displays bookmark icon in header', () => {
    const { container } = render(
      <SavedMessagesPanel
        bookmarks={[]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const icon = container.querySelector('[data-icon="bookmark"]');
    expect(icon).toBeInTheDocument();
    expect(icon?.getAttribute('data-size')).toBe('20');
  });

  it('shows empty state when no bookmarks', () => {
    render(
      <SavedMessagesPanel
        bookmarks={[]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    expect(screen.getByText('No saved messages yet')).toBeInTheDocument();
    expect(screen.getByText(/Right-click a message and select "Save Message"/i)).toBeInTheDocument();
  });

  it('displays bookmark-outline icon in empty state', () => {
    const { container } = render(
      <SavedMessagesPanel
        bookmarks={[]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const icon = container.querySelector('[data-icon="bookmark-outline"]');
    expect(icon).toBeInTheDocument();
    expect(icon?.getAttribute('data-size')).toBe('48');
  });

  it('renders saved message with all metadata', () => {
    render(
      <SavedMessagesPanel
        bookmarks={[mockBookmark]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    expect(screen.getByText('Alice')).toBeInTheDocument();
    expect(screen.getByText('#general')).toBeInTheDocument();
    expect(screen.getByText('This is a saved message')).toBeInTheDocument();
  });

  it('displays formatted timestamp', () => {
    render(
      <SavedMessagesPanel
        bookmarks={[mockBookmark]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const timestampElement = screen.getByText((content, element) => {
      return element?.className === 'saved-message-time' && content.length > 0;
    });
    expect(timestampElement).toBeInTheDocument();
  });

  it('truncates long messages with ellipsis', () => {
    const longMessage = {
      ...mockBookmark,
      content: 'a'.repeat(250),
    };
    render(
      <SavedMessagesPanel
        bookmarks={[longMessage]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const content = screen.getByText(/a+…/);
    expect(content.textContent).toHaveLength(201); // 200 chars + ellipsis
  });

  it('does not truncate short messages', () => {
    const shortMessage = {
      ...mockBookmark,
      content: 'Short message',
    };
    render(
      <SavedMessagesPanel
        bookmarks={[shortMessage]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    expect(screen.getByText('Short message')).toBeInTheDocument();
    expect(screen.queryByText(/…/)).not.toBeInTheDocument();
  });

  it('calls onJumpTo with correct args when Jump to is clicked', () => {
    render(
      <SavedMessagesPanel
        bookmarks={[mockBookmark]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const jumpButton = screen.getByText('Jump to');
    fireEvent.click(jumpButton);
    expect(mockOnJumpTo).toHaveBeenCalledWith('ch-1', 'msg-1');
    expect(mockOnJumpTo).toHaveBeenCalledTimes(1);
  });

  it('calls onRemove with correct message id when Remove is clicked', () => {
    render(
      <SavedMessagesPanel
        bookmarks={[mockBookmark]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const removeButton = screen.getByText('Remove');
    fireEvent.click(removeButton);
    expect(mockOnRemove).toHaveBeenCalledWith('msg-1');
    expect(mockOnRemove).toHaveBeenCalledTimes(1);
  });

  it('calls onClose when close button is clicked', () => {
    render(
      <SavedMessagesPanel
        bookmarks={[]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const closeButton = screen.getByRole('button', { name: 'Close' });
    fireEvent.click(closeButton);
    expect(mockOnClose).toHaveBeenCalledTimes(1);
  });

  it('calls onClose when overlay is clicked', () => {
    const { container } = render(
      <SavedMessagesPanel
        bookmarks={[]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const overlay = container.querySelector('.saved-messages-overlay');
    fireEvent.click(overlay!);
    expect(mockOnClose).toHaveBeenCalledTimes(1);
  });

  it('does not close when clicking inside panel', () => {
    const { container } = render(
      <SavedMessagesPanel
        bookmarks={[mockBookmark]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const panel = container.querySelector('.saved-messages-panel');
    fireEvent.click(panel!);
    expect(mockOnClose).not.toHaveBeenCalled();
  });

  it('renders multiple bookmarks', () => {
    const bookmarks = [
      mockBookmark,
      { ...mockBookmark, id: 'msg-2', author: 'Bob', content: 'Second message' },
      { ...mockBookmark, id: 'msg-3', author: 'Charlie', content: 'Third message' },
    ];
    render(
      <SavedMessagesPanel
        bookmarks={bookmarks}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    expect(screen.getByText('Alice')).toBeInTheDocument();
    expect(screen.getByText('Bob')).toBeInTheDocument();
    expect(screen.getByText('Charlie')).toBeInTheDocument();
  });

  it('applies correct button classes', () => {
    render(
      <SavedMessagesPanel
        bookmarks={[mockBookmark]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    const jumpButton = screen.getByText('Jump to');
    const removeButton = screen.getByText('Remove');
    expect(jumpButton).toHaveClass('btn', 'btn-outline', 'btn-sm');
    expect(removeButton).toHaveClass('btn', 'btn-outline', 'btn-sm', 'btn-danger');
  });

  it('displays channel name with # prefix', () => {
    const bookmark = { ...mockBookmark, channelName: 'random' };
    render(
      <SavedMessagesPanel
        bookmarks={[bookmark]}
        onRemove={mockOnRemove}
        onJumpTo={mockOnJumpTo}
        onClose={mockOnClose}
      />
    );
    expect(screen.getByText('#random')).toBeInTheDocument();
  });
});
