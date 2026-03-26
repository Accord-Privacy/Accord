import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { MessageContextMenu } from '../components/MessageContextMenu';
import { AppContext } from '../components/AppContext';
import type { AppContextType } from '../components/AppContext';
import type { Message } from '../types';

const handleReply = vi.fn();
const handleStartEdit = vi.fn();
const setShowDeleteConfirm = vi.fn();
const setShowPinConfirm = vi.fn();
const handleUnpinMessage = vi.fn();
const fingerprint = vi.fn((hash: string) => `fp-${hash.slice(0, 8)}`);
const canDeleteMessage = vi.fn(() => false);

const mockUser = {
  user_id: 'user-1',
  display_name: 'Alice',
  public_key_hash: 'abc123',
  created_at: Date.now(),
};

const mockCtx: Partial<AppContextType> = {
  appState: { user: mockUser } as any,
  selectedChannelId: 'ch1',
  handleReply,
  handleStartEdit,
  setShowDeleteConfirm,
  setShowPinConfirm,
  handleUnpinMessage,
  fingerprint,
  canDeleteMessage,
};

const Wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AppContext.Provider value={mockCtx as AppContextType}>
    {children}
  </AppContext.Provider>
);

const makeMessage = (overrides: Partial<Message> = {}): Message => ({
  id: 'msg-1',
  author: 'Bob',
  content: 'Hello world',
  timestamp: Date.now(),
  channel_id: 'ch1',
  ...overrides,
});

function openContextMenu(element: HTMLElement) {
  fireEvent.contextMenu(element);
}

describe('MessageContextMenu', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('renders children without showing menu initially', () => {
    const message = makeMessage();
    render(
      <MessageContextMenu message={message}>
        <div>Message text</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    expect(screen.getByText('Message text')).toBeInTheDocument();
    expect(screen.queryByText('Reply')).not.toBeInTheDocument();
  });

  it('shows context menu on right-click', () => {
    const message = makeMessage();
    render(
      <MessageContextMenu message={message}>
        <div>Right click me</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('Right click me'));
    expect(screen.getByText('Reply')).toBeInTheDocument();
  });

  it('always shows Reply item', () => {
    const message = makeMessage({ author: 'Alice' });
    render(
      <MessageContextMenu message={message}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    expect(screen.getByText('Reply')).toBeInTheDocument();
  });

  it('shows Edit Message for own messages', () => {
    // author matches current user display_name
    const message = makeMessage({ author: 'Alice' });
    render(
      <MessageContextMenu message={message}>
        <div>own msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('own msg'));
    expect(screen.getByText('Edit Message')).toBeInTheDocument();
  });

  it('does not show Edit Message for other users\' messages', () => {
    const message = makeMessage({ author: 'Bob' });
    render(
      <MessageContextMenu message={message}>
        <div>other msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('other msg'));
    expect(screen.queryByText('Edit Message')).not.toBeInTheDocument();
  });

  it('shows Copy Text item', () => {
    const message = makeMessage();
    render(
      <MessageContextMenu message={message}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    expect(screen.getByText('Copy Text')).toBeInTheDocument();
  });

  it('shows Copy Message Link item', () => {
    const message = makeMessage();
    render(
      <MessageContextMenu message={message}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    expect(screen.getByText('Copy Message Link')).toBeInTheDocument();
  });

  it('shows Mark as Unread item', () => {
    const message = makeMessage();
    render(
      <MessageContextMenu message={message}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    expect(screen.getByText('Mark as Unread')).toBeInTheDocument();
  });

  it('calls handleReply when Reply is clicked', () => {
    const message = makeMessage();
    render(
      <MessageContextMenu message={message}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    fireEvent.click(screen.getByText('Reply'));
    expect(handleReply).toHaveBeenCalledWith(message);
  });

  it('calls handleStartEdit when Edit Message is clicked', () => {
    const message = makeMessage({ author: 'Alice', id: 'msg-42', content: 'Original text' });
    render(
      <MessageContextMenu message={message}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    fireEvent.click(screen.getByText('Edit Message'));
    expect(handleStartEdit).toHaveBeenCalledWith('msg-42', 'Original text');
  });

  it('calls onMarkUnread when Mark as Unread is clicked', () => {
    const onMarkUnread = vi.fn();
    const message = makeMessage({ id: 'msg-99' });
    render(
      <MessageContextMenu message={message} onMarkUnread={onMarkUnread}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    fireEvent.click(screen.getByText('Mark as Unread'));
    expect(onMarkUnread).toHaveBeenCalledWith('msg-99');
  });

  it('shows Save Message when onToggleBookmark is provided', () => {
    const message = makeMessage();
    render(
      <MessageContextMenu message={message} onToggleBookmark={vi.fn()}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    expect(screen.getByText('Save Message')).toBeInTheDocument();
  });

  it('shows Remove Bookmark when isBookmarked is true', () => {
    const message = makeMessage();
    render(
      <MessageContextMenu message={message} isBookmarked={true} onToggleBookmark={vi.fn()}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    expect(screen.getByText('Remove Bookmark')).toBeInTheDocument();
  });

  it('shows Pin Message for messages that canDeleteMessage returns true', () => {
    canDeleteMessage.mockReturnValue(true);
    const message = makeMessage({ author: 'Bob' });
    render(
      <MessageContextMenu message={message}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    expect(screen.getByText('Pin Message')).toBeInTheDocument();
  });

  it('shows Unpin Message for pinned messages', () => {
    canDeleteMessage.mockReturnValue(true);
    const message = makeMessage({ author: 'Bob', pinned_at: Date.now() });
    render(
      <MessageContextMenu message={message}>
        <div>msg</div>
      </MessageContextMenu>,
      { wrapper: Wrapper }
    );
    openContextMenu(screen.getByText('msg'));
    expect(screen.getByText('Unpin Message')).toBeInTheDocument();
  });
});
