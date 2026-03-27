import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThreadsPanel, buildThreadItems, hasActiveThreads } from '../components/ThreadsPanel';
import type { Message } from '../types';

vi.mock('../avatarColor', () => ({
  avatarColor: vi.fn((_name: string) => '#ff5733'),
}));

describe('ThreadsPanel', () => {
  const mockMessage = (id: string, content: string, timestamp: number, replyCount = 0, replyTo?: string): Message => ({
    id,
    channel_id: 'channel-1',
    sender_id: `user-${id}`,
    author: `user-${id}`,
    content,
    timestamp,
    reply_count: replyCount,
    reply_to: replyTo,
  });

  let onThreadClickMock: (messageId: string) => void;
  let onCloseMock: () => void;
  let getDisplayNameMock: (userId: string) => string;

  beforeEach(() => {
    onThreadClickMock = vi.fn() as unknown as (messageId: string) => void;
    onCloseMock = vi.fn();
    getDisplayNameMock = vi.fn((userId: string) => `User ${userId}`) as unknown as (userId: string) => string;
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the threads panel with header', () => {
    render(
      <ThreadsPanel
        messages={[]}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    expect(screen.getByText('Threads')).toBeInTheDocument();
  });

  it('displays close button', () => {
    render(
      <ThreadsPanel
        messages={[]}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const closeButton = screen.getByLabelText('Close threads panel');
    expect(closeButton).toBeInTheDocument();
  });

  it('calls onClose when close button is clicked', () => {
    render(
      <ThreadsPanel
        messages={[]}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const closeButton = screen.getByLabelText('Close threads panel');
    fireEvent.click(closeButton);
    expect(onCloseMock).toHaveBeenCalledTimes(1);
  });

  it('calls onClose when overlay is clicked', () => {
    const { container } = render(
      <ThreadsPanel
        messages={[]}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const overlay = container.querySelector('.threads-panel-overlay');
    fireEvent.click(overlay!);
    expect(onCloseMock).toHaveBeenCalledTimes(1);
  });

  it('does not call onClose when panel content is clicked', () => {
    const { container } = render(
      <ThreadsPanel
        messages={[]}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const panel = container.querySelector('.threads-panel');
    fireEvent.click(panel!);
    expect(onCloseMock).not.toHaveBeenCalled();
  });

  it('displays empty state when no threads', () => {
    render(
      <ThreadsPanel
        messages={[]}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    expect(screen.getByText('No threads yet')).toBeInTheDocument();
    expect(screen.getByText('Reply to a message to start a thread.')).toBeInTheDocument();
  });

  it('displays thread items when messages have replies', () => {
    const messages = [
      mockMessage('msg-1', 'Original message', Date.now() - 1000, 3),
      mockMessage('msg-2', 'Reply 1', Date.now() - 500, 0, 'msg-1'),
      mockMessage('msg-3', 'Reply 2', Date.now() - 300, 0, 'msg-1'),
    ];
    render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    expect(screen.getByText('Original message')).toBeInTheDocument();
    expect(screen.getByText(/3 replies/)).toBeInTheDocument();
  });

  it('truncates long message previews with ellipsis', () => {
    const longContent = 'a'.repeat(150);
    const messages = [mockMessage('msg-1', longContent, Date.now(), 1)];
    render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const preview = screen.getByText(/a+…/);
    expect(preview.textContent?.length).toBeLessThanOrEqual(121); // 120 + '…'
  });

  it('calls onThreadClick when thread item is clicked', () => {
    const messages = [mockMessage('msg-1', 'Thread root', Date.now(), 2)];
    render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const threadItem = screen.getByText('Thread root').closest('.thread-item');
    fireEvent.click(threadItem!);
    expect(onThreadClickMock).toHaveBeenCalledWith('msg-1');
  });

  it('supports keyboard navigation with Enter key', () => {
    const messages = [mockMessage('msg-1', 'Thread root', Date.now(), 2)];
    render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const threadItem = screen.getByText('Thread root').closest('.thread-item');
    fireEvent.keyDown(threadItem!, { key: 'Enter' });
    expect(onThreadClickMock).toHaveBeenCalledWith('msg-1');
  });

  it('supports keyboard navigation with Space key', () => {
    const messages = [mockMessage('msg-1', 'Thread root', Date.now(), 2)];
    render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const threadItem = screen.getByText('Thread root').closest('.thread-item');
    fireEvent.keyDown(threadItem!, { key: ' ' });
    expect(onThreadClickMock).toHaveBeenCalledWith('msg-1');
  });

  it('displays singular "reply" for one reply', () => {
    const messages = [mockMessage('msg-1', 'Thread root', Date.now(), 1)];
    render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    expect(screen.getByText(/1 reply/)).toBeInTheDocument();
  });

  it('displays author name from getDisplayName', () => {
    const messages = [mockMessage('msg-1', 'Thread root', Date.now(), 2)];
    render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    expect(screen.getByText('User user-msg-1')).toBeInTheDocument();
  });

  it('displays last replier name when available', () => {
    const now = Date.now();
    const messages = [
      mockMessage('msg-1', 'Thread root', now - 1000, 2),
      mockMessage('msg-2', 'Reply 1', now - 500, 0, 'msg-1'),
      mockMessage('msg-3', 'Reply 2', now - 100, 0, 'msg-1'),
    ];
    render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    expect(screen.getByText(/Last reply by User user-msg-3/)).toBeInTheDocument();
  });

  it('sorts threads by most recent reply timestamp', () => {
    const now = Date.now();
    const messages = [
      mockMessage('msg-1', 'Older thread', now - 5000, 1),
      mockMessage('msg-2', 'Newer thread', now - 3000, 1),
      mockMessage('msg-3', 'Reply to older', now - 1000, 0, 'msg-1'),
    ];
    const { container } = render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const threadItems = container.querySelectorAll('.thread-item');
    const firstThreadContent = threadItems[0].querySelector('.thread-item-preview')?.textContent;
    expect(firstThreadContent).toBe('Older thread'); // Should be first due to recent reply
  });

  it('displays avatar with first letter of author name', () => {
    const messages = [mockMessage('msg-1', 'Thread root', Date.now(), 1)];
    const { container } = render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    const avatar = container.querySelector('.thread-item-avatar');
    expect(avatar?.textContent).toBe('U'); // First letter of "User user-msg-1"
  });

  it('displays fallback character when author name is empty', () => {
    const messages = [mockMessage('msg-1', 'Thread root', Date.now(), 1)];
    const emptyNameMock = vi.fn(() => '');
    const { container } = render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={emptyNameMock}
      />
    );
    const avatar = container.querySelector('.thread-item-avatar');
    expect(avatar?.textContent).toBe('?');
  });

  it('formats relative time correctly for recent messages', () => {
    const now = Date.now();
    const messages = [
      mockMessage('msg-1', 'Just now', now - 30000, 1), // 30 seconds ago
      mockMessage('msg-2', 'Minutes ago', now - 300000, 1), // 5 minutes ago
    ];
    const { container } = render(
      <ThreadsPanel
        messages={messages}
        onThreadClick={onThreadClickMock}
        onClose={onCloseMock}
        getDisplayName={getDisplayNameMock}
      />
    );
    // Check within thread item headers specifically
    const times = container.querySelectorAll('.thread-item-time');
    const timeTexts = Array.from(times).map(el => el.textContent);
    expect(timeTexts).toContain('just now');
    expect(timeTexts).toContain('5m ago');
  });
});

describe('buildThreadItems', () => {
  const mockMessage = (id: string, content: string, timestamp: number, replyCount = 0, replyTo?: string): Message => ({
    id,
    channel_id: 'channel-1',
    sender_id: `user-${id}`,
    author: `user-${id}`,
    content,
    timestamp,
    reply_count: replyCount,
    reply_to: replyTo,
  });

  const getDisplayName = (userId: string) => `User ${userId}`;

  it('returns empty array when no messages have replies', () => {
    const messages = [mockMessage('msg-1', 'No replies', Date.now())];
    const threads = buildThreadItems(messages, getDisplayName);
    expect(threads).toEqual([]);
  });

  it('identifies messages with reply_count > 0 as thread roots', () => {
    const messages = [mockMessage('msg-1', 'Thread root', Date.now(), 3)];
    const threads = buildThreadItems(messages, getDisplayName);
    expect(threads).toHaveLength(1);
    expect(threads[0].replyCount).toBe(3);
  });

  it('calculates reply count from actual replies when higher than reply_count', () => {
    const now = Date.now();
    const messages = [
      mockMessage('msg-1', 'Thread root', now, 1),
      mockMessage('msg-2', 'Reply 1', now - 100, 0, 'msg-1'),
      mockMessage('msg-3', 'Reply 2', now - 200, 0, 'msg-1'),
      mockMessage('msg-4', 'Reply 3', now - 300, 0, 'msg-1'),
    ];
    const threads = buildThreadItems(messages, getDisplayName);
    expect(threads[0].replyCount).toBe(3); // Actual count is higher than reply_count=1
  });

  it('sets lastReplyTimestamp to most recent reply timestamp', () => {
    const now = Date.now();
    const messages = [
      mockMessage('msg-1', 'Thread root', now - 1000, 2),
      mockMessage('msg-2', 'Older reply', now - 500, 0, 'msg-1'),
      mockMessage('msg-3', 'Newer reply', now - 100, 0, 'msg-1'),
    ];
    const threads = buildThreadItems(messages, getDisplayName);
    expect(threads[0].lastReplyTimestamp).toBe(now - 100);
  });

  it('sets lastReplierName from most recent reply', () => {
    const now = Date.now();
    const messages = [
      mockMessage('msg-1', 'Thread root', now - 1000, 2),
      mockMessage('msg-2', 'Old reply', now - 500, 0, 'msg-1'),
      mockMessage('msg-3', 'New reply', now - 100, 0, 'msg-1'),
    ];
    const threads = buildThreadItems(messages, getDisplayName);
    expect(threads[0].lastReplierName).toBe('User user-msg-3');
  });

  it('sorts threads by most recent reply timestamp descending', () => {
    const now = Date.now();
    const messages = [
      mockMessage('msg-1', 'Old thread', now - 5000, 1),
      mockMessage('msg-2', 'New thread', now - 1000, 1),
      mockMessage('msg-3', 'Middle thread', now - 3000, 1),
    ];
    const threads = buildThreadItems(messages, getDisplayName);
    expect(threads[0].message.id).toBe('msg-2');
    expect(threads[1].message.id).toBe('msg-3');
    expect(threads[2].message.id).toBe('msg-1');
  });
});

describe('hasActiveThreads', () => {
  const mockMessage = (id: string, timestamp: number, replyTo?: string): Message => ({
    id,
    channel_id: 'channel-1',
    sender_id: 'user-1',
    author: 'user-1',
    content: 'message',
    timestamp,
    reply_to: replyTo,
  });

  it('returns false when no messages', () => {
    expect(hasActiveThreads([])).toBe(false);
  });

  it('returns false when no messages have reply_to', () => {
    const messages = [mockMessage('msg-1', Date.now())];
    expect(hasActiveThreads(messages)).toBe(false);
  });

  it('returns true when a reply is within 24 hours', () => {
    const now = Date.now();
    const messages = [mockMessage('msg-1', now - 3600000, 'parent-1')]; // 1 hour ago
    expect(hasActiveThreads(messages)).toBe(true);
  });

  it('returns false when all replies are older than 24 hours', () => {
    const now = Date.now();
    const messages = [mockMessage('msg-1', now - 90000000, 'parent-1')]; // >24 hours ago
    expect(hasActiveThreads(messages)).toBe(false);
  });

  it('returns true if at least one reply is within 24 hours', () => {
    const now = Date.now();
    const messages = [
      mockMessage('msg-1', now - 90000000, 'parent-1'), // Old
      mockMessage('msg-2', now - 1000000, 'parent-2'), // Recent
    ];
    expect(hasActiveThreads(messages)).toBe(true);
  });
});
