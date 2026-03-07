import React, { useMemo } from 'react';
import { Icon } from './Icon';
import { avatarColor } from '../avatarColor';
import type { Message } from '../types';

export interface ThreadItem {
  /** The root message that has replies */
  message: Message;
  /** Number of replies */
  replyCount: number;
  /** Timestamp of the most recent reply */
  lastReplyTimestamp: number;
  /** Display name of the last replier (if known) */
  lastReplierName?: string;
}

interface ThreadsPanelProps {
  messages: Message[];
  onThreadClick: (messageId: string) => void;
  onClose: () => void;
  getDisplayName: (userId: string) => string;
}

function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp;
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}

export function buildThreadItems(
  messages: Message[],
  getDisplayName: (userId: string) => string,
): ThreadItem[] {
  // Find all messages that have reply_count > 0
  const threadRoots: ThreadItem[] = [];

  // Build a map of reply_to -> replies for computing last reply info
  const repliesByParent = new Map<string, Message[]>();
  for (const msg of messages) {
    if (msg.reply_to) {
      const existing = repliesByParent.get(msg.reply_to);
      if (existing) {
        existing.push(msg);
      } else {
        repliesByParent.set(msg.reply_to, [msg]);
      }
    }
  }

  for (const msg of messages) {
    const replyCount = msg.reply_count ?? 0;
    const replies = repliesByParent.get(msg.id);

    if (replyCount > 0 || (replies && replies.length > 0)) {
      const actualCount = Math.max(replyCount, replies?.length ?? 0);
      let lastReplyTimestamp = msg.timestamp;
      let lastReplierName: string | undefined;

      if (replies && replies.length > 0) {
        const sorted = [...replies].sort((a, b) => b.timestamp - a.timestamp);
        lastReplyTimestamp = sorted[0].timestamp;
        const replierId = sorted[0].sender_id || sorted[0].author;
        lastReplierName = getDisplayName(replierId);
      }

      threadRoots.push({
        message: msg,
        replyCount: actualCount,
        lastReplyTimestamp,
        lastReplierName,
      });
    }
  }

  // Sort by most recent reply
  threadRoots.sort((a, b) => b.lastReplyTimestamp - a.lastReplyTimestamp);
  return threadRoots;
}

/** Returns true if the channel has active threads (replies within the last 24 hours) */
export function hasActiveThreads(messages: Message[]): boolean {
  const oneDayAgo = Date.now() - 86400000;
  for (const msg of messages) {
    if (msg.reply_to && msg.timestamp > oneDayAgo) return true;
  }
  return false;
}

export const ThreadsPanel: React.FC<ThreadsPanelProps> = ({
  messages,
  onThreadClick,
  onClose,
  getDisplayName,
}) => {
  const threads = useMemo(
    () => buildThreadItems(messages, getDisplayName),
    [messages, getDisplayName],
  );

  return (
    <div className="threads-panel-overlay" onClick={onClose}>
      <div className="threads-panel" onClick={(e) => e.stopPropagation()}>
        <div className="threads-panel-header">
          <h2><Icon name="thread" size={20} /> Threads</h2>
          <button className="threads-panel-close" onClick={onClose} aria-label="Close threads panel">
            <Icon name="close" size={20} />
          </button>
        </div>
        <div className="threads-panel-list">
          {threads.length === 0 ? (
            <div className="threads-panel-empty">
              <Icon name="thread" size={48} />
              <p>No threads yet</p>
              <p className="threads-panel-empty-hint">
                Reply to a message to start a thread.
              </p>
            </div>
          ) : (
            threads.map((thread) => {
              const authorId = thread.message.sender_id || thread.message.author;
              const authorName = getDisplayName(authorId);
              const preview =
                thread.message.content.length > 120
                  ? thread.message.content.substring(0, 120) + '…'
                  : thread.message.content;
              const color = avatarColor(authorName);

              return (
                <div
                  key={thread.message.id}
                  className="thread-item"
                  onClick={() => onThreadClick(thread.message.id)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onThreadClick(thread.message.id);
                    }
                  }}
                >
                  <div className="thread-item-avatar" style={{ background: color }}>
                    {authorName[0]?.toUpperCase() || '?'}
                  </div>
                  <div className="thread-item-content">
                    <div className="thread-item-header">
                      <span className="thread-item-author">{authorName}</span>
                      <span className="thread-item-time">
                        {formatRelativeTime(thread.message.timestamp)}
                      </span>
                    </div>
                    <div className="thread-item-preview">{preview}</div>
                    <div className="thread-item-meta">
                      <Icon name="thread" size={14} />
                      <span className="thread-item-count">
                        {thread.replyCount} {thread.replyCount === 1 ? 'reply' : 'replies'}
                      </span>
                      {thread.lastReplierName && (
                        <>
                          <span className="thread-item-separator">·</span>
                          <span className="thread-item-last-reply">
                            Last reply by {thread.lastReplierName}
                          </span>
                        </>
                      )}
                      <span className="thread-item-separator">·</span>
                      <span className="thread-item-last-time">
                        {formatRelativeTime(thread.lastReplyTimestamp)}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
