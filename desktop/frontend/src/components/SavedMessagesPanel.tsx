import React from 'react';
import { Icon } from './Icon';
import type { SavedMessage } from '../hooks/useBookmarks';

interface SavedMessagesPanelProps {
  bookmarks: SavedMessage[];
  onRemove: (messageId: string) => void;
  onJumpTo: (channelId: string, messageId: string) => void;
  onClose: () => void;
}

export const SavedMessagesPanel: React.FC<SavedMessagesPanelProps> = ({
  bookmarks,
  onRemove,
  onJumpTo,
  onClose,
}) => {
  return (
    <div className="saved-messages-overlay" onClick={onClose}>
      <div className="saved-messages-panel" onClick={e => e.stopPropagation()}>
        <div className="saved-messages-header">
          <h2><Icon name="bookmark" size={20} /> Saved Messages</h2>
          <button className="saved-messages-close" onClick={onClose} aria-label="Close">
            <Icon name="close" size={20} />
          </button>
        </div>
        <div className="saved-messages-list">
          {bookmarks.length === 0 ? (
            <div className="saved-messages-empty">
              <Icon name="bookmark-outline" size={48} />
              <p>No saved messages yet</p>
              <p className="saved-messages-empty-hint">Right-click a message and select "Save Message" to bookmark it.</p>
            </div>
          ) : (
            bookmarks.map(b => (
              <div key={b.id} className="saved-message-item">
                <div className="saved-message-meta">
                  <span className="saved-message-author">{b.author}</span>
                  <span className="saved-message-channel">#{b.channelName}</span>
                  <span className="saved-message-time">{new Date(b.timestamp).toLocaleString()}</span>
                </div>
                <div className="saved-message-content">
                  {b.content.length > 200 ? b.content.substring(0, 200) + '…' : b.content}
                </div>
                <div className="saved-message-actions">
                  <button
                    className="btn btn-outline btn-sm"
                    onClick={() => onJumpTo(b.channelId, b.id)}
                  >
                    Jump to
                  </button>
                  <button
                    className="btn btn-outline btn-sm btn-danger"
                    onClick={() => onRemove(b.id)}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
