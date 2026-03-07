import React, { useEffect } from 'react';

export interface ChangelogEntry {
  version: string;
  date: string;
  title: string;
  description: string;
  icon?: string;
}

export const CHANGELOG: ChangelogEntry[] = [
  {
    version: '0.9.0',
    date: '2026-03-01',
    title: 'GIF Search, Slash Commands & Thread Panel',
    description: 'Search and send GIFs inline, use slash commands for quick actions, and keep conversations organized with the new thread panel.',
    icon: '🎉',
  },
  {
    version: '0.8.0',
    date: '2026-02-15',
    title: 'Channel Mute, Bookmarks & Delivery Status',
    description: 'Mute noisy channels, bookmark important messages for later, and see when your messages are delivered and read.',
    icon: '🔖',
  },
  {
    version: '0.7.0',
    date: '2026-02-01',
    title: 'Voice UI, Image Gallery & Keyboard Shortcuts',
    description: 'Redesigned voice chat interface, browse shared images in a gallery view, and navigate faster with keyboard shortcuts.',
    icon: '🎙️',
  },
];

export const CURRENT_VERSION = CHANGELOG[0].version;

const LS_KEY = 'accord-whats-new-seen';

export function getLastSeenVersion(): string | null {
  return localStorage.getItem(LS_KEY);
}

export function markVersionSeen(version: string): void {
  localStorage.setItem(LS_KEY, version);
}

export function hasUnseenChangelog(): boolean {
  return getLastSeenVersion() !== CURRENT_VERSION;
}

interface WhatsNewModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const WhatsNewModal: React.FC<WhatsNewModalProps> = ({ isOpen, onClose }) => {
  useEffect(() => {
    if (isOpen) {
      markVersionSeen(CURRENT_VERSION);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="modal-overlay whats-new-overlay" onClick={onClose}>
      <div className="whats-new-modal" onClick={(e) => e.stopPropagation()}>
        <div className="whats-new-header">
          <h2>{"What's New"}</h2>
          <button className="whats-new-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="whats-new-list">
          {CHANGELOG.map((entry) => (
            <div key={entry.version} className="whats-new-entry">
              <div className="whats-new-entry-header">
                {entry.icon && <span className="whats-new-icon">{entry.icon}</span>}
                <span className="whats-new-version">v{entry.version}</span>
                <span className="whats-new-date">{entry.date}</span>
              </div>
              <h3 className="whats-new-title">{entry.title}</h3>
              <p className="whats-new-desc">{entry.description}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
