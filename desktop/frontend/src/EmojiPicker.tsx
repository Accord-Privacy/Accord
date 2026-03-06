import React, { useEffect, useRef } from "react";
import type { CustomEmoji } from "./types";

const EMOJI_CATEGORIES = [
  { name: "Smileys", emojis: ["😀", "😂", "🥲", "😊", "😎", "🤔", "😴", "🤯", "🥳", "😤", "😭", "🫡"] },
  { name: "Reactions", emojis: ["❤️", "👍", "👎", "🔥", "💯", "🎉", "👀", "✅", "❌", "⭐", "💀", "🙏"] },
  { name: "Objects", emojis: ["📱", "💻", "🔒", "🔑", "📎", "📸", "🎵", "🎮", "⚡", "🚀", "💡", "🏠"] },
];

interface EmojiPickerProps {
  onSelect: (emoji: string) => void;
  onClose: () => void;
  customEmojis?: CustomEmoji[];
  getEmojiUrl?: (hash: string) => string;
}

export const EmojiPickerButton: React.FC<EmojiPickerProps & { isOpen: boolean; onToggle: () => void }> = ({ isOpen, onToggle, onSelect, onClose, customEmojis, getEmojiUrl }) => {
  const pickerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: MouseEvent) => {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [isOpen, onClose]);

  return (
    <div className="emoji-picker-wrapper" ref={pickerRef}>
      <button
        className="emoji-picker-toggle"
        onClick={onToggle}
        title="Emoji picker"
        type="button"
      >
        <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm3.5-9c.83 0 1.5-.67 1.5-1.5S16.33 8 15.5 8 14 8.67 14 9.5s.67 1.5 1.5 1.5zm-7 0c.83 0 1.5-.67 1.5-1.5S9.33 8 8.5 8 7 8.67 7 9.5 7.67 11 8.5 11zm3.5 6.5c2.33 0 4.31-1.46 5.11-3.5H6.89c.8 2.04 2.78 3.5 5.11 3.5z"/></svg>
      </button>
      {isOpen && (
        <div className="emoji-picker-popup">
          {customEmojis && customEmojis.length > 0 && getEmojiUrl && (
            <div className="emoji-picker-category">
              <div className="emoji-picker-category-label">Custom</div>
              <div className="emoji-picker-grid">
                {customEmojis.map((emoji) => (
                  <button
                    key={emoji.id}
                    className="emoji-picker-item"
                    onClick={() => onSelect(`:${emoji.name}:`)}
                    type="button"
                    title={`:${emoji.name}:`}
                  >
                    <img src={getEmojiUrl(emoji.content_hash)} alt={`:${emoji.name}:`} style={{ width: '22px', height: '22px', objectFit: 'contain' }} />
                  </button>
                ))}
              </div>
            </div>
          )}
          {EMOJI_CATEGORIES.map((cat) => (
            <div key={cat.name} className="emoji-picker-category">
              <div className="emoji-picker-category-label">{cat.name}</div>
              <div className="emoji-picker-grid">
                {cat.emojis.map((emoji) => (
                  <button
                    key={emoji}
                    className="emoji-picker-item"
                    onClick={() => onSelect(emoji)}
                    type="button"
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
