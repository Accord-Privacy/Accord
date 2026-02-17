import React, { useEffect, useRef } from "react";

const EMOJI_CATEGORIES = [
  { name: "Smileys", emojis: ["😀", "😂", "🥲", "😊", "😎", "🤔", "😴", "🤯", "🥳", "😤", "😭", "🫡"] },
  { name: "Reactions", emojis: ["❤️", "👍", "👎", "🔥", "💯", "🎉", "👀", "✅", "❌", "⭐", "💀", "🙏"] },
  { name: "Objects", emojis: ["📱", "💻", "🔒", "🔑", "📎", "📸", "🎵", "🎮", "⚡", "🚀", "💡", "🏠"] },
];

interface EmojiPickerProps {
  onSelect: (emoji: string) => void;
  onClose: () => void;
}

export const EmojiPickerButton: React.FC<EmojiPickerProps & { isOpen: boolean; onToggle: () => void }> = ({ isOpen, onToggle, onSelect, onClose }) => {
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
        🙂
      </button>
      {isOpen && (
        <div className="emoji-picker-popup">
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
