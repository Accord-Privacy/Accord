import React, { useRef, useEffect } from 'react';
import type { AutocompleteItem } from '../hooks/useMentionAutocomplete';

interface MentionAutocompleteProps {
  items: AutocompleteItem[];
  selectedIndex: number;
  triggerChar: '@' | '#' | null;
  visible: boolean;
  onSelect: (index: number) => void;
}

export const MentionAutocomplete: React.FC<MentionAutocompleteProps> = ({
  items,
  selectedIndex,
  triggerChar,
  visible,
  onSelect,
}) => {
  const listRef = useRef<HTMLDivElement>(null);

  // Scroll selected item into view
  useEffect(() => {
    if (!listRef.current) return;
    const selected = listRef.current.querySelector('.mention-autocomplete-item.selected');
    if (selected) {
      selected.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  if (!visible || items.length === 0) return null;

  return (
    <div className="mention-autocomplete" ref={listRef} role="listbox" aria-label={triggerChar === '@' ? 'User mentions' : 'Channel links'}>
      {items.map((item, i) => (
        <div
          key={`${item.type}-${item.id}`}
          className={`mention-autocomplete-item ${i === selectedIndex ? 'selected' : ''}`}
          role="option"
          aria-selected={i === selectedIndex}
          onMouseDown={(e) => { e.preventDefault(); onSelect(i); }}
          onMouseEnter={() => {/* selection follows keyboard, hover is visual only */}}
        >
          <div
            className="mention-autocomplete-avatar"
            style={{ background: item.avatarColor || 'var(--bg-tertiary)' }}
          >
            {item.type === 'channel' ? (
              <span className="mention-autocomplete-hash">#</span>
            ) : item.avatarUrl ? (
              <img
                src={item.avatarUrl}
                alt={item.label[0]}
                onError={(e) => {
                  const img = e.target as HTMLImageElement;
                  img.style.display = 'none';
                  if (img.parentElement) img.parentElement.textContent = item.label[0]?.toUpperCase() || '?';
                }}
              />
            ) : (
              item.label[0]?.toUpperCase() || '?'
            )}
          </div>
          <div className="mention-autocomplete-info">
            <span className="mention-autocomplete-name">{item.label}</span>
            {item.subtitle && (
              <span className="mention-autocomplete-role">{item.subtitle}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};
