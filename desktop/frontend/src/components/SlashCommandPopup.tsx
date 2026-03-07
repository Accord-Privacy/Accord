import React, { useRef, useEffect } from 'react';
import type { SlashCommand } from '../hooks/useSlashCommands';

interface SlashCommandPopupProps {
  items: SlashCommand[];
  selectedIndex: number;
  visible: boolean;
  onSelect: (index: number) => void;
}

export const SlashCommandPopup: React.FC<SlashCommandPopupProps> = ({
  items,
  selectedIndex,
  visible,
  onSelect,
}) => {
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!listRef.current) return;
    const selected = listRef.current.querySelector('.slash-command-item.selected');
    if (selected) {
      selected.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  if (!visible || items.length === 0) return null;

  return (
    <div className="mention-autocomplete slash-command-autocomplete" ref={listRef} role="listbox" aria-label="Slash commands">
      {items.map((cmd, i) => (
        <div
          key={cmd.name}
          className={`mention-autocomplete-item slash-command-item ${i === selectedIndex ? 'selected' : ''}`}
          role="option"
          aria-selected={i === selectedIndex}
          onMouseDown={(e) => { e.preventDefault(); onSelect(i); }}
        >
          <div
            className="mention-autocomplete-avatar slash-command-icon"
            style={{ background: 'var(--accent-color, #5865f2)', color: '#fff', fontSize: '14px', fontWeight: 700 }}
          >
            /
          </div>
          <div className="mention-autocomplete-info">
            <span className="mention-autocomplete-name">{cmd.usage}</span>
            <span className="mention-autocomplete-role">{cmd.description}</span>
          </div>
        </div>
      ))}
    </div>
  );
};
