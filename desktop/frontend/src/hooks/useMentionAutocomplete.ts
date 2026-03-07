import { useState, useCallback, useRef, useEffect } from 'react';

export interface AutocompleteItem {
  type: 'user' | 'channel';
  id: string;
  label: string;        // display name or channel name
  subtitle?: string;    // role for users
  avatarUrl?: string;
  avatarColor?: string;
  insertText: string;   // text to insert (e.g. "@DisplayName" or "#channel-name")
}

interface MentionState {
  active: boolean;
  triggerChar: '@' | '#' | null;
  query: string;
  startIndex: number;   // index of the trigger char in the input
  selectedIndex: number;
  items: AutocompleteItem[];
}

const INITIAL_STATE: MentionState = {
  active: false,
  triggerChar: null,
  query: '',
  startIndex: 0,
  selectedIndex: 0,
  items: [],
};

function fuzzyMatch(query: string, text: string): boolean {
  const q = query.toLowerCase();
  const t = text.toLowerCase();
  if (t.includes(q)) return true;
  // Simple fuzzy: all chars in order
  let qi = 0;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) qi++;
  }
  return qi === q.length;
}

export function useMentionAutocomplete(
  allUsers: AutocompleteItem[],
  allChannels: AutocompleteItem[],
) {
  const [state, setState] = useState<MentionState>(INITIAL_STATE);
  const stateRef = useRef(state);
  stateRef.current = state;

  const dismiss = useCallback(() => {
    setState(INITIAL_STATE);
  }, []);

  const handleInputChange = useCallback((value: string, cursorPos: number) => {
    // Look backwards from cursor for a trigger char
    const before = value.substring(0, cursorPos);
    
    // Find the last unmatched @ or # (not preceded by a non-space char)
    let triggerIdx = -1;
    let triggerChar: '@' | '#' | null = null;

    for (let i = before.length - 1; i >= 0; i--) {
      const ch = before[i];
      if (ch === ' ' || ch === '\n') break; // stop at whitespace
      if (ch === '@' || ch === '#') {
        // Valid trigger: at start of input or preceded by whitespace
        if (i === 0 || before[i - 1] === ' ' || before[i - 1] === '\n') {
          triggerIdx = i;
          triggerChar = ch as '@' | '#';
        }
        break;
      }
    }

    if (triggerIdx === -1 || !triggerChar) {
      if (stateRef.current.active) dismiss();
      return;
    }

    const query = before.substring(triggerIdx + 1);
    
    // Don't show if query has spaces (completed mention)
    if (query.includes(' ')) {
      if (stateRef.current.active) dismiss();
      return;
    }

    const source = triggerChar === '@' ? allUsers : allChannels;
    const filtered = query.length === 0
      ? source.slice(0, 10)
      : source.filter(item => fuzzyMatch(query, item.label)).slice(0, 10);

    setState(prev => ({
      active: true,
      triggerChar,
      query,
      startIndex: triggerIdx,
      selectedIndex: Math.min(prev.selectedIndex, Math.max(0, filtered.length - 1)),
      items: filtered,
    }));
  }, [allUsers, allChannels, dismiss]);

  const selectItem = useCallback((
    index: number,
    message: string,
    setMessage: (v: string) => void,
    inputRef: React.RefObject<HTMLTextAreaElement | null>,
  ) => {
    const s = stateRef.current;
    if (!s.active || index < 0 || index >= s.items.length) return;
    const item = s.items[index];
    const before = message.substring(0, s.startIndex);
    const after = message.substring(s.startIndex + 1 + s.query.length);
    const newMessage = before + item.insertText + ' ' + after;
    setMessage(newMessage);
    dismiss();
    // Restore focus and cursor
    requestAnimationFrame(() => {
      const el = inputRef.current;
      if (el) {
        el.focus();
        const pos = before.length + item.insertText.length + 1;
        el.selectionStart = pos;
        el.selectionEnd = pos;
      }
    });
  }, [dismiss]);

  const handleKeyDown = useCallback((
    e: React.KeyboardEvent,
    message: string,
    setMessage: (v: string) => void,
    inputRef: React.RefObject<HTMLTextAreaElement | null>,
  ): boolean => {
    const s = stateRef.current;
    if (!s.active || s.items.length === 0) return false;

    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setState(prev => ({
        ...prev,
        selectedIndex: prev.selectedIndex <= 0 ? prev.items.length - 1 : prev.selectedIndex - 1,
      }));
      return true;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setState(prev => ({
        ...prev,
        selectedIndex: prev.selectedIndex >= prev.items.length - 1 ? 0 : prev.selectedIndex + 1,
      }));
      return true;
    }
    if (e.key === 'Enter' || e.key === 'Tab') {
      e.preventDefault();
      selectItem(s.selectedIndex, message, setMessage, inputRef);
      return true;
    }
    if (e.key === 'Escape') {
      e.preventDefault();
      dismiss();
      return true;
    }
    return false;
  }, [dismiss, selectItem]);

  // Reset when items disappear
  useEffect(() => {
    if (state.active && state.items.length === 0 && state.query.length > 0) {
      // Keep popup open but empty — user may backspace
    }
  }, [state]);

  return {
    mentionState: state,
    handleMentionInput: handleInputChange,
    handleMentionKeyDown: handleKeyDown,
    selectMentionItem: selectItem,
    dismissMention: dismiss,
  };
}
