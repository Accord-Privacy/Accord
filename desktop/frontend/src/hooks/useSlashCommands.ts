import { useState, useCallback, useRef } from 'react';

export interface SlashCommand {
  name: string;
  description: string;
  usage: string;
  /** If true, command takes an argument after the name */
  hasArg: boolean;
  /** For immediate-execute commands like /shrug, the text to append */
  appendText?: string;
  /** If true, execute immediately on select (no arg needed) */
  immediate?: boolean;
}

export const SLASH_COMMANDS: SlashCommand[] = [
  { name: 'nick', description: 'Change display name', usage: '/nick [name]', hasArg: true },
  { name: 'status', description: 'Set custom status', usage: '/status [text]', hasArg: true },
  { name: 'clear', description: 'Clear chat (client-side only)', usage: '/clear', hasArg: false, immediate: true },
  { name: 'shrug', description: 'Append ¯\\_(ツ)_/¯ to message', usage: '/shrug', hasArg: false, appendText: '¯\\_(ツ)_/¯' },
  { name: 'tableflip', description: 'Append (╯°□°)╯︵ ┻━┻', usage: '/tableflip', hasArg: false, appendText: '(╯°□°)╯︵ ┻━┻' },
  { name: 'unflip', description: 'Append ┬─┬ノ( º _ ºノ)', usage: '/unflip', hasArg: false, appendText: '┬─┬ノ( º _ ºノ)' },
  { name: 'giphy', description: 'Search for a GIF (coming soon)', usage: '/giphy [query]', hasArg: true },
];

interface SlashState {
  active: boolean;
  query: string;
  selectedIndex: number;
  items: SlashCommand[];
}

const INITIAL_STATE: SlashState = {
  active: false,
  query: '',
  selectedIndex: 0,
  items: [],
};

export interface SlashCommandCallbacks {
  onNick: (name: string) => void;
  onStatus: (text: string) => void;
  onClear: () => void;
}

export function useSlashCommands(callbacks: SlashCommandCallbacks) {
  const [state, setState] = useState<SlashState>(INITIAL_STATE);
  const stateRef = useRef(state);
  stateRef.current = state;

  const dismiss = useCallback(() => {
    setState(INITIAL_STATE);
  }, []);

  const handleInputChange = useCallback((value: string, _cursorPos?: number) => {
    // Only activate when "/" is at the very start and there's no space yet (typing the command name)
    if (!value.startsWith('/')) {
      if (stateRef.current.active) dismiss();
      return;
    }

    const spaceIdx = value.indexOf(' ');
    // If there's a space, user is typing an argument — close autocomplete
    if (spaceIdx !== -1) {
      if (stateRef.current.active) dismiss();
      return;
    }

    const query = value.substring(1).toLowerCase();
    const filtered = SLASH_COMMANDS.filter(cmd =>
      cmd.name.startsWith(query)
    );

    setState(prev => ({
      active: true,
      query,
      selectedIndex: Math.min(prev.selectedIndex, Math.max(0, filtered.length - 1)),
      items: filtered,
    }));
  }, [dismiss]);

  const selectItem = useCallback((
    index: number,
    _message: string,
    setMessage: (v: string) => void,
    inputRef: React.RefObject<HTMLTextAreaElement | null>,
  ) => {
    const s = stateRef.current;
    if (!s.active || index < 0 || index >= s.items.length) return;
    const cmd = s.items[index];
    dismiss();

    if (cmd.appendText !== undefined) {
      // Kaomoji commands: replace input with just the emoticon (send it as a message)
      setMessage(cmd.appendText);
      requestAnimationFrame(() => {
        const el = inputRef.current;
        if (el) {
          el.focus();
          el.selectionStart = cmd.appendText!.length;
          el.selectionEnd = cmd.appendText!.length;
        }
      });
      return;
    }

    if (cmd.immediate) {
      // Execute immediately
      if (cmd.name === 'clear') {
        callbacks.onClear();
      }
      setMessage('');
      requestAnimationFrame(() => inputRef.current?.focus());
      return;
    }

    if (cmd.name === 'giphy') {
      setMessage('');
      alert('GIF search coming soon');
      requestAnimationFrame(() => inputRef.current?.focus());
      return;
    }

    // Commands with args: insert "/command " and let user type
    const newMsg = '/' + cmd.name + ' ';
    setMessage(newMsg);
    requestAnimationFrame(() => {
      const el = inputRef.current;
      if (el) {
        el.focus();
        el.selectionStart = newMsg.length;
        el.selectionEnd = newMsg.length;
      }
    });
  }, [dismiss, callbacks]);

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

  /** Process a message before send. Returns true if it was a slash command (message should not be sent). */
  const processCommand = useCallback((message: string): boolean => {
    const trimmed = message.trim();
    if (!trimmed.startsWith('/')) return false;

    const spaceIdx = trimmed.indexOf(' ');
    const cmdName = spaceIdx === -1 ? trimmed.substring(1) : trimmed.substring(1, spaceIdx);
    const arg = spaceIdx === -1 ? '' : trimmed.substring(spaceIdx + 1).trim();

    const cmd = SLASH_COMMANDS.find(c => c.name === cmdName);
    if (!cmd) return false;

    if (cmd.name === 'nick') {
      if (arg) callbacks.onNick(arg);
      return true;
    }
    if (cmd.name === 'status') {
      if (arg) callbacks.onStatus(arg);
      return true;
    }
    if (cmd.name === 'clear') {
      callbacks.onClear();
      return true;
    }
    if (cmd.name === 'giphy') {
      alert('GIF search coming soon');
      return true;
    }
    // shrug/tableflip/unflip won't reach here normally since selectItem replaces the message
    return false;
  }, [callbacks]);

  return {
    slashState: state,
    handleSlashInput: handleInputChange,
    handleSlashKeyDown: handleKeyDown,
    selectSlashItem: selectItem,
    dismissSlash: dismiss,
    processSlashCommand: processCommand,
  };
}
