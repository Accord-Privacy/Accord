/**
 * Keyboard shortcut manager for Accord.
 *
 * Registers global key handlers and dispatches actions while respecting
 * whether the user is currently typing in an input/textarea.
 */

export interface ShortcutDef {
  /** Human-readable key combo, e.g. "Ctrl+K" */
  label: string;
  /** Description shown in the help modal */
  description: string;
  /** If true, the shortcut fires even when an input/textarea is focused */
  allowInInput?: boolean;
}

/**
 * All registered shortcuts for display in the help modal.
 * Order matters — it controls the help modal rendering order.
 */
export const SHORTCUTS: ShortcutDef[] = [
  { label: 'Enter', description: 'Send message', allowInInput: true },
  { label: 'Shift + Enter', description: 'New line in message', allowInInput: true },
  { label: 'Escape', description: 'Close modal / Cancel edit / Deselect' },
  { label: 'Ctrl + K', description: 'Open search' },
  { label: 'Ctrl + E', description: 'Toggle emoji picker' },
  { label: 'Ctrl + ,', description: 'Open settings' },
  { label: 'Ctrl + /', description: 'Keyboard shortcuts help' },
  { label: '?', description: 'Keyboard shortcuts help (when not typing)' },
  { label: 'Alt + ↑ / ↓', description: 'Navigate channels up / down' },
  { label: 'Ctrl + Shift + M', description: 'Toggle mute (in voice)' },
  { label: 'Ctrl + Shift + D', description: 'Toggle deafen (in voice)' },
];

/** Returns true if the active element is a text input the user is typing into. */
export function isTypingInInput(): boolean {
  const el = document.activeElement;
  if (!el) return false;
  const tag = el.tagName.toLowerCase();
  if (tag === 'input') {
    const type = (el as HTMLInputElement).type;
    return ['text', 'search', 'email', 'password', 'url', 'tel', 'number', ''].includes(type);
  }
  return tag === 'textarea' || (el as HTMLElement).isContentEditable;
}

export interface KeyboardActions {
  openSearch: () => void;
  openSettings: () => void;
  toggleShortcutsHelp: () => void;
  closeTopModal: () => void;
  toggleEmojiPicker: () => void;
  navigateChannel: (direction: 'up' | 'down') => void;
  toggleMute: () => void;
  toggleDeafen: () => void;
}

/**
 * Initialise global keyboard shortcuts. Call once on App mount.
 * Returns a cleanup function to remove the listener.
 */
export function initKeyboardShortcuts(actions: KeyboardActions): () => void {
  const handler = (e: KeyboardEvent) => {
    const mod = e.ctrlKey || e.metaKey;
    const typing = isTypingInInput();

    // --- Shortcuts that work regardless of input focus ---

    // Escape — always close top modal
    if (e.key === 'Escape') {
      actions.closeTopModal();
      return;
    }

    // --- Shortcuts blocked when typing in an input ---
    if (typing) return;

    // ? — show shortcuts help (only when not in input)
    if (e.key === '?' && !mod && !e.shiftKey && !e.altKey) {
      actions.toggleShortcutsHelp();
      return;
    }

    // Ctrl+K / Cmd+K — search
    if (mod && (e.key === 'k' || e.key === 'f')) {
      e.preventDefault();
      actions.openSearch();
      return;
    }

    // Ctrl+, — settings
    if (mod && e.key === ',') {
      e.preventDefault();
      actions.openSettings();
      return;
    }

    // Ctrl+/ — shortcuts help
    if (mod && e.key === '/') {
      e.preventDefault();
      actions.toggleShortcutsHelp();
      return;
    }

    // Ctrl+E — emoji picker
    if (mod && e.key === 'e') {
      e.preventDefault();
      actions.toggleEmojiPicker();
      return;
    }

    // Alt+Up/Down — navigate channels
    if (e.altKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
      e.preventDefault();
      actions.navigateChannel(e.key === 'ArrowUp' ? 'up' : 'down');
      return;
    }

    // Ctrl+Shift+M — toggle mute
    if (mod && e.shiftKey && (e.key === 'M' || e.key === 'm')) {
      e.preventDefault();
      actions.toggleMute();
      return;
    }

    // Ctrl+Shift+D — toggle deafen
    if (mod && e.shiftKey && (e.key === 'D' || e.key === 'd')) {
      e.preventDefault();
      actions.toggleDeafen();
      return;
    }
  };

  document.addEventListener('keydown', handler);
  return () => document.removeEventListener('keydown', handler);
}
