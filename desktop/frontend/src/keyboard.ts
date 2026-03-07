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

export interface ShortcutGroup {
  title: string;
  shortcuts: ShortcutDef[];
}

/**
 * All registered shortcuts grouped for the help modal.
 */
export const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    title: 'Navigation',
    shortcuts: [
      { label: 'Alt + ↑ / ↓', description: 'Navigate channels up / down' },
      { label: 'Ctrl + K', description: 'Open search' },
      { label: 'Ctrl + ,', description: 'Open settings' },
      { label: 'Ctrl + /', description: 'Keyboard shortcuts help' },
      { label: '?', description: 'Keyboard shortcuts help (when not typing)' },
    ],
  },
  {
    title: 'Messaging',
    shortcuts: [
      { label: 'Enter', description: 'Send message', allowInInput: true },
      { label: 'Shift + Enter', description: 'New line in message', allowInInput: true },
      { label: 'Ctrl + B', description: 'Toggle bold in message', allowInInput: true },
      { label: 'Ctrl + E', description: 'Toggle emoji picker' },
      { label: 'Escape', description: 'Cancel edit / Close modal' },
    ],
  },
  {
    title: 'Voice',
    shortcuts: [
      { label: 'Ctrl + Shift + M', description: 'Toggle mute' },
      { label: 'Ctrl + Shift + D', description: 'Toggle deafen' },
    ],
  },
  {
    title: 'UI',
    shortcuts: [
      { label: 'Ctrl + Shift + I', description: 'Toggle member sidebar' },
      { label: 'Ctrl + Shift + A', description: 'Mark all as read' },
      { label: 'Escape', description: 'Close modal / Deselect' },
    ],
  },
];

/** Flat list of all shortcuts (for backward compat). */
export const SHORTCUTS: ShortcutDef[] = SHORTCUT_GROUPS.flatMap(g => g.shortcuts);

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
  toggleMemberSidebar: () => void;
  markAllAsRead: () => void;
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

    // Ctrl+Shift+I — toggle member sidebar
    if (mod && e.shiftKey && (e.key === 'I' || e.key === 'i')) {
      e.preventDefault();
      actions.toggleMemberSidebar();
      return;
    }

    // Ctrl+Shift+A — mark all as read
    if (mod && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
      e.preventDefault();
      actions.markAllAsRead();
      return;
    }
  };

  document.addEventListener('keydown', handler);
  return () => document.removeEventListener('keydown', handler);
}
