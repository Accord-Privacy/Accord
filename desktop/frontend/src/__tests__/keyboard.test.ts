import { describe, it, expect, vi, afterEach } from 'vitest';
import { initKeyboardShortcuts, isTypingInInput, KeyboardActions } from '../keyboard';

function makeActions(): KeyboardActions {
  return {
    openSearch: vi.fn(),
    openSettings: vi.fn(),
    toggleShortcutsHelp: vi.fn(),
    closeTopModal: vi.fn(),
    toggleEmojiPicker: vi.fn(),
    navigateChannel: vi.fn(),
    toggleMute: vi.fn(),
    toggleDeafen: vi.fn(),
  };
}

function fireKey(key: string, opts: Partial<KeyboardEventInit> = {}) {
  document.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, ...opts }));
}

describe('keyboard shortcuts', () => {
  let cleanup: () => void;
  let actions: KeyboardActions;

  afterEach(() => {
    cleanup?.();
  });

  it('Escape calls closeTopModal', () => {
    actions = makeActions();
    cleanup = initKeyboardShortcuts(actions);
    fireKey('Escape');
    expect(actions.closeTopModal).toHaveBeenCalledOnce();
  });

  it('Ctrl+K calls openSearch', () => {
    actions = makeActions();
    cleanup = initKeyboardShortcuts(actions);
    fireKey('k', { ctrlKey: true });
    expect(actions.openSearch).toHaveBeenCalledOnce();
  });

  it('Ctrl+, calls openSettings', () => {
    actions = makeActions();
    cleanup = initKeyboardShortcuts(actions);
    fireKey(',', { ctrlKey: true });
    expect(actions.openSettings).toHaveBeenCalledOnce();
  });

  it('Ctrl+E calls toggleEmojiPicker', () => {
    actions = makeActions();
    cleanup = initKeyboardShortcuts(actions);
    fireKey('e', { ctrlKey: true });
    expect(actions.toggleEmojiPicker).toHaveBeenCalledOnce();
  });

  it('? calls toggleShortcutsHelp when not typing', () => {
    actions = makeActions();
    cleanup = initKeyboardShortcuts(actions);
    fireKey('?');
    expect(actions.toggleShortcutsHelp).toHaveBeenCalledOnce();
  });

  it('Alt+ArrowUp navigates channel up', () => {
    actions = makeActions();
    cleanup = initKeyboardShortcuts(actions);
    fireKey('ArrowUp', { altKey: true });
    expect(actions.navigateChannel).toHaveBeenCalledWith('up');
  });

  it('Alt+ArrowDown navigates channel down', () => {
    actions = makeActions();
    cleanup = initKeyboardShortcuts(actions);
    fireKey('ArrowDown', { altKey: true });
    expect(actions.navigateChannel).toHaveBeenCalledWith('down');
  });

  it('cleanup removes listener', () => {
    actions = makeActions();
    cleanup = initKeyboardShortcuts(actions);
    cleanup();
    fireKey('Escape');
    // closeTopModal called 0 times after cleanup
    expect(actions.closeTopModal).not.toHaveBeenCalled();
  });

  it('isTypingInInput returns false when body is focused', () => {
    (document.body as HTMLElement).focus();
    expect(isTypingInInput()).toBeFalsy();
  });
});
