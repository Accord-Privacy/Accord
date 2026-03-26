/**
 * useSlashCommands hook unit tests
 *
 * Covers:
 * - Command registration and lookup (SLASH_COMMANDS)
 * - Command matching from input text
 * - Argument parsing
 * - Edge cases (empty input, no match, partial match)
 */

import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useSlashCommands, SLASH_COMMANDS } from '../hooks/useSlashCommands';
import type { SlashCommandCallbacks } from '../hooks/useSlashCommands';

// ─── helpers ──────────────────────────────────────────────────────────────────

const makeCallbacks = (): SlashCommandCallbacks => ({
  onNick: vi.fn(),
  onStatus: vi.fn(),
  onClear: vi.fn(),
});

const makeKeyEvent = (key: string): React.KeyboardEvent => ({
  key,
  preventDefault: vi.fn(),
} as unknown as React.KeyboardEvent);

const nullInputRef = { current: null } as React.RefObject<HTMLTextAreaElement | null>;

beforeEach(() => {
  vi.clearAllMocks();
});

// ─── SLASH_COMMANDS constant ──────────────────────────────────────────────────

describe('SLASH_COMMANDS — command registry', () => {
  it('exports a non-empty array of commands', () => {
    expect(Array.isArray(SLASH_COMMANDS)).toBe(true);
    expect(SLASH_COMMANDS.length).toBeGreaterThan(0);
  });

  it('every command has required fields: name, description, usage, hasArg', () => {
    for (const cmd of SLASH_COMMANDS) {
      expect(typeof cmd.name).toBe('string');
      expect(typeof cmd.description).toBe('string');
      expect(typeof cmd.usage).toBe('string');
      expect(typeof cmd.hasArg).toBe('boolean');
    }
  });

  it('contains "nick" command with hasArg=true', () => {
    const nick = SLASH_COMMANDS.find(c => c.name === 'nick');
    expect(nick).toBeDefined();
    expect(nick!.hasArg).toBe(true);
  });

  it('contains "status" command with hasArg=true', () => {
    const status = SLASH_COMMANDS.find(c => c.name === 'status');
    expect(status).toBeDefined();
    expect(status!.hasArg).toBe(true);
  });

  it('contains "clear" command with immediate=true', () => {
    const clear = SLASH_COMMANDS.find(c => c.name === 'clear');
    expect(clear).toBeDefined();
    expect(clear!.immediate).toBe(true);
  });

  it('contains "shrug" command with appendText', () => {
    const shrug = SLASH_COMMANDS.find(c => c.name === 'shrug');
    expect(shrug).toBeDefined();
    expect(typeof shrug!.appendText).toBe('string');
  });

  it('all command names are unique', () => {
    const names = SLASH_COMMANDS.map(c => c.name);
    const unique = new Set(names);
    expect(unique.size).toBe(names.length);
  });
});

// ─── Initial state ────────────────────────────────────────────────────────────

describe('useSlashCommands — initial state', () => {
  it('slashState.active is false initially', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.slashState.active).toBe(false);
  });

  it('slashState.items is empty initially', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.slashState.items).toEqual([]);
  });

  it('slashState.query is empty string initially', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.slashState.query).toBe('');
  });

  it('slashState.selectedIndex is 0 initially', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.slashState.selectedIndex).toBe(0);
  });
});

// ─── handleSlashInput — command matching ─────────────────────────────────────

describe('useSlashCommands — handleSlashInput', () => {
  it('typing "/" shows all commands', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    expect(result.current.slashState.active).toBe(true);
    expect(result.current.slashState.items).toHaveLength(SLASH_COMMANDS.length);
  });

  it('typing "/n" filters to commands starting with "n"', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/n'));
    const names = result.current.slashState.items.map(c => c.name);
    expect(names.every(n => n.startsWith('n'))).toBe(true);
    expect(names).toContain('nick');
  });

  it('typing "/cl" filters to commands starting with "cl"', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/cl'));
    const names = result.current.slashState.items.map(c => c.name);
    expect(names).toContain('clear');
    expect(names).not.toContain('nick');
  });

  it('typing "/sh" shows shrug command', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/sh'));
    const names = result.current.slashState.items.map(c => c.name);
    expect(names).toContain('shrug');
  });

  it('partial match on exact command name still works', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/nick'));
    const names = result.current.slashState.items.map(c => c.name);
    expect(names).toContain('nick');
  });

  it('no match yields empty items but stays active', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/zzzznotacommand'));
    expect(result.current.slashState.active).toBe(true);
    expect(result.current.slashState.items).toHaveLength(0);
  });

  it('empty string dismisses autocomplete', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    act(() => result.current.handleSlashInput(''));
    expect(result.current.slashState.active).toBe(false);
  });

  it('non-slash text dismisses autocomplete when active', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/nick'));
    expect(result.current.slashState.active).toBe(true);
    act(() => result.current.handleSlashInput('hello'));
    expect(result.current.slashState.active).toBe(false);
  });

  it('space after command dismisses autocomplete (argument mode)', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/nick'));
    expect(result.current.slashState.active).toBe(true);
    act(() => result.current.handleSlashInput('/nick newname'));
    expect(result.current.slashState.active).toBe(false);
  });

  it('query is set to the text after "/"', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/stat'));
    expect(result.current.slashState.query).toBe('stat');
  });

  it('matching is case-insensitive', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/NICK'));
    const names = result.current.slashState.items.map(c => c.name);
    expect(names).toContain('nick');
  });
});

// ─── dismissSlash ─────────────────────────────────────────────────────────────

describe('useSlashCommands — dismissSlash', () => {
  it('dismissSlash resets to initial state', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/nick'));
    act(() => result.current.dismissSlash());
    expect(result.current.slashState.active).toBe(false);
    expect(result.current.slashState.items).toEqual([]);
    expect(result.current.slashState.query).toBe('');
    expect(result.current.slashState.selectedIndex).toBe(0);
  });
});

// ─── handleSlashKeyDown — keyboard navigation ────────────────────────────────

describe('useSlashCommands — handleSlashKeyDown', () => {
  it('ArrowDown increments selectedIndex', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    act(() => result.current.handleSlashKeyDown(makeKeyEvent('ArrowDown'), '/', vi.fn(), nullInputRef));
    expect(result.current.slashState.selectedIndex).toBe(1);
  });

  it('ArrowUp decrements selectedIndex', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    // Advance to index 2 first
    act(() => result.current.handleSlashKeyDown(makeKeyEvent('ArrowDown'), '/', vi.fn(), nullInputRef));
    act(() => result.current.handleSlashKeyDown(makeKeyEvent('ArrowDown'), '/', vi.fn(), nullInputRef));
    act(() => result.current.handleSlashKeyDown(makeKeyEvent('ArrowUp'), '/', vi.fn(), nullInputRef));
    expect(result.current.slashState.selectedIndex).toBe(1);
  });

  it('ArrowUp from 0 wraps to last item', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    const len = SLASH_COMMANDS.length;
    act(() => result.current.handleSlashKeyDown(makeKeyEvent('ArrowUp'), '/', vi.fn(), nullInputRef));
    expect(result.current.slashState.selectedIndex).toBe(len - 1);
  });

  it('ArrowDown from last item wraps to 0', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    const len = SLASH_COMMANDS.length;
    // Navigate to last
    for (let i = 0; i < len - 1; i++) {
      act(() => result.current.handleSlashKeyDown(makeKeyEvent('ArrowDown'), '/', vi.fn(), nullInputRef));
    }
    expect(result.current.slashState.selectedIndex).toBe(len - 1);
    act(() => result.current.handleSlashKeyDown(makeKeyEvent('ArrowDown'), '/', vi.fn(), nullInputRef));
    expect(result.current.slashState.selectedIndex).toBe(0);
  });

  it('Escape dismisses autocomplete', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    act(() => result.current.handleSlashKeyDown(makeKeyEvent('Escape'), '/', vi.fn(), nullInputRef));
    expect(result.current.slashState.active).toBe(false);
  });

  it('Enter selects the current item', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/shrug'));
    act(() => result.current.handleSlashKeyDown(makeKeyEvent('Enter'), '/shrug', setMsg, nullInputRef));
    expect(setMsg).toHaveBeenCalled();
    expect(result.current.slashState.active).toBe(false);
  });

  it('Tab selects the current item', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/shrug'));
    act(() => result.current.handleSlashKeyDown(makeKeyEvent('Tab'), '/shrug', setMsg, nullInputRef));
    expect(setMsg).toHaveBeenCalled();
    expect(result.current.slashState.active).toBe(false);
  });

  it('returns false when inactive', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    let handled: boolean;
    act(() => {
      handled = result.current.handleSlashKeyDown(makeKeyEvent('ArrowDown'), 'hello', vi.fn(), nullInputRef);
    });
    expect(handled!).toBe(false);
  });

  it('returns true for handled keys when active', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    let handled: boolean;
    act(() => {
      handled = result.current.handleSlashKeyDown(makeKeyEvent('ArrowDown'), '/', vi.fn(), nullInputRef);
    });
    expect(handled!).toBe(true);
  });

  it('returns false for unhandled keys (e.g. "a") when active', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    let handled: boolean;
    act(() => {
      handled = result.current.handleSlashKeyDown(makeKeyEvent('a'), '/', vi.fn(), nullInputRef);
    });
    expect(handled!).toBe(false);
  });

  it('ArrowDown calls preventDefault', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    const evt = makeKeyEvent('ArrowDown');
    act(() => result.current.handleSlashKeyDown(evt, '/', vi.fn(), nullInputRef));
    expect(evt.preventDefault).toHaveBeenCalled();
  });
});

// ─── selectSlashItem ──────────────────────────────────────────────────────────

describe('useSlashCommands — selectSlashItem', () => {
  it('selects shrug: sets message to appendText', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/shrug'));
    const idx = result.current.slashState.items.findIndex(c => c.name === 'shrug');
    act(() => result.current.selectSlashItem(idx, '/shrug', setMsg, nullInputRef));
    expect(setMsg).toHaveBeenCalledWith('¯\\_(ツ)_/¯');
    expect(result.current.slashState.active).toBe(false);
  });

  it('selects tableflip: sets message to appendText', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/tableflip'));
    const idx = result.current.slashState.items.findIndex(c => c.name === 'tableflip');
    act(() => result.current.selectSlashItem(idx, '/tableflip', setMsg, nullInputRef));
    expect(setMsg).toHaveBeenCalledWith('(╯°□°)╯︵ ┻━┻');
  });

  it('selects unflip: sets message to appendText', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/unflip'));
    const idx = result.current.slashState.items.findIndex(c => c.name === 'unflip');
    act(() => result.current.selectSlashItem(idx, '/unflip', setMsg, nullInputRef));
    expect(setMsg).toHaveBeenCalledWith('┬─┬ノ( º _ ºノ)');
  });

  it('selects clear: calls onClear, sets message to ""', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/cl'));
    const idx = result.current.slashState.items.findIndex(c => c.name === 'clear');
    act(() => result.current.selectSlashItem(idx, '/clear', setMsg, nullInputRef));
    expect(cbs.onClear).toHaveBeenCalled();
    expect(setMsg).toHaveBeenCalledWith('');
  });

  it('selects nick: sets message to "/nick "', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/nick'));
    const idx = result.current.slashState.items.findIndex(c => c.name === 'nick');
    act(() => result.current.selectSlashItem(idx, '/nick', setMsg, nullInputRef));
    expect(setMsg).toHaveBeenCalledWith('/nick ');
  });

  it('selects status: sets message to "/status "', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/stat'));
    const idx = result.current.slashState.items.findIndex(c => c.name === 'status');
    act(() => result.current.selectSlashItem(idx, '/status', setMsg, nullInputRef));
    expect(setMsg).toHaveBeenCalledWith('/status ');
  });

  it('ignores out-of-range index', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/nick'));
    act(() => result.current.selectSlashItem(999, '/nick', setMsg, nullInputRef));
    expect(setMsg).not.toHaveBeenCalled();
    // Still active (select did nothing)
    expect(result.current.slashState.active).toBe(true);
  });

  it('ignores negative index', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const setMsg = vi.fn();
    act(() => result.current.handleSlashInput('/nick'));
    act(() => result.current.selectSlashItem(-1, '/nick', setMsg, nullInputRef));
    expect(setMsg).not.toHaveBeenCalled();
  });
});

// ─── processSlashCommand — argument parsing ───────────────────────────────────

describe('useSlashCommands — processSlashCommand', () => {
  it('returns true for valid command', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.processSlashCommand('/clear')).toBe(true);
  });

  it('returns false for non-slash message', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.processSlashCommand('hello world')).toBe(false);
  });

  it('returns false for unknown command', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.processSlashCommand('/doesnotexist')).toBe(false);
  });

  it('/clear calls onClear callback', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('/clear');
    expect(cbs.onClear).toHaveBeenCalledTimes(1);
  });

  it('/nick calls onNick with the argument', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('/nick CoolName');
    expect(cbs.onNick).toHaveBeenCalledWith('CoolName');
  });

  it('/nick with multi-word arg passes full argument', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('/nick Cool Name');
    expect(cbs.onNick).toHaveBeenCalledWith('Cool Name');
  });

  it('/nick without arg does not call onNick', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('/nick');
    expect(cbs.onNick).not.toHaveBeenCalled();
  });

  it('/status calls onStatus with argument', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('/status Working from home');
    expect(cbs.onStatus).toHaveBeenCalledWith('Working from home');
  });

  it('/status without arg does not call onStatus', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('/status');
    expect(cbs.onStatus).not.toHaveBeenCalled();
  });

  it('whitespace-only arg is treated as no arg (trimmed)', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('/nick   ');
    // trimmed arg is '', so onNick should not be called
    expect(cbs.onNick).not.toHaveBeenCalled();
  });

  it('returns true for /nick even with no arg (still a recognized command)', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.processSlashCommand('/nick')).toBe(true);
  });

  it('returns true for /status even with no arg', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.processSlashCommand('/status')).toBe(true);
  });

  it('empty string returns false', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.processSlashCommand('')).toBe(false);
  });

  it('trimmed command still matches', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('  /clear  ');
    expect(cbs.onClear).toHaveBeenCalled();
  });
});
