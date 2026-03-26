/**
 * useMentionAutocomplete hook unit tests
 *
 * Covers:
 * - Initial inactive state
 * - @ trigger detection activates with user list
 * - # trigger detection activates with channel list
 * - Query filtering / fuzzy matching
 * - Space after trigger dismisses autocomplete
 * - No trigger char stays inactive
 * - ArrowUp / ArrowDown navigation (with wrap-around)
 * - Enter / Tab select and insert text
 * - Escape dismisses
 * - dismissMention API
 * - selectMentionItem API
 * - Edge cases: empty members, empty channels, no match
 */

import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { useMentionAutocomplete, type AutocompleteItem } from '../hooks/useMentionAutocomplete';
import React from 'react';

// ─── helpers ──────────────────────────────────────────────────────────────────

function makeUser(id: string, label: string): AutocompleteItem {
  return { type: 'user', id, label, insertText: `@${label}` };
}

function makeChannel(id: string, label: string): AutocompleteItem {
  return { type: 'channel', id, label, insertText: `#${label}` };
}

function makeKeyEvent(key: string): React.KeyboardEvent {
  return { key, preventDefault: vi.fn() } as unknown as React.KeyboardEvent;
}

const USERS: AutocompleteItem[] = [
  makeUser('u1', 'Alice'),
  makeUser('u2', 'Bob'),
  makeUser('u3', 'John'),
  makeUser('u4', 'Joanna'),
];

const CHANNELS: AutocompleteItem[] = [
  makeChannel('c1', 'general'),
  makeChannel('c2', 'random'),
  makeChannel('c3', 'off-topic'),
];

// ─── tests ────────────────────────────────────────────────────────────────────

describe('useMentionAutocomplete', () => {

  // ── initial state ──────────────────────────────────────────────────────────

  describe('initial state', () => {
    it('is inactive with no items', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      expect(result.current.mentionState.active).toBe(false);
      expect(result.current.mentionState.items).toEqual([]);
      expect(result.current.mentionState.triggerChar).toBeNull();
      expect(result.current.mentionState.query).toBe('');
      expect(result.current.mentionState.selectedIndex).toBe(0);
    });
  });

  // ── @ trigger ──────────────────────────────────────────────────────────────

  describe('@ trigger', () => {
    it('activates with full user list when query is empty', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));
      expect(result.current.mentionState.active).toBe(true);
      expect(result.current.mentionState.triggerChar).toBe('@');
      expect(result.current.mentionState.items).toHaveLength(USERS.length);
    });

    it('all returned items are of type user', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));
      const types = result.current.mentionState.items.map(i => i.type);
      expect(types.every(t => t === 'user')).toBe(true);
    });

    it('filters users by prefix', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@Al', 3));
      const labels = result.current.mentionState.items.map(i => i.label);
      expect(labels).toContain('Alice');
      expect(labels).not.toContain('Bob');
      expect(labels).not.toContain('John');
    });

    it('filters users by partial match (jo matches John and Joanna)', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@jo', 3));
      const labels = result.current.mentionState.items.map(i => i.label);
      expect(labels).toContain('John');
      expect(labels).toContain('Joanna');
      expect(labels).not.toContain('Alice');
      expect(labels).not.toContain('Bob');
    });

    it('case-insensitive matching', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@ALICE', 6));
      const labels = result.current.mentionState.items.map(i => i.label);
      expect(labels).toContain('Alice');
    });

    it('returns empty items list when query matches nothing', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@zzznomatch', 11));
      expect(result.current.mentionState.active).toBe(true);
      expect(result.current.mentionState.items).toHaveLength(0);
    });
  });

  // ── # trigger ──────────────────────────────────────────────────────────────

  describe('# trigger', () => {
    it('activates with full channel list when query is empty', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('#', 1));
      expect(result.current.mentionState.active).toBe(true);
      expect(result.current.mentionState.triggerChar).toBe('#');
      expect(result.current.mentionState.items).toHaveLength(CHANNELS.length);
    });

    it('all returned items are of type channel', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('#', 1));
      const types = result.current.mentionState.items.map(i => i.type);
      expect(types.every(t => t === 'channel')).toBe(true);
    });

    it('filters channels by query', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('#gen', 4));
      const labels = result.current.mentionState.items.map(i => i.label);
      expect(labels).toContain('general');
      expect(labels).not.toContain('random');
    });
  });

  // ── dismissal ──────────────────────────────────────────────────────────────

  describe('dismissal', () => {
    it('space after trigger dismisses autocomplete', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));
      expect(result.current.mentionState.active).toBe(true);
      act(() => result.current.handleMentionInput('@ ', 2));
      expect(result.current.mentionState.active).toBe(false);
    });

    it('no trigger char keeps state inactive', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('hello world', 11));
      expect(result.current.mentionState.active).toBe(false);
    });

    it('dismissMention deactivates from active state', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));
      expect(result.current.mentionState.active).toBe(true);
      act(() => result.current.dismissMention());
      expect(result.current.mentionState.active).toBe(false);
    });

    it('Escape key dismisses', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('Escape'), '@', vi.fn(), { current: null } as any);
      });
      expect(result.current.mentionState.active).toBe(false);
    });

    it('Escape key resets items', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('Escape'), '@', vi.fn(), { current: null } as any);
      });
      expect(result.current.mentionState.items).toEqual([]);
    });
  });

  // ── navigation ─────────────────────────────────────────────────────────────

  describe('keyboard navigation', () => {
    it('ArrowDown increments selectedIndex', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));
      expect(result.current.mentionState.selectedIndex).toBe(0);

      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('ArrowDown'), '@', vi.fn(), { current: null } as any);
      });
      expect(result.current.mentionState.selectedIndex).toBe(1);
    });

    it('ArrowUp decrements selectedIndex', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));

      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('ArrowDown'), '@', vi.fn(), { current: null } as any);
      });
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('ArrowDown'), '@', vi.fn(), { current: null } as any);
      });
      expect(result.current.mentionState.selectedIndex).toBe(2);

      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('ArrowUp'), '@', vi.fn(), { current: null } as any);
      });
      expect(result.current.mentionState.selectedIndex).toBe(1);
    });

    it('ArrowUp wraps from 0 to last item', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));
      expect(result.current.mentionState.selectedIndex).toBe(0);

      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('ArrowUp'), '@', vi.fn(), { current: null } as any);
      });
      expect(result.current.mentionState.selectedIndex).toBe(USERS.length - 1);
    });

    it('ArrowDown wraps from last to 0', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));

      // Move to last item
      for (let i = 0; i < USERS.length - 1; i++) {
        act(() => {
          result.current.handleMentionKeyDown(makeKeyEvent('ArrowDown'), '@', vi.fn(), { current: null } as any);
        });
      }
      expect(result.current.mentionState.selectedIndex).toBe(USERS.length - 1);

      // One more wraps to 0
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('ArrowDown'), '@', vi.fn(), { current: null } as any);
      });
      expect(result.current.mentionState.selectedIndex).toBe(0);
    });
  });

  // ── selection and insertion ────────────────────────────────────────────────

  describe('selection and insertion', () => {
    it('Enter selects the current item and inserts text', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));

      const setMsg = vi.fn();
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('Enter'), '@', setMsg, { current: null } as any);
      });
      // First item is Alice, insertText is @Alice + trailing space
      expect(setMsg).toHaveBeenCalledWith('@Alice ');
      expect(result.current.mentionState.active).toBe(false);
    });

    it('Tab selects the current item and inserts text', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));

      const setMsg = vi.fn();
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('Tab'), '@', setMsg, { current: null } as any);
      });
      expect(setMsg).toHaveBeenCalledWith('@Alice ');
      expect(result.current.mentionState.active).toBe(false);
    });

    it('Enter on second item inserts second item text', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));

      // Navigate to Bob (index 1)
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('ArrowDown'), '@', vi.fn(), { current: null } as any);
      });

      const setMsg = vi.fn();
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('Enter'), '@', setMsg, { current: null } as any);
      });
      expect(setMsg).toHaveBeenCalledWith('@Bob ');
    });

    it('selectMentionItem inserts text and dismisses', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));

      const setMsg = vi.fn();
      act(() => {
        result.current.selectMentionItem(0, '@', setMsg, { current: null } as any);
      });
      expect(setMsg).toHaveBeenCalledWith('@Alice ');
      expect(result.current.mentionState.active).toBe(false);
    });

    it('inserts after preceding text correctly', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      // "Hello @" — cursor at position 7
      act(() => result.current.handleMentionInput('Hello @', 7));

      const setMsg = vi.fn();
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('Enter'), 'Hello @', setMsg, { current: null } as any);
      });
      expect(setMsg).toHaveBeenCalledWith('Hello @Alice ');
    });

    it('inserts channel mention correctly', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('#', 1));

      const setMsg = vi.fn();
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('Enter'), '#', setMsg, { current: null } as any);
      });
      expect(setMsg).toHaveBeenCalledWith('#general ');
    });
  });

  // ── fuzzy matching ─────────────────────────────────────────────────────────

  describe('fuzzy matching', () => {
    it('substring match: "ob" matches Bob', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@ob', 3));
      const labels = result.current.mentionState.items.map(i => i.label);
      expect(labels).toContain('Bob');
    });

    it('character-order fuzzy: "ace" matches Alice (a...c...e in order)', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('@ace', 4));
      const labels = result.current.mentionState.items.map(i => i.label);
      expect(labels).toContain('Alice');
    });
  });

  // ── edge cases ─────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('empty users list: @ activates with empty items', () => {
      const { result } = renderHook(() => useMentionAutocomplete([], CHANNELS));
      act(() => result.current.handleMentionInput('@', 1));
      expect(result.current.mentionState.active).toBe(true);
      expect(result.current.mentionState.items).toHaveLength(0);
    });

    it('empty channels list: # activates with empty items', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, []));
      act(() => result.current.handleMentionInput('#', 1));
      expect(result.current.mentionState.active).toBe(true);
      expect(result.current.mentionState.items).toHaveLength(0);
    });

    it('navigation keys are no-ops when state is inactive', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      // Not active
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('ArrowDown'), '', vi.fn(), { current: null } as any);
      });
      expect(result.current.mentionState.selectedIndex).toBe(0);
      expect(result.current.mentionState.active).toBe(false);
    });

    it('Enter is no-op when state is inactive', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      const setMsg = vi.fn();
      act(() => {
        result.current.handleMentionKeyDown(makeKeyEvent('Enter'), 'hello', setMsg, { current: null } as any);
      });
      expect(setMsg).not.toHaveBeenCalled();
    });

    it('trigger mid-word is not activated (preceded by non-space char)', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      // "email@" — @ is not at start or after space
      act(() => result.current.handleMentionInput('email@', 6));
      expect(result.current.mentionState.active).toBe(false);
    });

    it('result is capped at 10 items', () => {
      const manyUsers: AutocompleteItem[] = Array.from({ length: 20 }, (_, i) =>
        makeUser(`u${i}`, `User${i}`)
      );
      const { result } = renderHook(() => useMentionAutocomplete(manyUsers, []));
      act(() => result.current.handleMentionInput('@', 1));
      expect(result.current.mentionState.items.length).toBeLessThanOrEqual(10);
    });

    it('calling handleMentionInput with empty string keeps state inactive', () => {
      const { result } = renderHook(() => useMentionAutocomplete(USERS, CHANNELS));
      act(() => result.current.handleMentionInput('', 0));
      expect(result.current.mentionState.active).toBe(false);
    });
  });
});
