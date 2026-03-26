/**
 * useBookmarks hook unit tests
 *
 * Covers:
 * - Initial state (empty and from localStorage)
 * - Adding bookmarks (including duplicate prevention)
 * - Removing bookmarks
 * - isBookmarked predicate
 * - Ordering (prepend / most-recent first)
 * - Persistence to localStorage
 * - Loading from localStorage on mount
 * - Graceful handling of corrupted localStorage
 */

import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { useBookmarks, type SavedMessage } from '../hooks/useBookmarks';

// ─── helpers ──────────────────────────────────────────────────────────────────

const STORAGE_KEY = 'accord_saved_messages';

function makeMsg(id: string, overrides: Partial<SavedMessage> = {}): SavedMessage {
  return {
    id,
    content: `Content of ${id}`,
    channelId: 'ch-general',
    channelName: 'general',
    author: 'alice',
    timestamp: Date.now(),
    savedAt: Date.now(),
    ...overrides,
  };
}

// ─── tests ────────────────────────────────────────────────────────────────────

describe('useBookmarks', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  // ── initial state ──────────────────────────────────────────────────────────

  describe('initial state', () => {
    it('starts empty when localStorage has no data', () => {
      const { result } = renderHook(() => useBookmarks());
      expect(result.current.bookmarks).toEqual([]);
    });

    it('returns an array (not null/undefined)', () => {
      const { result } = renderHook(() => useBookmarks());
      expect(Array.isArray(result.current.bookmarks)).toBe(true);
    });
  });

  // ── addBookmark ────────────────────────────────────────────────────────────

  describe('addBookmark', () => {
    it('adds a single bookmark', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(makeMsg('m1')));
      expect(result.current.bookmarks).toHaveLength(1);
      expect(result.current.bookmarks[0].id).toBe('m1');
    });

    it('stores the full message fields', () => {
      const msg = makeMsg('m1', { content: 'Hello world', author: 'bob', channelName: 'random' });
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(msg));
      const stored = result.current.bookmarks[0];
      expect(stored.content).toBe('Hello world');
      expect(stored.author).toBe('bob');
      expect(stored.channelName).toBe('random');
    });

    it('prevents adding the same message twice (deduplication)', () => {
      const { result } = renderHook(() => useBookmarks());
      const msg = makeMsg('m1');
      act(() => {
        result.current.addBookmark(msg);
        result.current.addBookmark(msg);
      });
      expect(result.current.bookmarks).toHaveLength(1);
    });

    it('allows adding messages with different ids', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => {
        result.current.addBookmark(makeMsg('m1'));
        result.current.addBookmark(makeMsg('m2'));
        result.current.addBookmark(makeMsg('m3'));
      });
      expect(result.current.bookmarks).toHaveLength(3);
    });

    it('prepends new bookmarks (most-recent first)', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(makeMsg('first')));
      act(() => result.current.addBookmark(makeMsg('second')));
      act(() => result.current.addBookmark(makeMsg('third')));
      expect(result.current.bookmarks[0].id).toBe('third');
      expect(result.current.bookmarks[1].id).toBe('second');
      expect(result.current.bookmarks[2].id).toBe('first');
    });
  });

  // ── removeBookmark ─────────────────────────────────────────────────────────

  describe('removeBookmark', () => {
    it('removes an existing bookmark by id', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(makeMsg('m1')));
      act(() => result.current.removeBookmark('m1'));
      expect(result.current.bookmarks).toEqual([]);
    });

    it('removing a non-existent id is a no-op', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(makeMsg('m1')));
      act(() => result.current.removeBookmark('does-not-exist'));
      expect(result.current.bookmarks).toHaveLength(1);
    });

    it('only removes the targeted bookmark, leaving others intact', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => {
        result.current.addBookmark(makeMsg('m1'));
        result.current.addBookmark(makeMsg('m2'));
        result.current.addBookmark(makeMsg('m3'));
      });
      act(() => result.current.removeBookmark('m2'));
      const ids = result.current.bookmarks.map(b => b.id);
      expect(ids).not.toContain('m2');
      expect(ids).toContain('m1');
      expect(ids).toContain('m3');
    });

    it('can remove all bookmarks one by one', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => {
        result.current.addBookmark(makeMsg('m1'));
        result.current.addBookmark(makeMsg('m2'));
      });
      act(() => result.current.removeBookmark('m1'));
      act(() => result.current.removeBookmark('m2'));
      expect(result.current.bookmarks).toEqual([]);
    });
  });

  // ── isBookmarked ───────────────────────────────────────────────────────────

  describe('isBookmarked', () => {
    it('returns true for a bookmarked message', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(makeMsg('m1')));
      expect(result.current.isBookmarked('m1')).toBe(true);
    });

    it('returns false for a non-bookmarked message', () => {
      const { result } = renderHook(() => useBookmarks());
      expect(result.current.isBookmarked('not-there')).toBe(false);
    });

    it('returns false after a bookmark is removed', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(makeMsg('m1')));
      act(() => result.current.removeBookmark('m1'));
      expect(result.current.isBookmarked('m1')).toBe(false);
    });

    it('returns true for one and false for another', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(makeMsg('m1')));
      expect(result.current.isBookmarked('m1')).toBe(true);
      expect(result.current.isBookmarked('m2')).toBe(false);
    });
  });

  // ── localStorage persistence ───────────────────────────────────────────────

  describe('persistence', () => {
    it('persists added bookmarks to localStorage', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(makeMsg('m1')));
      const raw = localStorage.getItem(STORAGE_KEY);
      expect(raw).not.toBeNull();
      const stored = JSON.parse(raw!);
      expect(stored).toHaveLength(1);
      expect(stored[0].id).toBe('m1');
    });

    it('persists removal to localStorage', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => {
        result.current.addBookmark(makeMsg('m1'));
        result.current.addBookmark(makeMsg('m2'));
      });
      act(() => result.current.removeBookmark('m1'));
      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.map((b: SavedMessage) => b.id)).not.toContain('m1');
      expect(stored.map((b: SavedMessage) => b.id)).toContain('m2');
    });

    it('persists multiple bookmarks in order', () => {
      const { result } = renderHook(() => useBookmarks());
      act(() => {
        result.current.addBookmark(makeMsg('m1'));
        result.current.addBookmark(makeMsg('m2'));
      });
      const stored: SavedMessage[] = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored[0].id).toBe('m2'); // prepended
      expect(stored[1].id).toBe('m1');
    });
  });

  // ── loading from localStorage ──────────────────────────────────────────────

  describe('loading from localStorage on mount', () => {
    it('loads existing bookmarks from localStorage', () => {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([makeMsg('m5'), makeMsg('m6')]));
      const { result } = renderHook(() => useBookmarks());
      expect(result.current.bookmarks).toHaveLength(2);
      const ids = result.current.bookmarks.map(b => b.id);
      expect(ids).toContain('m5');
      expect(ids).toContain('m6');
    });

    it('isBookmarked reflects loaded state', () => {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([makeMsg('pre-loaded')]));
      const { result } = renderHook(() => useBookmarks());
      expect(result.current.isBookmarked('pre-loaded')).toBe(true);
    });

    it('does not add duplicate when adding an already-loaded bookmark', () => {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([makeMsg('m5')]));
      const { result } = renderHook(() => useBookmarks());
      act(() => result.current.addBookmark(makeMsg('m5')));
      expect(result.current.bookmarks).toHaveLength(1);
    });
  });

  // ── corrupted storage ──────────────────────────────────────────────────────

  describe('corrupted localStorage', () => {
    it('starts with empty array on invalid JSON', () => {
      localStorage.setItem(STORAGE_KEY, '{broken json{{');
      const { result } = renderHook(() => useBookmarks());
      expect(result.current.bookmarks).toEqual([]);
    });

    it('does not throw on empty string in localStorage', () => {
      localStorage.setItem(STORAGE_KEY, '');
      const { result } = renderHook(() => useBookmarks());
      expect(result.current.bookmarks).toEqual([]);
    });
  });
});
