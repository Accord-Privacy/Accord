/**
 * useTyping hook unit tests
 *
 * Covers:
 * - Typing indicator state management
 * - Timer-based auto-clear of typing status
 * - Multiple users typing simultaneously
 * - Cleanup on unmount
 */

import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { useTyping } from '../hooks/useTyping';
import type { NodeMember, User } from '../types';

// ─── helpers ──────────────────────────────────────────────────────────────────

const makeUser = (id: string, name: string): User => ({
  id,
  public_key_hash: `hash-${id}`,
  public_key: `pk-${id}`,
  created_at: 0,
  display_name: name,
});

const makeMembers = (
  users: Array<{ id: string; name: string }>,
): Array<NodeMember & { user: User }> =>
  users.map(({ id, name }) => ({
    node_id: 'n1',
    user_id: id,
    public_key_hash: `hash-${id}`,
    role: 'member' as const,
    joined_at: 0,
    user: makeUser(id, name),
  }));

const members = makeMembers([
  { id: 'u1', name: 'Alice' },
  { id: 'u2', name: 'Bob' },
  { id: 'u3', name: 'Carol' },
  { id: 'u4', name: 'Dave' },
]);

const makeWs = () => ({ sendTypingStart: vi.fn() });

// ─── setup/teardown ──────────────────────────────────────────────────────────

beforeEach(() => {
  vi.useFakeTimers();
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation((key: string) => {
    if (key === 'accord_user_id') return 'self';
    if (key === 'accord-typing-indicators') return 'true';
    return null;
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ─── Initial state ────────────────────────────────────────────────────────────

describe('useTyping — initial state', () => {
  it('typingUsers map is initially empty', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    expect(result.current.typingUsers.size).toBe(0);
  });

  it('formatTypingUsers returns empty string for unknown channel', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    expect(result.current.formatTypingUsers('ch-unknown')).toBe('');
  });

  it('getTypingUsersForChannel returns empty array for unknown channel', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    expect(result.current.getTypingUsersForChannel('ch-unknown')).toEqual([]);
  });
});

// ─── sendTypingIndicator ──────────────────────────────────────────────────────

describe('useTyping — sendTypingIndicator', () => {
  it('sends typing start via ws', () => {
    const ws = makeWs();
    const { result } = renderHook(() => useTyping(ws as any, members));
    act(() => result.current.sendTypingIndicator('ch1'));
    expect(ws.sendTypingStart).toHaveBeenCalledWith('ch1');
    expect(ws.sendTypingStart).toHaveBeenCalledTimes(1);
  });

  it('does not send if ws is null', () => {
    const { result } = renderHook(() => useTyping(null, members));
    // Should not throw
    act(() => result.current.sendTypingIndicator('ch1'));
  });

  it('does not send if channelId is empty', () => {
    const ws = makeWs();
    const { result } = renderHook(() => useTyping(ws as any, members));
    act(() => result.current.sendTypingIndicator(''));
    expect(ws.sendTypingStart).not.toHaveBeenCalled();
  });

  it('throttles to at most one send per 3s', () => {
    const ws = makeWs();
    const { result } = renderHook(() => useTyping(ws as any, members));
    act(() => result.current.sendTypingIndicator('ch1'));
    act(() => result.current.sendTypingIndicator('ch1'));
    act(() => result.current.sendTypingIndicator('ch1'));
    expect(ws.sendTypingStart).toHaveBeenCalledTimes(1);
  });

  it('sends again after 3s throttle window', () => {
    const ws = makeWs();
    const { result } = renderHook(() => useTyping(ws as any, members));
    act(() => result.current.sendTypingIndicator('ch1'));
    act(() => vi.advanceTimersByTime(3100));
    act(() => result.current.sendTypingIndicator('ch1'));
    expect(ws.sendTypingStart).toHaveBeenCalledTimes(2);
  });

  it('does not send if typing indicators disabled in localStorage', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation((key: string) => {
      if (key === 'accord-typing-indicators') return 'false';
      if (key === 'accord_user_id') return 'self';
      return null;
    });
    const ws = makeWs();
    const { result } = renderHook(() => useTyping(ws as any, members));
    act(() => result.current.sendTypingIndicator('ch1'));
    expect(ws.sendTypingStart).not.toHaveBeenCalled();
  });
});

// ─── handleTypingStart & formatTypingUsers ────────────────────────────────────

describe('useTyping — handleTypingStart and formatTypingUsers', () => {
  it('single user shows "X is typing"', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice'));
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');
  });

  it('two users shows "X and Y are typing"', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'u2', 'Bob');
    });
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice and Bob are typing');
  });

  it('three users shows "X, Y, and Z are typing"', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'u2', 'Bob');
      result.current.handleTypingStart('ch1', 'u3', 'Carol');
    });
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice, Bob, and Carol are typing');
  });

  it('four or more users shows "Several people are typing"', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'u2', 'Bob');
      result.current.handleTypingStart('ch1', 'u3', 'Carol');
      result.current.handleTypingStart('ch1', 'u4', 'Dave');
    });
    expect(result.current.formatTypingUsers('ch1')).toBe('Several people are typing');
  });

  it('excludes current user (self) from typing display', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => result.current.handleTypingStart('ch1', 'self', 'Me'));
    expect(result.current.formatTypingUsers('ch1')).toBe('');
  });

  it('only shows non-self users when mixed with self', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'self', 'Me');
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
    });
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');
  });

  it('resolves display name from member list', () => {
    const customMembers = makeMembers([{ id: 'u99', name: 'ResolvedName' }]);
    const { result } = renderHook(() => useTyping(makeWs() as any, customMembers));
    // Pass a different displayName — hook should prefer member's user.display_name
    act(() => result.current.handleTypingStart('ch1', 'u99', 'FallbackName'));
    expect(result.current.formatTypingUsers('ch1')).toBe('ResolvedName is typing');
  });

  it('falls back to displayName arg when not in member list', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => result.current.handleTypingStart('ch1', 'u-unknown', 'GuestUser'));
    expect(result.current.formatTypingUsers('ch1')).toBe('GuestUser is typing');
  });

  it('tracks typing per channel independently', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch2', 'u2', 'Bob');
    });
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');
    expect(result.current.formatTypingUsers('ch2')).toBe('Bob is typing');
  });

  it('adding same user twice does not duplicate', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
    });
    // Still just one user
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');
  });
});

// ─── Timer-based auto-clear ───────────────────────────────────────────────────

describe('useTyping — auto-clear timer', () => {
  it('removes user after 5s timeout', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice'));
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');

    act(() => vi.advanceTimersByTime(5100));
    expect(result.current.formatTypingUsers('ch1')).toBe('');
  });

  it('does not clear before 5s', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice'));
    act(() => vi.advanceTimersByTime(4900));
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');
  });

  it('resets timer when same user sends another typing start', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice'));
    act(() => vi.advanceTimersByTime(3000));
    // Refresh timer
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice'));
    act(() => vi.advanceTimersByTime(3000));
    // Only 3s since the refresh — should still be typing
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');
    act(() => vi.advanceTimersByTime(2100));
    // 5.1s since refresh — should be cleared
    expect(result.current.formatTypingUsers('ch1')).toBe('');
  });

  it('both users cleared after 5s when added simultaneously', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    // Add both users in one act so their timers are batched and not cancelled by each other
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'u2', 'Bob');
    });
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice and Bob are typing');
    act(() => vi.advanceTimersByTime(5100));
    expect(result.current.formatTypingUsers('ch1')).toBe('');
  });

  it('timers across channels: users added sequentially expire correctly', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    // Add Alice, let 5.1s pass so she times out, then add Bob in ch2
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice'));
    act(() => vi.advanceTimersByTime(5100));
    // Alice is now gone
    expect(result.current.formatTypingUsers('ch1')).toBe('');
    // Now Bob starts typing in ch2
    act(() => result.current.handleTypingStart('ch2', 'u2', 'Bob'));
    expect(result.current.formatTypingUsers('ch2')).toBe('Bob is typing');
    // ch1 is still clear
    expect(result.current.formatTypingUsers('ch1')).toBe('');
  });
});

// ─── getTypingUsersForChannel ─────────────────────────────────────────────────

describe('useTyping — getTypingUsersForChannel', () => {
  it('returns array of resolved user objects', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => result.current.handleTypingStart('ch1', 'u1', 'FallbackName'));
    const users = result.current.getTypingUsersForChannel('ch1');
    expect(users).toHaveLength(1);
    expect(users[0].user_id).toBe('u1');
    expect(users[0].displayName).toBe('Alice'); // resolved from members
  });

  it('excludes self from returned list', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'self', 'Me');
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
    });
    const users = result.current.getTypingUsersForChannel('ch1');
    expect(users).toHaveLength(1);
    expect(users[0].user_id).toBe('u1');
  });

  it('returns empty array for channel with no typing users', () => {
    const { result } = renderHook(() => useTyping(makeWs() as any, members));
    expect(result.current.getTypingUsersForChannel('ch-empty')).toEqual([]);
  });
});

// ─── Cleanup on unmount ───────────────────────────────────────────────────────

describe('useTyping — cleanup on unmount', () => {
  it('clears pending timeouts on unmount without throwing', () => {
    const clearTimeoutSpy = vi.spyOn(window, 'clearTimeout');
    const { result, unmount } = renderHook(() => useTyping(makeWs() as any, members));

    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'u2', 'Bob');
    });

    unmount();
    // clearTimeout should have been called for each active timeout
    expect(clearTimeoutSpy).toHaveBeenCalled();
  });

  it('does not crash when unmounted before any typing events', () => {
    const { unmount } = renderHook(() => useTyping(makeWs() as any, members));
    expect(() => unmount()).not.toThrow();
  });
});
