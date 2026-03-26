/**
 * usePresence hook unit tests
 *
 * Covers:
 * - Default offline state for unknown users
 * - Explicit presence from presenceMap (highest priority)
 * - Inference from recent message activity (<5 min = online)
 * - Old message time not promoting to online (>5 min)
 * - Fallback to NodeMember.status
 * - Fallback to NodeMember.profile.status
 * - Priority order: presenceMap > message time > member status > profile status > offline
 * - recordMessageTime updates the lastMessageTimes map
 * - setPresenceMap replaces the full map
 * - setLastMessageTimes replaces the full map
 */

import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { usePresence } from '../hooks/usePresence';
import type { NodeMember, User } from '../types';
import { PresenceStatus } from '../types';

// ─── helpers ──────────────────────────────────────────────────────────────────

function makeUser(id: string): User {
  return {
    id,
    public_key_hash: `hash-${id}`,
    public_key: `pk-${id}`,
    created_at: 0,
    display_name: `User ${id}`,
  };
}

type FullMember = NodeMember & { user: User };

function makeMember(
  userId: string,
  opts: {
    status?: PresenceStatus;
    profileStatus?: PresenceStatus;
  } = {}
): FullMember {
  return {
    node_id: 'n1',
    user_id: userId,
    public_key_hash: `hash-${userId}`,
    role: 'member',
    joined_at: 0,
    status: opts.status,
    profile: opts.profileStatus
      ? { user_id: userId, status: opts.profileStatus, display_name: `User ${userId}`, updated_at: 0 }
      : undefined,
    user: makeUser(userId),
  };
}

// ─── tests ────────────────────────────────────────────────────────────────────

describe('usePresence', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // ── default / offline ──────────────────────────────────────────────────────

  describe('default state', () => {
    it('returns offline for unknown user with no members', () => {
      const { result } = renderHook(() => usePresence([]));
      expect(result.current.getPresenceStatus('nobody')).toBe('offline');
    });

    it('returns offline for unknown user when members list is non-empty', () => {
      const { result } = renderHook(() => usePresence([makeMember('u1')]));
      expect(result.current.getPresenceStatus('ghost')).toBe('offline');
    });

    it('starts with empty presenceMap', () => {
      const { result } = renderHook(() => usePresence([]));
      expect(result.current.presenceMap.size).toBe(0);
    });

    it('starts with empty lastMessageTimes', () => {
      const { result } = renderHook(() => usePresence([]));
      expect(result.current.lastMessageTimes.size).toBe(0);
    });
  });

  // ── explicit presenceMap ───────────────────────────────────────────────────

  describe('explicit presenceMap', () => {
    it('returns DND from explicit presenceMap entry', () => {
      const { result } = renderHook(() => usePresence([]));
      act(() => {
        result.current.setPresenceMap(new Map([['u1', PresenceStatus.DND]]));
      });
      expect(result.current.getPresenceStatus('u1')).toBe('dnd');
    });

    it('returns idle from explicit presenceMap entry', () => {
      const { result } = renderHook(() => usePresence([]));
      act(() => {
        result.current.setPresenceMap(new Map([['u1', PresenceStatus.Idle]]));
      });
      expect(result.current.getPresenceStatus('u1')).toBe('idle');
    });

    it('returns online from explicit presenceMap entry', () => {
      const { result } = renderHook(() => usePresence([]));
      act(() => {
        result.current.setPresenceMap(new Map([['u1', PresenceStatus.Online]]));
      });
      expect(result.current.getPresenceStatus('u1')).toBe('online');
    });

    it('presenceMap takes priority over recent message time', () => {
      const { result } = renderHook(() => usePresence([]));
      act(() => {
        result.current.setPresenceMap(new Map([['u1', PresenceStatus.DND]]));
        result.current.recordMessageTime('u1');
      });
      expect(result.current.getPresenceStatus('u1')).toBe('dnd');
    });

    it('presenceMap takes priority over member status', () => {
      const { result } = renderHook(() =>
        usePresence([makeMember('u1', { status: PresenceStatus.Idle })])
      );
      act(() => {
        result.current.setPresenceMap(new Map([['u1', PresenceStatus.Online]]));
      });
      expect(result.current.getPresenceStatus('u1')).toBe('online');
    });

    it('setPresenceMap replaces entire map', () => {
      const { result } = renderHook(() => usePresence([]));
      act(() => {
        result.current.setPresenceMap(new Map([['u1', PresenceStatus.Online], ['u2', PresenceStatus.Idle]]));
      });
      act(() => {
        result.current.setPresenceMap(new Map([['u3', PresenceStatus.DND]]));
      });
      expect(result.current.getPresenceStatus('u1')).toBe('offline');
      expect(result.current.getPresenceStatus('u3')).toBe('dnd');
    });
  });

  // ── message time inference ─────────────────────────────────────────────────

  describe('message time inference', () => {
    it('infers online from message time less than 5 minutes ago', () => {
      const { result } = renderHook(() => usePresence([]));
      act(() => result.current.recordMessageTime('u1'));
      expect(result.current.getPresenceStatus('u1')).toBe('online');
    });

    it('does not infer online from message time older than 5 minutes', () => {
      const { result } = renderHook(() => usePresence([]));
      act(() => {
        result.current.setLastMessageTimes(
          new Map([['u1', Date.now() - 6 * 60 * 1000]])
        );
      });
      expect(result.current.getPresenceStatus('u1')).toBe('offline');
    });

    it('5-minute boundary: exactly 5 min old is not online', () => {
      vi.useFakeTimers();
      const now = Date.now();
      const { result } = renderHook(() => usePresence([]));
      act(() => {
        result.current.setLastMessageTimes(
          new Map([['u1', now - 5 * 60 * 1000]])
        );
      });
      // Exactly at the boundary: Date.now() - lastMsg === 5 * 60 * 1000, not < 5min
      expect(result.current.getPresenceStatus('u1')).toBe('offline');
      vi.useRealTimers();
    });

    it('message time does not override member status for old messages', () => {
      const { result } = renderHook(() =>
        usePresence([makeMember('u1', { status: PresenceStatus.Idle })])
      );
      act(() => {
        result.current.setLastMessageTimes(
          new Map([['u1', Date.now() - 10 * 60 * 1000]])
        );
      });
      expect(result.current.getPresenceStatus('u1')).toBe('idle');
    });
  });

  // ── recordMessageTime ──────────────────────────────────────────────────────

  describe('recordMessageTime', () => {
    it('adds a recent timestamp to lastMessageTimes', () => {
      const before = Date.now();
      const { result } = renderHook(() => usePresence([]));
      act(() => result.current.recordMessageTime('u7'));
      expect(result.current.lastMessageTimes.has('u7')).toBe(true);
      const t = result.current.lastMessageTimes.get('u7')!;
      expect(t).toBeGreaterThanOrEqual(before);
      expect(Date.now() - t).toBeLessThan(1000);
    });

    it('updates existing entry for the same user', () => {
      const { result } = renderHook(() => usePresence([]));
      act(() => {
        result.current.setLastMessageTimes(
          new Map([['u1', Date.now() - 60_000]])
        );
      });
      act(() => result.current.recordMessageTime('u1'));
      const t = result.current.lastMessageTimes.get('u1')!;
      expect(Date.now() - t).toBeLessThan(1000);
    });

    it('does not affect other users\' message times', () => {
      const { result } = renderHook(() => usePresence([]));
      act(() => result.current.recordMessageTime('u1'));
      expect(result.current.lastMessageTimes.has('u2')).toBe(false);
    });
  });

  // ── member status fallback ─────────────────────────────────────────────────

  describe('member status fallback', () => {
    it('falls back to NodeMember.status', () => {
      const { result } = renderHook(() =>
        usePresence([makeMember('u1', { status: PresenceStatus.Idle })])
      );
      expect(result.current.getPresenceStatus('u1')).toBe('idle');
    });

    it('falls back to NodeMember.profile.status when member.status is absent', () => {
      const { result } = renderHook(() =>
        usePresence([makeMember('u1', { profileStatus: PresenceStatus.Online })])
      );
      expect(result.current.getPresenceStatus('u1')).toBe('online');
    });

    it('member.status takes priority over profile.status', () => {
      const member: FullMember = {
        ...makeMember('u1', { status: PresenceStatus.DND, profileStatus: PresenceStatus.Online }),
      };
      const { result } = renderHook(() => usePresence([member]));
      expect(result.current.getPresenceStatus('u1')).toBe('dnd');
    });

    it('returns offline when member has no status or profile status', () => {
      const { result } = renderHook(() => usePresence([makeMember('u1')]));
      expect(result.current.getPresenceStatus('u1')).toBe('offline');
    });
  });

  // ── priority chain ─────────────────────────────────────────────────────────

  describe('priority chain', () => {
    it('explicit presenceMap > message time > member status', () => {
      const members = [makeMember('u1', { status: PresenceStatus.Idle })];
      const { result } = renderHook(() => usePresence(members));

      // Only member status → idle
      expect(result.current.getPresenceStatus('u1')).toBe('idle');

      // Add recent message time → online
      act(() => result.current.recordMessageTime('u1'));
      expect(result.current.getPresenceStatus('u1')).toBe('online');

      // Add explicit DND → DND wins
      act(() => {
        result.current.setPresenceMap(new Map([['u1', PresenceStatus.DND]]));
      });
      expect(result.current.getPresenceStatus('u1')).toBe('dnd');
    });
  });

  // ── multiple users ─────────────────────────────────────────────────────────

  describe('multiple users', () => {
    it('tracks presence independently for multiple users', () => {
      const members = [
        makeMember('u1', { status: PresenceStatus.Online }),
        makeMember('u2', { status: PresenceStatus.Idle }),
        makeMember('u3'),
      ];
      const { result } = renderHook(() => usePresence(members));
      expect(result.current.getPresenceStatus('u1')).toBe('online');
      expect(result.current.getPresenceStatus('u2')).toBe('idle');
      expect(result.current.getPresenceStatus('u3')).toBe('offline');
    });
  });
});
