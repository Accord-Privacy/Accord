/**
 * useBlocking hook unit tests
 *
 * Covers:
 * - Block/unblock user actions and state updates
 * - Blocked users list state management
 * - API call verification
 * - Guard conditions (missing token, missing auth)
 * - Error propagation
 * - Initial load from API on authentication
 */

import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useBlocking } from '../hooks/useBlocking';

// ─── API mock ─────────────────────────────────────────────────────────────────

vi.mock('../api', () => ({
  api: {
    blockUser: vi.fn().mockResolvedValue({ status: 'ok' }),
    unblockUser: vi.fn().mockResolvedValue({ status: 'ok' }),
    getBlockedUsers: vi.fn().mockResolvedValue({ blocked_users: [] }),
  },
}));

// ─── helpers ──────────────────────────────────────────────────────────────────

async function flushPromises() {
  await act(async () => {
    await new Promise(r => setTimeout(r, 0));
  });
}

// ─── tests ────────────────────────────────────────────────────────────────────

describe('useBlocking', () => {
  beforeEach(() => vi.clearAllMocks());

  // ── initial state ──────────────────────────────────────────────────────────

  describe('initial state', () => {
    it('starts with an empty blocked set (unauthenticated)', () => {
      const { result } = renderHook(() => useBlocking(undefined, false));
      expect(result.current.blockedUsers.size).toBe(0);
    });

    it('starts with an empty blocked set (authenticated, before fetch resolves)', () => {
      const { result } = renderHook(() => useBlocking('tok', true));
      // Before the useEffect async resolves, set should still be empty
      expect(result.current.blockedUsers).toBeInstanceOf(Set);
    });
  });

  // ── API load on auth ───────────────────────────────────────────────────────

  describe('fetchBlockedUsers on mount', () => {
    it('fetches blocked users when authenticated', async () => {
      const { api } = await import('../api');
      (api.getBlockedUsers as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        blocked_users: [
          { user_id: 'u10', created_at: 1000 },
          { user_id: 'u11', created_at: 2000 },
        ],
      });

      const { result } = renderHook(() => useBlocking('tok', true));
      await flushPromises();

      expect(api.getBlockedUsers).toHaveBeenCalledWith('tok');
      expect(result.current.blockedUsers.has('u10')).toBe(true);
      expect(result.current.blockedUsers.has('u11')).toBe(true);
      expect(result.current.blockedUsers.size).toBe(2);
    });

    it('does not fetch when not authenticated', async () => {
      const { api } = await import('../api');
      renderHook(() => useBlocking('tok', false));
      await flushPromises();
      expect(api.getBlockedUsers).not.toHaveBeenCalled();
    });

    it('does not fetch when token is undefined', async () => {
      const { api } = await import('../api');
      renderHook(() => useBlocking(undefined, true));
      await flushPromises();
      expect(api.getBlockedUsers).not.toHaveBeenCalled();
    });

    it('handles fetch error gracefully (does not throw)', async () => {
      const { api } = await import('../api');
      (api.getBlockedUsers as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('network error')
      );
      // Should not throw
      const { result } = renderHook(() => useBlocking('tok', true));
      await flushPromises();
      expect(result.current.blockedUsers.size).toBe(0);
    });
  });

  // ── block user ─────────────────────────────────────────────────────────────

  describe('handleBlockUser', () => {
    it('adds user to blocked set after successful API call', async () => {
      const { result } = renderHook(() => useBlocking('tok', true));
      await act(async () => {
        await result.current.handleBlockUser('u1');
      });
      expect(result.current.blockedUsers.has('u1')).toBe(true);
    });

    it('calls api.blockUser with correct userId and token', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useBlocking('tok', true));
      await act(async () => {
        await result.current.handleBlockUser('u2');
      });
      expect(api.blockUser).toHaveBeenCalledWith('u2', 'tok');
    });

    it('can block multiple users independently', async () => {
      const { result } = renderHook(() => useBlocking('tok', true));
      await act(async () => {
        await result.current.handleBlockUser('u1');
        await result.current.handleBlockUser('u2');
        await result.current.handleBlockUser('u3');
      });
      expect(result.current.blockedUsers.has('u1')).toBe(true);
      expect(result.current.blockedUsers.has('u2')).toBe(true);
      expect(result.current.blockedUsers.has('u3')).toBe(true);
      expect(result.current.blockedUsers.size).toBe(3);
    });

    it('does nothing when token is undefined', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useBlocking(undefined, false));
      await act(async () => {
        await result.current.handleBlockUser('u1');
      });
      expect(api.blockUser).not.toHaveBeenCalled();
      expect(result.current.blockedUsers.size).toBe(0);
    });

    it('propagates API errors', async () => {
      const { api } = await import('../api');
      (api.blockUser as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('server error')
      );
      const { result } = renderHook(() => useBlocking('tok', true));
      await expect(
        act(async () => {
          await result.current.handleBlockUser('u1');
        })
      ).rejects.toThrow('server error');
    });

    it('does not add to blocked set when API fails', async () => {
      const { api } = await import('../api');
      (api.blockUser as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('fail')
      );
      const { result } = renderHook(() => useBlocking('tok', true));
      try {
        await act(async () => {
          await result.current.handleBlockUser('u1');
        });
      } catch {
        // expected
      }
      expect(result.current.blockedUsers.has('u1')).toBe(false);
    });
  });

  // ── unblock user ───────────────────────────────────────────────────────────

  describe('handleUnblockUser', () => {
    it('removes user from blocked set after successful API call', async () => {
      const { result } = renderHook(() => useBlocking('tok', true));
      await act(async () => {
        await result.current.handleBlockUser('u1');
      });
      expect(result.current.blockedUsers.has('u1')).toBe(true);

      await act(async () => {
        await result.current.handleUnblockUser('u1');
      });
      expect(result.current.blockedUsers.has('u1')).toBe(false);
    });

    it('calls api.unblockUser with correct userId and token', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useBlocking('tok', true));
      await act(async () => {
        await result.current.handleBlockUser('u2');
      });
      vi.clearAllMocks();
      await act(async () => {
        await result.current.handleUnblockUser('u2');
      });
      expect(api.unblockUser).toHaveBeenCalledWith('u2', 'tok');
    });

    it('does nothing when token is undefined', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useBlocking(undefined, false));
      await act(async () => {
        await result.current.handleUnblockUser('u1');
      });
      expect(api.unblockUser).not.toHaveBeenCalled();
    });

    it('unblocking non-blocked user does not crash', async () => {
      const { result } = renderHook(() => useBlocking('tok', true));
      await act(async () => {
        await result.current.handleUnblockUser('u-nonexistent');
      });
      expect(result.current.blockedUsers.size).toBe(0);
    });

    it('unblocking one user leaves others intact', async () => {
      const { result } = renderHook(() => useBlocking('tok', true));
      await act(async () => {
        await result.current.handleBlockUser('u1');
        await result.current.handleBlockUser('u2');
      });
      await act(async () => {
        await result.current.handleUnblockUser('u1');
      });
      expect(result.current.blockedUsers.has('u1')).toBe(false);
      expect(result.current.blockedUsers.has('u2')).toBe(true);
    });

    it('propagates API errors', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useBlocking('tok', true));
      await act(async () => {
        await result.current.handleBlockUser('u1');
      });
      (api.unblockUser as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('unblock failed')
      );
      await expect(
        act(async () => {
          await result.current.handleUnblockUser('u1');
        })
      ).rejects.toThrow('unblock failed');
    });
  });

  // ── round-trip ─────────────────────────────────────────────────────────────

  describe('block/unblock round-trip', () => {
    it('block → unblock → block results in user being blocked', async () => {
      const { result } = renderHook(() => useBlocking('tok', true));
      await act(async () => { await result.current.handleBlockUser('u1'); });
      expect(result.current.blockedUsers.has('u1')).toBe(true);
      await act(async () => { await result.current.handleUnblockUser('u1'); });
      expect(result.current.blockedUsers.has('u1')).toBe(false);
      await act(async () => { await result.current.handleBlockUser('u1'); });
      expect(result.current.blockedUsers.has('u1')).toBe(true);
    });
  });
});
