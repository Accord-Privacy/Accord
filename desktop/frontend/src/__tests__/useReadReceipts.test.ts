/**
 * useReadReceipts hook unit tests
 *
 * Covers:
 * - Initial state (empty map)
 * - handleReadReceiptEvent: adds receipt to correct channel
 * - handleReadReceiptEvent: replaces existing receipt from same user in same channel
 * - handleReadReceiptEvent: tracks receipts per channel independently
 * - handleReadReceiptEvent: multiple users in same channel
 * - sendReadReceipt: calls api.markChannelRead with correct args
 * - sendReadReceipt: deduplicates consecutive calls for same channel+message
 * - sendReadReceipt: skips call when token is missing
 * - sendReadReceipt: skips call when messageId is empty
 * - sendReadReceipt: skips call when channelId is empty
 * - sendReadReceipt: sends after different message in same channel
 */

import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useReadReceipts } from '../hooks/useReadReceipts';

// ─── API mock ─────────────────────────────────────────────────────────────────

vi.mock('../api', () => ({
  api: {
    markChannelRead: vi.fn().mockResolvedValue({ status: 'ok' }),
  },
}));

// ─── tests ────────────────────────────────────────────────────────────────────

describe('useReadReceipts', () => {
  beforeEach(() => vi.clearAllMocks());

  // ── initial state ──────────────────────────────────────────────────────────

  describe('initial state', () => {
    it('starts with an empty receipts map', () => {
      const { result } = renderHook(() => useReadReceipts());
      expect(result.current.readReceipts).toBeInstanceOf(Map);
      expect(result.current.readReceipts.size).toBe(0);
    });
  });

  // ── handleReadReceiptEvent ─────────────────────────────────────────────────

  describe('handleReadReceiptEvent', () => {
    it('adds a read receipt for the given channel', () => {
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.handleReadReceiptEvent('ch1', 'u1', 'msg1', 1000);
      });
      const receipts = result.current.readReceipts.get('ch1');
      expect(receipts).toHaveLength(1);
      expect(receipts![0]).toEqual({ user_id: 'u1', message_id: 'msg1', timestamp: 1000 });
    });

    it('replaces prior receipt from same user in same channel', () => {
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.handleReadReceiptEvent('ch1', 'u1', 'msg1', 1000);
      });
      act(() => {
        result.current.handleReadReceiptEvent('ch1', 'u1', 'msg2', 2000);
      });
      const receipts = result.current.readReceipts.get('ch1');
      expect(receipts).toHaveLength(1);
      expect(receipts![0].message_id).toBe('msg2');
      expect(receipts![0].timestamp).toBe(2000);
    });

    it('keeps receipts from different users in the same channel', () => {
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.handleReadReceiptEvent('ch1', 'u1', 'msg1', 1000);
        result.current.handleReadReceiptEvent('ch1', 'u2', 'msg1', 1000);
      });
      const receipts = result.current.readReceipts.get('ch1');
      expect(receipts).toHaveLength(2);
      const userIds = receipts!.map(r => r.user_id);
      expect(userIds).toContain('u1');
      expect(userIds).toContain('u2');
    });

    it('tracks receipts per channel independently', () => {
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.handleReadReceiptEvent('ch1', 'u1', 'msg1', 1000);
        result.current.handleReadReceiptEvent('ch2', 'u1', 'msg2', 2000);
      });
      expect(result.current.readReceipts.get('ch1')).toHaveLength(1);
      expect(result.current.readReceipts.get('ch2')).toHaveLength(1);
      expect(result.current.readReceipts.get('ch1')![0].message_id).toBe('msg1');
      expect(result.current.readReceipts.get('ch2')![0].message_id).toBe('msg2');
    });

    it('preserves correct user when replacing receipt', () => {
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.handleReadReceiptEvent('ch1', 'u1', 'msg1', 1000);
        result.current.handleReadReceiptEvent('ch1', 'u2', 'msg1', 1000);
      });
      // Update only u1
      act(() => {
        result.current.handleReadReceiptEvent('ch1', 'u1', 'msg5', 9999);
      });
      const receipts = result.current.readReceipts.get('ch1')!;
      expect(receipts).toHaveLength(2);
      const u1 = receipts.find(r => r.user_id === 'u1')!;
      const u2 = receipts.find(r => r.user_id === 'u2')!;
      expect(u1.message_id).toBe('msg5');
      expect(u2.message_id).toBe('msg1');
    });

    it('handles multiple channels with multiple users', () => {
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.handleReadReceiptEvent('ch1', 'u1', 'a', 1);
        result.current.handleReadReceiptEvent('ch1', 'u2', 'b', 2);
        result.current.handleReadReceiptEvent('ch2', 'u3', 'c', 3);
      });
      expect(result.current.readReceipts.get('ch1')).toHaveLength(2);
      expect(result.current.readReceipts.get('ch2')).toHaveLength(1);
    });
  });

  // ── sendReadReceipt ────────────────────────────────────────────────────────

  describe('sendReadReceipt', () => {
    it('calls api.markChannelRead with correct arguments', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.sendReadReceipt('ch1', 'msg1', 'my-token');
      });
      expect(api.markChannelRead).toHaveBeenCalledWith('ch1', 'msg1', 'my-token');
      expect(api.markChannelRead).toHaveBeenCalledTimes(1);
    });

    it('deduplicates consecutive calls for the same channel+message', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.sendReadReceipt('ch1', 'msg1', 'tok');
        result.current.sendReadReceipt('ch1', 'msg1', 'tok');
        result.current.sendReadReceipt('ch1', 'msg1', 'tok');
      });
      expect(api.markChannelRead).toHaveBeenCalledTimes(1);
    });

    it('sends again for a new message in the same channel', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.sendReadReceipt('ch1', 'msg1', 'tok');
      });
      act(() => {
        result.current.sendReadReceipt('ch1', 'msg2', 'tok');
      });
      expect(api.markChannelRead).toHaveBeenCalledTimes(2);
    });

    it('sends independently per channel', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.sendReadReceipt('ch1', 'msg1', 'tok');
        result.current.sendReadReceipt('ch2', 'msg1', 'tok');
      });
      expect(api.markChannelRead).toHaveBeenCalledTimes(2);
    });

    it('skips call when token is undefined', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.sendReadReceipt('ch1', 'msg1', undefined);
      });
      expect(api.markChannelRead).not.toHaveBeenCalled();
    });

    it('skips call when token is empty string', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.sendReadReceipt('ch1', 'msg1', '');
      });
      expect(api.markChannelRead).not.toHaveBeenCalled();
    });

    it('skips call when messageId is empty string', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.sendReadReceipt('ch1', '', 'tok');
      });
      expect(api.markChannelRead).not.toHaveBeenCalled();
    });

    it('skips call when channelId is empty string', async () => {
      const { api } = await import('../api');
      const { result } = renderHook(() => useReadReceipts());
      act(() => {
        result.current.sendReadReceipt('', 'msg1', 'tok');
      });
      expect(api.markChannelRead).not.toHaveBeenCalled();
    });
  });
});
