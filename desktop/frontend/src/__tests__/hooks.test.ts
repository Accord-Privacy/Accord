/**
 * Hook unit tests for Accord frontend
 * Tests: useVoice, usePresence, useReadReceipts, useTyping, useBlocking, useBookmarks
 */
import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ─── useVoice ────────────────────────────────────────────────────────────────

import { useVoice } from '../hooks/useVoice';

describe('useVoice', () => {
  it('initializes with null/default state', () => {
    const { result } = renderHook(() => useVoice());
    expect(result.current.voiceChannelId).toBeNull();
    expect(result.current.voiceChannelName).toBe('');
    expect(result.current.voiceConnectedAt).toBeNull();
    expect(result.current.voiceMuted).toBe(false);
    expect(result.current.voiceDeafened).toBe(false);
    expect(result.current.voiceChannelUsers).toEqual([]);
  });

  it('sets voice channel id and name', () => {
    const { result } = renderHook(() => useVoice());
    act(() => {
      result.current.setVoiceChannelId('ch-1');
      result.current.setVoiceChannelName('General Voice');
    });
    expect(result.current.voiceChannelId).toBe('ch-1');
    expect(result.current.voiceChannelName).toBe('General Voice');
  });

  it('tracks connection time', () => {
    const { result } = renderHook(() => useVoice());
    const now = Date.now();
    act(() => result.current.setVoiceConnectedAt(now));
    expect(result.current.voiceConnectedAt).toBe(now);
  });

  it('toggles mute and deafen independently', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceMuted(true));
    expect(result.current.voiceMuted).toBe(true);
    expect(result.current.voiceDeafened).toBe(false);

    act(() => result.current.setVoiceDeafened(true));
    expect(result.current.voiceMuted).toBe(true);
    expect(result.current.voiceDeafened).toBe(true);
  });

  it('manages voice channel user list', () => {
    const { result } = renderHook(() => useVoice());
    const users = [
      { userId: 'u1', displayName: 'Alice', isSpeaking: true },
      { userId: 'u2', displayName: 'Bob', isSpeaking: false, isMuted: true },
    ];
    act(() => result.current.setVoiceChannelUsers(users));
    expect(result.current.voiceChannelUsers).toHaveLength(2);
    expect(result.current.voiceChannelUsers[0].isSpeaking).toBe(true);
    expect(result.current.voiceChannelUsers[1].isMuted).toBe(true);
  });

  it('clears state on disconnect', () => {
    const { result } = renderHook(() => useVoice());
    act(() => {
      result.current.setVoiceChannelId('ch-1');
      result.current.setVoiceChannelName('Voice');
      result.current.setVoiceConnectedAt(Date.now());
      result.current.setVoiceChannelUsers([{ userId: 'u1', displayName: 'A', isSpeaking: false }]);
    });
    // Simulate disconnect
    act(() => {
      result.current.setVoiceChannelId(null);
      result.current.setVoiceChannelName('');
      result.current.setVoiceConnectedAt(null);
      result.current.setVoiceChannelUsers([]);
    });
    expect(result.current.voiceChannelId).toBeNull();
    expect(result.current.voiceChannelUsers).toEqual([]);
  });
});

// ─── usePresence ─────────────────────────────────────────────────────────────

import { usePresence } from '../hooks/usePresence';
import { PresenceStatus } from '../types';

describe('usePresence', () => {
  const makeMembers = (overrides: Partial<{ user_id: string; status: PresenceStatus; profile: { status: PresenceStatus; display_name: string } }>[] = []) =>
    overrides.map(o => {
      const uid = o.user_id ?? 'u-default';
      return {
        node_id: 'n1',
        user_id: uid,
        public_key_hash: 'hash',
        role: 'member' as const,
        joined_at: 0,
        status: o.status,
        profile: o.profile ? { ...o.profile, user_id: uid, updated_at: 0 } : undefined,
        user: { id: uid, public_key_hash: `hash-${uid}`, public_key: `pk-${uid}`, created_at: 0, display_name: 'Test' },
      };
    });

  it('returns offline for unknown user', () => {
    const { result } = renderHook(() => usePresence([]));
    expect(result.current.getPresenceStatus('nonexistent')).toBe('offline');
  });

  it('returns explicit presence from presenceMap', () => {
    const { result } = renderHook(() => usePresence([]));
    act(() => {
      result.current.setPresenceMap(new Map([['u1', PresenceStatus.DND]]));
    });
    expect(result.current.getPresenceStatus('u1')).toBe('dnd');
  });

  it('infers online from recent message time (<5min)', () => {
    const { result } = renderHook(() => usePresence([]));
    act(() => result.current.recordMessageTime('u2'));
    expect(result.current.getPresenceStatus('u2')).toBe('online');
  });

  it('does not infer online from old message time (>5min)', () => {
    const { result } = renderHook(() => usePresence([]));
    act(() => {
      result.current.setLastMessageTimes(new Map([['u3', Date.now() - 6 * 60 * 1000]]));
    });
    expect(result.current.getPresenceStatus('u3')).toBe('offline');
  });

  it('falls back to member status', () => {
    const members = makeMembers([{ user_id: 'u4', status: PresenceStatus.Idle }]);
    const { result } = renderHook(() => usePresence(members));
    expect(result.current.getPresenceStatus('u4')).toBe('idle');
  });

  it('falls back to member profile status', () => {
    const members = makeMembers([{
      user_id: 'u5',
      profile: { status: PresenceStatus.Online, display_name: 'U5' },
    }]);
    const { result } = renderHook(() => usePresence(members));
    expect(result.current.getPresenceStatus('u5')).toBe('online');
  });

  it('presenceMap takes priority over message time', () => {
    const { result } = renderHook(() => usePresence([]));
    act(() => {
      result.current.setPresenceMap(new Map([['u6', PresenceStatus.DND]]));
      result.current.recordMessageTime('u6');
    });
    expect(result.current.getPresenceStatus('u6')).toBe('dnd');
  });

  it('recordMessageTime updates for user', () => {
    const { result } = renderHook(() => usePresence([]));
    act(() => result.current.recordMessageTime('u7'));
    expect(result.current.lastMessageTimes.has('u7')).toBe(true);
    const t = result.current.lastMessageTimes.get('u7')!;
    expect(Date.now() - t).toBeLessThan(1000);
  });
});

// ─── useReadReceipts ─────────────────────────────────────────────────────────

import { useReadReceipts } from '../hooks/useReadReceipts';

vi.mock('../api', () => ({
  api: {
    markChannelRead: vi.fn().mockResolvedValue({ status: 'ok' }),
    blockUser: vi.fn().mockResolvedValue({ status: 'ok' }),
    unblockUser: vi.fn().mockResolvedValue({ status: 'ok' }),
    getBlockedUsers: vi.fn().mockResolvedValue({ blocked_users: [] }),
  },
}));

describe('useReadReceipts', () => {
  beforeEach(() => vi.clearAllMocks());

  it('initializes with empty receipts map', () => {
    const { result } = renderHook(() => useReadReceipts());
    expect(result.current.readReceipts.size).toBe(0);
  });

  it('handles read receipt events', () => {
    const { result } = renderHook(() => useReadReceipts());
    act(() => {
      result.current.handleReadReceiptEvent('ch1', 'u1', 'msg1', 1000);
    });
    const receipts = result.current.readReceipts.get('ch1');
    expect(receipts).toHaveLength(1);
    expect(receipts![0]).toEqual({ user_id: 'u1', message_id: 'msg1', timestamp: 1000 });
  });

  it('replaces receipt for same user in same channel', () => {
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
  });

  it('tracks receipts per channel independently', () => {
    const { result } = renderHook(() => useReadReceipts());
    act(() => {
      result.current.handleReadReceiptEvent('ch1', 'u1', 'msg1', 1000);
      result.current.handleReadReceiptEvent('ch2', 'u1', 'msg2', 2000);
    });
    expect(result.current.readReceipts.get('ch1')).toHaveLength(1);
    expect(result.current.readReceipts.get('ch2')).toHaveLength(1);
  });

  it('sends read receipt via api', async () => {
    const { api } = await import('../api');
    const { result } = renderHook(() => useReadReceipts());
    act(() => {
      result.current.sendReadReceipt('ch1', 'msg1', 'tok');
    });
    expect(api.markChannelRead).toHaveBeenCalledWith('ch1', 'msg1', 'tok');
  });

  it('deduplicates consecutive sendReadReceipt for same channel+message', async () => {
    const { api } = await import('../api');
    const { result } = renderHook(() => useReadReceipts());
    act(() => {
      result.current.sendReadReceipt('ch1', 'msg1', 'tok');
      result.current.sendReadReceipt('ch1', 'msg1', 'tok');
    });
    expect(api.markChannelRead).toHaveBeenCalledTimes(1);
  });

  it('does not send if token is missing', async () => {
    const { api } = await import('../api');
    const { result } = renderHook(() => useReadReceipts());
    act(() => {
      result.current.sendReadReceipt('ch1', 'msg1', undefined);
    });
    expect(api.markChannelRead).not.toHaveBeenCalled();
  });

  it('does not send if messageId is empty', async () => {
    const { api } = await import('../api');
    const { result } = renderHook(() => useReadReceipts());
    act(() => {
      result.current.sendReadReceipt('ch1', '', 'tok');
    });
    expect(api.markChannelRead).not.toHaveBeenCalled();
  });
});

// ─── useTyping ───────────────────────────────────────────────────────────────

import { useTyping } from '../hooks/useTyping';

describe('useTyping', () => {
  let mockWs: { sendTypingStart: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    mockWs = { sendTypingStart: vi.fn() };
    vi.useFakeTimers();
    // Default: current user is 'self'
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

  const makeUser = (id: string, name: string) => ({
    id, public_key_hash: `hash-${id}`, public_key: `pk-${id}`, created_at: 0, display_name: name,
  });

  const members = [
    {
      node_id: 'n1', user_id: 'u1', public_key_hash: 'h', role: 'member' as const, joined_at: 0,
      user: makeUser('u1', 'Alice'),
    },
    {
      node_id: 'n1', user_id: 'u2', public_key_hash: 'h', role: 'member' as const, joined_at: 0,
      user: makeUser('u2', 'Bob'),
    },
    {
      node_id: 'n1', user_id: 'u3', public_key_hash: 'h', role: 'member' as const, joined_at: 0,
      user: makeUser('u3', 'Carol'),
    },
  ];

  it('sends typing indicator via ws', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => result.current.sendTypingIndicator('ch1'));
    expect(mockWs.sendTypingStart).toHaveBeenCalledWith('ch1');
  });

  it('throttles typing to 3s intervals', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => result.current.sendTypingIndicator('ch1'));
    act(() => result.current.sendTypingIndicator('ch1')); // within 3s
    expect(mockWs.sendTypingStart).toHaveBeenCalledTimes(1);

    act(() => vi.advanceTimersByTime(3100));
    act(() => result.current.sendTypingIndicator('ch1'));
    expect(mockWs.sendTypingStart).toHaveBeenCalledTimes(2);
  });

  it('does not send if ws is null', () => {
    const { result } = renderHook(() => useTyping(null, members));
    act(() => result.current.sendTypingIndicator('ch1'));
    // No crash, no call
  });

  it('handles typing start and formats single user', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice'));
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');
  });

  it('formats two typing users', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'u2', 'Bob');
    });
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice and Bob are typing');
  });

  it('formats three typing users', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'u2', 'Bob');
      result.current.handleTypingStart('ch1', 'u3', 'Carol');
    });
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice, Bob, and Carol are typing');
  });

  it('formats 4+ as "Several people are typing"', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'u2', 'Bob');
      result.current.handleTypingStart('ch1', 'u3', 'Carol');
      result.current.handleTypingStart('ch1', 'u4', 'Dave');
    });
    expect(result.current.formatTypingUsers('ch1')).toBe('Several people are typing');
  });

  it('excludes self from typing display', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => result.current.handleTypingStart('ch1', 'self', 'Me'));
    expect(result.current.formatTypingUsers('ch1')).toBe('');
  });

  it('auto-removes typing user after 5s timeout', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice'));
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');

    act(() => vi.advanceTimersByTime(5100));
    expect(result.current.formatTypingUsers('ch1')).toBe('');
  });

  it('resets timeout on repeated typing start from same user', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice'));
    act(() => vi.advanceTimersByTime(3000));
    act(() => result.current.handleTypingStart('ch1', 'u1', 'Alice')); // resets timer
    act(() => vi.advanceTimersByTime(3000)); // 3s after reset, not 5s
    expect(result.current.formatTypingUsers('ch1')).toBe('Alice is typing');
    act(() => vi.advanceTimersByTime(2100)); // now past 5s from reset
    expect(result.current.formatTypingUsers('ch1')).toBe('');
  });

  it('returns empty string for channel with no typing', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    expect(result.current.formatTypingUsers('ch-none')).toBe('');
  });

  it('getTypingUsersForChannel returns resolved names excluding self', () => {
    const { result } = renderHook(() => useTyping(mockWs as any, members));
    act(() => {
      result.current.handleTypingStart('ch1', 'u1', 'Alice');
      result.current.handleTypingStart('ch1', 'self', 'Me');
    });
    const users = result.current.getTypingUsersForChannel('ch1');
    expect(users).toHaveLength(1);
    expect(users[0].displayName).toBe('Alice');
  });
});

// ─── useBlocking ─────────────────────────────────────────────────────────────

import { useBlocking } from '../hooks/useBlocking';

describe('useBlocking', () => {
  beforeEach(() => vi.clearAllMocks());

  it('initializes with empty blocked set', () => {
    const { result } = renderHook(() => useBlocking('tok', false));
    expect(result.current.blockedUsers.size).toBe(0);
  });

  it('blocks a user and updates set', async () => {
    const { result } = renderHook(() => useBlocking('tok', true));
    await act(async () => {
      await result.current.handleBlockUser('u1');
    });
    expect(result.current.blockedUsers.has('u1')).toBe(true);
  });

  it('unblocks a user and removes from set', async () => {
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

  it('does nothing when token is undefined', async () => {
    const { api } = await import('../api');
    const { result } = renderHook(() => useBlocking(undefined, false));
    await act(async () => {
      await result.current.handleBlockUser('u1');
    });
    expect(api.blockUser).not.toHaveBeenCalled();
    expect(result.current.blockedUsers.size).toBe(0);
  });

  it('fetches blocked users on auth', async () => {
    const { api } = await import('../api');
    (api.getBlockedUsers as any).mockResolvedValueOnce({
      blocked_users: [{ user_id: 'u10', created_at: 1000 }],
    });
    const { result } = renderHook(() => useBlocking('tok', true));
    // Wait for the useEffect
    await act(async () => {
      await new Promise(r => setTimeout(r, 0));
    });
    expect(result.current.blockedUsers.has('u10')).toBe(true);
  });

  it('unblock does nothing when token is undefined', async () => {
    const { api } = await import('../api');
    const { result } = renderHook(() => useBlocking(undefined, false));
    await act(async () => {
      await result.current.handleUnblockUser('u1');
    });
    expect(api.unblockUser).not.toHaveBeenCalled();
    expect(result.current.blockedUsers.size).toBe(0);
  });

  it('propagates block API error', async () => {
    const { api } = await import('../api');
    (api.blockUser as any).mockRejectedValueOnce(new Error('network'));
    const { result } = renderHook(() => useBlocking('tok', true));
    await expect(
      act(async () => {
        await result.current.handleBlockUser('u1');
      })
    ).rejects.toThrow('network');
  });
});

// ─── useBookmarks ────────────────────────────────────────────────────────────

import { useBookmarks, type SavedMessage } from '../hooks/useBookmarks';

describe('useBookmarks', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  const makeSavedMsg = (id: string): SavedMessage => ({
    id,
    content: `Message ${id}`,
    channelId: 'ch1',
    channelName: 'general',
    author: 'alice',
    timestamp: Date.now(),
    savedAt: Date.now(),
  });

  it('initializes empty when no localStorage', () => {
    const { result } = renderHook(() => useBookmarks());
    expect(result.current.bookmarks).toEqual([]);
  });

  it('adds a bookmark', () => {
    const { result } = renderHook(() => useBookmarks());
    const msg = makeSavedMsg('m1');
    act(() => result.current.addBookmark(msg));
    expect(result.current.bookmarks).toHaveLength(1);
    expect(result.current.bookmarks[0].id).toBe('m1');
  });

  it('prevents duplicate bookmarks', () => {
    const { result } = renderHook(() => useBookmarks());
    const msg = makeSavedMsg('m1');
    act(() => {
      result.current.addBookmark(msg);
      result.current.addBookmark(msg);
    });
    expect(result.current.bookmarks).toHaveLength(1);
  });

  it('removes a bookmark', () => {
    const { result } = renderHook(() => useBookmarks());
    act(() => result.current.addBookmark(makeSavedMsg('m1')));
    act(() => result.current.removeBookmark('m1'));
    expect(result.current.bookmarks).toEqual([]);
  });

  it('isBookmarked returns correct boolean', () => {
    const { result } = renderHook(() => useBookmarks());
    act(() => result.current.addBookmark(makeSavedMsg('m1')));
    expect(result.current.isBookmarked('m1')).toBe(true);
    expect(result.current.isBookmarked('m2')).toBe(false);
  });

  it('prepends new bookmarks (most recent first)', () => {
    const { result } = renderHook(() => useBookmarks());
    act(() => result.current.addBookmark(makeSavedMsg('m1')));
    act(() => result.current.addBookmark(makeSavedMsg('m2')));
    expect(result.current.bookmarks[0].id).toBe('m2');
    expect(result.current.bookmarks[1].id).toBe('m1');
  });

  it('persists to localStorage', () => {
    const { result } = renderHook(() => useBookmarks());
    act(() => result.current.addBookmark(makeSavedMsg('m1')));
    const stored = JSON.parse(localStorage.getItem('accord_saved_messages')!);
    expect(stored).toHaveLength(1);
    expect(stored[0].id).toBe('m1');
  });

  it('loads from localStorage on init', () => {
    localStorage.setItem('accord_saved_messages', JSON.stringify([makeSavedMsg('m5')]));
    const { result } = renderHook(() => useBookmarks());
    expect(result.current.bookmarks).toHaveLength(1);
    expect(result.current.bookmarks[0].id).toBe('m5');
  });

  it('handles corrupted localStorage gracefully', () => {
    localStorage.setItem('accord_saved_messages', '{broken');
    const { result } = renderHook(() => useBookmarks());
    expect(result.current.bookmarks).toEqual([]);
  });
});

// ─── useMentionAutocomplete ─────────────────────────────────────────────────

import { useMentionAutocomplete, type AutocompleteItem } from '../hooks/useMentionAutocomplete';

describe('useMentionAutocomplete', () => {
  const users: AutocompleteItem[] = [
    { type: 'user', id: 'u1', label: 'Alice', insertText: '@Alice' },
    { type: 'user', id: 'u2', label: 'Bob', insertText: '@Bob' },
    { type: 'user', id: 'u3', label: 'John', insertText: '@John' },
    { type: 'user', id: 'u4', label: 'Joanna', insertText: '@Joanna' },
  ];

  const channels: AutocompleteItem[] = [
    { type: 'channel', id: 'c1', label: 'general', insertText: '#general' },
    { type: 'channel', id: 'c2', label: 'random', insertText: '#random' },
  ];

  it('initial state is inactive', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    expect(result.current.mentionState.active).toBe(false);
    expect(result.current.mentionState.items).toEqual([]);
  });

  it('typing @ activates with user list', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    act(() => result.current.handleMentionInput('@', 1));
    expect(result.current.mentionState.active).toBe(true);
    expect(result.current.mentionState.triggerChar).toBe('@');
    expect(result.current.mentionState.items).toHaveLength(4);
  });

  it('typing # activates with channel list', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    act(() => result.current.handleMentionInput('#', 1));
    expect(result.current.mentionState.active).toBe(true);
    expect(result.current.mentionState.triggerChar).toBe('#');
    expect(result.current.mentionState.items).toHaveLength(2);
  });

  it('typing @jo filters to matching users', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    act(() => result.current.handleMentionInput('@jo', 3));
    expect(result.current.mentionState.active).toBe(true);
    const labels = result.current.mentionState.items.map(i => i.label);
    expect(labels).toContain('John');
    expect(labels).toContain('Joanna');
    expect(labels).not.toContain('Alice');
    expect(labels).not.toContain('Bob');
  });

  it('space after trigger dismisses', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    act(() => result.current.handleMentionInput('@', 1));
    expect(result.current.mentionState.active).toBe(true);
    act(() => result.current.handleMentionInput('@ ', 2));
    expect(result.current.mentionState.active).toBe(false);
  });

  it('ArrowUp/ArrowDown cycles selectedIndex', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    act(() => result.current.handleMentionInput('@', 1));
    expect(result.current.mentionState.selectedIndex).toBe(0);

    const makeKeyEvent = (key: string) => ({
      key,
      preventDefault: vi.fn(),
    } as unknown as React.KeyboardEvent);

    const setMsg = vi.fn();
    const inputRef = { current: null };

    act(() => {
      result.current.handleMentionKeyDown(makeKeyEvent('ArrowDown'), '@', setMsg, inputRef as any);
    });
    expect(result.current.mentionState.selectedIndex).toBe(1);

    act(() => {
      result.current.handleMentionKeyDown(makeKeyEvent('ArrowUp'), '@', setMsg, inputRef as any);
    });
    expect(result.current.mentionState.selectedIndex).toBe(0);

    // ArrowUp from 0 wraps to last
    act(() => {
      result.current.handleMentionKeyDown(makeKeyEvent('ArrowUp'), '@', setMsg, inputRef as any);
    });
    expect(result.current.mentionState.selectedIndex).toBe(3);
  });

  it('Enter selects item and inserts text', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    act(() => result.current.handleMentionInput('@', 1));

    const setMsg = vi.fn();
    const inputRef = { current: null };
    const makeKeyEvent = (key: string) => ({
      key,
      preventDefault: vi.fn(),
    } as unknown as React.KeyboardEvent);

    act(() => {
      result.current.handleMentionKeyDown(makeKeyEvent('Enter'), '@', setMsg, inputRef as any);
    });
    expect(setMsg).toHaveBeenCalledWith('@Alice ');
    expect(result.current.mentionState.active).toBe(false);
  });

  it('Tab selects item and inserts text', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    act(() => result.current.handleMentionInput('@', 1));

    const setMsg = vi.fn();
    const inputRef = { current: null };
    const makeKeyEvent = (key: string) => ({
      key,
      preventDefault: vi.fn(),
    } as unknown as React.KeyboardEvent);

    act(() => {
      result.current.handleMentionKeyDown(makeKeyEvent('Tab'), '@', setMsg, inputRef as any);
    });
    expect(setMsg).toHaveBeenCalledWith('@Alice ');
    expect(result.current.mentionState.active).toBe(false);
  });

  it('Escape dismisses', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    act(() => result.current.handleMentionInput('@', 1));
    expect(result.current.mentionState.active).toBe(true);

    const makeKeyEvent = (key: string) => ({
      key,
      preventDefault: vi.fn(),
    } as unknown as React.KeyboardEvent);

    act(() => {
      result.current.handleMentionKeyDown(makeKeyEvent('Escape'), '@', vi.fn(), { current: null } as any);
    });
    expect(result.current.mentionState.active).toBe(false);
  });

  it('fuzzyMatch works for substring and character-order matching', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    // "ace" should fuzzy-match "Alice" (a...l...i...c...e — a,c,e in order)
    act(() => result.current.handleMentionInput('@ace', 4));
    const labels = result.current.mentionState.items.map(i => i.label);
    expect(labels).toContain('Alice');
    // substring match: "ob" matches "Bob"
    act(() => result.current.handleMentionInput('@ob', 3));
    const labels2 = result.current.mentionState.items.map(i => i.label);
    expect(labels2).toContain('Bob');
  });

  it('no trigger char keeps state inactive', () => {
    const { result } = renderHook(() => useMentionAutocomplete(users, channels));
    act(() => result.current.handleMentionInput('hello world', 11));
    expect(result.current.mentionState.active).toBe(false);
  });
});

// ─── useSlashCommands ───────────────────────────────────────────────────────

import { useSlashCommands, SLASH_COMMANDS } from '../hooks/useSlashCommands';

describe('useSlashCommands', () => {
  const makeCallbacks = () => ({
    onNick: vi.fn(),
    onStatus: vi.fn(),
    onClear: vi.fn(),
  });

  it('initial state is inactive', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    expect(result.current.slashState.active).toBe(false);
    expect(result.current.slashState.items).toEqual([]);
  });

  it('typing / activates with all commands', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/'));
    expect(result.current.slashState.active).toBe(true);
    expect(result.current.slashState.items).toHaveLength(SLASH_COMMANDS.length);
  });

  it('typing /sh filters to shrug', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/sh'));
    expect(result.current.slashState.active).toBe(true);
    const names = result.current.slashState.items.map(i => i.name);
    expect(names).toContain('shrug');
    expect(names).not.toContain('clear');
  });

  it('space dismisses autocomplete (user typing argument)', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/nick'));
    expect(result.current.slashState.active).toBe(true);
    act(() => result.current.handleSlashInput('/nick newname'));
    expect(result.current.slashState.active).toBe(false);
  });

  it('processCommand returns true for valid commands', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    const handled = result.current.processSlashCommand('/clear');
    expect(handled).toBe(true);
  });

  it('processCommand calls onNick with argument', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('/nick CoolName');
    expect(cbs.onNick).toHaveBeenCalledWith('CoolName');
  });

  it('processCommand calls onClear for /clear', () => {
    const cbs = makeCallbacks();
    const { result } = renderHook(() => useSlashCommands(cbs));
    result.current.processSlashCommand('/clear');
    expect(cbs.onClear).toHaveBeenCalled();
  });

  it('processCommand returns false for unknown commands', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    const handled = result.current.processSlashCommand('/unknowncmd foo');
    expect(handled).toBe(false);
  });

  it('selectItem with appendText (shrug) sets message to emoticon', () => {
    const { result } = renderHook(() => useSlashCommands(makeCallbacks()));
    act(() => result.current.handleSlashInput('/shrug'));
    const shrugIdx = result.current.slashState.items.findIndex(i => i.name === 'shrug');
    expect(shrugIdx).toBeGreaterThanOrEqual(0);

    const setMsg = vi.fn();
    const inputRef = { current: null };
    act(() => {
      result.current.selectSlashItem(shrugIdx, '/shrug', setMsg, inputRef as any);
    });
    expect(setMsg).toHaveBeenCalledWith('¯\\_(ツ)_/¯');
    expect(result.current.slashState.active).toBe(false);
  });
});
