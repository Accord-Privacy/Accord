/**
 * useVoice hook unit tests
 *
 * Note: useVoice is a state-management hook — WebRTC, ICE candidates, and
 * peer-connection logic live in the parent component/context that *drives* this
 * hook. These tests verify the full surface of the hook's API contract:
 * initial state, join/leave lifecycle, mute/deafen toggling, VAD speaking
 * indicators, and user-list management.
 */

import { renderHook, act } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { useVoice, VoiceChannelUser } from '../hooks/useVoice';

// ─── helpers ─────────────────────────────────────────────────────────────────

const makeUser = (
  userId: string,
  overrides: Partial<VoiceChannelUser> = {}
): VoiceChannelUser => ({
  userId,
  displayName: `User-${userId}`,
  isSpeaking: false,
  ...overrides,
});

// ─── Initial state ────────────────────────────────────────────────────────────

describe('useVoice — initial state', () => {
  it('voiceChannelId is null', () => {
    const { result } = renderHook(() => useVoice());
    expect(result.current.voiceChannelId).toBeNull();
  });

  it('voiceChannelName is empty string', () => {
    const { result } = renderHook(() => useVoice());
    expect(result.current.voiceChannelName).toBe('');
  });

  it('voiceConnectedAt is null (not connected)', () => {
    const { result } = renderHook(() => useVoice());
    expect(result.current.voiceConnectedAt).toBeNull();
  });

  it('voiceMuted is false by default', () => {
    const { result } = renderHook(() => useVoice());
    expect(result.current.voiceMuted).toBe(false);
  });

  it('voiceDeafened is false by default', () => {
    const { result } = renderHook(() => useVoice());
    expect(result.current.voiceDeafened).toBe(false);
  });

  it('voiceChannelUsers is an empty array', () => {
    const { result } = renderHook(() => useVoice());
    expect(result.current.voiceChannelUsers).toEqual([]);
  });

  it('exposes all required setter functions', () => {
    const { result } = renderHook(() => useVoice());
    expect(typeof result.current.setVoiceChannelId).toBe('function');
    expect(typeof result.current.setVoiceChannelName).toBe('function');
    expect(typeof result.current.setVoiceConnectedAt).toBe('function');
    expect(typeof result.current.setVoiceMuted).toBe('function');
    expect(typeof result.current.setVoiceDeafened).toBe('function');
    expect(typeof result.current.setVoiceChannelUsers).toBe('function');
  });
});

// ─── Join / leave channel lifecycle ──────────────────────────────────────────

describe('useVoice — join channel', () => {
  it('records channelId on join', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelId('vc-general'));
    expect(result.current.voiceChannelId).toBe('vc-general');
  });

  it('records channelName on join', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelName('General Voice'));
    expect(result.current.voiceChannelName).toBe('General Voice');
  });

  it('records connectedAt timestamp on join', () => {
    const { result } = renderHook(() => useVoice());
    const before = Date.now();
    act(() => result.current.setVoiceConnectedAt(before));
    expect(result.current.voiceConnectedAt).toBe(before);
  });

  it('voiceConnectedAt > 0 indicates a live connection', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceConnectedAt(Date.now()));
    expect(result.current.voiceConnectedAt).toBeGreaterThan(0);
  });

  it('channelId and name can be set together atomically', () => {
    const { result } = renderHook(() => useVoice());
    act(() => {
      result.current.setVoiceChannelId('vc-99');
      result.current.setVoiceChannelName('Lobby');
    });
    expect(result.current.voiceChannelId).toBe('vc-99');
    expect(result.current.voiceChannelName).toBe('Lobby');
  });

  it('switching channels updates channelId correctly', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelId('vc-1'));
    act(() => result.current.setVoiceChannelId('vc-2'));
    expect(result.current.voiceChannelId).toBe('vc-2');
  });
});

describe('useVoice — leave channel / peer cleanup', () => {
  it('resets channelId to null on disconnect', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelId('vc-1'));
    act(() => result.current.setVoiceChannelId(null));
    expect(result.current.voiceChannelId).toBeNull();
  });

  it('clears channelName on disconnect', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelName('Gaming'));
    act(() => result.current.setVoiceChannelName(''));
    expect(result.current.voiceChannelName).toBe('');
  });

  it('clears connectedAt on disconnect', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceConnectedAt(Date.now()));
    act(() => result.current.setVoiceConnectedAt(null));
    expect(result.current.voiceConnectedAt).toBeNull();
  });

  it('clears peer user list on disconnect', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelUsers([makeUser('u1'), makeUser('u2')]));
    act(() => result.current.setVoiceChannelUsers([]));
    expect(result.current.voiceChannelUsers).toEqual([]);
  });

  it('full disconnect clears all state fields', () => {
    const { result } = renderHook(() => useVoice());
    // Simulate join
    act(() => {
      result.current.setVoiceChannelId('vc-1');
      result.current.setVoiceChannelName('War Room');
      result.current.setVoiceConnectedAt(Date.now());
      result.current.setVoiceChannelUsers([makeUser('u1'), makeUser('u2')]);
    });
    // Simulate disconnect / peer cleanup
    act(() => {
      result.current.setVoiceChannelId(null);
      result.current.setVoiceChannelName('');
      result.current.setVoiceConnectedAt(null);
      result.current.setVoiceChannelUsers([]);
    });
    expect(result.current.voiceChannelId).toBeNull();
    expect(result.current.voiceChannelName).toBe('');
    expect(result.current.voiceConnectedAt).toBeNull();
    expect(result.current.voiceChannelUsers).toEqual([]);
  });
});

// ─── Audio mute / unmute ──────────────────────────────────────────────────────

describe('useVoice — mute / unmute', () => {
  it('mutes the microphone', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceMuted(true));
    expect(result.current.voiceMuted).toBe(true);
  });

  it('unmutes the microphone', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceMuted(true));
    act(() => result.current.setVoiceMuted(false));
    expect(result.current.voiceMuted).toBe(false);
  });

  it('mute toggle does not affect deafen state', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceMuted(true));
    expect(result.current.voiceDeafened).toBe(false);
  });

  it('deafening does not automatically mute', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceDeafened(true));
    expect(result.current.voiceMuted).toBe(false);
  });

  it('mute and deafen are independently settable', () => {
    const { result } = renderHook(() => useVoice());
    act(() => {
      result.current.setVoiceMuted(true);
      result.current.setVoiceDeafened(true);
    });
    expect(result.current.voiceMuted).toBe(true);
    expect(result.current.voiceDeafened).toBe(true);
  });

  it('unmuting does not affect deafen', () => {
    const { result } = renderHook(() => useVoice());
    act(() => {
      result.current.setVoiceMuted(true);
      result.current.setVoiceDeafened(true);
    });
    act(() => result.current.setVoiceMuted(false));
    expect(result.current.voiceMuted).toBe(false);
    expect(result.current.voiceDeafened).toBe(true);
  });

  it('repeated mute calls are idempotent', () => {
    const { result } = renderHook(() => useVoice());
    act(() => {
      result.current.setVoiceMuted(true);
      result.current.setVoiceMuted(true);
    });
    expect(result.current.voiceMuted).toBe(true);
  });
});

// ─── VAD — voice activity detection (speaking indicators) ────────────────────

describe('useVoice — VAD / speaking indicators', () => {
  it('adds a speaking user', () => {
    const { result } = renderHook(() => useVoice());
    act(() =>
      result.current.setVoiceChannelUsers([makeUser('u1', { isSpeaking: true })])
    );
    expect(result.current.voiceChannelUsers[0].isSpeaking).toBe(true);
  });

  it('marks user as not speaking', () => {
    const { result } = renderHook(() => useVoice());
    act(() =>
      result.current.setVoiceChannelUsers([makeUser('u1', { isSpeaking: true })])
    );
    act(() =>
      result.current.setVoiceChannelUsers([makeUser('u1', { isSpeaking: false })])
    );
    expect(result.current.voiceChannelUsers[0].isSpeaking).toBe(false);
  });

  it('tracks multiple users with different speaking states', () => {
    const { result } = renderHook(() => useVoice());
    act(() =>
      result.current.setVoiceChannelUsers([
        makeUser('u1', { isSpeaking: true }),
        makeUser('u2', { isSpeaking: false }),
        makeUser('u3', { isSpeaking: true }),
      ])
    );
    const users = result.current.voiceChannelUsers;
    expect(users.filter(u => u.isSpeaking)).toHaveLength(2);
    expect(users.filter(u => !u.isSpeaking)).toHaveLength(1);
  });

  it('updates only one user speaking without affecting others', () => {
    const { result } = renderHook(() => useVoice());
    const initial = [makeUser('u1', { isSpeaking: false }), makeUser('u2', { isSpeaking: true })];
    act(() => result.current.setVoiceChannelUsers(initial));

    // u1 starts speaking; u2 unchanged
    act(() =>
      result.current.setVoiceChannelUsers(prev =>
        prev.map(u => (u.userId === 'u1' ? { ...u, isSpeaking: true } : u))
      )
    );
    expect(result.current.voiceChannelUsers.find(u => u.userId === 'u1')!.isSpeaking).toBe(true);
    expect(result.current.voiceChannelUsers.find(u => u.userId === 'u2')!.isSpeaking).toBe(true);
  });

  it('no users are speaking initially', () => {
    const { result } = renderHook(() => useVoice());
    expect(result.current.voiceChannelUsers.filter(u => u.isSpeaking)).toHaveLength(0);
  });
});

// ─── User list management (simulates peer join/leave events) ─────────────────

describe('useVoice — peer user list management', () => {
  it('adds first peer', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelUsers([makeUser('u1')]));
    expect(result.current.voiceChannelUsers).toHaveLength(1);
  });

  it('adds multiple peers', () => {
    const { result } = renderHook(() => useVoice());
    act(() =>
      result.current.setVoiceChannelUsers([makeUser('u1'), makeUser('u2'), makeUser('u3')])
    );
    expect(result.current.voiceChannelUsers).toHaveLength(3);
  });

  it('removes a peer when they leave', () => {
    const { result } = renderHook(() => useVoice());
    act(() =>
      result.current.setVoiceChannelUsers([makeUser('u1'), makeUser('u2')])
    );
    act(() =>
      result.current.setVoiceChannelUsers(prev => prev.filter(u => u.userId !== 'u1'))
    );
    expect(result.current.voiceChannelUsers).toHaveLength(1);
    expect(result.current.voiceChannelUsers[0].userId).toBe('u2');
  });

  it('preserves user displayName', () => {
    const { result } = renderHook(() => useVoice());
    act(() =>
      result.current.setVoiceChannelUsers([
        { userId: 'u1', displayName: 'Alice', isSpeaking: false },
      ])
    );
    expect(result.current.voiceChannelUsers[0].displayName).toBe('Alice');
  });

  it('tracks isMuted field per user', () => {
    const { result } = renderHook(() => useVoice());
    act(() =>
      result.current.setVoiceChannelUsers([
        makeUser('u1', { isMuted: true }),
        makeUser('u2', { isMuted: false }),
      ])
    );
    expect(result.current.voiceChannelUsers[0].isMuted).toBe(true);
    expect(result.current.voiceChannelUsers[1].isMuted).toBe(false);
  });

  it('isMuted is optional and defaults to undefined', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelUsers([makeUser('u1')]));
    expect(result.current.voiceChannelUsers[0].isMuted).toBeUndefined();
  });

  it('replaces entire user list atomically', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelUsers([makeUser('u1'), makeUser('u2')]));
    act(() => result.current.setVoiceChannelUsers([makeUser('u3')]));
    expect(result.current.voiceChannelUsers).toHaveLength(1);
    expect(result.current.voiceChannelUsers[0].userId).toBe('u3');
  });

  it('functional updater merges with previous state', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelUsers([makeUser('u1')]));
    act(() =>
      result.current.setVoiceChannelUsers(prev => [...prev, makeUser('u2')])
    );
    expect(result.current.voiceChannelUsers).toHaveLength(2);
  });
});

// ─── ICE failure / reconnect simulation ──────────────────────────────────────
// The hook stores state that the parent component uses to handle ICE failures.
// When ICE fails the parent signals disconnect by clearing channel state.

describe('useVoice — ICE failure state reset', () => {
  it('state is clean after simulated ICE failure / reconnect cycle', () => {
    const { result } = renderHook(() => useVoice());

    // Join
    act(() => {
      result.current.setVoiceChannelId('vc-1');
      result.current.setVoiceChannelName('Stage');
      result.current.setVoiceConnectedAt(Date.now());
      result.current.setVoiceChannelUsers([makeUser('u1'), makeUser('u2')]);
    });

    // ICE failure → parent clears state (mirrors disconnect)
    act(() => {
      result.current.setVoiceChannelId(null);
      result.current.setVoiceConnectedAt(null);
      result.current.setVoiceChannelUsers([]);
    });

    expect(result.current.voiceChannelId).toBeNull();
    expect(result.current.voiceConnectedAt).toBeNull();
    expect(result.current.voiceChannelUsers).toHaveLength(0);
  });

  it('reconnect restores channel state after ICE failure', () => {
    const { result } = renderHook(() => useVoice());

    // First connection
    act(() => {
      result.current.setVoiceChannelId('vc-1');
      result.current.setVoiceConnectedAt(1000);
    });

    // ICE failure clears
    act(() => {
      result.current.setVoiceChannelId(null);
      result.current.setVoiceConnectedAt(null);
    });

    // Reconnect
    const reconnectTime = 2000;
    act(() => {
      result.current.setVoiceChannelId('vc-1');
      result.current.setVoiceConnectedAt(reconnectTime);
    });

    expect(result.current.voiceChannelId).toBe('vc-1');
    expect(result.current.voiceConnectedAt).toBe(reconnectTime);
  });
});

// ─── P2P vs relay mode toggle ─────────────────────────────────────────────────
// useVoice doesn't own relay-mode state directly; it holds the user list and
// connection ID that switches with each mode change. These tests confirm state
// remains consistent across simulated mode switches.

describe('useVoice — P2P vs relay mode switching', () => {
  it('channel ID persists across mode switch', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceChannelId('vc-relay'));
    // Mode switch: parent replaces peers, channel stays
    act(() => result.current.setVoiceChannelUsers([makeUser('relay-peer-1')]));
    expect(result.current.voiceChannelId).toBe('vc-relay');
    expect(result.current.voiceChannelUsers[0].userId).toBe('relay-peer-1');
  });

  it('switching mode clears peer list then repopulates', () => {
    const { result } = renderHook(() => useVoice());
    act(() =>
      result.current.setVoiceChannelUsers([makeUser('p2p-peer-1'), makeUser('p2p-peer-2')])
    );
    // Simulate mode switch: clear peers, then add relay peers
    act(() => result.current.setVoiceChannelUsers([]));
    expect(result.current.voiceChannelUsers).toHaveLength(0);

    act(() => result.current.setVoiceChannelUsers([makeUser('relay-peer-1')]));
    expect(result.current.voiceChannelUsers).toHaveLength(1);
    expect(result.current.voiceChannelUsers[0].userId).toBe('relay-peer-1');
  });

  it('mute state is preserved across mode switch', () => {
    const { result } = renderHook(() => useVoice());
    act(() => result.current.setVoiceMuted(true));
    // Mode switch: peer list refreshes
    act(() => result.current.setVoiceChannelUsers([makeUser('u1')]));
    expect(result.current.voiceMuted).toBe(true);
  });
});
