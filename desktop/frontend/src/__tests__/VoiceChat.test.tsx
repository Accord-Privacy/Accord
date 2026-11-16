/**
 * SPEC-03 F tests of the voice panel (`VoiceChat.tsx`) over the in-memory
 * relay of `voice/relay.testkit.ts`, with the real `RelayVoiceConnection`
 * and `CallKeyManager`, fake bridges, fake media and a manual clock:
 * T-5 (F), T-11, T-23, T-27 (F: storage, IndexedDB, console and the Tauri
 * shell), T-31, T-39 (F), T-40 (F), T-41 (F), and the Share Screen state on
 * a relay without `screen/1` (§8.4; the screen tests are in VoiceChat.screen.test.tsx).
 */
import React, { useState } from 'react';
import { act, cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppContext, type AppContextType } from '../components/AppContext';
import { RELAY_P2P_NOTE, VoiceChat, type VoiceCallEnvironment } from '../VoiceChat';
import { A, B, C, CH, CH2, D, E, NODE, readCall } from '../voice/callKeys.testkit';
import type { RelayVoiceConnection } from '../voice/relay';
import type { CallKeyManager } from '../voice/callKeys';
import {
  FakeBridge,
  FakeMediaInput,
  FakeMediaOutput,
  FakeVoiceRelay,
  callSecretsIn,
  pcmMarker,
  spyText,
  voiceClient,
  type VoiceClient,
} from '../voice/relay.testkit';

let relay: FakeVoiceRelay;
let peerConnections = 0;

beforeEach(() => {
  relay = new FakeVoiceRelay();
  peerConnections = 0;
  // T-39: a stub that counts constructions; the expected count is always 0.
  vi.stubGlobal('RTCPeerConnection', class {
    constructor() {
      peerConnections++;
    }
  });
});

afterEach(() => {
  cleanup();
  for (const s of relay.sockets.values()) s.connected = false;
  vi.unstubAllGlobals();
});

interface Member {
  id: string;
  name: string;
}

interface PanelOptions {
  self?: string;
  selfName?: string;
  bridge?: FakeBridge;
  channelId?: string;
  muted?: boolean;
  deafened?: boolean;
  members?: Member[];
}

interface Panel {
  self: string;
  bridge: FakeBridge;
  input: FakeMediaInput;
  output: FakeMediaOutput;
  conns: RelayVoiceConnection[];
  conn(): RelayVoiceConnection;
  setChannel(ch: string): void;
  setMembers(m: Member[]): void;
  rerenderSame(): void;
}

function membersOf(list: Member[]): AppContextType['members'] {
  return list.map(m => ({
    node_id: NODE,
    user_id: m.id,
    public_key_hash: '',
    role: 'member',
    joined_at: 0,
    user: { id: m.id, display_name: m.name },
  })) as unknown as AppContextType['members'];
}

function renderPanel(opts: PanelOptions = {}): Panel {
  const self = opts.self ?? A;
  const bridge = opts.bridge ?? new FakeBridge(self);
  const input = new FakeMediaInput();
  const output = new FakeMediaOutput();
  const conns: RelayVoiceConnection[] = [];
  const env: VoiceCallEnvironment = {
    input,
    output,
    clock: relay.clock,
    onConnection: c => {
      conns.push(c);
      relay.track(c);
    },
  };
  const sock = relay.socket(self);
  let setChannel: (ch: string) => void = () => undefined;
  let setMembers: (m: Member[]) => void = () => undefined;
  let bump: () => void = () => undefined;

  const Harness: React.FC = () => {
    const [muted, setMuted] = useState(opts.muted ?? false);
    const [deafened, setDeafened] = useState(opts.deafened ?? false);
    const [channel, setCh] = useState(opts.channelId ?? CH);
    const [members, setMem] = useState<Member[]>(opts.members ?? []);
    const [, setTick] = useState(0);
    setChannel = setCh;
    setMembers = setMem;
    bump = () => setTick(t => t + 1);
    const ctx = {
      voiceMuted: muted,
      setVoiceMuted: setMuted,
      voiceDeafened: deafened,
      setVoiceDeafened: setDeafened,
      appState: { user: { display_name: opts.selfName ?? 'Alice' } },
      members: membersOf(members),
      setVoiceChannelUsers: () => undefined,
    } as unknown as AppContextType;
    return (
      <AppContext.Provider value={ctx}>
        <VoiceChat
          ws={sock as never}
          currentUserId={self}
          channelId={channel}
          channelName="Voice"
          nodeId={NODE}
          bridge={bridge}
          onLeave={() => undefined}
          callEnv={env}
        />
      </AppContext.Provider>
    );
  };
  render(<Harness />);
  return {
    self,
    bridge,
    input,
    output,
    conns,
    conn: () => conns[conns.length - 1],
    setChannel: ch => act(() => setChannel(ch)),
    setMembers: m => act(() => setMembers(m)),
    rerenderSame: () => act(() => bump()),
  };
}

async function settle(): Promise<void> {
  await act(async () => {
    await relay.settle();
  });
}

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await relay.advance(ms);
  });
}

async function peer(id: string, opts: { channelId?: string } = {}): Promise<VoiceClient> {
  const c = voiceClient(relay, id, { channelId: opts.channelId ?? CH });
  void c.conn.connect();
  await settle();
  return c;
}

function participantRow(user: string): HTMLElement {
  const row = document.querySelector<HTMLElement>(`[data-testid="voice-participant"][data-user-id="${user}"]`);
  if (!row) throw new Error(`no row for ${user}`);
  return row;
}

function displayed(): string[] {
  return [...document.querySelectorAll<HTMLElement>('[data-testid="voice-participant"]')].map(e => e.dataset.userId!);
}

function stateOf(user: string): string {
  return participantRow(user).querySelector('.voice-user-pill-state')?.textContent ?? '';
}

function framesSentBy(user: string): number {
  return relay.sent(user, 'SrtpVoicePacket').length;
}

const PEER_EVENTS = ['p2p_signal', 'voice_offer', 'voice_answer', 'voice_ice_candidate'];

describe('T-23 (REQ-23) secure voice unavailable', () => {
  it('sends no JoinVoiceChannel and shows the unavailable state while the bridge is not ready', async () => {
    const bridge = new FakeBridge(A);
    bridge.ready = false;
    const p = renderPanel({ bridge });
    await settle();
    await advance(15_000);
    expect(relay.sent(A, 'JoinVoiceChannel')).toHaveLength(0);
    expect(p.input.starts).toBe(0);
    expect(screen.getByRole('status')).toHaveTextContent('Secure voice unavailable; sign in again');
    expect(screen.getByRole('button', { name: /Secure voice unavailable/ })).toBeInTheDocument();
  });
});

describe('the voice panel of a relay-mode call', () => {
  it('shows the indicator, each participant\'s state and short id, and no mode badge or toggle', async () => {
    renderPanel();
    await settle();
    expect(screen.getByRole('status')).toHaveTextContent('Voice connected');
    expect(screen.getByRole('button', { name: /Waiting for others/ })).toBeInTheDocument();
    await peer(B);
    await advance(3000);
    const row = participantRow(B);
    expect(row.querySelector('.voice-user-pill-shortid')?.textContent).toBe('00000000');
    expect(stateOf(B)).toBe('Secure');
    expect(row.querySelector('[aria-label="Receives your current call key"]')).not.toBeNull();
    const indicator = screen.getByRole('button', { name: /End-to-end encrypted · not verified/ });
    // Activating the indicator lists every participant with its state and short id (§8.1).
    expect(screen.queryByText(/marked with a key/)).toBeNull();
    await act(async () => indicator.click());
    const details = document.getElementById('voice-security-details')!;
    expect(details).toHaveTextContent('00000000');
    expect(details).toHaveTextContent('Secure');
    expect(details).toHaveTextContent('identities are not verified');
    // No mode badge, no toggle, no P2P anywhere in the panel.
    expect(document.querySelector('.voice-mode-badge')).toBeNull();
    expect(screen.getByTestId('voice-panel').textContent).not.toMatch(/P2P|Relay mode/);
  });

  it('on a relay without screen/1, Share Screen is disabled with the §8.4 reason, as visible text (REQ-42)', async () => {
    renderPanel();
    await settle();
    const button = screen.getByRole('button', { name: 'Share Screen' });
    expect(button).toBeDisabled();
    // The state is visible text, not only a tooltip or an accessible name:
    // a disabled button's tooltip is not shown in every engine.
    const reason = "Encrypted screen sharing isn't available on this relay yet.";
    expect(screen.getByText(reason)).toBeVisible();
    expect(button).toHaveAccessibleDescription(expect.stringContaining(reason));
    expect(screen.queryByRole('button', { name: /Watch/ })).toBeNull();
    expect(screen.getByTestId('voice-panel').textContent).not.toMatch(/Not in this release/);
  });
});

describe('T-5 (REQ-5) F: the mute state applies before the first frame of every instance', () => {
  it('first join, channel switch, a relay-reported p2p and back, and a rejoin after reconnect send nothing until unmuted', async () => {
    const p = renderPanel({ muted: true });
    await settle();
    const b = await peer(B);
    await advance(3000);
    expect(p.input.mutedAtStart).toEqual([true]);
    p.input.produce(pcmMarker(1, 0));
    await advance(100);
    expect(framesSentBy(A)).toBe(0);

    // A channel switch builds a new instance, muted from the start.
    await peer(C, { channelId: CH2 });
    p.setChannel(CH2);
    await settle();
    await advance(3000);
    expect(p.conns).toHaveLength(2);
    expect(p.input.mutedAtStart).toEqual([true, true]);
    expect(relay.sent(A, 'LeaveVoiceChannel').map(m => m.body.channel_id)).toEqual([CH]);
    p.input.produce(pcmMarker(1, 1));
    await advance(100);
    expect(framesSentBy(A)).toBe(0);

    // Relay mode reports change nothing: same connection, same instance.
    const inst = p.conn().state.instanceId;
    relay.inject(A, { type: 'voice_mode_changed', channel_id: CH2, voice_mode: 'p2p', changed_by: C });
    await settle();
    relay.inject(A, { type: 'voice_mode_changed', channel_id: CH2, voice_mode: 'relay', changed_by: C });
    await settle();
    expect(p.conns).toHaveLength(2);
    expect(p.conn().state.instanceId).toBe(inst);
    expect(p.input.starts).toBe(2);
    p.input.produce(pcmMarker(1, 2));
    await advance(100);
    expect(framesSentBy(A)).toBe(0);

    // A rejoin after a reconnect: a new instance, still muted.
    await act(async () => {
      relay.closeSocket(A);
      await relay.settle();
      relay.reopenSocket(A);
      await relay.settle();
    });
    await advance(3000);
    expect(p.conn().state.instanceId).not.toBe(inst);
    expect(p.input.mutedAtStart).toEqual([true, true, true]);
    p.input.produce(pcmMarker(1, 3));
    await advance(100);
    expect(framesSentBy(A)).toBe(0);

    // Unmuting sends.
    await act(async () => screen.getByTitle('Unmute').click());
    p.input.produce(pcmMarker(1, 4));
    await settle();
    expect(framesSentBy(A)).toBe(1);
    void b;
  });

  it('a deafened user gets no playback', async () => {
    const p = renderPanel({ deafened: true });
    await settle();
    const b = await peer(B);
    await advance(3000);
    expect(p.input.mutedAtStart).toEqual([true]);
    for (let i = 0; i < 6; i++) b.input.produce(pcmMarker(2, i));
    await settle();
    await advance(500);
    expect(p.output.played).toHaveLength(0);
    expect(p.output.deafened).toBe(true);
  });
});

describe('T-39 (REQ-39) F and T-41 (REQ-41) F', () => {
  it('P2P signaling and mode reports from users in V and outside it build no peer connection and change nothing but the note', async () => {
    const p = renderPanel();
    await settle();
    const b = await peer(B);
    await advance(3000);
    const inst = p.conn().state.instanceId;
    const listened = relay.socket(A).listenedEvents();
    for (const e of PEER_EVENTS) expect(listened).not.toContain(e);

    for (const from of [B, E]) {
      relay.inject(A, { type: 'voice_mode_changed', channel_id: CH, voice_mode: 'p2p', changed_by: from });
      relay.inject(A, { type: 'p2p_signal', channel_id: CH, from, signal_data: JSON.stringify({ type: 'screen-sdp', sdp: 'v=0' }) });
      relay.inject(A, { type: 'p2p_signal', channel_id: CH, from, signal_data: JSON.stringify({ type: 'sdp', sdp: { type: 'offer', sdp: 'v=0' } }) });
      relay.inject(A, { type: 'p2p_signal', channel_id: CH, from, signal_data: JSON.stringify({ type: 'ice', candidate: { candidate: 'candidate:1 1 udp 1 10.0.0.1 5000 typ host' } }) });
      relay.inject(A, { type: 'voice_offer', channel_id: CH, from, sdp: 'v=0' });
      relay.inject(A, { type: 'voice_answer', channel_id: CH, from, sdp: 'v=0' });
      relay.inject(A, { type: 'voice_ice_candidate', channel_id: CH, from, candidate: 'x' });
    }
    await settle();
    expect(peerConnections).toBe(0);
    // The note of §8.3 appears; nothing modal, no badge.
    expect(screen.getByRole('note', { name: '' })).toBeDefined();
    expect(screen.getByText(RELAY_P2P_NOTE)).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.querySelector('.voice-mode-badge')).toBeNull();
    // The per-participant note: no call message from B since the report.
    expect(within(participantRow(B)).getByText('May be using an older app in P2P mode')).toBeInTheDocument();

    // Audio keeps flowing, with the same instance (a fifth frame ends the burst).
    for (let i = 0; i < 5; i++) b.input.produce(pcmMarker(3, i));
    await settle();
    await advance(400);
    expect(p.output.markers(B).map(m => m.n).slice(0, 4)).toEqual([0, 1, 2, 3]);
    expect(p.conn().state.instanceId).toBe(inst);
    expect(p.conns).toHaveLength(1);

    // A self-check reply and a later join report saying p2p change nothing either.
    relay.voiceMode = 'p2p';
    await advance(35_000);
    expect(p.conn().state.instanceId).toBe(inst);

    relay.voiceMode = 'relay';
    relay.inject(A, { type: 'voice_mode', channel_id: CH, voice_mode: 'relay' });
    await settle();
    expect(screen.queryByText(RELAY_P2P_NOTE)).toBeNull();
    expect(p.conn().state.instanceId).toBe(inst);

    // Nothing P2P or mode-related ever left the client.
    const types = new Set(relay.sent(A).map(m => m.type));
    for (const t of ['P2PSignal', 'SetVoiceMode', 'VoiceOffer', 'VoiceAnswer', 'VoiceIceCandidate', 'VoicePacket']) expect(types.has(t)).toBe(false);
    expect(peerConnections).toBe(0);
  });
});

describe('T-40 (REQ-40) F', () => {
  it('only the exact eviction ends the call and shows the removal message', async () => {
    const p = renderPanel();
    await settle();
    await peer(B);
    await advance(3000);
    relay.inject(A, { type: 'voice_channel_left', channel_id: CH, user_id: A });
    relay.inject(A, { type: 'voice_channel_left', channel_id: CH2, user_id: A, reason: 'removed' });
    await settle();
    expect(screen.getByRole('status')).toHaveTextContent('Voice connected');
    relay.inject(A, { type: 'voice_channel_left', channel_id: CH, user_id: A, reason: 'removed' });
    await settle();
    expect(screen.getByRole('status')).toHaveTextContent('You were removed from the voice channel');
    expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument();
    expect(p.input.active).toBe(false);
    expect(displayed()).toEqual([]);
  });
});

describe('T-11 (REQ-11) F: who is shown', () => {
  it('after random joins, leaves and eligibility changes, every recipient is shown, every member of V has a short id, and duplicate names are marked', async () => {
    const names: Member[] = [
      { id: B, name: 'Sam' },
      { id: C, name: 'Sam' }, // same name as B
      { id: D, name: 'Alice' }, // same name as the local user
      { id: E, name: 'Eve' },
    ];
    const p = renderPanel({ members: names, selfName: 'Alice' });
    await settle();
    let seed = 7;
    const rnd = (n: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    const peers = new Map<string, VoiceClient>();
    const ids = [B, C, D, E];
    // REQ-11: at the moment of every send, the target is in the call's view,
    // which the panel displays (checked against the DOM after every step).
    const viewOf = () => ((p.conn() as any).call?.mgr as CallKeyManager | undefined)?.participants() ?? [];
    const sock = relay.socket(A);
    const sendCallMessage = sock.sendCallMessage.bind(sock);
    const notInView: string[] = [];
    sock.sendCallMessage = (channelId: string, target: string, wrappedKey: string) => {
      if (!viewOf().includes(target)) notInView.push(target);
      return sendCallMessage(channelId, target, wrappedKey);
    };
    let sentTo = 0;
    for (let step = 0; step < 24; step++) {
      const id = ids[rnd(ids.length)];
      const action = rnd(3);
      const logStart = relay.log.length;
      const shownBefore = displayed();
      if (action === 0 && !peers.has(id)) {
        peers.set(id, await peer(id));
      } else if (action === 1 && peers.has(id)) {
        await act(async () => {
          peers.get(id)!.conn.disconnect();
          peers.delete(id);
          await relay.settle();
        });
      } else {
        await act(async () => {
          p.bridge.setMembership(id, p.bridge.membership(NODE, CH, id) === 'member' ? 'not_member' : 'member');
          await relay.settle();
        });
      }
      await advance(700);
      const shown = displayed();
      const view = p.conn().state.call!.participants.map(v => v.userId);
      expect(shown).toEqual(view);
      for (const u of shown) expect(participantRow(u).querySelector('.voice-user-pill-shortid')?.textContent).toMatch(/^[0-9a-f]{8}$/);
      // The current recipients R_g are displayed participants, and exactly
      // they carry the key mark.
      const recipients = ((p.conn() as any).call.mgr as CallKeyManager).currentRecipients();
      for (const u of recipients) expect(shown).toContain(u);
      const marked = [...document.querySelectorAll('[aria-label="Receives your current call key"]')].map(
        el => (el.closest('[data-testid="voice-participant"]') as HTMLElement).dataset.userId,
      );
      expect([...marked].sort()).toEqual([...recipients].sort());
      // Every call message of the step went to a participant displayed
      // before or after it, and was in the call's view when it was sent.
      for (const m of relay.log.slice(logStart).filter(x => x.from === A && x.type === 'VoiceKeyExchange')) {
        expect([...shownBefore, ...shown]).toContain(m.body.target_user_id);
        sentTo++;
      }
      expect(notInView).toEqual([]);
      // Duplicate names: B and C, and D with the local user.
      const dup = (u: string) => participantRow(u).textContent!.includes('Same name as another participant');
      if (shown.includes(B) && shown.includes(C)) expect(dup(B) && dup(C)).toBe(true);
      if (shown.includes(B) && !shown.includes(C)) expect(dup(B)).toBe(false);
      if (shown.includes(D)) {
        expect(dup(D)).toBe(true);
        expect(screen.getByTestId('voice-self').textContent).toContain('Same name as another participant');
      }
      if (shown.includes(E)) expect(dup(E)).toBe(false);
    }
    expect(sentTo).toBeGreaterThan(0); // the script did send call messages
    expect(peerConnections).toBe(0);
  });
});

describe('T-31 (REQ-31) F: the labels of §8.1 and §8.2 over time', () => {
  it('queued for session, a hello at 3 s, an ACK at 5 s, then a rotation without an ACK', async () => {
    // Self is B; P is A, the lower id: B holds its messages until A's first
    // Double Ratchet message establishes the session (REQ-10).
    const bridgeB = new FakeBridge(B);
    bridgeB.noSession.add(A);
    const start = relay.clock.now();
    const held: Array<Record<string, any>> = [];
    let ackAt = Infinity;
    let dropAcks = false;
    relay.filter = (to, data) => {
      if (to !== B || data.type !== 'voice_key_exchange' || data.from !== A) return true;
      const body = readCall(data.wrapped_key);
      const now = relay.clock.now();
      if (now < start + 3000) {
        held.push(data); // A's hello reaches B at 3 s
        return false;
      }
      if (body.type === 'call_key_ack' && (dropAcks || now < ackAt)) {
        if (!dropAcks) held.push(data);
        return false;
      }
      return true;
    };
    const a = voiceClient(relay, A, { channelId: CH });
    a.bridge.noSession.add(B);
    void a.conn.connect();
    await settle();
    renderPanel({ self: B, bridge: bridgeB, selfName: 'Bob', members: [{ id: A, name: 'Ann' }] });
    await settle();
    expect(stateOf(A)).toBe('Connecting');
    expect(screen.getByRole('button', { name: /Connecting securely…/ })).toBeInTheDocument();

    await advance(1000);
    expect(stateOf(A)).toBe('Connecting');
    // 3 s: A's hello arrives; the session exists, B sends its hello and key.
    await advance(2000);
    ackAt = start + 5000;
    const release = held.splice(0);
    for (const m of release) relay.inject(B, m);
    await settle();
    expect(stateOf(A)).toBe('Connecting');
    // 5 s: A's ACK arrives.
    await advance(2100);
    for (const m of held.splice(0)) relay.inject(B, m);
    await settle();
    await advance(500);
    expect(stateOf(A)).toBe('Secure');
    expect(screen.getByRole('button', { name: /End-to-end encrypted · not verified/ })).toBeInTheDocument();

    // Speaking flags, display names, mode reports and screen announcements change no state.
    relay.inject(B, { type: 'voice_speaking_state', channel_id: CH, user_id: A, speaking: true });
    relay.inject(B, { type: 'voice_mode_changed', channel_id: CH, voice_mode: 'p2p', changed_by: A });
    relay.inject(B, { type: 'screen_share_started', channel_id: CH, user_id: A });
    await settle();
    expect(stateOf(A)).toBe('Secure');
    expect(screen.getByRole('button', { name: /End-to-end encrypted · not verified/ })).toBeInTheDocument();
    expect(participantRow(A).className).toContain('speaking');
    relay.inject(B, { type: 'voice_mode_changed', channel_id: CH, voice_mode: 'relay', changed_by: A });
    await settle();

    // A rotation that A never acknowledges: Secure for 6 s after the first
    // transmission, then Connecting until 12 s, then "They can't hear you".
    dropAcks = true;
    await peer(D);
    const rotationAt = relay.clock.now();
    await advance(3000);
    expect(stateOf(A)).toBe('Secure');
    await advance(rotationAt + 8000 - relay.clock.now());
    expect(stateOf(A)).toBe('Connecting');
    await advance(rotationAt + 14_000 - relay.clock.now());
    expect(stateOf(A)).toBe("They can't hear you");
    // Never a P2P row in the indicator (A1).
    expect(screen.queryByRole('button', { name: /P2P/ })).toBeNull();
    expect(peerConnections).toBe(0);
  });
});

describe('T-27 (REQ-27) F: nothing reaches storage, IndexedDB, the console or the shell', () => {
  it('a call script with audio, a rotation, a reconnect and a leave', async () => {
    const stored: string[] = [];
    const setItem = Storage.prototype.setItem;
    const storageSpy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function (this: Storage, k: string, v: string) {
      stored.push(`${k}=${v}`);
      setItem.call(this, k, v);
    });
    const idb = { open: vi.fn(), deleteDatabase: vi.fn() };
    vi.stubGlobal('indexedDB', idb);
    const invoke = vi.fn(async (..._args: unknown[]) => undefined);
    (window as any).__TAURI__ = { core: { invoke } };
    const logged: string[] = [];
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map(m =>
      vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
        logged.push(spyText(args));
      }),
    );
    try {
      const p = renderPanel();
      await settle();
      const b = await peer(B);
      const c = await peer(C);
      await advance(3000);
      for (let i = 0; i < 6; i++) {
        p.input.produce(pcmMarker(1, i));
        b.input.produce(pcmMarker(2, i));
      }
      await settle();
      await advance(400);
      expect(p.output.markers(B).length).toBeGreaterThan(0); // the script carried audio
      // A departure: A rotates.
      await act(async () => {
        c.conn.disconnect();
        await relay.settle();
      });
      await advance(3000);
      // A reconnect: a new instance with new keys.
      await act(async () => {
        relay.closeSocket(A);
        await relay.settle();
        relay.reopenSocket(A);
        await relay.settle();
      });
      await advance(3000);
      for (let i = 0; i < 6; i++) p.input.produce(pcmMarker(1, 10 + i));
      await settle();
      await advance(400);
      // Leave: the panel unmounts.
      cleanup();
      await settle();
    } finally {
      for (const s of spies) s.mockRestore();
      storageSpy.mockRestore();
      delete (window as any).__TAURI__;
    }
    expect(idb.open).not.toHaveBeenCalled();
    expect(idb.deleteDatabase).not.toHaveBeenCalled();
    expect(logged).toEqual([]);
    // The shell is only asked to arm and then disarm the microphone gate,
    // and, without arguments, whether it supports display capture (REQ-57;
    // every connection of the script probes once per voice session).
    const probes = invoke.mock.calls.filter(call => call[0] === 'display_capture_supported');
    expect(probes.length).toBeGreaterThan(0);
    for (const call of probes) expect(call).toEqual(['display_capture_supported']);
    expect(invoke.mock.calls.filter(call => call[0] !== 'display_capture_supported')).toEqual([
      ['set_voice_capture_armed', { armed: true }],
      ['set_voice_capture_armed', { armed: false }],
    ]);
    // No spy saw a secret, an instance id or a call-message plaintext.
    const { forms, plaintexts } = callSecretsIn(relay.log);
    expect(forms.length).toBeGreaterThan(0);
    for (const line of [...stored, ...logged, ...invoke.mock.calls.map(call => spyText(call))]) {
      for (const f of forms) expect(line.includes(f)).toBe(false);
      for (const pt of plaintexts) expect(line.includes(pt)).toBe(false);
      expect(line.includes('accord-call')).toBe(false);
    }
  });
});

describe('OD-52: no cap, a warning above 25 participants', () => {
  it('warns when the call has more than 25 participants', async () => {
    renderPanel();
    await settle();
    expect(screen.queryByText(/Large call/)).toBeNull();
    const many = Array.from({ length: 25 }, (_, i) => `00000000-0000-4000-8000-0000000001${i.toString(16).padStart(2, '0')}`);
    // A later voice_channel_joined only reconciles V (REQ-5).
    relay.inject(A, { type: 'voice_channel_joined', channel_id: CH, participants: [A, ...many], voice_mode: 'relay' });
    await settle();
    expect(displayed()).toHaveLength(25);
    expect(screen.getByText(/Large call/)).toBeInTheDocument();
  });
});
