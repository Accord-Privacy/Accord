/**
 * A headless client (HC) of SPEC-03 §10.1: the real `ws.ts` on Node 22's
 * global WebSocket, the real `E2EEManager`, the bridge implementation
 * (`CallKeyBridgeImpl`), `CallKeyManager` and `RelayVoiceConnection`, plus
 * the DM and Sender Key receive paths of SPEC-02's two-client harness
 * (`TestClient`, which wires the decode function and the key-distribution
 * consumer exactly as App.tsx does).
 *
 * Media is synthetic:
 * - the capture source produces 20 ms PCM frames (codec 0x00) whose first
 *   two samples are a marker, the HC's tag and the frame number;
 * - the playback sink records every buffer with its attributed sender;
 * - screen sharing uses the screen fakes of `voice/screenShare.testkit.ts`:
 *   a synthetic VP8 encoder whose outputs carry valid frame tags and
 *   key-frame headers followed by a marker (tag, output number, source
 *   picture), and a recording decoder that checks each chunk's VP8 header
 *   and records the marker.
 *
 * For the regression tests the HC also keeps, in memory, every call key it
 * received (the "HC keeps every key it ever received" of RG-C112-1), every
 * frame and fragment it sent with the time it sent it, and every call
 * message it decrypted. None of this is production behaviour; it is read
 * by the tests only.
 */

import { TestClient, waitFor } from '../../src/__integration__/client';
import { CallKeyBridgeImpl } from '../../src/voice/callKeyBridgeImpl';
import type { DecryptResult } from '../../src/voice/callKeyBridge';
import { RelayVoiceConnection, type RelayVoiceTimings, type VoiceConnectionState } from '../../src/voice/relay';
import type { CallKeyTimings, CallKeySnapshot, ParticipantView } from '../../src/voice/callKeys';
import { FakeMediaInput, FakeMediaOutput, markerOf, pcmMarker } from '../../src/voice/relay.testkit';
import { FakeScreenPlatform, FakeSurface, type VideoMarker } from '../../src/voice/screenShare.testkit';
import { systemCallClock } from '../../src/voice/callKeyBridge';
import { decodeWireBase64, encodeBase64 } from '../../src/attachments/base64';
import { readKeyDistribution } from '../../src/e2ee/plaintext';
import { parseDistributionMessage, type SenderKeyDistributionMessage } from '../../src/e2ee/senderKeys';
import { AccordWebSocket } from '../../src/ws';
import type { PreKeyBundle } from '../../src/e2ee/keys';

/** The call tag of §6.3.2, as the plaintext's first 13 characters. */
export const CALL_TAG = '\u001eaccord-call\u001e';

export interface HcOptions {
  /** The marker tag of this client's audio and video (1 to 32767). */
  readonly tag: number;
  readonly muted?: boolean;
  readonly deafened?: boolean;
  readonly callTimings?: Partial<CallKeyTimings>;
  readonly voiceTimings?: Partial<RelayVoiceTimings>;
  /** `MEMBER_REFETCH_MIN` of the bridge (REQ-9). */
  readonly refetchMinMs?: number;
}

/** A call key this HC received and decrypted (REQ-1: only ever inside a call_key). */
export interface ReceivedKey {
  readonly from: string;
  /** The sender's instance, standard base64. */
  readonly inst: string;
  readonly epoch: number;
  readonly secret: Uint8Array;
  readonly at: number;
  /**
   * Decrypted with a stored skipped message key: the voice path refuses it
   * (REQ-32). Every entry is a key this client learned, not necessarily one
   * it installed; `heldEpochs` (common.ts) reads what the manager holds.
   */
  readonly skipped: boolean;
}

/** A call message this HC decrypted, whatever happened to it afterwards. */
export interface DecryptedCallMessage {
  readonly from: string;
  readonly type: string;
  readonly body: Record<string, any>;
  readonly usedSkippedKey: boolean;
  readonly at: number;
}

/** A call message this HC encrypted, by the wire value it produced (§6.3.1). */
export interface OutgoingCall {
  readonly at: number;
  readonly from: string;
  readonly to: string;
  readonly type: string;
  readonly body: Record<string, any>;
  /** `acv1:` ‖ base64(UTF-8(envelope)), exactly as `sendCallMessage` sends it. */
  readonly wire: string;
}

/**
 * Every call message any HC of this process encrypted, by its wire value,
 * so that HRP rules can tell a hello from a key or an acknowledgment (the
 * relay only sees ciphertext; the harness knows what its clients sent).
 */
export const outgoingCalls = new Map<string, OutgoingCall>();

/** The call message behind a `wrapped_key` an HC sent, or undefined. */
export function classifyWire(wrappedKey: unknown): OutgoingCall | undefined {
  return typeof wrappedKey === 'string' ? outgoingCalls.get(wrappedKey) : undefined;
}

export interface SentFrame {
  readonly at: number;
  readonly channelId: string;
  readonly bytes: Uint8Array;
  /** `bufferedAmount` of the socket just before the frame or fragment was handed off (REQ-47 pacing). */
  readonly bufferedAhead?: number;
}

export interface PlayedMarker {
  readonly from: string;
  readonly tag: number;
  readonly n: number;
  readonly at: number;
}

const lower = (s: string) => s.toLowerCase();

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** The JSON body of an `accord-call` plaintext, or null. */
export function callBody(plaintext: string): Record<string, any> | null {
  if (!plaintext.startsWith(CALL_TAG)) return null;
  try {
    const v = JSON.parse(plaintext.slice(CALL_TAG.length));
    return v && typeof v === 'object' ? v : null;
  } catch {
    return null;
  }
}

export class HC {
  readonly client: TestClient;
  readonly bridge: CallKeyBridgeImpl;
  readonly input = new FakeMediaInput();
  readonly output = new FakeMediaOutput();
  readonly screen: FakeScreenPlatform;
  readonly surfaces = new Map<string, FakeSurface>();
  readonly receivedKeys: ReceivedKey[] = [];
  readonly decrypted: DecryptedCallMessage[] = [];
  /** Every call message this client encrypted, in order. */
  readonly encrypted: OutgoingCall[] = [];
  readonly sentFrames: SentFrame[] = [];
  readonly sentFragments: SentFrame[] = [];
  readonly sentCallMessages: Array<{ at: number; target: string; wrappedKey: string; handedOff: boolean }> = [];
  /** Every played buffer's marker, with its attributed sender (§10.1 playback sink). */
  readonly played: PlayedMarker[] = [];
  /** Every picture drawn on a tile, with its marker and the time (§10.1 recording canvas). */
  readonly draws: Array<{ sharer: string; marker: VideoMarker | null; at: number }> = [];
  /** When the synthetic screen source delivered each picture (by picture number, per source). */
  readonly pushedAt = new Map<number, number>();
  /** Every state the connection reported, with the time. */
  readonly states: Array<{ at: number; state: VoiceConnectionState }> = [];
  conn: RelayVoiceConnection | null = null;
  /** The number of the last audio frame the capture source produced. */
  frameNo = 0;
  /** The user interface's mute and deafen state, passed to each new voice connection (REQ-5). */
  muted: boolean;
  deafened: boolean;
  private audioTimer: ReturnType<typeof setInterval> | null = null;
  private screenTimer: ReturnType<typeof setInterval> | null = null;
  private extraSockets: AccordWebSocket[] = [];
  readonly options: HcOptions;

  private constructor(client: TestClient, options: HcOptions) {
    this.client = client;
    this.options = options;
    this.muted = options.muted ?? false;
    this.deafened = options.deafened ?? false;
    this.screen = new FakeScreenPlatform(options.tag);
    this.screen.clock = systemCallClock;
    // The relay-served web client: no shell, so the API probe alone decides (REQ-57).
    this.screen.shell = null;
    const base = new CallKeyBridgeImpl({
      e2ee: () => (client.e2ee.isInitialized ? client.e2ee : null),
      selfId: () => client.userId || null,
      fetchBundle: peer => this.fetchBundle(peer),
      fetchMembers: async node => (await client.api.getNodeMembers(node, client.token)).map(m => m.user_id),
      fetchChannels: async node => (await client.api.getNodeChannels(node, client.token)).map(c => c.id),
      refetchMinMs: options.refetchMinMs,
    });
    // Record every call message this client decrypts, and every key it receives.
    const decryptFrom = base.decryptFrom.bind(base);
    base.decryptFrom = (peer: string, envelope: string): Promise<DecryptResult> => {
      const p = decryptFrom(peer, envelope);
      void p.then(r => {
        if (!r.ok) return;
        const body = callBody(r.plaintext);
        if (!body) return;
        const at = Date.now();
        this.decrypted.push({ from: lower(peer), type: String(body.type), body, usedSkippedKey: r.usedSkippedKey, at });
        if (body.type === 'call_key' && typeof body.key === 'string' && typeof body.inst === 'string' && typeof body.epoch === 'number') {
          const secret = decodeWireBase64(body.key);
          if (secret) this.receivedKeys.push({ from: lower(peer), inst: body.inst, epoch: body.epoch, secret: Uint8Array.from(secret), at, skipped: r.usedSkippedKey });
        }
      });
      return p;
    };
    // Record what every call message this client encrypts is (for HRP rules and scans).
    const encryptFor = base.encryptFor.bind(base);
    base.encryptFor = async (peer: string, plaintext: string, useCredit: boolean) => {
      const r = await encryptFor(peer, plaintext, useCredit);
      const body = callBody(plaintext);
      if (r.ok && body) {
        const wire = 'acv1:' + encodeBase64(new TextEncoder().encode(r.envelope));
        const rec: OutgoingCall = { at: Date.now(), from: this.userId, to: lower(peer), type: String(body.type), body, wire };
        outgoingCalls.set(wire, rec);
        this.encrypted.push(rec);
      }
      return r;
    };
    this.bridge = base;
    this.output.play = (userId: string, pcm: Int16Array) => {
      const m = markerOf(pcm);
      this.played.push({ from: lower(userId), tag: m.tag, n: m.n, at: Date.now() });
      this.output.played.push({ userId, pcm: Int16Array.from(pcm) });
    };
  }

  static async create(name: string, baseUrl: string, options: HcOptions): Promise<HC> {
    const client = await TestClient.create(name, baseUrl);
    return new HC(client, options);
  }

  get name(): string {
    return this.client.name;
  }

  get userId(): string {
    return lower(this.client.userId);
  }

  get ws(): AccordWebSocket {
    const ws = this.client.ws;
    if (!ws) throw new Error(`${this.name} is not connected`);
    return ws;
  }

  private async fetchBundle(peer: string): Promise<PreKeyBundle | undefined> {
    try {
      const resp = await this.client.api.fetchKeyBundle(peer, this.client.token);
      return {
        identityKey: fromBase64(resp.identity_key),
        signedPrekey: fromBase64(resp.signed_prekey),
        oneTimePrekey: resp.one_time_prekey ? fromBase64(resp.one_time_prekey) : undefined,
      };
    } catch {
      return undefined;
    }
  }

  /** Open the WebSocket as App.tsx does, with the bridge's event wiring (REQ-9) and the pending sender-key path. */
  async connect(): Promise<void> {
    await this.client.connect();
    const ws = this.ws;
    ws.on('member_joined' as never, ((d: Record<string, unknown>) => {
      if (typeof d.node_id === 'string') this.bridge.noteMemberJoined(d.node_id);
    }) as never);
    ws.on('sender_key_rotation_required' as never, ((d: Record<string, unknown>) => {
      if (d.channel_id && d.removed_user_id) this.bridge.noteRotationRequired(String(d.channel_id), String(d.removed_user_id));
    }) as never);
    // App.tsx's `pending_sender_keys` consumer (SPEC-02 REQ-53): classify, act on skdm and nmk only, acknowledge.
    ws.on('pending_sender_keys' as never, ((d: Record<string, unknown>) => {
      if (!Array.isArray(d.distributions)) return;
      const ids: string[] = [];
      for (const dist of d.distributions as Array<Record<string, unknown>>) {
        try {
          const from = String(dist.from_user_id);
          const payload = String(dist.encrypted_payload);
          let json: string;
          try {
            json = atob(payload);
          } catch {
            json = payload;
          }
          const read = readKeyDistribution(this.client.e2ee.decryptEnvelope(from, json));
          if (read?.kind === 'legacy' && read.message.type === 'skdm') {
            const msg = read.message as unknown as SenderKeyDistributionMessage;
            this.client.senderKeys.setPeerKey(msg.ch, from, parseDistributionMessage(msg).state);
          } else if (read?.kind === 'legacy') {
            this.client.acceptNmkDistribution(read.message);
          }
          if (typeof dist.id === 'string') ids.push(dist.id);
        } catch {
          // discarded silently (REQ-53)
        }
      }
      if (ids.length > 0) this.ws.ackSenderKeys(ids);
    }) as never);
    this.tapSocket(ws);
  }

  /** Record what the voice code hands to the socket (frames, fragments, call messages). */
  private tapSocket(ws: AccordWebSocket): void {
    const sendMediaFrame = ws.sendMediaFrame.bind(ws);
    ws.sendMediaFrame = (channelId: string, frame: Uint8Array) => {
      const ahead = ws.bufferedAmount();
      const ok = sendMediaFrame(channelId, frame);
      if (ok) this.sentFrames.push({ at: Date.now(), channelId, bytes: Uint8Array.from(frame), bufferedAhead: ahead });
      return ok;
    };
    const sendScreenFragment = ws.sendScreenFragment.bind(ws);
    ws.sendScreenFragment = (channelId: string, fragment: Uint8Array) => {
      const ahead = ws.bufferedAmount();
      const ok = sendScreenFragment(channelId, fragment);
      if (ok) this.sentFragments.push({ at: Date.now(), channelId, bytes: Uint8Array.from(fragment), bufferedAhead: ahead });
      return ok;
    };
    const sendCallMessage = ws.sendCallMessage.bind(ws);
    ws.sendCallMessage = (channelId: string, target: string, wrappedKey: string) => {
      const ok = sendCallMessage(channelId, target, wrappedKey);
      this.sentCallMessages.push({ at: Date.now(), target: lower(target), wrappedKey, handedOff: ok });
      return ok;
    };
  }

  /** Subscribe to a text channel (`JoinChannel`), as selecting it in App.tsx does, so rotation events reach this client. */
  async subscribe(channelId: string): Promise<void> {
    await this.client.join(channelId);
  }

  /** A second, idle WebSocket of the same account (T-38, C154). */
  async openIdleSocket(): Promise<AccordWebSocket> {
    const ws = new AccordWebSocket(this.client.token, this.client.baseUrl);
    let ok = false;
    ws.on('authenticated', () => {
      ok = true;
    });
    ws.connect();
    this.extraSockets.push(ws);
    await waitFor(`${this.name} idle socket`, () => ok);
    return ws;
  }

  // ---------------------------------------------------------------------------
  // Voice
  // ---------------------------------------------------------------------------

  /** Select voice channel C of node N: create the voice session and start the first call. */
  async joinVoice(channelId: string, nodeId: string): Promise<RelayVoiceConnection> {
    this.leaveVoice();
    const conn = new RelayVoiceConnection({
      ws: this.ws,
      channelId,
      nodeId,
      bridge: this.bridge,
      muted: this.muted,
      deafened: this.deafened,
      input: this.input,
      output: this.output,
      clock: systemCallClock,
      callTimings: this.options.callTimings,
      voiceTimings: this.options.voiceTimings,
      screen: this.screen,
    });
    conn.onStateChange = state => {
      this.states.push({ at: Date.now(), state });
    };
    this.conn = conn;
    for (const [sharer, surface] of this.surfaces) conn.attachScreenSurface(sharer, surface);
    await conn.connect();
    return conn;
  }

  leaveVoice(): void {
    this.conn?.disconnect();
    this.conn = null;
  }

  setMuted(muted: boolean): void {
    this.muted = muted;
    this.conn?.setMuted(muted);
  }

  /** Start the synthetic capture source: one marked PCM frame every `intervalMs`. */
  startAudio(intervalMs = 20): void {
    this.stopAudio();
    this.audioTimer = setInterval(() => {
      if (!this.input.active) return;
      this.frameNo = (this.frameNo + 1) & 0x7fff;
      this.input.produce(pcmMarker(this.options.tag, this.frameNo));
    }, intervalMs);
  }

  stopAudio(): void {
    if (this.audioTimer) clearInterval(this.audioTimer);
    this.audioTimer = null;
  }

  get state(): VoiceConnectionState {
    if (!this.conn) throw new Error(`${this.name} has no voice connection`);
    return this.conn.state;
  }

  get snapshot(): CallKeySnapshot | null {
    return this.conn?.state.call ?? null;
  }

  get inst(): string | null {
    return this.conn?.state.instanceId ?? null;
  }

  participant(other: HC): ParticipantView | undefined {
    return this.snapshot?.participants.find(p => p.userId === other.userId);
  }

  /** Markers played at this HC from `from` (all senders when omitted). */
  playedFrom(from?: HC): PlayedMarker[] {
    return this.played.filter(p => !from || p.from === from.userId);
  }

  /** Wait until this HC plays at least `count` new markers from `from` after `since` (a `Date.now()`). */
  async hears(from: HC, opts: { since?: number; count?: number; timeoutMs?: number } = {}): Promise<PlayedMarker[]> {
    const since = opts.since ?? 0;
    const count = opts.count ?? 5;
    return waitFor(`${this.name} hears ${from.name}`, () => {
      const got = this.played.filter(p => p.from === from.userId && p.tag === from.options.tag && p.at >= since);
      return got.length >= count ? got : undefined;
    }, opts.timeoutMs ?? 20_000);
  }

  // ---------------------------------------------------------------------------
  // Screen sharing
  // ---------------------------------------------------------------------------

  /** Click Share Screen (REQ-43) and keep pushing source frames of `width` × `height` at `fps`. */
  shareScreen(opts: { fps?: number; width?: number; height?: number } = {}): boolean {
    const conn = this.conn;
    if (!conn) throw new Error('not in a call');
    const ok = conn.startScreenShare();
    this.startScreenSource(opts);
    return ok;
  }

  startScreenSource(opts: { fps?: number; width?: number; height?: number } = {}): void {
    this.stopScreenSource();
    const fps = opts.fps ?? 15;
    const w = opts.width ?? 1280;
    const h = opts.height ?? 720;
    this.screenTimer = setInterval(() => {
      const s = this.screen.sources[this.screen.sources.length - 1];
      if (s && !s.closed) this.pushedAt.set(s.push(w, h).picture, Date.now());
    }, Math.round(1000 / fps));
  }

  /** The screen stops changing (a static screen: the source delivers no frames). */
  stopScreenSource(): void {
    if (this.screenTimer) clearInterval(this.screenTimer);
    this.screenTimer = null;
  }

  stopSharing(): void {
    this.conn?.stopScreenShare();
    this.stopScreenSource();
  }

  /** Click Watch on `sharer`'s tile, with a recording canvas (REQ-50). */
  watch(sharer: HC): boolean {
    const conn = this.conn;
    if (!conn) throw new Error('not in a call');
    let surface = this.surfaces.get(sharer.userId);
    if (!surface) {
      surface = new FakeSurface();
      const draw = surface.draw.bind(surface);
      const surf = surface;
      surface.draw = (frame, width, height) => {
        draw(frame, width, height);
        this.draws.push({ sharer: sharer.userId, marker: surf.draws[surf.draws.length - 1]?.marker ?? null, at: Date.now() });
      };
      this.surfaces.set(sharer.userId, surface);
    }
    conn.attachScreenSurface(sharer.userId, surface);
    return conn.watchScreen(sharer.userId);
  }

  unwatch(sharer: HC): void {
    this.conn?.unwatchScreen(sharer.userId);
  }

  /** Make the synthetic encoder's outputs follow its configured bitrate (keyframes `keyFactor` times a delta). */
  outputsFollowBitrate(keyFactor = 4): void {
    this.screen.outputSize = o => {
      const enc = this.screen.encoders[this.screen.encoders.length - 1];
      const cfg = enc?.configs[enc.configs.length - 1];
      const perFrame = Math.max(200, Math.floor((cfg?.bitrate ?? 1_500_000) / 8 / 15));
      return Math.min(o.key ? perFrame * keyFactor : perFrame, 1_000_000);
    };
  }

  /** Video markers this HC's recording decoder received from `sharer`. */
  decodedFrom(sharer: HC): VideoMarker[] {
    return this.screen.decodedMarkers.filter(m => m.tag === sharer.options.tag);
  }

  /** Markers drawn on `sharer`'s tile. */
  drawnFrom(sharer: HC): VideoMarker[] {
    return (this.surfaces.get(sharer.userId)?.draws ?? []).flatMap(d => (d.marker && d.marker.tag === sharer.options.tag ? [d.marker] : []));
  }

  async decodes(sharer: HC, opts: { count?: number; since?: number; timeoutMs?: number } = {}): Promise<VideoMarker[]> {
    const before = opts.since ?? 0;
    const count = opts.count ?? 3;
    return waitFor(`${this.name} decodes ${sharer.name}`, () => {
      const got = this.decodedFrom(sharer).slice(before);
      return got.length >= count ? got : undefined;
    }, opts.timeoutMs ?? 20_000);
  }

  // ---------------------------------------------------------------------------
  // Teardown
  // ---------------------------------------------------------------------------

  async dispose(): Promise<void> {
    this.stopAudio();
    this.stopScreenSource();
    this.leaveVoice();
    for (const s of this.extraSockets.splice(0)) s.disconnect();
    this.client.disconnect();
    await sleep(0);
  }

  /** Every received epoch secret, for scans. */
  secrets(): Uint8Array[] {
    return this.receivedKeys.map(k => k.secret);
  }
}

export { toBase64, sleep, waitFor };
