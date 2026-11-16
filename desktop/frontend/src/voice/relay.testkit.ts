/**
 * @module voice/relay.testkit
 * Test support for `RelayVoiceConnection` (SPEC-03 §10.1, U and F tests):
 * an in-memory relay that speaks the voice WebSocket messages of the
 * baseline relay, a fake socket per client that records every send attempt,
 * and fake media input and output carrying marked PCM frames. Imported by
 * tests only; nothing in the app imports it.
 */

import { decodeWireBase64, encodeBase64 } from '../attachments/base64';
import type { ScreenLimits, SendResult } from '../ws';
import { FakeBridge, ManualClock, NODE, fakePlaintextOf, readCall } from './callKeys.testkit';
import type { AudioDecoderPort, CaptureSink, VoiceMediaInput, VoiceMediaOutput } from './mediaIo';
import { RelayVoiceConnection, type RelayVoiceOptions, type RelayVoiceTimings } from './relay';
import type { CallKeyTimings } from './callKeys';
import { decodeScreenUp, encodeScreenUp } from './screenFrame';
import type { ScreenPlatform } from './screenShare';

export { FakeBridge, ManualClock } from './callKeys.testkit';

/** One client → relay message. */
export interface ClientMessage {
  readonly from: string;
  readonly type: string;
  readonly body: Record<string, any>;
  readonly at: number;
  /** Whether the socket was open and authenticated (REQ-37). */
  readonly handedOff: boolean;
}

/** One relay → client delivery. */
export interface Delivery {
  readonly to: string;
  readonly data: Record<string, any>;
  readonly at: number;
}

/** One binary `SCREEN_UP` a client handed off (§6.12.2). */
export interface BinaryMessage {
  readonly from: string;
  readonly bytes: Uint8Array;
  readonly at: number;
  /** `bufferedAmount` just before the message was handed off. */
  readonly bufferedBefore: number;
}

/** The feature token and limits of a screen-capable relay (§6.12.1). */
export const SCREEN_HELLO = Object.freeze({ features: ['screen/1'], screen_limits: { max_sharers: 2, max_bytes_per_second: 500_000 } });

type Listener = (data: any) => void;

let messageSeq = 0;

/** The relay WebSocket of one client, as `RelayVoiceConnection` uses it. */
export class FakeVoiceSocket {
  readonly user: string;
  connected = true;
  readonly listeners = new Map<string, Set<Listener>>();
  /** Every send attempt, handed off or not. */
  readonly attempts: ClientMessage[] = [];
  /** Every binary message handed off. */
  readonly binary: BinaryMessage[] = [];
  /** The current socket's `hello` (SPEC-01 §6.8): processed, its features and its screen limits. */
  helloSeen = true;
  features: string[] = [];
  limits: ScreenLimits | null = null;
  /**
   * `bufferedAmount` (REQ-47): a fixed value when `fixedBuffered` is set;
   * otherwise every handed-off message adds its size, and `drainPerMs`
   * bytes leave per millisecond of the relay clock (Infinity: always 0).
   */
  fixedBuffered: number | null = null;
  drainPerMs = Infinity;
  /** `bufferedAmount` just before each audio frame was handed off. */
  readonly bufferedBeforeAudio: number[] = [];
  private queued = 0;
  private queuedAt = 0;
  private readonly relay: FakeVoiceRelay;

  constructor(relay: FakeVoiceRelay, user: string) {
    this.relay = relay;
    this.user = user;
  }

  on(event: string, listener: Listener): void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener);
  }

  off(event: string, listener: Listener): void {
    this.listeners.get(event)?.delete(listener);
  }

  listenerCount(event: string): number {
    return this.listeners.get(event)?.size ?? 0;
  }

  /** Event types with at least one listener. */
  listenedEvents(): string[] {
    return [...this.listeners].filter(([, s]) => s.size > 0).map(([e]) => e);
  }

  emit(event: string, data?: unknown): void {
    for (const l of [...(this.listeners.get(event) ?? [])]) l(data);
  }

  isSocketConnected(): boolean {
    return this.connected;
  }

  joinVoiceChannel(channelId: string): SendResult {
    return this.send('JoinVoiceChannel', { channel_id: channelId });
  }

  leaveVoiceChannel(channelId: string): SendResult {
    return this.send('LeaveVoiceChannel', { channel_id: channelId });
  }

  getVoiceParticipants(channelId: string): SendResult {
    return this.send('GetVoiceParticipants', { channel_id: channelId });
  }

  sendVoiceSpeakingState(channelId: string, userId: string, speaking: boolean): void {
    this.send('VoiceSpeakingState', { channel_id: channelId, user_id: userId, speaking });
  }

  sendCallMessage(channelId: string, targetUserId: string, wrappedKey: string): boolean {
    return this.send('VoiceKeyExchange', {
      channel_id: channelId,
      wrapped_key: wrappedKey,
      target_user_id: targetUserId,
      sender_ssrc: 0,
      key_generation: 0,
    }).handedOff;
  }

  sendMediaFrame(channelId: string, frame: Uint8Array): boolean {
    if (this.connected) this.bufferedBeforeAudio.push(this.bufferedAmount());
    return this.send('SrtpVoicePacket', { channel_id: channelId, packet_data: encodeBase64(frame) }).handedOff;
  }

  // Screen sharing (§6.12), as `ws.ts` provides it.

  isScreenCapable(): boolean {
    return this.connected && this.helloSeen && this.features.includes('screen/1') && this.limits !== null;
  }

  screenLimits(): ScreenLimits | null {
    return this.connected && this.helloSeen ? this.limits : null;
  }

  helloProcessed(): boolean {
    return this.connected && this.helloSeen;
  }

  relayFeatures(): readonly string[] {
    return this.features;
  }

  bufferedAmount(): number {
    if (!this.connected) return 0;
    if (this.fixedBuffered !== null) return this.fixedBuffered;
    const now = this.relay.clock.now();
    if (this.drainPerMs === Infinity) this.queued = 0;
    else this.queued = Math.max(0, this.queued - (now - this.queuedAt) * this.drainPerMs);
    this.queuedAt = now;
    return Math.floor(this.queued);
  }

  sendScreenFragment(channelId: string, fragment: Uint8Array): boolean {
    if (!this.isScreenCapable()) return false;
    let bytes: Uint8Array;
    try {
      bytes = encodeScreenUp(channelId, fragment);
    } catch {
      return false;
    }
    const before = this.bufferedAmount();
    this.queued += bytes.length;
    this.binary.push({ from: this.user, bytes, at: this.relay.clock.now(), bufferedBefore: before });
    this.relay.receiveBinary(this.user, bytes);
    return true;
  }

  screenShareStart(channelId: string): SendResult {
    return this.sendScreen('ScreenShareStart', { channel_id: channelId });
  }

  screenShareStop(channelId: string): SendResult {
    return this.sendScreen('ScreenShareStop', { channel_id: channelId });
  }

  screenWatch(channelId: string, sharerId: string, watch: boolean): SendResult {
    return this.sendScreen('ScreenWatch', { channel_id: channelId, sharer_id: sharerId, watch });
  }

  screenKeyframeRequest(channelId: string, sharerId: string): SendResult {
    return this.sendScreen('ScreenKeyframeRequest', { channel_id: channelId, sharer_id: sharerId });
  }

  /** The screen JSON messages go only to a screen-capable relay (as in `ws.ts`). */
  private sendScreen(type: string, body: Record<string, any>): SendResult {
    if (!this.isScreenCapable()) {
      const messageId = `m-${++messageSeq}`;
      this.attempts.push({ from: this.user, type, body, at: this.relay.clock.now(), handedOff: false });
      return { handedOff: false, messageId };
    }
    return this.send(type, body);
  }

  private send(type: string, body: Record<string, any>): SendResult {
    const messageId = `m-${++messageSeq}`;
    const msg: ClientMessage = { from: this.user, type, body: { ...body, message_id: messageId }, at: this.relay.clock.now(), handedOff: this.connected };
    this.attempts.push(msg);
    if (!this.connected) return { handedOff: false, messageId };
    if (this.fixedBuffered === null && this.drainPerMs !== Infinity) {
      this.bufferedAmount();
      this.queued += JSON.stringify(body).length;
    }
    this.relay.receive(msg);
    return { handedOff: true, messageId };
  }
}

/**
 * The relay: voice participation per channel (a user list, as at the
 * baseline), forwarding of call messages to their target and of frames to
 * the other participants, all through one FIFO queue that `settle` drains.
 */
export class FakeVoiceRelay {
  readonly clock = new ManualClock();
  readonly sockets = new Map<string, FakeVoiceSocket>();
  /** channel → participants, in join order. */
  readonly voice = new Map<string, string[]>();
  /** Every message a client handed off. */
  readonly log: ClientMessage[] = [];
  readonly deliveries: Delivery[] = [];
  /** What `voice_channel_joined` and `voice_participants` report. */
  voiceMode = 'relay';
  /** Decide each delivery; false drops it. */
  filter: (to: string, data: Record<string, any>) => boolean = () => true;
  /**
   * The screen path of §6.12 (per user: the test kit has one connection per
   * user). Off by default: a relay at the baseline, whose `hello` has no
   * `screen/1`.
   */
  screen = { enabled: false, maxSharers: 2, maxBytesPerSecond: 500_000 };
  /** channel → sharers, oldest first. */
  readonly shares = new Map<string, string[]>();
  /** channel → sharer → watching users. */
  readonly watches = new Map<string, Map<string, Set<string>>>();
  /** Every binary message handed off, from every client. */
  readonly binaryLog: BinaryMessage[] = [];
  /** Every `SCREEN_DOWN` delivered: to, from, the fragment. */
  readonly screenDown: Array<{ to: string; from: string; fragment: Uint8Array; at: number }> = [];
  /** Decide each `SCREEN_DOWN` delivery; false drops it. */
  screenFilter: (to: string, from: string, fragment: Uint8Array) => boolean = () => true;
  private readonly lastWatchers = new Map<string, number>();
  private readonly lastKfr = new Map<string, number>();
  private queue: Array<() => void> = [];
  private readonly connections = new Set<RelayVoiceConnection>();

  socket(user: string): FakeVoiceSocket {
    let s = this.sockets.get(user);
    if (!s) {
      s = new FakeVoiceSocket(this, user);
      this.sockets.set(user, s);
      this.applyHello(s);
    }
    return s;
  }

  /** Turn the screen path on (or off) and send every connected socket a new `hello`. */
  enableScreen(on = true, limits: { maxSharers?: number; maxBytesPerSecond?: number } = {}): void {
    this.screen = { enabled: on, maxSharers: limits.maxSharers ?? this.screen.maxSharers, maxBytesPerSecond: limits.maxBytesPerSecond ?? this.screen.maxBytesPerSecond };
    for (const s of this.sockets.values()) if (s.connected) this.sendHello(s.user);
  }

  /** Deliver a `hello` with `features` and `screen_limits` as given (the relay's own by default). */
  sendHello(user: string, hello?: { features?: unknown; screen_limits?: unknown }): void {
    const s = this.socket(user);
    const data = hello ?? this.helloBody();
    s.helloSeen = true;
    s.features = Array.isArray(data.features) ? data.features.filter((f: unknown): f is string => typeof f === 'string') : [];
    const l = data.screen_limits as Record<string, unknown> | undefined;
    const sharers = l?.max_sharers;
    const rate = l?.max_bytes_per_second;
    s.limits = typeof sharers === 'number' && Number.isSafeInteger(sharers) && sharers >= 1 && sharers <= 8 && typeof rate === 'number' && Number.isSafeInteger(rate) && rate >= 200_000
      ? { maxSharers: sharers, maxBytesPerSecond: rate }
      : null;
    s.emit('hello', { type: 'hello', protocol_version: 1, ...data });
  }

  private helloBody(): { features: string[]; screen_limits?: unknown } {
    return this.screen.enabled
      ? { features: ['screen/1'], screen_limits: { max_sharers: this.screen.maxSharers, max_bytes_per_second: this.screen.maxBytesPerSecond } }
      : { features: [] };
  }

  private applyHello(s: FakeVoiceSocket): void {
    const body = this.helloBody();
    s.helloSeen = true;
    s.features = [...body.features];
    s.limits = this.screen.enabled ? { maxSharers: this.screen.maxSharers, maxBytesPerSecond: this.screen.maxBytesPerSecond } : null;
  }

  track(conn: RelayVoiceConnection): void {
    this.connections.add(conn);
  }

  participants(channel: string): string[] {
    return [...(this.voice.get(channel) ?? [])];
  }

  receive(msg: ClientMessage): void {
    this.log.push(msg);
    this.queue.push(() => this.handle(msg));
  }

  /** Deliver `data` to `to` as the relay would (after the queue drains). */
  inject(to: string, data: Record<string, any>): void {
    this.queue.push(() => this.deliver(to, data));
  }

  /** Deliver `data` to `to` now, bypassing the filter. */
  deliverNow(to: string, data: Record<string, any>): void {
    this.sockets.get(to)?.emit(String(data.type), data);
  }

  private deliver(to: string, data: Record<string, any>): void {
    const s = this.sockets.get(to);
    if (!s || !s.connected) return;
    if (!this.filter(to, data)) return;
    this.deliveries.push({ to, data, at: this.clock.now() });
    s.emit(String(data.type), data);
  }

  /** `screen_sharers` for the join and participants replies, on a screen-capable relay. */
  private sharersField(ch: string): Record<string, unknown> {
    return this.screen.enabled ? { screen_sharers: [...(this.shares.get(ch) ?? [])] } : {};
  }

  private handle(msg: ClientMessage): void {
    const b = msg.body;
    const ch = String(b.channel_id ?? '');
    const list = this.voice.get(ch) ?? [];
    const ts = Math.floor(this.clock.now() / 1000);
    switch (msg.type) {
      case 'JoinVoiceChannel': {
        if (!list.includes(msg.from)) list.push(msg.from);
        this.voice.set(ch, list);
        this.deliver(msg.from, { type: 'voice_channel_joined', channel_id: ch, participants: [...list], voice_mode: this.voiceMode, ...this.sharersField(ch) });
        for (const o of list) if (o !== msg.from) this.deliver(o, { type: 'voice_peer_joined', channel_id: ch, user_id: msg.from });
        break;
      }
      case 'LeaveVoiceChannel': {
        if (list.includes(msg.from)) {
          this.voice.set(ch, list.filter(u => u !== msg.from));
          this.screenCleanup(ch, msg.from, 'left');
          for (const o of this.voice.get(ch)!) this.deliver(o, { type: 'voice_peer_left', channel_id: ch, user_id: msg.from });
        }
        this.deliver(msg.from, { type: 'voice_channel_left', channel_id: ch, user_id: msg.from });
        break;
      }
      case 'GetVoiceParticipants':
        this.deliver(msg.from, { type: 'voice_participants', channel_id: ch, participants: [...list], voice_mode: this.voiceMode, ...this.sharersField(ch) });
        break;
      case 'ScreenShareStart':
      case 'ScreenShareStop':
      case 'ScreenWatch':
      case 'ScreenKeyframeRequest':
        this.handleScreen(msg, ch, list);
        break;
      case 'VoiceKeyExchange':
        if (typeof b.target_user_id === 'string') {
          this.deliver(b.target_user_id, {
            type: 'voice_key_exchange',
            from: msg.from,
            channel_id: ch,
            wrapped_key: b.wrapped_key,
            sender_ssrc: b.sender_ssrc,
            key_generation: b.key_generation,
            timestamp: ts,
          });
        }
        break;
      case 'SrtpVoicePacket':
        for (const o of list) {
          if (o !== msg.from) this.deliver(o, { type: 'srtp_voice_packet', from: msg.from, channel_id: ch, packet_data: b.packet_data, timestamp: ts });
        }
        break;
      case 'VoiceSpeakingState':
        for (const o of list) {
          if (o !== msg.from) this.deliver(o, { type: 'voice_speaking_state', channel_id: ch, user_id: msg.from, speaking: b.speaking });
        }
        break;
      default:
        break;
    }
  }

  // -------------------------------------------------------------------------
  // The screen path (§6.12), per user
  // -------------------------------------------------------------------------

  private watchMap(ch: string): Map<string, Set<string>> {
    let m = this.watches.get(ch);
    if (!m) {
      m = new Map();
      this.watches.set(ch, m);
    }
    return m;
  }

  /** The users watching `sharer` in `ch`. */
  watchersOf(ch: string, sharer: string): string[] {
    return [...(this.watches.get(ch)?.get(sharer) ?? [])];
  }

  private sendWatchers(ch: string, sharer: string): void {
    const n = this.watches.get(ch)?.get(sharer)?.size ?? 0;
    const key = `${ch}|${sharer}`;
    if (this.lastWatchers.get(key) === n) return;
    this.lastWatchers.set(key, n);
    this.deliver(sharer, { type: 'screen_watchers', channel_id: ch, watchers: n });
  }

  private handleScreen(msg: ClientMessage, ch: string, list: string[]): void {
    const b = msg.body;
    const requestId = b.message_id;
    const u = msg.from;
    const shares = this.shares.get(ch) ?? [];
    switch (msg.type) {
      case 'ScreenShareStart': {
        const reject = (reason: string) => this.deliver(u, { type: 'screen_share_rejected', channel_id: ch, reason, error: reason, request_id: requestId });
        if (!this.screen.enabled) return reject('disabled');
        if (!list.includes(u)) return reject('not_participant');
        if (shares.includes(u)) {
          this.deliver(u, { type: 'screen_share_started', channel_id: ch, user_id: u, request_id: requestId });
          return;
        }
        if (shares.length >= this.screen.maxSharers) return reject('limit');
        this.shares.set(ch, [...shares, u]);
        this.watchMap(ch).set(u, new Set());
        for (const o of list) this.deliver(o, { type: 'screen_share_started', channel_id: ch, user_id: u, ...(o === u ? { request_id: requestId } : {}) });
        this.lastWatchers.delete(`${ch}|${u}`);
        this.sendWatchers(ch, u);
        return;
      }
      case 'ScreenShareStop': {
        if (!shares.includes(u)) return;
        this.endShare(ch, u, 'stopped', requestId);
        return;
      }
      case 'ScreenWatch': {
        const sharer = String(b.sharer_id ?? '').toLowerCase();
        const m = this.watchMap(ch);
        if (b.watch !== true) {
          if (m.get(sharer)?.delete(u)) this.sendWatchers(ch, sharer);
          return;
        }
        const reject = (reason: string) => this.deliver(u, { type: 'screen_watch_rejected', channel_id: ch, sharer_id: sharer, reason, error: reason, request_id: requestId });
        if (!this.screen.enabled) return reject('disabled');
        if (!list.includes(u)) return reject('not_participant');
        if (!shares.includes(sharer) || sharer === u) return reject('not_sharing');
        let mine = 0;
        for (const set of m.values()) if (set.has(u)) mine++;
        if (!m.has(sharer)) m.set(sharer, new Set());
        if (!m.get(sharer)!.has(u) && mine >= 2) return reject('watch_limit');
        m.get(sharer)!.add(u);
        this.sendWatchers(ch, sharer);
        return;
      }
      case 'ScreenKeyframeRequest': {
        const sharer = String(b.sharer_id ?? '').toLowerCase();
        if (!this.watches.get(ch)?.get(sharer)?.has(u) || !list.includes(u)) return;
        const key = `${ch}|${u}|${sharer}`;
        const now = this.clock.now();
        if (now - (this.lastKfr.get(key) ?? -Infinity) < 1000) return;
        this.lastKfr.set(key, now);
        this.deliver(sharer, { type: 'screen_keyframe_request', channel_id: ch, from: u });
        return;
      }
    }
  }

  private endShare(ch: string, sharer: string, reason: string, requestId?: string): void {
    const shares = this.shares.get(ch) ?? [];
    if (!shares.includes(sharer)) return;
    this.shares.set(ch, shares.filter(x => x !== sharer));
    this.watches.get(ch)?.delete(sharer);
    this.lastWatchers.delete(`${ch}|${sharer}`);
    const targets = new Set([...(this.voice.get(ch) ?? []), sharer]);
    for (const o of targets) {
      this.deliver(o, { type: 'screen_share_stopped', channel_id: ch, user_id: sharer, reason, ...(o === sharer && requestId ? { request_id: requestId } : {}) });
    }
  }

  /** §6.12.4: a user leaving C ends its share and its watches. */
  private screenCleanup(ch: string, user: string, reason: string): void {
    this.endShare(ch, user, reason);
    const m = this.watches.get(ch);
    if (!m) return;
    for (const [sharer, set] of m) if (set.delete(user)) this.sendWatchers(ch, sharer);
  }

  /** A binary message from `from` (§6.12.2): a `SCREEN_UP` from a sharer goes to its watchers. */
  receiveBinary(from: string, bytes: Uint8Array): void {
    this.binaryLog.push({ from, bytes: Uint8Array.from(bytes), at: this.clock.now(), bufferedBefore: 0 });
    const up = decodeScreenUp(bytes);
    if (!up || !this.screen.enabled) return;
    const ch = up.channelId;
    if (!(this.shares.get(ch) ?? []).includes(from) || !(this.voice.get(ch) ?? []).includes(from)) return;
    const fragment = Uint8Array.from(up.fragment);
    for (const w of this.watchersOf(ch, from)) {
      if (w === from || !(this.voice.get(ch) ?? []).includes(w)) continue;
      this.queue.push(() => this.deliverFragment(w, ch, from, fragment));
    }
  }

  private deliverFragment(to: string, ch: string, from: string, fragment: Uint8Array): void {
    const s = this.sockets.get(to);
    if (!s || !s.connected || !this.screenFilter(to, from, fragment)) return;
    this.screenDown.push({ to, from, fragment, at: this.clock.now() });
    s.emit('screen_fragment', { channelId: ch, from, fragment: Uint8Array.from(fragment) });
  }

  /** Deliver a `SCREEN_DOWN` to `to` as the relay would (an injection). */
  injectFragment(to: string, ch: string, from: string, fragment: Uint8Array): void {
    this.queue.push(() => this.deliverFragment(to, ch, from, fragment));
  }

  /**
   * `user`'s socket closes: like the baseline relay (C154), it removes the
   * user from every voice channel and tells only the others.
   */
  closeSocket(user: string, opts: { tellOthers?: boolean } = {}): void {
    const s = this.socket(user);
    s.connected = false;
    s.helloSeen = false;
    s.features = [];
    s.limits = null;
    this.dropFromVoice(user, opts.tellOthers ?? true);
    s.emit('disconnected');
  }

  /** A new socket authenticates; its `hello` follows unless `hello` is false. */
  reopenSocket(user: string, opts: { hello?: boolean } = {}): void {
    const s = this.socket(user);
    s.connected = true;
    s.helloSeen = false;
    s.features = [];
    s.limits = null;
    s.emit('authenticated', { user_id: user });
    if (opts.hello ?? true) this.sendHello(user);
  }

  /** The relay drops `user` from voice without telling the user (another socket closed, C154). */
  dropFromVoice(user: string, tellOthers = true): void {
    for (const [ch, list] of this.voice) {
      if (!list.includes(user)) continue;
      const rest = list.filter(u => u !== user);
      this.voice.set(ch, rest);
      this.screenCleanup(ch, user, 'left');
      if (tellOthers) for (const o of rest) this.deliver(o, { type: 'voice_peer_left', channel_id: ch, user_id: user });
    }
  }

  /** Messages of `type` that `from` handed off. */
  sent(from: string, type?: string): ClientMessage[] {
    return this.log.filter(m => m.from === from && (!type || m.type === type));
  }

  /** Every attempt of `user` to send `type`, handed off or not. */
  attempts(user: string, type?: string): ClientMessage[] {
    return (this.sockets.get(user)?.attempts ?? []).filter(m => !type || m.type === type);
  }

  /** Run queued deliveries and asynchronous work until everything is quiet. */
  async settle(): Promise<void> {
    for (let i = 0; i < 10_000; i++) {
      await Promise.all([...this.connections].map(c => c.whenIdle()));
      await new Promise<void>(r => setImmediate(r));
      if (this.queue.length === 0) {
        await Promise.all([...this.connections].map(c => c.whenIdle()));
        await new Promise<void>(r => setImmediate(r));
        if (this.queue.length === 0) return;
      }
      const q = this.queue;
      this.queue = [];
      for (const f of q) f();
    }
    throw new Error('the relay did not settle');
  }

  async advance(ms: number): Promise<void> {
    await this.clock.advance(ms, () => this.settle());
  }
}

// ---------------------------------------------------------------------------
// Media
// ---------------------------------------------------------------------------

/** A PCM plaintext (`codec 0x00 ‖ samples`) whose first two samples are a marker. */
export function pcmMarker(tag: number, n: number, samples = 32): Uint8Array {
  const out = new Uint8Array(1 + 2 * samples);
  const view = new DataView(out.buffer);
  out[0] = 0x00;
  view.setInt16(1, tag, true);
  view.setInt16(3, n, true);
  for (let i = 2; i < samples; i++) view.setInt16(1 + 2 * i, (i * 37) % 1000, true);
  return out;
}

/** A plaintext with another codec byte and the same marker layout. */
export function codecMarker(codec: number, tag: number, n: number, samples = 32): Uint8Array {
  const out = pcmMarker(tag, n, samples);
  out[0] = codec;
  return out;
}

export interface Marker {
  readonly tag: number;
  readonly n: number;
}

export function markerOf(pcm: Int16Array): Marker {
  return { tag: pcm[0], n: pcm[1] };
}

/** A microphone: frames are produced on demand, whatever the mute state (the connection must gate them). */
export class FakeMediaInput implements VoiceMediaInput {
  available = true;
  sink: CaptureSink | null = null;
  muted: boolean | null = null;
  readonly mutedAtStart: boolean[] = [];
  starts = 0;
  stops = 0;

  async start(muted: boolean, sink: CaptureSink): Promise<boolean> {
    this.starts++;
    this.mutedAtStart.push(muted);
    this.muted = muted;
    if (!this.available) return false;
    this.sink = sink;
    return true;
  }

  setMuted(muted: boolean): void {
    this.muted = muted;
  }

  stop(): void {
    this.stops++;
    this.sink = null;
  }

  get active(): boolean {
    return this.sink !== null;
  }

  produce(plaintext: Uint8Array): void {
    this.sink?.frame(Uint8Array.from(plaintext));
  }

  speak(speaking: boolean): void {
    this.sink?.speaking(speaking);
  }
}

/**
 * What the fake "Opus" decoder does with one packet instead of answering:
 * throw from `decode`, report a decoder error (in a microtask, as WebCodecs
 * does), or hold it and never answer.
 */
export type OpusFault = 'throw' | 'error' | 'hold';

/**
 * Playback that records every frame. Its "Opus" decoder, when present,
 * reads the payload as little-endian samples and answers in a microtask,
 * unless `opusFault` returns a fault for the packet.
 */
export class FakeMediaOutput implements VoiceMediaOutput {
  opus: 'missing' | 'echo' = 'missing';
  /** Asked for every packet handed to a decoder; a fault replaces the answer. */
  opusFault: ((data: Uint8Array) => OpusFault | undefined) | null = null;
  readonly played: Array<{ userId: string; pcm: Int16Array }> = [];
  readonly removed: string[] = [];
  deafened: boolean | null = null;
  decodersCreated = 0;
  decodersClosed = 0;
  opened = 0;
  closed = 0;

  async open(): Promise<boolean> {
    this.opened++;
    return true;
  }

  createOpusDecoder(onPcm: (pcm: Int16Array) => void, onError: () => void): AudioDecoderPort | null {
    if (this.opus === 'missing') return null;
    this.decodersCreated++;
    let closed = false;
    return {
      decode: (data: Uint8Array) => {
        const fault = this.opusFault?.(data);
        if (fault === 'throw') throw new Error('decode failed');
        if (fault === 'hold') return;
        if (fault === 'error') {
          queueMicrotask(() => {
            if (!closed) onError();
          });
          return;
        }
        const copy = Uint8Array.from(data);
        queueMicrotask(() => {
          if (closed) return;
          const pcm = new Int16Array(copy.length >> 1);
          const view = new DataView(copy.buffer);
          for (let i = 0; i < pcm.length; i++) pcm[i] = view.getInt16(2 * i, true);
          onPcm(pcm);
        });
      },
      close: () => {
        if (!closed) this.decodersClosed++;
        closed = true;
      },
    };
  }

  play(userId: string, pcm: Int16Array): void {
    this.played.push({ userId, pcm: Int16Array.from(pcm) });
  }

  removeUser(userId: string): void {
    this.removed.push(userId);
  }

  setDeafened(deafened: boolean): void {
    this.deafened = deafened;
  }

  close(): void {
    this.closed++;
  }

  /** Markers played for `from`, in order. */
  markers(from?: string): Marker[] {
    return this.played.filter(p => !from || p.userId === from).map(p => markerOf(p.pcm));
  }
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

export interface VoiceClient {
  readonly id: string;
  readonly sock: FakeVoiceSocket;
  readonly bridge: FakeBridge;
  readonly input: FakeMediaInput;
  readonly output: FakeMediaOutput;
  conn: RelayVoiceConnection;
}

export interface VoiceClientOptions {
  channelId: string;
  nodeId?: string | null;
  muted?: boolean;
  deafened?: boolean;
  bridge?: FakeBridge;
  input?: FakeMediaInput;
  output?: FakeMediaOutput;
  callTimings?: Partial<CallKeyTimings>;
  voiceTimings?: Partial<RelayVoiceTimings>;
  random?: RelayVoiceOptions['random'];
  /** Screen capture, codecs and renderer (the screen fakes of §10.1). */
  screen?: ScreenPlatform;
}

/** A client with its own socket, bridge and media, tracked by the relay's `settle`. */
export function voiceClient(relay: FakeVoiceRelay, id: string, opts: VoiceClientOptions): VoiceClient {
  const sock = relay.socket(id);
  const bridge = opts.bridge ?? new FakeBridge(id);
  const input = opts.input ?? new FakeMediaInput();
  const output = opts.output ?? new FakeMediaOutput();
  const conn = new RelayVoiceConnection({
    ws: sock as never,
    channelId: opts.channelId,
    nodeId: opts.nodeId === undefined ? NODE : opts.nodeId,
    bridge,
    muted: opts.muted ?? false,
    deafened: opts.deafened ?? false,
    input,
    output,
    clock: relay.clock,
    callTimings: opts.callTimings,
    voiceTimings: opts.voiceTimings,
    random: opts.random,
    screen: opts.screen,
  });
  relay.track(conn);
  return { id, sock, bridge, input, output, conn };
}

// ---------------------------------------------------------------------------
// T-27: what no spy may see
// ---------------------------------------------------------------------------

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/** Standard base64, base64url without padding, hex and the raw bytes as a string. */
export function encodingsOf(bytes: Uint8Array): string[] {
  const b64 = encodeBase64(bytes);
  return [b64, b64.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'), hexOf(bytes), String.fromCharCode(...bytes)];
}

/**
 * Every encoding of the epoch secrets and instance ids that the call
 * messages in `log` carried, and those messages' plaintexts (T-27, REQ-27).
 */
export function callSecretsIn(log: readonly ClientMessage[]): { forms: string[]; plaintexts: string[] } {
  const forms = new Set<string>();
  const plaintexts = new Set<string>();
  for (const m of log) {
    if (m.type !== 'VoiceKeyExchange' || typeof m.body.wrapped_key !== 'string') continue;
    plaintexts.add(fakePlaintextOf(m.body.wrapped_key));
    const body = readCall(m.body.wrapped_key);
    for (const field of ['key', 'inst', 'to_inst'] as const) {
      const v = body[field];
      const bytes = typeof v === 'string' ? decodeWireBase64(v) : null;
      if (bytes) for (const f of encodingsOf(bytes)) forms.add(f);
    }
  }
  return { forms: [...forms], plaintexts: [...plaintexts] };
}

/** One spy call as text: strings as they are, bytes in every encoding, objects as JSON. */
export function spyText(args: readonly unknown[]): string {
  const bytesOf = (v: unknown): Uint8Array | null =>
    v instanceof Uint8Array ? v : v instanceof ArrayBuffer ? new Uint8Array(v) : ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength) : null;
  return args
    .map(a => {
      if (typeof a === 'string') return a;
      if (a instanceof Error) return `${a.message} ${a.stack ?? ''}`;
      const bytes = bytesOf(a);
      if (bytes) return encodingsOf(bytes).join(' ');
      try {
        return JSON.stringify(a, (_k, v) => {
          const b = bytesOf(v);
          return b ? encodingsOf(b).join(' ') : v;
        });
      } catch {
        return String(a);
      }
    })
    .join(' ');
}
