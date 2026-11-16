/**
 * @module voice/callKeys.testkit
 * Test support for `CallKeyManager` (SPEC-03 §10.1, U tests): a manual
 * clock, a fake E2EE bridge, and an in-memory relay that connects several
 * managers, records every call message and media frame, and can drop,
 * withhold or inject them. Imported by tests only; nothing in the app
 * imports it.
 */

import { encodeBase64, decodeWireBase64 } from '../attachments/base64';
import { classifyFor, strictToPlain, encodeControlPayloadFor, type ControlBody } from '../e2ee/plaintext';
import { CALL_CHAIN_LIMIT, type CallKeyBridge, type DecryptResult, type EncryptResult, type Eligibility, type HeadClaim, type IdentityLabel, type MembershipCause } from './callKeyBridge';
import {
  CALL_ENVELOPE_PREFIX,
  CallKeyManager,
  type CallClock,
  type CallKeyHooks,
  type CallKeyManagerOptions,
  type CallKeyTimings,
  type ReceivedAudioFrame,
  type RemoteResetCause,
} from './callKeys';

export const CH = '00000000-0000-4000-8000-0000000000c1';
export const CH2 = '00000000-0000-4000-8000-0000000000c2';
export const NODE = '00000000-0000-4000-8000-0000000000e1';
export const NODE2 = '00000000-0000-4000-8000-0000000000e2';
export const A = '00000000-0000-4000-8000-0000000000a1';
export const B = '00000000-0000-4000-8000-0000000000a2';
export const C = '00000000-0000-4000-8000-0000000000a3';
export const D = '00000000-0000-4000-8000-0000000000a4';
export const E = '00000000-0000-4000-8000-0000000000a5';

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

interface Timer {
  readonly at: number;
  readonly seq: number;
  readonly fn: () => void;
}

/** A manual clock: timers run only inside `advance`, in time order. */
export class ManualClock implements CallClock {
  private t = 1_000_000;
  private seq = 0;
  private readonly timers = new Map<number, Timer>();

  now(): number {
    return this.t;
  }

  setTimeout(fn: () => void, ms: number): unknown {
    const id = ++this.seq;
    this.timers.set(id, { at: this.t + Math.max(0, ms), seq: id, fn });
    return id;
  }

  clearTimeout(handle: unknown): void {
    this.timers.delete(handle as number);
  }

  get pendingTimers(): number {
    return this.timers.size;
  }

  /** Run every timer due within `ms`, settling asynchronous work after each. */
  async advance(ms: number, settle: () => Promise<void> = async () => undefined): Promise<void> {
    const target = this.t + ms;
    await settle();
    for (;;) {
      let next: [number, Timer] | null = null;
      for (const entry of this.timers) {
        const tm = entry[1];
        if (tm.at > target) continue;
        if (!next || tm.at < next[1].at || (tm.at === next[1].at && tm.seq < next[1].seq)) next = entry;
      }
      if (!next) break;
      this.timers.delete(next[0]);
      this.t = Math.max(this.t, next[1].at);
      next[1].fn();
      await settle();
    }
    this.t = target;
    await settle();
  }
}

// ---------------------------------------------------------------------------
// Fake bridge
// ---------------------------------------------------------------------------

/** The fake "envelope": the plaintext in the clear, with a sequence number. */
interface FakeEnvelope {
  readonly from: string;
  readonly to: string;
  readonly n: number;
  readonly pt: string;
}

let envelopeSeq = 0;

export function fakeEnvelope(from: string, to: string, plaintext: string): string {
  return JSON.stringify({ from, to, n: ++envelopeSeq, pt: plaintext } satisfies FakeEnvelope);
}

/**
 * A bridge with programmable membership, sessions and chain lengths. Its
 * "encryption" puts the plaintext in the envelope as is, so tests can read
 * every call message. Every peer is a member with a session unless set
 * otherwise.
 */
export class FakeBridge implements CallKeyBridge {
  ready = true;
  ruleValue: 'interim' | 'final' = 'interim';
  pinned = false;
  withheld = false;
  /** Membership per peer; peers not listed are members. */
  readonly membershipOf = new Map<string, 'member' | 'not_member' | 'unknown'>();
  /** Extra ineligibility (SPEC-05 states etc.), checked after membership. */
  readonly ineligible = new Map<string, Eligibility & { eligible: false }>();
  /** Peers without a usable session. */
  readonly noSession = new Set<string>();
  /** Chain lengths per peer; every encryption adds 1, decryption resets when `resetOnReceive`. */
  readonly chain = new Map<string, number>();
  resetOnReceive = false;
  /** Envelope sequence numbers to report as decrypted with a skipped key. */
  readonly skipped = new Set<number>();
  /** Envelope sequence numbers whose decryption fails. */
  readonly failing = new Set<number>();
  /** Peers whose bundle fetch fails. */
  readonly noBundle = new Set<string>();
  readonly encryptCalls: Array<{ peer: string; plaintext: string; useCredit: boolean }> = [];
  readonly decryptCalls: Array<{ peer: string; n: number }> = [];
  readonly refreshCalls: Array<{ node: string; cause: MembershipCause }> = [];
  initiations = 0;
  refreshFails = false;
  head: HeadClaim | null = null;
  readonly offeredHeads: Array<{ node: string; from: string; head: HeadClaim }> = [];
  sessionVersion: 'legacy' | 'v2' = 'legacy';
  peerIsk: Uint8Array | null = null;
  readonly pins = new Map<string, Uint8Array>();
  readonly rosterIsks = new Map<string, Uint8Array>();
  private readonly elig = new Set<(node: string) => void>();
  private readonly usable = new Set<(peer: string) => void>();
  private readonly self: string;

  constructor(self: string) {
    this.self = self;
  }

  isReady(): boolean {
    return this.ready;
  }
  selfId(): string {
    return this.self;
  }
  rule(): 'interim' | 'final' {
    return this.ruleValue;
  }
  pinnedSessionsOnly(): boolean {
    return this.pinned;
  }
  hasUsableSession(peer: string): boolean {
    return !this.noSession.has(peer);
  }
  sendingChainLength(peer: string): number | null {
    return this.noSession.has(peer) ? null : (this.chain.get(peer) ?? 0);
  }

  async encryptFor(peer: string, plaintext: string, useCredit: boolean): Promise<EncryptResult> {
    this.encryptCalls.push({ peer, plaintext, useCredit });
    if (!this.ready) return { ok: false, error: 'store_locked' };
    if (this.noSession.has(peer)) {
      if (!(this.self < peer)) return { ok: false, error: 'await_peer' };
      if (this.noBundle.has(peer)) return { ok: false, error: 'bundle_unavailable' };
      this.noSession.delete(peer);
      this.initiations++;
    }
    const len = this.chain.get(peer) ?? 0;
    if (len >= CALL_CHAIN_LIMIT && !useCredit) return { ok: false, error: 'chain_limit' };
    this.chain.set(peer, len + 1);
    return { ok: true, envelope: fakeEnvelope(this.self, peer, plaintext) };
  }

  decryptFrom(peer: string, envelope: string): Promise<DecryptResult> {
    let env: FakeEnvelope;
    try {
      env = JSON.parse(envelope) as FakeEnvelope;
    } catch {
      return Promise.resolve({ ok: false, error: 'decrypt_failed' });
    }
    this.decryptCalls.push({ peer, n: env.n });
    if (this.failing.has(env.n)) return Promise.resolve({ ok: false, error: 'decrypt_failed' });
    if (this.noSession.has(peer)) {
      this.noSession.delete(peer);
      queueMicrotask(() => this.usable.forEach(l => l(peer)));
    }
    if (this.resetOnReceive) this.chain.set(peer, 0);
    return Promise.resolve({
      ok: true,
      plaintext: env.pt,
      usedSkippedKey: this.skipped.has(env.n),
      sessionVersion: this.sessionVersion,
      peer: { isk: this.peerIsk, ik: new Uint8Array(32) },
    });
  }

  membership(_node: string, _channel: string, peer: string): 'member' | 'not_member' | 'unknown' {
    return this.membershipOf.get(peer) ?? 'member';
  }

  eligibility(node: string, channel: string, peer: string): Eligibility {
    if (peer === this.self) return { eligible: false, reason: 'not_in_view' };
    const m = this.membership(node, channel, peer);
    if (m === 'unknown') return { eligible: false, reason: 'membership_unknown' };
    if (m === 'not_member') return { eligible: false, reason: 'not_member' };
    return this.ineligible.get(peer) ?? { eligible: true };
  }

  refreshMembership(node: string, cause: MembershipCause): Promise<void> {
    this.refreshCalls.push({ node, cause });
    return this.refreshFails ? Promise.reject(new Error('fetch failed')) : Promise.resolve();
  }

  governanceHead(): HeadClaim | null {
    return this.head;
  }
  offerHead(node: string, from: string, head: HeadClaim): void {
    this.offeredHeads.push({ node, from, head });
  }
  identityLabel(peer: string): IdentityLabel {
    return { shortId: peer.replace(/-/g, '').slice(0, 8), verified: this.verified.has(peer) };
  }
  readonly verified = new Set<string>();
  pinnedIsk(peer: string): Uint8Array | null {
    return this.pins.get(peer) ?? null;
  }
  rosterIsk(_node: string, peer: string): Uint8Array | null {
    return this.rosterIsks.get(peer) ?? null;
  }
  audienceWithheld(): boolean {
    return this.withheld;
  }

  onEligibilityChange(listener: (node: string) => void): () => void {
    this.elig.add(listener);
    return () => this.elig.delete(listener);
  }
  onSessionUsable(listener: (peer: string) => void): () => void {
    this.usable.add(listener);
    return () => this.usable.delete(listener);
  }

  /** Change membership and fire the eligibility listeners synchronously. */
  setMembership(peer: string, m: 'member' | 'not_member' | 'unknown', node: string = NODE): void {
    this.membershipOf.set(peer, m);
    this.emitEligibility(node);
  }

  emitEligibility(node: string = NODE): void {
    for (const l of [...this.elig]) l(node);
  }

  emitSessionUsable(peer: string): void {
    for (const l of [...this.usable]) l(peer);
  }
}

// ---------------------------------------------------------------------------
// Reading and making call messages
// ---------------------------------------------------------------------------

/** A call message's JSON body, read from a fake envelope's plaintext. */
export type CallBody = Record<string, unknown> & { type: string };

/** The plaintext inside a `wrapped_key` produced with the fake bridge. */
export function fakePlaintextOf(wrappedKey: string): string {
  if (!wrappedKey.startsWith(CALL_ENVELOPE_PREFIX)) throw new Error('not a call message');
  const raw = decodeWireBase64(wrappedKey.slice(CALL_ENVELOPE_PREFIX.length));
  if (!raw) throw new Error('bad base64');
  return (JSON.parse(new TextDecoder().decode(raw)) as FakeEnvelope).pt;
}

/** The body of a call message sent through the fake bridge. */
export function readCall(wrappedKey: string): CallBody {
  const c = classifyFor('voice', fakePlaintextOf(wrappedKey));
  if (!c || c.class !== 'control' || !c.valid) throw new Error('not a call payload');
  return strictToPlain(c.body) as CallBody;
}

/** A `wrapped_key` carrying `plaintext` in a fake envelope. */
export function wrapFake(from: string, to: string, plaintext: string): string {
  return CALL_ENVELOPE_PREFIX + encodeBase64(new TextEncoder().encode(fakeEnvelope(from, to, plaintext)));
}

/** A valid call payload plaintext. */
export function callPlaintext(body: Record<string, unknown>): string {
  return encodeControlPayloadFor('voice', body as unknown as ControlBody);
}

export function b64(bytes: Uint8Array): string {
  return encodeBase64(bytes);
}

// ---------------------------------------------------------------------------
// In-memory relay
// ---------------------------------------------------------------------------

export interface CallRecord {
  readonly from: string;
  readonly to: string;
  readonly channel: string;
  readonly wrappedKey: string;
  readonly at: number;
}

export interface MediaRecord {
  readonly from: string;
  readonly channel: string;
  readonly frame: Uint8Array;
  readonly at: number;
}

export type Verdict = 'deliver' | 'drop' | 'withhold';

export interface Heard extends ReceivedAudioFrame {
  readonly from: string;
}

export class Client {
  readonly id: string;
  readonly bridge: CallKeyBridge;
  mgr: CallKeyManager;
  connected = true;
  readonly heard: Heard[] = [];
  readonly resets: Array<{ from: string; cause: RemoteResetCause }> = [];
  readonly switches: number[] = [];
  readonly installed: Array<{ from: string; epoch: number }> = [];
  readonly fragments: Array<{ from: string; kid: number; plaintext: Uint8Array }> = [];
  readonly videoFailures: Array<{ from: string; consecutive: number }> = [];
  readonly rejoins: string[] = [];
  readonly watching = new Set<string>();
  decryptBudget = Infinity;
  stateChanges = 0;

  constructor(id: string, bridge: CallKeyBridge, mgr: CallKeyManager) {
    this.id = id;
    this.bridge = bridge;
    this.mgr = mgr;
  }

  get fake(): FakeBridge {
    if (!(this.bridge instanceof FakeBridge)) throw new Error('not a fake bridge');
    return this.bridge;
  }
}

export interface ClientOptions {
  bridge?: CallKeyBridge;
  channelId?: string;
  nodeId?: string;
  timings?: Partial<CallKeyTimings>;
  random?: (n: number) => Uint8Array;
  seal?: CallKeyManagerOptions['seal'];
  counterStart?: CallKeyManagerOptions['counterStart'];
  hooks?: Partial<CallKeyHooks>;
}

/** Connects managers like the relay does, one FIFO queue for everything. */
export class Net {
  readonly clock = new ManualClock();
  readonly clients = new Map<string, Client>();
  readonly calls: CallRecord[] = [];
  readonly media: MediaRecord[] = [];
  readonly withheld: CallRecord[] = [];
  /** Decide each call message's fate. */
  callFilter: (m: CallRecord) => Verdict = () => 'deliver';
  /** False makes the transport report a call message as not handed off (REQ-37). */
  handOff: (m: CallRecord) => boolean = () => true;
  /** Decide each media frame's fate per receiver. */
  mediaFilter: (m: MediaRecord, to: string) => boolean = () => true;
  private queue: Array<() => void> = [];

  client(id: string, opts: ClientOptions = {}): Client {
    const bridge = opts.bridge ?? new FakeBridge(id);
    let client: Client | null = null;
    const mgr = this.manager(id, bridge, this.hooksFor(() => client!, opts), opts);
    client = new Client(id, bridge, mgr);
    this.clients.set(id, client);
    return client;
  }

  /** A new manager for an existing client: a new call and instance (REQ-5). */
  newCall(c: Client, opts: ClientOptions = {}): CallKeyManager {
    c.mgr.end();
    c.mgr = this.manager(c.id, c.bridge, this.hooksFor(() => c, opts), opts);
    return c.mgr;
  }

  private hooksFor(get: () => Client, opts: ClientOptions): CallKeyHooks {
    return {
      onAudioFrame: (from, f) => get().heard.push({ from, ...f }),
      isWatching: from => get().watching.has(from),
      takeVideoDecryption: () => {
        const c = get();
        if (c.decryptBudget <= 0) return false;
        c.decryptBudget--;
        return true;
      },
      onVideoFragment: (from, kid, plaintext) => get().fragments.push({ from, kid, plaintext }),
      onVideoAeadFailures: (from, consecutive) => get().videoFailures.push({ from, consecutive }),
      onRemoteReset: (from, cause) => get().resets.push({ from, cause }),
      onRemoteKeyInstalled: (from, epoch) => get().installed.push({ from, epoch }),
      onEpochSwitch: epoch => get().switches.push(epoch),
      onRejoinNeeded: cause => get().rejoins.push(cause),
      onStateChange: () => {
        const c = get();
        if (c) c.stateChanges++;
      },
      ...(opts.hooks ?? {}),
    };
  }

  private manager(id: string, bridge: CallKeyBridge, hooks: CallKeyHooks, opts: ClientOptions): CallKeyManager {
    return new CallKeyManager({
      channelId: opts.channelId ?? CH,
      nodeId: opts.nodeId ?? NODE,
      bridge,
      clock: this.clock,
      hooks,
      timings: opts.timings,
      random: opts.random,
      seal: opts.seal,
      counterStart: opts.counterStart,
      transport: {
        sendCallMessage: (channel, to, wrappedKey) => {
          const c = this.clients.get(id);
          if (c && !c.connected) return false;
          const rec: CallRecord = { from: id, to, channel, wrappedKey, at: this.clock.now() };
          if (!this.handOff(rec)) return false;
          this.calls.push(rec);
          const verdict = this.callFilter(rec);
          if (verdict === 'withhold') this.withheld.push(rec);
          else if (verdict === 'deliver') this.queue.push(() => this.deliverCall(rec));
          return true;
        },
        sendMediaFrame: (channel, frame) => {
          const c = this.clients.get(id);
          if (c && !c.connected) return false;
          const rec: MediaRecord = { from: id, channel, frame: Uint8Array.from(frame), at: this.clock.now() };
          this.media.push(rec);
          this.queue.push(() => this.deliverMedia(rec));
          return true;
        },
      },
    });
  }

  /** Deliver one recorded call message now (a withheld or recorded one, for replays). */
  deliverCall(rec: CallRecord): void {
    const to = this.clients.get(rec.to);
    if (!to || !to.connected) return;
    to.mgr.handleKeyExchange({ from: rec.from, channel_id: rec.channel, wrapped_key: rec.wrappedKey });
  }

  deliverMedia(rec: MediaRecord, only?: string): void {
    for (const c of this.clients.values()) {
      if (c.id === rec.from || !c.connected || (only && c.id !== only)) continue;
      if (!this.mediaFilter(rec, c.id)) continue;
      c.mgr.receiveAudioFrame(rec.from, rec.channel, rec.frame);
    }
  }

  /** Inject a call message as the relay would deliver it. */
  inject(to: string, from: string, wrappedKey: string, channel: string = CH): void {
    this.queue.push(() => this.clients.get(to)?.mgr.handleKeyExchange({ from, channel_id: channel, wrapped_key: wrappedKey }));
  }

  /** Run queued deliveries and asynchronous work until everything is quiet. */
  async settle(): Promise<void> {
    for (let i = 0; i < 10_000; i++) {
      await Promise.all([...this.clients.values()].map(c => c.mgr.whenIdle()));
      await new Promise<void>(r => setImmediate(r));
      if (this.queue.length === 0) {
        await Promise.all([...this.clients.values()].map(c => c.mgr.whenIdle()));
        if (this.queue.length === 0) return;
      }
      const q = this.queue;
      this.queue = [];
      for (const f of q) f();
    }
    throw new Error('the network did not settle');
  }

  async advance(ms: number): Promise<void> {
    await this.clock.advance(ms, () => this.settle());
  }

  /** Everyone in `ids` joins C at once: each gets `voice_channel_joined` listing the others. */
  async join(...ids: string[]): Promise<void> {
    for (const id of ids) {
      const c = this.clients.get(id)!;
      c.mgr.start();
      c.mgr.onJoined(ids.filter(x => x !== id));
    }
    await this.settle();
  }

  /** `id` joins an existing call of `others`. */
  async joinLate(id: string, others: string[]): Promise<void> {
    for (const o of others) this.clients.get(o)!.mgr.onPeerJoined(id);
    const c = this.clients.get(id)!;
    c.mgr.start();
    c.mgr.onJoined(others);
    await this.settle();
  }

  /** Call messages from `from` to `to`, read with the fake bridge, optionally of one type. */
  callsBetween(from: string, to: string, type?: string): Array<CallRecord & { body: CallBody }> {
    return this.calls
      .filter(m => m.from === from && m.to === to)
      .map(m => ({ ...m, body: readCall(m.wrappedKey) }))
      .filter(m => !type || m.body.type === type);
  }
}

/** A distinct 16-byte instance for tests. */
export function testInst(seed: number): Uint8Array {
  const b = new Uint8Array(16);
  b.fill(seed & 0xff);
  b[0] = 0xa0;
  return b;
}
