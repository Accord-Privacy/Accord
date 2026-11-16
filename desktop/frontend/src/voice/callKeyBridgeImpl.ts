/**
 * @module voice/callKeyBridgeImpl
 * The E2EE bridge of SPEC-03 §6.10 for clients without SPEC-05 and SPEC-06:
 * the interim rule of REQ-9.
 *
 * - Sessions: the existing Double Ratchet sessions of `E2EEManager`. Without
 *   a session the lower user id initiates from the relay-served prekey
 *   bundle; the higher id waits for the peer (REQ-10). Every legacy session
 *   is usable (§5.1, before SPEC-05).
 * - Membership (REQ-9 (b)): the relay's member list and channel list of the
 *   call's node N (`GET /nodes/:id/members`, `GET /nodes/:id/channels`),
 *   cached per node, fetched at call start and on the manager's timer, and
 *   on `member_joined`, `sender_key_rotation_required` and members missing
 *   from the list, those coalesced to one fetch per 5 s per node. A trigger
 *   that arrives while a fetch is running gets one more fetch after it.
 *   The call-start fetch is authoritative: the lists an earlier call cached
 *   answer nothing until it completes, so nobody is eligible while it runs
 *   or after it fails. `sender_key_rotation_required` for any channel of N
 *   excludes the named user at once, until a fetch that started after the
 *   event lists the user again.
 * - Identity labels: the short id only; nobody is verified (§8.1 "not verified").
 *
 * One instance serves the app (App.tsx) or a test client. Nothing here logs
 * or stores a plaintext or an envelope (REQ-13, REQ-27).
 */

import type { E2EEManager, PreKeyBundle } from '../e2ee';
import {
  CALL_CHAIN_LIMIT,
  shortIdOf,
  systemCallClock,
  type CallClock,
  type CallKeyBridge,
  type DecryptResult,
  type Eligibility,
  type EncryptResult,
  type HeadClaim,
  type IdentityLabel,
  type MembershipCause,
  type Uuid,
} from './callKeyBridge';

/** `MEMBER_REFETCH_MIN`: event-triggered and on-demand fetches per node (REQ-9). */
export const MEMBER_REFETCH_MIN_MS = 5000;
/** How long a rotation event for a channel of a not-yet-listed node is remembered. */
const PENDING_EVENT_MS = 120_000;
const PENDING_EVENTS_MAX = 256;

export interface CallKeyBridgeDeps {
  /** The app's E2EE manager, or null before it is initialized. */
  e2ee(): E2EEManager | null;
  /** The local user id, or null when signed out. */
  selfId(): string | null;
  /** The relay-served prekey bundle of `peer` (cached by the caller), or undefined. */
  fetchBundle(peer: string): Promise<PreKeyBundle | undefined>;
  /** `GET /nodes/:id/members`: the member user ids. Rejects on failure. */
  fetchMembers(node: string): Promise<readonly string[]>;
  /** `GET /nodes/:id/channels`: the channel ids. Rejects on failure. */
  fetchChannels(node: string): Promise<readonly string[]>;
  clock?: CallClock;
  /** `MEMBER_REFETCH_MIN`; tests may shorten it. */
  refetchMinMs?: number;
}

interface NodeState {
  members: Set<string> | null;
  channels: Set<string> | null;
  inFlight: Promise<void> | null;
  lastStartedAt: number;
  scheduled: { timer: unknown; promise: Promise<void> } | null;
  /** An event or on-demand trigger arrived while a fetch was running: it needs a fetch that starts after it (REQ-9). */
  followUp: boolean;
  /** user → sequence number of the rotation event that excluded it. */
  readonly excluded: Map<string, number>;
  /** Members missing from the list: 'requested' until a fetch that started after the request completes. */
  readonly missing: Map<string, { state: 'requested' | 'checked'; seq: number }>;
}

const lower = (s: string) => s.toLowerCase();

export class CallKeyBridgeImpl implements CallKeyBridge {
  private readonly deps: CallKeyBridgeDeps;
  private readonly clock: CallClock;
  private readonly refetchMinMs: number;
  private readonly nodes = new Map<string, NodeState>();
  private readonly eligibilityListeners = new Set<(node: Uuid) => void>();
  private readonly sessionListeners = new Set<(peer: Uuid) => void>();
  private pendingEvents: Array<{ channel: string; user: string; at: number; seq: number }> = [];
  /** Orders events and fetch starts: "a fetch that started after the event" (REQ-9). */
  private seq = 0;

  constructor(deps: CallKeyBridgeDeps) {
    this.deps = deps;
    this.clock = deps.clock ?? systemCallClock;
    this.refetchMinMs = deps.refetchMinMs ?? MEMBER_REFETCH_MIN_MS;
  }

  // -------------------------------------------------------------------------
  // Sessions
  // -------------------------------------------------------------------------

  isReady(): boolean {
    return !!this.deps.e2ee()?.isInitialized && !!this.deps.selfId();
  }

  selfId(): Uuid {
    return lower(this.deps.selfId() ?? '');
  }

  rule(): 'interim' | 'final' {
    return 'interim';
  }

  pinnedSessionsOnly(): boolean {
    return false;
  }

  hasUsableSession(peer: Uuid): boolean {
    return this.deps.e2ee()?.hasSession(peer) ?? false;
  }

  sendingChainLength(peer: Uuid): number | null {
    return this.deps.e2ee()?.sendingChainLength(peer) ?? null;
  }

  async encryptFor(peer: Uuid, plaintext: string, useCredit: boolean): Promise<EncryptResult> {
    let mgr = this.deps.e2ee();
    if (!mgr?.isInitialized) return { ok: false, error: 'store_locked' };
    let bundle: PreKeyBundle | undefined;
    const had = mgr.hasSession(peer);
    if (!had) {
      // REQ-10: only the lower id initiates; ids compare as lowercase strings, by code unit.
      if (!(this.selfId() < lower(peer))) return { ok: false, error: 'await_peer' };
      try {
        bundle = await this.deps.fetchBundle(peer);
      } catch {
        bundle = undefined;
      }
      mgr = this.deps.e2ee();
      if (!mgr?.isInitialized) return { ok: false, error: 'store_locked' };
      if (!bundle && !mgr.hasSession(peer)) return { ok: false, error: 'bundle_unavailable' };
    }
    const len = mgr.sendingChainLength(peer);
    if (len !== null && len >= CALL_CHAIN_LIMIT && !useCredit) return { ok: false, error: 'chain_limit' };
    const before = mgr.hasSession(peer);
    let envelope: string;
    try {
      // `encryptEnvelope` re-checks the session synchronously, so two
      // concurrent first messages cannot both initiate.
      envelope = mgr.encryptEnvelope(peer, plaintext, bundle);
    } catch {
      return { ok: false, error: mgr.hasSession(peer) ? 'store_locked' : 'bundle_unavailable' };
    }
    if (!before) this.emitSessionUsable(peer);
    return { ok: true, envelope };
  }

  decryptFrom(peer: Uuid, envelope: string): Promise<DecryptResult> {
    const mgr = this.deps.e2ee();
    if (!mgr?.isInitialized) return Promise.resolve({ ok: false, error: 'store_locked' });
    const had = mgr.hasSession(peer);
    let plaintext: string;
    let usedSkippedKey: boolean;
    try {
      // Synchronous before SPEC-05: the call itself fixes the Double Ratchet order.
      ({ plaintext, usedSkippedKey } = mgr.decryptEnvelopeDetailed(peer, envelope));
    } catch {
      return Promise.resolve({ ok: false, error: had ? 'decrypt_failed' : 'no_session' });
    }
    if (!had && mgr.hasSession(peer)) this.emitSessionUsable(peer);
    return Promise.resolve({
      ok: true,
      plaintext,
      usedSkippedKey,
      sessionVersion: 'legacy',
      // Legacy sessions keep no peer identity key; nothing reads it before SPEC-05.
      peer: { isk: null, ik: new Uint8Array(0) },
    });
  }

  // -------------------------------------------------------------------------
  // Membership (REQ-9)
  // -------------------------------------------------------------------------

  membership(node: Uuid, channel: Uuid, peer: Uuid): 'member' | 'not_member' | 'unknown' {
    const st = this.nodes.get(lower(node));
    if (!st || !st.members || !st.channels) return st && this.pending(st) ? 'unknown' : 'not_member';
    const u = lower(peer);
    if (!st.channels.has(lower(channel))) return 'not_member';
    if (st.excluded.has(u)) return 'not_member';
    if (st.members.has(u)) return 'member';
    // A member of V missing from the cached list triggers a re-fetch (REQ-9).
    const m = st.missing.get(u);
    if (m?.state === 'checked') return 'not_member';
    if (!m) {
      st.missing.set(u, { state: 'requested', seq: ++this.seq });
      this.refreshMembership(node, 'on_demand').catch(() => undefined);
    }
    return this.pending(st) ? 'unknown' : 'not_member';
  }

  eligibility(node: Uuid, channel: Uuid, peer: Uuid): Eligibility {
    const u = lower(peer);
    if (u === this.selfId()) return { eligible: false, reason: 'not_in_view' };
    const st = this.nodes.get(lower(node));
    if (st?.channels && !st.channels.has(lower(channel))) return { eligible: false, reason: 'channel_not_in_node' };
    switch (this.membership(node, channel, peer)) {
      case 'member':
        return { eligible: true };
      case 'unknown':
        return { eligible: false, reason: 'membership_unknown' };
      default:
        return { eligible: false, reason: 'not_member' };
    }
  }

  refreshMembership(node: Uuid, cause: MembershipCause): Promise<void> {
    const n = lower(node);
    const st = this.state(n);
    if (cause === 'call_start') {
      // REQ-9: "If the list cannot be fetched at call start, no participant
      // is eligible until it can." Lists cached by an earlier call on N
      // answer nothing from now on: `membership` says 'unknown' while this
      // fetch runs and 'not_member' if it fails. Exclusions stay until a
      // fetch that started after their event lists the user again.
      st.members = null;
      st.channels = null;
      st.missing.clear();
    }
    if (st.inFlight) {
      // The running fetch started before this trigger, so it cannot answer it.
      if (cause === 'event' || cause === 'on_demand') st.followUp = true;
      return st.inFlight;
    }
    if (cause === 'event' || cause === 'on_demand') {
      if (st.scheduled) return st.scheduled.promise;
      const wait = st.lastStartedAt + this.refetchMinMs - this.clock.now();
      if (wait > 0) {
        let resolve!: () => void;
        let reject!: (e: unknown) => void;
        const promise = new Promise<void>((res, rej) => {
          resolve = res;
          reject = rej;
        });
        promise.catch(() => undefined);
        const timer = this.clock.setTimeout(() => {
          st.scheduled = null;
          this.fetch(n).then(resolve, reject);
        }, wait);
        st.scheduled = { timer, promise };
        return promise;
      }
    }
    return this.fetch(n);
  }

  /**
   * `sender_key_rotation_required` (REQ-9): if the channel belongs to a
   * tracked node, exclude `removedUserId` there at once and re-fetch.
   * Listeners run synchronously, so the manager's rotation begins in the
   * same event-loop turn (REQ-16 (c)).
   */
  noteRotationRequired(channelId: string, removedUserId: string): void {
    if (typeof channelId !== 'string' || typeof removedUserId !== 'string') return;
    const ch = lower(channelId);
    const user = lower(removedUserId);
    const now = this.clock.now();
    const seq = ++this.seq;
    let matched = false;
    for (const [node, st] of this.nodes) {
      if (!st.channels?.has(ch)) continue;
      matched = true;
      st.excluded.set(user, seq);
      this.emitEligibility(node);
      this.refreshMembership(node, 'event').catch(() => undefined);
    }
    if (!matched) {
      // The node's channel list may not be known yet: apply it when it is.
      this.pendingEvents.push({ channel: ch, user, at: now, seq });
      this.pendingEvents = this.pendingEvents.filter(e => now - e.at < PENDING_EVENT_MS).slice(-PENDING_EVENTS_MAX);
    }
  }

  /** `member_joined` for a node: a refresh hint (REQ-9). */
  noteMemberJoined(nodeId: string): void {
    if (typeof nodeId !== 'string') return;
    const n = lower(nodeId);
    if (this.nodes.has(n)) this.refreshMembership(n, 'event').catch(() => undefined);
  }

  private state(node: string): NodeState {
    let st = this.nodes.get(node);
    if (!st) {
      st = {
        members: null,
        channels: null,
        inFlight: null,
        lastStartedAt: -Infinity,
        scheduled: null,
        followUp: false,
        excluded: new Map(),
        missing: new Map(),
      };
      this.nodes.set(node, st);
    }
    return st;
  }

  private pending(st: NodeState): boolean {
    return st.inFlight !== null || st.scheduled !== null;
  }

  private fetch(node: string): Promise<void> {
    const st = this.state(node);
    if (st.inFlight) return st.inFlight;
    const startedAt = this.clock.now();
    const startSeq = ++this.seq;
    st.lastStartedAt = startedAt;
    const run = (async () => {
      try {
        const [members, channels] = await Promise.all([this.deps.fetchMembers(node), this.deps.fetchChannels(node)]);
        st.members = new Set(members.filter(m => typeof m === 'string').map(lower));
        st.channels = new Set(channels.filter(c => typeof c === 'string').map(lower));
        for (const [user, seq] of st.excluded) {
          if (startSeq > seq && st.members.has(user)) st.excluded.delete(user);
        }
        for (const [user, m] of st.missing) {
          if (st.members.has(user)) st.missing.delete(user);
          else if (m.state === 'requested' && startSeq > m.seq) st.missing.set(user, { state: 'checked', seq: m.seq });
        }
        const keep: typeof this.pendingEvents = [];
        for (const e of this.pendingEvents) {
          if (!st.channels.has(e.channel)) {
            keep.push(e);
            continue;
          }
          if (!(startSeq > e.seq && st.members.has(e.user))) st.excluded.set(e.user, e.seq);
        }
        this.pendingEvents = keep;
      } finally {
        st.inFlight = null;
        // Events, and members found missing, while this fetch was running
        // need one more (coalesced like any event-triggered fetch), whether
        // or not this one succeeded.
        if (st.followUp) {
          st.followUp = false;
          this.refreshMembership(node, 'event').catch(() => undefined);
        }
        this.emitEligibility(node);
      }
    })();
    st.inFlight = run;
    run.catch(() => undefined);
    return run;
  }

  // -------------------------------------------------------------------------
  // Identity (SPEC-05, SPEC-06: not yet)
  // -------------------------------------------------------------------------

  governanceHead(): HeadClaim | null {
    return null;
  }

  offerHead(): void {
    // SPEC-06 REQ-7: no governance log before SPEC-06.
  }

  identityLabel(peer: Uuid): IdentityLabel {
    return { shortId: shortIdOf(peer), verified: false };
  }

  pinnedIsk(): Uint8Array | null {
    return null;
  }

  rosterIsk(): Uint8Array | null {
    return null;
  }

  audienceWithheld(): boolean {
    return false;
  }

  // -------------------------------------------------------------------------
  // Events
  // -------------------------------------------------------------------------

  onEligibilityChange(listener: (node: Uuid) => void): () => void {
    this.eligibilityListeners.add(listener);
    return () => this.eligibilityListeners.delete(listener);
  }

  onSessionUsable(listener: (peer: Uuid) => void): () => void {
    this.sessionListeners.add(listener);
    return () => this.sessionListeners.delete(listener);
  }

  private emitEligibility(node: string): void {
    for (const l of [...this.eligibilityListeners]) {
      try {
        l(node);
      } catch {
        // A listener's failure must not stop the others.
      }
    }
  }

  private emitSessionUsable(peer: string): void {
    // After the current call returns, so the caller sees its own result first.
    queueMicrotask(() => {
      for (const l of [...this.sessionListeners]) {
        try {
          l(lower(peer));
        } catch {
          // ignored, as above
        }
      }
    });
  }
}
