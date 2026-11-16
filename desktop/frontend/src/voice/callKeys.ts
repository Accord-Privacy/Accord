/**
 * @module voice/callKeys
 * `CallKeyManager`: the call-key logic of SPEC-03 stage 0 with amendment A1,
 * for one call (one local instance).
 *
 * It is pure logic over injected parts: a clock, the transport (the relay's
 * WebSocket), the E2EE bridge of §6.10 and the timings of §6.5. It handles:
 *
 * - the local instance (REQ-5), its epochs, their recipient sets R_g
 *   (REQ-7) and rotation (REQ-16, REQ-17; 10 minutes, OD-50);
 * - call messages (§6.3): `call_hello`, `call_key` and `call_key_ack`,
 *   accepted only under REQ-12, REQ-32 and REQ-33, with retransmission and
 *   recovery (REQ-20, REQ-36), the chain cap and credits (REQ-21, OD-58),
 *   and the hold of envelopes during a membership fetch (REQ-12);
 * - the receiver key store, keyed by (media kind, KID), with the retained
 *   anti-rollback record of each remote user (REQ-18, REQ-34), the overlap
 *   and key-age timers, the replay windows per media kind and epoch (REQ-15
 *   and REQ-34 as amended by A2, §14.1) and the per-sender queues of REQ-35;
 * - sealing (in counter order, REQ-6) and opening AMF1 audio frames and
 *   video fragments (§6.2.5, §6.2.6, §6.2.8 steps 1 to 9), and A1's video
 *   keys per epoch, VCTR and the keyframe-at-switch signal (REQ-17, REQ-45);
 * - the per-participant states and the call security indicator of §8.1 and
 *   §8.2, computed only from local key state, eligibility and timers (REQ-31).
 *
 * Eligibility follows the interim rule (§6.4, REQ-9) or, once SPEC-05 and
 * SPEC-06 land, the final rule; the bridge evaluates it. Calls that contain
 * outdated clients are allowed: they receive nothing secret and are noted
 * (REQ-4, OD-54).
 *
 * Everything lives in memory only and is erased by `end()` (REQ-27). Nothing
 * here logs, and no error derived from a plaintext leaves this module.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { encodeControlPayloadFor, StrictObject, type ControlBody, type StrictValue } from '../e2ee/plaintext';
import { decodeWireBase64, encodeBase64 } from '../attachments/base64';
import { parseCallPayload, type CallKey } from './callPayload';
import { ReplayWindow, REPLAY_WINDOW_AUDIO, REPLAY_WINDOW_VIDEO } from './replayWindow';
import {
  CALL_SUITE,
  CTR_LIMIT,
  INST_LEN,
  KID_LIMIT,
  MEDIA_KIND_AUDIO,
  MEDIA_KIND_VIDEO,
  SECRET_LEN,
  deriveEpochKeys,
  frameContext,
  importHkdfKey,
  openFrame,
  parseFrame,
  sealFrame,
  type EpochKeys,
  type FrameContext,
  type KindKeys,
  type MediaKind,
  type ParsedFrame,
} from './mediaFrame';
import {
  FRAG_FLAG_KEY,
  FRAG_PAYLOAD,
  FRAGS_MAX,
  VCODEC_VP8,
  fragmentCount,
  fragmentRulesHold,
  sealScreenFrame,
  type EncodedScreenFrame,
} from './screenFrame';
import { CALL_CHAIN_LIMIT, shortIdOf, systemCallClock, type CallClock, type CallKeyBridge, type DecryptResult, type HeadClaim, type Ineligible } from './callKeyBridge';

// ---------------------------------------------------------------------------
// Constants (§6.5)
// ---------------------------------------------------------------------------

/** The `wrapped_key` prefix of this spec's call messages (§6.3.1). */
export const CALL_ENVELOPE_PREFIX = 'acv1:';
/** `v` of every call payload. */
export const CALL_VERSION = 1;
/** `REPLACED_MAX`: replaced instance ids kept per remote user (REQ-34). */
export const REPLACED_MAX = 64;
/** Sizes of a legacy raw key (REQ-4). */
const LEGACY_KEY_SIZES = new Set([16, 24, 32]);

/** The timers and limits of §6.5 that this module uses. Tests may pass shorter values. */
export interface CallKeyTimings {
  /** `JOIN_COALESCE` (REQ-16 (a), (d), (f)). */
  joinCoalesceMs: number;
  /** `SWITCH_DEADLINE` (REQ-17). */
  switchDeadlineMs: number;
  /** `OVERLAP` (REQ-18). */
  overlapMs: number;
  /** `KEY_MAX_AGE` (REQ-18, A1). */
  keyMaxAgeMs: number;
  /** `ROTATION_INTERVAL` (REQ-16 (e); OD-50). */
  rotationIntervalMs: number;
  /** `HELLO_RETRY`: offsets from the first hello. */
  helloRetryMs: readonly number[];
  /** `HELLO_RECOVERY`. */
  helloRecoveryMs: number;
  /** `ACK_TIMEOUT`. */
  ackTimeoutMs: number;
  /** `MAX_RETX` per epoch and recipient instance. */
  maxRetx: number;
  /** `RECOVERY_INTERVAL`. */
  recoveryIntervalMs: number;
  /** `SEND_MIN_GAP`, per recipient, for CKMs and for hellos. */
  sendMinGapMs: number;
  /** `CALL_CHAIN_LIMIT` (REQ-21). */
  chainLimit: number;
  /** `HOLD_MAX` envelopes per sender, for `holdMs` (REQ-12). */
  holdMax: number;
  holdMs: number;
  /** `PENDING_FRAMES_MAX` and `PENDING_FRAGMENTS_MAX` (REQ-35). */
  pendingFramesMax: number;
  pendingFragmentsMax: number;
  /** `MEMBER_REFRESH` (REQ-9) or `ROSTER_SYNC` (REQ-8). */
  memberRefreshMs: number;
  /** The existing backoff for failed fetches (§6.4, §8.3). */
  retryBackoffMs: readonly number[];
  /** `CONNECT_GRACE`, `ACK_GRACE` (§8.2). */
  connectGraceMs: number;
  ackGraceMs: number;
  /** `AEAD_FAIL_NOTICE` (§8.3). */
  aeadFailNotice: number;
  /** The video replay window W, at least 1024 (REQ-15). */
  videoReplayWindow: number;
}

export const DEFAULT_CALL_TIMINGS: Readonly<CallKeyTimings> = Object.freeze({
  joinCoalesceMs: 500,
  switchDeadlineMs: 2000,
  overlapMs: 2000,
  keyMaxAgeMs: 11 * 60_000,
  rotationIntervalMs: 10 * 60_000,
  helloRetryMs: Object.freeze([2000, 4000, 8000]),
  helloRecoveryMs: 60_000,
  ackTimeoutMs: 2000,
  maxRetx: 5,
  recoveryIntervalMs: 15_000,
  sendMinGapMs: 2000,
  chainLimit: CALL_CHAIN_LIMIT,
  holdMax: 16,
  holdMs: 10_000,
  pendingFramesMax: 50,
  pendingFragmentsMax: 128,
  memberRefreshMs: 60_000,
  retryBackoffMs: Object.freeze([2000, 4000, 6000, 8000, 10_000]),
  connectGraceMs: 12_000,
  ackGraceMs: 6000,
  aeadFailNotice: 50,
  videoReplayWindow: REPLAY_WINDOW_VIDEO,
});

// ---------------------------------------------------------------------------
// Injected parts
// ---------------------------------------------------------------------------

export { systemCallClock };
export type { CallClock };

/**
 * The relay transport (REQ-37). Both methods use the WebSocket's
 * non-queuing primitive and return whether the message was handed to an
 * open, authenticated socket; a message that was not does not count as a
 * transmission.
 */
export interface CallTransport {
  /** `VoiceKeyExchange { channel_id, wrapped_key, target_user_id, sender_ssrc: 0, key_generation: 0 }`. */
  sendCallMessage(channelId: string, targetUserId: string, wrappedKey: string): boolean;
  /** `SrtpVoicePacket { channel_id, packet_data: base64(frame) }`. */
  sendMediaFrame(channelId: string, frame: Uint8Array): boolean;
}

/** An authenticated audio frame (§6.2.6 step 9): `codec ‖ payload`, with its CTR. */
export interface ReceivedAudioFrame {
  /** The authenticated CTR, the only playout sequence (REQ-15). */
  readonly ctr: number;
  /**
   * The frame's epoch (KID). Frames of one sender instance arrive here in
   * non-decreasing epoch order (step 5). The first frame under a newer epoch
   * that the caller pushes resets the sender's jitter buffer if its CTR is
   * not above the highest CTR received (REQ-15 as amended by A2), so
   * counters seen under an older epoch cannot hold back playout under it.
   */
  readonly epoch: number;
  readonly codec: number;
  readonly payload: Uint8Array;
}

export type RemoteResetCause = 'erased' | 'new_instance';

/** Where the manager's results go. Every hook is optional. */
export interface CallKeyHooks {
  /** §6.2.6 step 9: the caller checks the codec, decodes, and pushes into S's jitter buffer with sequence = CTR. */
  onAudioFrame?(from: string, frame: ReceivedAudioFrame): void;
  /** §6.2.8 step 1: the local client watches `from` (REQ-50). Default: false. */
  isWatching?(from: string): boolean;
  /** §6.2.8 step 7: take a token of the sharer's decryption budget. Default: true. */
  takeVideoDecryption?(from: string): boolean;
  /** §6.2.8 steps 10 and 11: the authenticated fragment plaintext and its KID, for reassembly. */
  onVideoFragment?(from: string, kid: number, plaintext: Uint8Array): void;
  /** Consecutive AEAD failures of a watched, keyed sharer (REQ-48); 0 after a success. */
  onVideoAeadFailures?(from: string, consecutive: number): void;
  /**
   * REQ-35: S's keys were erased or a new instance of S was recorded. Reset
   * S's jitter buffer and audio decoder; discard S's reassembly buffers,
   * close its video decoder and put a watched share into awaiting-keyframe.
   */
  onRemoteReset?(from: string, cause: RemoteResetCause): void;
  /** Keys (both kinds) for `from`'s current instance were installed (REQ-50: keyframe request). */
  onRemoteKeyInstalled?(from: string, epoch: number): void;
  /** The local sender switched to `epoch`: the next video frame must be a keyframe (REQ-17, REQ-44). */
  onEpochSwitch?(epoch: number): void;
  /** CTR, VCTR or the epoch counter is exhausted: end the instance and rejoin (REQ-6). */
  onRejoinNeeded?(cause: 'counter_exhausted' | 'epoch_exhausted'): void;
  /** Something the panel shows changed. */
  onStateChange?(): void;
}

export type SealFunction = typeof sealFrame;

export interface CallKeyManagerOptions {
  /** C, the active channel. */
  channelId: string;
  /** N, the node recorded with C when the user selected it (REQ-9). */
  nodeId: string;
  bridge: CallKeyBridge;
  transport: CallTransport;
  hooks?: CallKeyHooks;
  clock?: CallClock;
  timings?: Partial<CallKeyTimings>;
  /** The platform CSPRNG; tests may wrap it. */
  random?: (length: number) => Uint8Array;
  /** AMF1 sealing; tests may wrap it (T-6). */
  seal?: SealFunction;
  /** Test only: start CTR and VCTR elsewhere than 0 (T-6, T-14). */
  counterStart?: { ctr?: number; vctr?: number };
}

// ---------------------------------------------------------------------------
// User-visible states (§8.1, §8.2)
// ---------------------------------------------------------------------------

export type OutboundState = 'blocked' | 'session' | 'hello' | 'keying' | 'secure' | 'capped';
export type InboundState = 'blocked' | 'waiting' | 'keyed';

export type ParticipantLabel =
  | 'identity_changed'
  | 'checking_membership'
  | 'not_verified_member'
  | 'secure'
  | 'connecting'
  | 'cant_connect'
  | 'they_cant_hear_you'
  | 'cant_hear_them';

export const PARTICIPANT_LABEL_TEXT: Readonly<Record<ParticipantLabel, string>> = Object.freeze({
  identity_changed: 'Identity changed, audio blocked',
  checking_membership: 'Checking membership…',
  not_verified_member: 'Not a verified member, audio blocked',
  secure: 'Secure',
  connecting: 'Connecting',
  cant_connect: "Can't connect securely",
  they_cant_hear_you: "They can't hear you",
  cant_hear_them: "Can't hear them",
});

export type IndicatorState =
  | 'unavailable'
  | 'waiting_for_others'
  | 'checking_membership'
  | 'cant_verify_members'
  | 'connecting'
  | 'e2ee_not_verified'
  | 'e2ee_verified';

export const INDICATOR_TEXT: Readonly<Record<IndicatorState, string>> = Object.freeze({
  unavailable: 'Secure voice unavailable',
  waiting_for_others: 'Waiting for others',
  checking_membership: 'Checking membership…',
  cant_verify_members: "Can't verify members",
  connecting: 'Connecting securely…',
  e2ee_not_verified: 'End-to-end encrypted · not verified',
  e2ee_verified: 'End-to-end encrypted · verified',
});

export interface ParticipantNotes {
  /** The last `voice_key_exchange` from P failed Double Ratchet decryption (§8.2). */
  readonly sessionProblem: boolean;
  /** Legacy evidence (REQ-4): "May be using an outdated app". */
  readonly outdatedApp: boolean;
  /** The relay reports P2P and nothing was accepted from P since (REQ-41). */
  readonly olderAppP2p: boolean;
  /** `AEAD_FAIL_NOTICE` consecutive audio failures: "Audio from X can't be verified" (§8.3). */
  readonly audioUnverifiable: boolean;
}

export interface ParticipantView {
  readonly userId: string;
  readonly shortId: string;
  readonly fingerprintGroup?: string;
  readonly verified: boolean;
  /** A member of the current epoch's R (the key mark of REQ-11). */
  readonly recipient: boolean;
  readonly outbound: OutboundState;
  readonly inbound: InboundState;
  readonly label: ParticipantLabel;
  readonly ineligibleReason: Ineligible | null;
  readonly notes: ParticipantNotes;
}

export interface CallKeySnapshot {
  readonly indicator: IndicatorState;
  /** V, in the order users entered it. */
  readonly participants: readonly ParticipantView[];
  /** The epoch frames are sealed under, or null before epoch 0's keys are ready. */
  readonly sendingEpoch: number | null;
  /** The newest epoch created. */
  readonly newestEpoch: number | null;
}

/** REQ-54: who can see the screen. */
export interface VideoAudience {
  readonly epoch: number;
  /** R_e of the epoch under which fragments are being sealed. */
  readonly members: readonly string[];
  /** How many of them acknowledged e. Never lowers `members.length` (D41). */
  readonly acknowledged: number;
}

/**
 * One encoded video frame's reservation (REQ-46): its epoch, fixed at frame
 * start, and a contiguous range of `count` VCTR values.
 */
export interface VideoFrameTicket {
  readonly epoch: number;
  readonly firstVctr: number;
  readonly count: number;
}

/** A remote user's retained record (REQ-34), for inspection. */
export interface RetainedRecordView {
  readonly currentInst: string | null;
  readonly replaced: readonly string[];
  readonly maxEpoch: number;
  readonly maxEpochFirstInstalledAt: number | null;
  readonly highestAuthEpoch: { readonly audio: number; readonly video: number };
  /** The highest committed counter of each kind over the windows kept, or −1. */
  readonly replayHighest: { readonly audio: number; readonly video: number };
  /** The replay windows kept, one per epoch (KID) and kind (REQ-15, REQ-34 as amended by A2), by KID. */
  readonly replayWindows: readonly { readonly kid: number; readonly audio: number; readonly video: number }[];
  /** The key store's entries, keyed by (media kind, KID). */
  readonly keys: readonly { readonly kind: MediaKind; readonly kid: number }[];
}

// ---------------------------------------------------------------------------
// Internal state (§6.7)
// ---------------------------------------------------------------------------

interface SenderEpoch {
  readonly epoch: number;
  /** The epoch secret, kept only to encode CKMs; zero-filled when replaced (REQ-27). */
  readonly secret: Uint8Array;
  readonly recipients: ReadonlySet<string>;
  readonly createdAt: number;
  readonly deadline: number;
  keys: EpochKeys | null;
  /** Video frames still being sealed under this epoch (REQ-17). */
  videoUsers: number;
  retired: boolean;
}

interface CkmState {
  readonly epoch: number;
  readonly inst: string;
  txCount: number;
  firstTxAt: number | null;
  lastTxAt: number;
  immediate: boolean;
}

interface HelloState {
  seriesStart: number | null;
  sent: number;
  lastSentAt: number;
  lastFailedAt: number;
  failDelay: number;
  requested: boolean;
  inFlight: boolean;
  timer: unknown;
}

interface PeerOut {
  hello: HelloState;
  ckm: CkmState | null;
  ckmInFlight: boolean;
  ckmTimer: unknown;
  lastCkmAt: number;
  ckmFailedAt: number;
  ckmFailDelay: number;
  /** P's current instance named the local instance in an accepted message. */
  confirmed: boolean;
  /** The highest epoch P's current instance acknowledged, and when. */
  acked: number;
  ackedAt: number;
  /** Epochs below this are never sent to P's current instance (REQ-33 (e)). */
  instFloor: number;
  /**
   * REQ-33 (e), third case (A2): a hello from P's current instance after it
   * acknowledged the current epoch earns one more transmission of the
   * current CKM. `resendFor` is the (instance, epoch) last granted, so each
   * gets at most one; `resend` is set until that transmission is handed off.
   */
  resendFor: string | null;
  resend: boolean;
  /** REQ-21 credit (at most one outstanding). */
  credit: boolean;
  capped: boolean;
  /** Before SPEC-05, as the higher id: waiting for P to establish the session (REQ-10). */
  held: boolean;
  bundleFailures: number;
  sendChain: Promise<unknown>;
}

interface EpochEntry {
  readonly epoch: number;
  readonly keys: EpochKeys;
  readonly firstInstalledAt: number;
  overlapTimer: unknown;
  ageTimer: unknown;
}

/** The replay windows of one epoch (KID) of a sender instance, one per kind (REQ-15). */
interface EpochWindows {
  readonly audio: ReplayWindow;
  readonly video: ReplayWindow;
}

interface InstanceRecord {
  readonly id: string;
  readonly ctx: FrameContext;
  maxEpoch: number;
  maxEpochFirstInstalledAt: number;
  maxEpochDigest: Uint8Array | null;
  readonly highestAuth: { audio: number; video: number };
  /**
   * REQ-15 and REQ-34 as amended by A2 (§14.1): one replay window per media
   * kind and epoch, kept for every epoch whose key is installed and for the
   * highest accepted epoch while REQ-33 (c) may still reinstall it. A frame
   * is checked against, and marks, only the window of its own epoch.
   */
  readonly windows: Map<number, EpochWindows>;
  /** Drops the highest epoch's window once it can no longer be reinstalled. */
  windowTimer: unknown;
  /** The receiver key store of this instance, keyed by (media kind, KID). */
  readonly store: Map<string, KindKeys>;
  readonly epochs: Map<number, EpochEntry>;
}

type ParsedOk = Extract<ParsedFrame, { ok: true }>;

interface Peer {
  readonly id: string;
  eligible: boolean;
  t0: number;
  current: InstanceRecord | null;
  readonly replaced: string[];
  readonly out: PeerOut;
  /** Call messages accepted for processing and not finished (REQ-35, §6.2.6). */
  busy: number;
  installFailed: boolean;
  pendingAudio: ParsedOk[];
  pendingVideo: ParsedOk[];
  msgChain: Promise<unknown>;
  audioChain: Promise<unknown>;
  videoChain: Promise<unknown>;
  held: string[];
  holdTimer: unknown;
  legacyEvidence: boolean;
  sessionProblem: boolean;
  lastAcceptedAt: number;
  aeadFails: { audio: number; video: number };
}

interface AudioSlot {
  readonly epoch: number;
  done: boolean;
  frame: Uint8Array | null;
}

interface TicketState {
  /** The frame's epoch; its keys are read at sealing time, so erasing them reaches every ticket. */
  readonly ep: SenderEpoch;
  used: boolean;
  released: boolean;
}

type DeliveryOutcome = 'sent' | 'not_handed_off' | 'held' | 'capped' | 'bundle' | 'failed' | 'stale';

const keyOf = (kind: MediaKind, kid: number): string => `${kind}:${kid}`;
const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * Every rule of §6.2.7 for the fragments `sealScreenFrame` would build from
 * `frame` (REQ-46). They differ only in `frag_index` and payload length, and
 * every payload but the last is exactly `FRAG_PAYLOAD` bytes, so checking
 * the last fragment's header checks them all.
 */
function screenFrameRulesHold(frame: EncodedScreenFrame, count: number): boolean {
  const header = {
    vcodec: VCODEC_VP8,
    flags: frame.key ? FRAG_FLAG_KEY : 0,
    shareSeq: frame.shareSeq,
    frameNo: frame.frameNo,
    fragIndex: count - 1,
    fragCount: count,
    width: frame.width,
    height: frame.height,
  };
  return fragmentRulesHold(header, frame.data.length - (count - 1) * FRAG_PAYLOAD);
}

function bytesEqual(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function toHeadClaim(v: StrictValue | undefined): HeadClaim | null {
  if (!(v instanceof StrictObject)) return null;
  const seq = v.get('seq');
  const hash = v.get('hash');
  const prev = v.get('prev');
  const rcpt = v.get('rcpt');
  if (typeof seq !== 'number' || typeof hash !== 'string' || typeof prev !== 'string' || typeof rcpt !== 'string') return null;
  return { seq, hash, prev, rcpt };
}

// ---------------------------------------------------------------------------
// CallKeyManager
// ---------------------------------------------------------------------------

export class CallKeyManager {
  readonly channelId: string;
  readonly nodeId: string;
  private readonly bridge: CallKeyBridge;
  private readonly transport: CallTransport;
  private readonly hooks: CallKeyHooks;
  private readonly clock: CallClock;
  private readonly t: CallKeyTimings;
  private readonly random: (length: number) => Uint8Array;
  private readonly seal: SealFunction;
  private readonly self: string;
  private readonly inst: Uint8Array;
  private readonly instId: string;
  private readonly selfCtx: FrameContext;

  private started = false;
  /** The first call-start fetch of N's lists, settled either way (§6.6 step 1). */
  private startFetch: Promise<void> | null = null;
  private joined = false;
  private ended = false;
  private readonly view = new Set<string>();
  private readonly peers = new Map<string, Peer>();

  private newest: SenderEpoch | null = null;
  private active: SenderEpoch | null = null;
  private suspended = false;
  /** No frame or fragment of an epoch below this may be handed off (REQ-17 (b), (c)). */
  private invalidBelow = 0;
  private ctrNext: number;
  private vctrNext: number;
  private readonly audioOut: AudioSlot[] = [];
  private readonly tickets = new WeakMap<VideoFrameTicket, TicketState>();
  /** Replaced epochs whose video key is kept for a frame still being sealed (REQ-17). */
  private readonly heldVideo = new Set<SenderEpoch>();

  private coalesceTimer: unknown = null;
  private rotationTimer: unknown = null;
  private switchTimer: unknown = null;
  private stateTimer: unknown = null;
  private readonly timers = new Set<unknown>();

  private membershipState: 'checking' | 'ok' | 'failed' = 'checking';
  private localFailures = 0;
  private localError = false;
  private p2pReportAt: number | null = null;
  private joinedAt = 0;

  private inflight = 0;
  private idleWaiters: Array<() => void> = [];
  private readonly unsubscribe: Array<() => void> = [];

  constructor(opts: CallKeyManagerOptions) {
    this.channelId = opts.channelId.toLowerCase();
    this.nodeId = opts.nodeId.toLowerCase();
    this.bridge = opts.bridge;
    this.transport = opts.transport;
    this.hooks = opts.hooks ?? {};
    this.clock = opts.clock ?? systemCallClock;
    this.t = { ...DEFAULT_CALL_TIMINGS, ...(opts.timings ?? {}) };
    if (this.t.videoReplayWindow < REPLAY_WINDOW_VIDEO) throw new RangeError('the video replay window is at least 1024');
    this.random = opts.random ?? (n => crypto.getRandomValues(new Uint8Array(n)));
    this.seal = opts.seal ?? sealFrame;
    this.self = this.bridge.selfId().toLowerCase();
    // REQ-5: a new 16-byte instance per call, from the platform CSPRNG.
    this.inst = Uint8Array.from(this.random(INST_LEN));
    if (this.inst.length !== INST_LEN) throw new RangeError('instance length');
    this.instId = encodeBase64(this.inst);
    this.selfCtx = frameContext(this.channelId, this.self, this.inst);
    this.ctrNext = opts.counterStart?.ctr ?? 0;
    this.vctrNext = opts.counterStart?.vctr ?? 0;
    this.unsubscribe.push(
      this.bridge.onEligibilityChange(node => {
        if (node.toLowerCase() === this.nodeId) this.reevaluate();
      }),
      this.bridge.onSessionUsable(peer => this.sessionUsable(peer.toLowerCase())),
    );
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /** This call's instance, standard base64 (the `inst` of every call message). */
  get instanceId(): string {
    return this.instId;
  }

  get isEnded(): boolean {
    return this.ended;
  }

  /**
   * Call start (§6.6 step 1): fetch N's channel list and member list (REQ-9),
   * retrying on the existing backoff, and refresh them every
   * `MEMBER_REFRESH`. Returns false, doing nothing, while the E2EE manager is
   * not ready (REQ-23): the caller must then not join.
   */
  start(): boolean {
    if (this.ended) return false;
    if (this.started) return true;
    if (!this.bridge.isReady()) return false;
    this.started = true;
    this.fetchAtStart(0);
    this.scheduleRefresh();
    return true;
  }

  /**
   * Settles once the first call-start fetch of N's channel and member lists
   * has completed or failed (§6.6 step 1: the lists are fetched, then the
   * client sends `JoinVoiceChannel`). Resolves at once before `start()`.
   */
  whenMembershipChecked(): Promise<void> {
    return this.startFetch ?? Promise.resolve();
  }

  /**
   * `voice_channel_joined` for C. The first one creates epoch 0 with R_0 =
   * the eligible members of V and sends them hellos (§6.6 step 1.2); a later
   * one only reconciles V (REQ-5).
   */
  onJoined(participants: readonly string[]): void {
    if (this.ended) return;
    if (!this.started) this.start();
    const list = this.normalizeList(participants);
    if (this.joined) {
      this.reconcileParticipants(list);
      return;
    }
    this.joined = true;
    this.joinedAt = this.clock.now();
    for (const u of list) {
      const p = this.addToView(u);
      p.t0 = this.joinedAt;
      p.eligible = this.evalEligible(u);
    }
    this.createEpoch();
    for (const u of list) {
      const p = this.peers.get(u)!;
      if (p.eligible) this.restartHello(p);
    }
    this.changed();
  }

  /** `voice_peer_joined` for C (§6.6 step 3). */
  onPeerJoined(userId: string): void {
    const u = userId.toLowerCase();
    if (!this.joined || this.ended || u === this.self || this.view.has(u)) return;
    const p = this.addToView(u);
    p.t0 = this.clock.now();
    p.legacyEvidence = false; // REQ-4: cleared when the user re-enters V
    p.eligible = this.evalEligible(u);
    if (p.eligible) this.restartHello(p);
    this.requestRotation(); // REQ-16 (a)
    this.changed();
  }

  /** `voice_peer_left` for C (§6.6 step 4). The rotation begins in this turn (REQ-16). */
  onPeerLeft(userId: string): void {
    const u = userId.toLowerCase();
    if (!this.joined || this.ended || !this.view.has(u)) return;
    const p = this.peers.get(u)!;
    this.view.delete(u);
    p.eligible = false;
    this.discardHeld(p);
    this.eraseReceiveKeys(p);
    this.stopOutbound(p);
    if (this.inCurrentRecipients(u)) this.rotateNow('leave'); // REQ-16 (b)
    this.changed();
  }

  /**
   * REQ-38 reconciliation: listed users missing from V are handled as
   * `voice_peer_joined`, members of V that are not listed as
   * `voice_peer_left`.
   */
  reconcileParticipants(participants: readonly string[]): void {
    if (!this.joined || this.ended) return;
    const list = this.normalizeList(participants);
    const listed = new Set(list);
    for (const u of [...this.view]) if (!listed.has(u)) this.onPeerLeft(u);
    for (const u of list) if (!this.view.has(u)) this.onPeerJoined(u);
  }

  /** The latest relay-reported mode for C (REQ-41): only drives notes. */
  noteRelayMode(mode: string): void {
    if (this.ended) return;
    this.p2pReportAt = mode === 'p2p' ? this.clock.now() : null;
    this.changed();
  }

  /** A legacy `voice_packet` for C (REQ-3, REQ-4): discarded, recorded as evidence. */
  noteLegacyVoicePacket(from: string, channelId: string): void {
    const u = from.toLowerCase();
    if (!this.joined || this.ended || channelId.toLowerCase() !== this.channelId || !this.view.has(u)) return;
    this.peers.get(u)!.legacyEvidence = true;
    this.changed();
  }

  /**
   * End of the call (leave, eviction, disconnect, rejoin, channel switch):
   * erase all call state, including retained records, zero-fill every secret
   * and clear every timer (REQ-18, REQ-22, REQ-27).
   */
  end(): void {
    if (this.ended) return;
    this.ended = true;
    for (const h of this.timers) this.clock.clearTimeout(h);
    this.timers.clear();
    for (const ep of [this.newest, this.active]) if (ep) this.retireEpoch(ep, true);
    // Older epochs kept only for a frame whose ticket was never sealed or released.
    for (const ep of [...this.heldVideo]) this.dropKeys(ep);
    this.newest = null;
    this.active = null;
    for (const p of this.peers.values()) {
      if (p.current) this.eraseAllKeys(p.current);
      p.current = null;
      p.replaced.length = 0;
      p.held = [];
      p.pendingAudio = [];
      p.pendingVideo = [];
    }
    this.peers.clear();
    this.view.clear();
    this.audioOut.length = 0;
    this.inst.fill(0);
    for (const u of this.unsubscribe.splice(0)) u();
    this.hooks.onStateChange?.();
  }

  /** Resolves once no asynchronous work of this manager is in flight (tests). */
  async whenIdle(): Promise<void> {
    while (this.inflight > 0) await new Promise<void>(r => this.idleWaiters.push(r));
  }

  // -------------------------------------------------------------------------
  // Call messages in (§6.3.6)
  // -------------------------------------------------------------------------

  /**
   * A `voice_key_exchange` from the relay. Runs the REQ-12 pre-checks and
   * starts the decryption synchronously, so the message keeps its place in
   * the sender's Double Ratchet order (§11.3); call it from the WebSocket
   * handler itself, before any await.
   */
  handleKeyExchange(msg: { from?: unknown; channel_id?: unknown; wrapped_key?: unknown }): void {
    if (!this.joined || this.ended) return;
    if (typeof msg.channel_id !== 'string' || msg.channel_id.toLowerCase() !== this.channelId) return;
    if (typeof msg.from !== 'string' || typeof msg.wrapped_key !== 'string') return;
    const s = msg.from.toLowerCase();
    if (s === this.self || !this.view.has(s)) return; // not decrypted
    const peer = this.peers.get(s)!;
    const wk = msg.wrapped_key;
    if (!wk.startsWith(CALL_ENVELOPE_PREFIX)) {
      this.noteLegacyKey(peer, wk);
      return;
    }
    if (peer.held.length > 0) {
      this.hold(peer, wk); // behind the envelopes already held
      return;
    }
    const gate = this.bridge.membership(this.nodeId, this.channelId, s);
    if (gate === 'unknown') {
      this.hold(peer, wk);
      return;
    }
    if (gate !== 'member') return; // not decrypted
    this.acceptEnvelope(peer, wk);
  }

  private noteLegacyKey(peer: Peer, wk: string): void {
    // REQ-4: never imported. A raw-key-shaped value is only evidence.
    const raw = decodeWireBase64(wk);
    if (raw && LEGACY_KEY_SIZES.has(raw.length)) {
      peer.legacyEvidence = true;
      this.changed();
    }
    raw?.fill(0);
  }

  private hold(peer: Peer, wk: string): void {
    if (peer.held.length >= this.t.holdMax) return; // beyond the 16th: discarded
    peer.held.push(wk);
    if (peer.holdTimer === null) {
      peer.holdTimer = this.after(this.t.holdMs, () => {
        peer.holdTimer = null;
        peer.held = [];
        this.changed();
      });
    }
    this.changed();
  }

  private discardHeld(peer: Peer): void {
    peer.held = [];
    this.cancel(peer.holdTimer);
    peer.holdTimer = null;
  }

  /** After a membership fetch: process held envelopes in order, or discard them (REQ-12). */
  private processHeld(): void {
    for (const peer of this.peers.values()) {
      if (peer.held.length === 0) continue;
      if (!this.view.has(peer.id)) {
        this.discardHeld(peer);
        continue;
      }
      const gate = this.bridge.membership(this.nodeId, this.channelId, peer.id);
      if (gate === 'unknown') continue;
      const held = peer.held;
      this.discardHeld(peer);
      if (gate === 'member') for (const wk of held) this.acceptEnvelope(peer, wk);
    }
  }

  private acceptEnvelope(peer: Peer, wk: string): void {
    const raw = decodeWireBase64(wk.slice(CALL_ENVELOPE_PREFIX.length));
    if (!raw) return;
    let envelope: string;
    try {
      envelope = strictUtf8.decode(raw);
    } catch {
      return;
    }
    let result: Promise<DecryptResult>;
    try {
      result = this.bridge.decryptFrom(peer.id, envelope); // before any await (§6.10)
    } catch {
      result = Promise.resolve({ ok: false, error: 'decrypt_failed' });
    }
    peer.busy++;
    const run = peer.msgChain
      .then(() => result)
      .then(r => this.processDecrypted(peer, r))
      .catch(() => undefined)
      .then(() => {
        peer.busy--;
        if (peer.busy === 0) this.drainPending(peer);
      });
    peer.msgChain = run;
    this.track(run);
  }

  private async processDecrypted(peer: Peer, r: DecryptResult): Promise<void> {
    const s = peer.id;
    if (this.ended || !this.view.has(s)) return;
    if (!r.ok) {
      peer.sessionProblem = true; // §8.2 note, non-sticky
      this.changed();
      return;
    }
    if (peer.sessionProblem) {
      peer.sessionProblem = false;
      this.changed();
    }
    if (r.usedSkippedKey) return; // REQ-32: not a decryption failure
    const p = parseCallPayload(r.plaintext, { from: s, ch: this.channelId });
    if (!p) return;
    const wipe = () => {
      if (p.type === 'call_key') p.key.fill(0);
    };
    // REQ-12 after decryption, with SPEC-05 and SPEC-06.
    if (this.bridge.pinnedSessionsOnly()) {
      const pin = this.bridge.pinnedIsk(s);
      if (r.sessionVersion !== 'v2' || !bytesEqual(r.peer.isk, pin)) return wipe();
    }
    const final = this.bridge.rule() === 'final';
    if (final && !bytesEqual(r.peer.isk, this.bridge.rosterIsk(this.nodeId, s))) return wipe();
    // REQ-33 (a)
    const instResult = this.applyInstance(peer, p.inst);
    if (instResult === 'stale') return wipe();
    // An accepted call message.
    const now = this.clock.now();
    peer.out.credit = true; // REQ-21
    peer.lastAcceptedAt = now;
    peer.legacyEvidence = false;
    if (final && p.type !== 'call_key_ack') {
      const head = toHeadClaim(p.gh);
      if (head) this.bridge.offerHead(this.nodeId, s, head);
    }
    // REQ-16 (f), REQ-33 (e): a member of R recorded with a new instance gets
    // a new epoch, never the current one.
    if (instResult === 'replaced' && this.newest?.recipients.has(s)) this.requestRotation();
    const namesLocal = p.toInst !== null && bytesEqual(p.toInst, this.inst);
    if (namesLocal && !peer.out.confirmed) {
      peer.out.confirmed = true; // hello retransmissions stop (REQ-36)
      peer.out.hello.requested = false;
      this.cancel(peer.out.hello.timer);
    }
    switch (p.type) {
      case 'call_hello':
        this.onHello(peer, instResult, namesLocal);
        break;
      case 'call_key':
        if (!namesLocal) {
          wipe(); // REQ-33 (b)
          this.replyHello(peer);
        } else {
          await this.onCallKey(peer, p);
        }
        break;
      case 'call_key_ack':
        if (!namesLocal) this.replyHello(peer);
        else this.onAck(peer, p.epoch);
        break;
    }
    if (this.ended) return;
    // REQ-20: in recovery, one immediate retransmission per accepted message.
    const st = peer.out.ckm;
    if (st && st.txCount > this.t.maxRetx) st.immediate = true;
    this.pumpCkm(peer);
    this.pumpHello(peer);
    this.changed();
  }

  /** REQ-33 (a). */
  private applyInstance(peer: Peer, instBytes: Uint8Array): 'same' | 'first' | 'replaced' | 'stale' {
    const id = encodeBase64(instBytes);
    if (peer.replaced.includes(id)) return 'stale';
    if (peer.current?.id === id) return 'same';
    const now = this.clock.now();
    const first = peer.current === null;
    if (!first) {
      const old = peer.current!;
      this.eraseAllKeys(old);
      // A replaced instance's messages and frames are refused: its windows go too.
      this.cancel(old.windowTimer);
      old.windowTimer = null;
      old.windows.clear();
      peer.replaced.push(old.id);
      if (peer.replaced.length > REPLACED_MAX) peer.replaced.splice(0, peer.replaced.length - REPLACED_MAX);
      peer.pendingAudio = [];
      peer.pendingVideo = [];
      peer.aeadFails = { audio: 0, video: 0 };
      this.hooks.onRemoteReset?.(peer.id, 'new_instance');
      // REQ-33 (e): the new instance never receives an epoch it could share
      // with the replaced one.
      peer.out.instFloor = (this.newest?.epoch ?? -1) + 1;
      const h = peer.out.hello;
      this.cancel(h.timer);
      Object.assign(h, { seriesStart: null, sent: 0, requested: false, timer: null });
    }
    peer.current = this.newRecord(peer.id, instBytes);
    const out = peer.out;
    out.confirmed = false;
    out.acked = -1;
    out.ackedAt = 0;
    out.ckm = null;
    out.resend = false;
    peer.t0 = now;
    return first ? 'first' : 'replaced';
  }

  private newRecord(userId: string, instBytes: Uint8Array): InstanceRecord {
    return {
      id: encodeBase64(instBytes),
      ctx: frameContext(this.channelId, userId, instBytes),
      maxEpoch: -1,
      maxEpochFirstInstalledAt: 0,
      maxEpochDigest: null,
      highestAuth: { audio: -1, video: -1 },
      windows: new Map(),
      windowTimer: null,
      store: new Map(),
      epochs: new Map(),
    };
  }

  /** §6.6 step 2, REQ-33 (e), REQ-36. */
  private onHello(peer: Peer, instResult: 'same' | 'first' | 'replaced', namesLocal: boolean): void {
    const ep = this.newest;
    const inR = !!ep && ep.recipients.has(peer.id);
    const out = peer.out;
    let answered = false;
    if (instResult === 'replaced' && inR) {
      answered = true; // the new epoch's CKM answers it (REQ-16 (f), requested above)
    } else if (inR && out.instFloor <= ep!.epoch && peer.eligible) {
      if (out.acked < ep!.epoch) {
        // (e), second case: not yet acknowledged.
        this.ensureCkmState(peer);
        if (out.ckm) out.ckm.immediate = true;
        answered = true;
      } else if (instResult === 'same') {
        // (e), third case (A2): acknowledged, yet the instance says hello
        // again, so it may have erased its keys (a forged leave and its own
        // rejoin). Once more per (instance, epoch), without a new epoch.
        const grant = `${peer.current!.id}|${ep!.epoch}`;
        if (out.resendFor !== grant) {
          out.resendFor = grant;
          out.resend = true;
          this.ensureCkmState(peer);
          if (out.ckm) out.ckm.immediate = true;
        }
        answered = true;
      }
    }
    if (!answered && !namesLocal) this.replyHello(peer);
  }

  /** REQ-33 (c). */
  private async onCallKey(peer: Peer, p: CallKey): Promise<void> {
    const rec = peer.current!;
    const now = this.clock.now();
    if (!peer.eligible) {
      p.key.fill(0); // REQ-18: no keys are held for an ineligible sender
      return;
    }
    const digest = sha256(p.key);
    if (p.epoch > rec.maxEpoch) {
      if (!(await this.install(peer, rec, p.epoch, p.key, now, true))) return;
      rec.maxEpoch = p.epoch;
      rec.maxEpochFirstInstalledAt = now;
      rec.maxEpochDigest = digest;
      // A2 (REQ-34): the windows of epochs that can no longer be installed go;
      // this one's goes once REQ-33 (c) can no longer reinstall it.
      this.pruneWindows(rec);
      this.cancel(rec.windowTimer);
      rec.windowTimer = this.after(this.t.keyMaxAgeMs, () => {
        rec.windowTimer = null;
        this.pruneWindows(rec);
      });
      this.sendAck(peer, rec, p.epoch);
      return;
    }
    if (p.epoch === rec.maxEpoch) {
      const same = bytesEqual(digest, rec.maxEpochDigest);
      if (rec.epochs.has(p.epoch)) {
        p.key.fill(0);
        if (same) this.sendAck(peer, rec, p.epoch); // a duplicate: acknowledge
        return;
      }
      // Erased under REQ-18: reinstall within KEY_MAX_AGE of the first
      // installation, with the retained replay window (never a fresh one).
      if (same && now - rec.maxEpochFirstInstalledAt < this.t.keyMaxAgeMs && rec.windows.has(p.epoch)) {
        if (await this.install(peer, rec, p.epoch, p.key, rec.maxEpochFirstInstalledAt, false)) this.sendAck(peer, rec, p.epoch);
        return;
      }
    }
    p.key.fill(0);
  }

  /** REQ-33 (d). */
  private onAck(peer: Peer, epoch: number): void {
    const ep = this.newest;
    if (!ep || !ep.recipients.has(peer.id) || epoch > ep.epoch) return;
    if (epoch > peer.out.acked) {
      peer.out.acked = epoch;
      peer.out.ackedAt = this.clock.now();
    }
    // A granted re-send (REQ-33 (e), third case) still goes: an ACK sent before it does not answer it.
    if (peer.out.acked >= ep.epoch && !peer.out.resend) {
      this.cancel(peer.out.ckmTimer);
      peer.out.ckmTimer = null;
    }
  }

  // -------------------------------------------------------------------------
  // Receiver key store (REQ-18, REQ-34, REQ-35)
  // -------------------------------------------------------------------------

  /**
   * Install an epoch's keys of both kinds for `rec` (REQ-45). The secret is
   * zero-filled right after its import (REQ-27). An installation is complete
   * only once the video keys are derived too (REQ-35).
   */
  private async install(peer: Peer, rec: InstanceRecord, epoch: number, secret: Uint8Array, firstInstalledAt: number, fresh: boolean): Promise<boolean> {
    let keys: EpochKeys;
    try {
      const base = importHkdfKey(secret, { wipe: true });
      keys = await deriveEpochKeys(await base, epoch, 'decrypt');
    } catch {
      secret.fill(0);
      peer.installFailed = true;
      return false;
    }
    // A re-delivered epoch is installed only with its retained window (REQ-33 (c)).
    if (this.ended || peer.current !== rec || !this.view.has(peer.id) || (!fresh && !rec.windows.has(epoch))) {
      keys.audio.salt.fill(0);
      keys.video.salt.fill(0);
      peer.installFailed = true;
      return false;
    }
    // REQ-15 (A2): a new epoch starts with windows of its own.
    if (fresh) rec.windows.set(epoch, { audio: new ReplayWindow(REPLAY_WINDOW_AUDIO), video: new ReplayWindow(this.t.videoReplayWindow) });
    const entry: EpochEntry = { epoch, keys, firstInstalledAt, overlapTimer: null, ageTimer: null };
    rec.epochs.set(epoch, entry);
    rec.store.set(keyOf(MEDIA_KIND_AUDIO, epoch), keys.audio);
    rec.store.set(keyOf(MEDIA_KIND_VIDEO, epoch), keys.video);
    const age = firstInstalledAt + this.t.keyMaxAgeMs - this.clock.now();
    entry.ageTimer = this.after(Math.max(0, age), () => this.eraseEpoch(peer, rec, epoch, true));
    for (const other of rec.epochs.values()) {
      if (other.epoch < epoch && other.overlapTimer === null) {
        other.overlapTimer = this.after(this.t.overlapMs, () => this.eraseEpoch(peer, rec, other.epoch, false));
      }
    }
    while (rec.epochs.size > 2) this.eraseEpoch(peer, rec, Math.min(...rec.epochs.keys()), false);
    this.hooks.onRemoteKeyInstalled?.(peer.id, epoch);
    this.changed();
    return true;
  }

  private eraseEpoch(peer: Peer, rec: InstanceRecord, epoch: number, byAge: boolean): void {
    const e = rec.epochs.get(epoch);
    if (!e) return;
    rec.epochs.delete(epoch);
    rec.store.delete(keyOf(MEDIA_KIND_AUDIO, epoch));
    rec.store.delete(keyOf(MEDIA_KIND_VIDEO, epoch));
    this.cancel(e.overlapTimer);
    this.cancel(e.ageTimer);
    e.keys.audio.salt.fill(0);
    e.keys.video.salt.fill(0);
    this.pruneWindows(rec);
    if (byAge && rec.epochs.size === 0 && peer.current === rec) {
      this.hooks.onRemoteReset?.(peer.id, 'erased');
    }
    this.changed();
  }

  private eraseAllKeys(rec: InstanceRecord): void {
    for (const e of [...rec.epochs.values()]) {
      rec.epochs.delete(e.epoch);
      this.cancel(e.overlapTimer);
      this.cancel(e.ageTimer);
      e.keys.audio.salt.fill(0);
      e.keys.video.salt.fill(0);
    }
    rec.store.clear();
    this.pruneWindows(rec);
  }

  /**
   * REQ-34 as amended by A2: keep the windows of every epoch whose key is
   * installed, and of the highest accepted epoch m while REQ-33 (c) may still
   * reinstall it (less than `KEY_MAX_AGE` after its first installation).
   * Every other epoch can never be installed again (REQ-33 (c): epoch < m is
   * discarded), so its window is dropped.
   */
  private pruneWindows(rec: InstanceRecord): void {
    const now = this.clock.now();
    const reinstallable = (e: number) => e === rec.maxEpoch && now - rec.maxEpochFirstInstalledAt < this.t.keyMaxAgeMs;
    for (const e of [...rec.windows.keys()]) {
      if (!rec.epochs.has(e) && !reinstallable(e)) rec.windows.delete(e);
    }
  }

  /** REQ-18: erase the keys of the current instance and reset the pipeline; keep the record. */
  private eraseReceiveKeys(peer: Peer): void {
    peer.pendingAudio = [];
    peer.pendingVideo = [];
    if (peer.current && peer.current.epochs.size > 0) {
      this.eraseAllKeys(peer.current);
    }
    this.hooks.onRemoteReset?.(peer.id, 'erased');
  }

  // -------------------------------------------------------------------------
  // Frames in (§6.2.6, §6.2.8)
  // -------------------------------------------------------------------------

  /** An `srtp_voice_packet`: `bytes` is the base64-decoded `packet_data`. */
  receiveAudioFrame(from: string, channelId: string, bytes: Uint8Array): void {
    const s = from.toLowerCase();
    // Step 1.
    if (!this.joined || this.ended || channelId.toLowerCase() !== this.channelId) return;
    if (s === this.self || !this.view.has(s)) return;
    const peer = this.peers.get(s)!;
    if (!peer.eligible) return;
    // Steps 2 to 4.
    const f = parseFrame(bytes, MEDIA_KIND_AUDIO);
    if (!f.ok) return;
    // Step 5's wait (REQ-35): frames queue behind call messages being processed.
    if (peer.busy > 0) {
      peer.pendingAudio.push(f);
      if (peer.pendingAudio.length > this.t.pendingFramesMax) peer.pendingAudio.shift();
      return;
    }
    this.enqueueAudio(peer, f);
  }

  /** A `SCREEN_DOWN` from `from` (§6.12.2): `fragment` is the AMF1 fragment. */
  receiveVideoFragment(from: string, channelId: string, fragment: Uint8Array): void {
    const s = from.toLowerCase();
    if (!this.joined || this.ended || channelId.toLowerCase() !== this.channelId) return;
    if (s === this.self || !this.view.has(s)) return;
    const peer = this.peers.get(s)!;
    if (!peer.eligible || !(this.hooks.isWatching?.(s) ?? false)) return;
    const f = parseFrame(fragment, MEDIA_KIND_VIDEO);
    if (!f.ok) return;
    if (peer.busy > 0) {
      peer.pendingVideo.push(f);
      if (peer.pendingVideo.length > this.t.pendingFragmentsMax) peer.pendingVideo.shift();
      return;
    }
    this.enqueueVideo(peer, f);
  }

  private drainPending(peer: Peer): void {
    const audio = peer.pendingAudio;
    const video = peer.pendingVideo;
    peer.pendingAudio = [];
    peer.pendingVideo = [];
    if (peer.installFailed) {
      peer.installFailed = false; // REQ-35: dropped if the installation failed
      return;
    }
    for (const f of audio) this.enqueueAudio(peer, f);
    for (const f of video) this.enqueueVideo(peer, f);
  }

  private enqueueAudio(peer: Peer, f: ParsedOk): void {
    const run = peer.audioChain.then(() => this.openAudio(peer, f)).catch(() => undefined);
    peer.audioChain = run;
    this.track(run);
  }

  private enqueueVideo(peer: Peer, f: ParsedOk): void {
    const run = peer.videoChain.then(() => this.openVideo(peer, f)).catch(() => undefined);
    peer.videoChain = run;
    this.track(run);
  }

  private async openAudio(peer: Peer, f: ParsedOk): Promise<void> {
    if (this.ended || !this.view.has(peer.id) || !peer.eligible) return;
    const rec = peer.current;
    // Step 5.
    if (!rec) return;
    const k = rec.epochs.get(f.kid);
    const win = rec.windows.get(f.kid);
    if (!k || !win || f.kid < rec.highestAuth.audio) return;
    // Step 6: the window of the frame's own epoch only (REQ-15, A2).
    if (!win.audio.check(f.ctr)) return;
    // Step 7.
    const pt = await openFrame(f, k.keys, rec.ctx);
    if (this.ended || peer.current !== rec) return;
    if (!pt) {
      peer.aeadFails.audio++;
      if (peer.aeadFails.audio === this.t.aeadFailNotice) this.changed();
      return;
    }
    // Step 8.
    if (f.kid < rec.highestAuth.audio || rec.windows.get(f.kid) !== win || !win.audio.commit(f.ctr)) return;
    rec.highestAuth.audio = f.kid;
    if (peer.aeadFails.audio >= this.t.aeadFailNotice) this.changed();
    peer.aeadFails.audio = 0;
    // Step 9.
    if (pt.length < 2) return;
    this.hooks.onAudioFrame?.(peer.id, { ctr: f.ctr, epoch: f.kid, codec: pt[0], payload: pt.subarray(1) });
  }

  private async openVideo(peer: Peer, f: ParsedOk): Promise<void> {
    if (this.ended || !this.view.has(peer.id) || !peer.eligible) return;
    if (!(this.hooks.isWatching?.(peer.id) ?? false)) return;
    const rec = peer.current;
    // Step 5.
    if (!rec) return;
    const k = rec.epochs.get(f.kid);
    const win = rec.windows.get(f.kid);
    if (!k || !win || f.kid < rec.highestAuth.video) return;
    // Step 6: the window of the fragment's own epoch only (REQ-15, A2).
    if (!win.video.check(f.ctr)) return;
    // Step 7: over budget is discarded before decryption, and is no AEAD failure.
    if (!(this.hooks.takeVideoDecryption?.(peer.id) ?? true)) return;
    // Step 8.
    const pt = await openFrame(f, k.keys, rec.ctx);
    if (this.ended || peer.current !== rec) return;
    if (!pt) {
      peer.aeadFails.video++;
      this.hooks.onVideoAeadFailures?.(peer.id, peer.aeadFails.video);
      return;
    }
    // Step 9.
    if (f.kid < rec.highestAuth.video || rec.windows.get(f.kid) !== win || !win.video.commit(f.ctr)) return;
    rec.highestAuth.video = f.kid;
    if (peer.aeadFails.video !== 0) {
      peer.aeadFails.video = 0;
      this.hooks.onVideoAeadFailures?.(peer.id, 0);
    }
    // Steps 10 and 11 belong to the viewer.
    this.hooks.onVideoFragment?.(peer.id, f.kid, pt);
  }

  // -------------------------------------------------------------------------
  // Frames out (§6.2.5, REQ-2, REQ-6, REQ-17, REQ-46)
  // -------------------------------------------------------------------------

  /**
   * Seal one captured audio plaintext (`codec ‖ payload`) and hand it off in
   * CTR order. Returns false, discarding it, when no current epoch key is
   * ready, sending is suspended, or `voice_channel_joined` has not arrived
   * (REQ-2). The caller discards audio while the mute state is not applied.
   */
  sendAudio(plaintext: Uint8Array): boolean {
    const ep = this.sendableEpoch();
    if (!ep) return false;
    if (this.ctrNext >= CTR_LIMIT) {
      this.hooks.onRejoinNeeded?.('counter_exhausted');
      return false;
    }
    const ctr = this.ctrNext++; // reserved before sealing: never reused
    if (this.ctrNext >= CTR_LIMIT) this.hooks.onRejoinNeeded?.('counter_exhausted');
    const slot: AudioSlot = { epoch: ep.epoch, done: false, frame: null };
    this.audioOut.push(slot);
    let sealing: Promise<Uint8Array>;
    try {
      sealing = this.seal(MEDIA_KIND_AUDIO, ep.keys!, ctr, this.selfCtx, plaintext);
    } catch (e) {
      sealing = Promise.reject(e);
    }
    const run = sealing.then(
      frame => {
        slot.frame = frame;
      },
      () => {
        slot.frame = null;
        this.localFailure();
      },
    ).then(() => {
      slot.done = true;
      this.flushAudio();
    });
    this.track(run);
    return true;
  }

  /** Hand off sealed audio frames in CTR order (REQ-6). */
  private flushAudio(): void {
    while (this.audioOut.length > 0 && this.audioOut[0].done) {
      const slot = this.audioOut.shift()!;
      if (!slot.frame || this.ended || slot.epoch < this.invalidBelow) continue;
      this.transport.sendMediaFrame(this.channelId, slot.frame);
    }
  }

  private sendableEpoch(): SenderEpoch | null {
    if (!this.joined || this.ended || this.suspended || this.localError) return null;
    const ep = this.active;
    return ep && ep.keys && !ep.retired ? ep : null;
  }

  /** The epoch frames are sealed under now, or null when sending is not possible. */
  sendingEpoch(): number | null {
    return this.sendableEpoch()?.epoch ?? null;
  }

  /**
   * Frame start (REQ-46): fix the frame's epoch (the current one) and reserve
   * `fragments` consecutive VCTR values. The epoch's video key is kept until
   * the frame is sealed, even across a switch (REQ-17). Null when nothing may
   * be sent (REQ-2, REQ-47): the frame is then discarded.
   */
  beginVideoFrame(fragments: number): VideoFrameTicket | null {
    if (!Number.isInteger(fragments) || fragments < 1 || fragments > FRAGS_MAX) throw new RangeError('fragment count');
    const ep = this.sendableEpoch();
    if (!ep) return null;
    if (this.vctrNext + fragments > CTR_LIMIT) {
      this.hooks.onRejoinNeeded?.('counter_exhausted');
      return null;
    }
    const ticket: VideoFrameTicket = Object.freeze({ epoch: ep.epoch, firstVctr: this.vctrNext, count: fragments });
    this.vctrNext += fragments; // never reused, even if sealing or hand-off fails
    if (this.vctrNext >= CTR_LIMIT) this.hooks.onRejoinNeeded?.('counter_exhausted');
    ep.videoUsers++;
    this.tickets.set(ticket, { ep, used: false, released: false });
    return ticket;
  }

  /**
   * Seal every fragment of the frame under the ticket's epoch, with its VCTR
   * range (REQ-46). Resolves to the fragments in hand-off order, or null when
   * the frame must be discarded. Releases the ticket's hold on the video key.
   *
   * Rejects with a `RangeError`, without sealing and without touching audio,
   * when the frame does not fit the ticket or breaks a rule of §6.2.7 (a
   * size outside `VIDEO_CAPS`, `share_seq` 0, a `frame_no` above 2^32 − 1):
   * that is the caller's error, not the local encryption failure of §8.3.
   */
  async sealVideoFrame(ticket: VideoFrameTicket, frame: EncodedScreenFrame): Promise<Uint8Array[] | null> {
    const st = this.tickets.get(ticket);
    if (!st || st.used) throw new Error('video frame ticket already used');
    st.used = true;
    try {
      if (fragmentCount(frame.data.length) !== ticket.count) throw new RangeError('fragment count');
      if (!screenFrameRulesHold(frame, ticket.count)) throw new RangeError('screen frame breaks §6.2.7');
      const keys = st.ep.keys;
      if (!this.mayHandOff(ticket) || !keys) return null;
      const run = sealScreenFrame(frame, keys, ticket.firstVctr, this.selfCtx, this.seal);
      this.track(run);
      let fragments: Uint8Array[];
      try {
        fragments = await run;
      } catch {
        // Only the encryption itself can fail here: the input was checked above.
        this.localFailure();
        return null;
      }
      // A departure or removal trigger while sealing (REQ-17): discard them all.
      return this.mayHandOff(ticket) ? fragments : null;
    } finally {
      this.releaseTicket(st);
    }
  }

  /** Give up a ticket without sealing its frame. */
  releaseVideoFrame(ticket: VideoFrameTicket): void {
    const st = this.tickets.get(ticket);
    if (!st) return;
    st.used = true;
    this.releaseTicket(st);
  }

  /**
   * Whether the ticket's fragments may still be handed off. False after a
   * departure or removal trigger (REQ-17): the rest of the frame is discarded.
   */
  mayHandOff(ticket: VideoFrameTicket): boolean {
    return !this.ended && !this.localError && ticket.epoch >= this.invalidBelow;
  }

  private releaseTicket(st: TicketState): void {
    if (st.released) return;
    st.released = true;
    st.ep.videoUsers--;
    // REQ-17: the epoch's video key goes once its last frame is sealed.
    if (st.ep.retired && st.ep.videoUsers === 0) this.dropKeys(st.ep);
  }

  /** REQ-54: the members of R_e for the epoch fragments are sealed under. */
  videoAudience(): VideoAudience | null {
    const ep = this.sendableEpoch();
    if (!ep) return null;
    let acknowledged = 0;
    for (const u of ep.recipients) {
      const p = this.peers.get(u);
      if (p && p.out.acked >= ep.epoch) acknowledged++;
    }
    return { epoch: ep.epoch, members: [...ep.recipients], acknowledged };
  }

  /** `userId` is in V and eligible (REQ-50: a sharer that may be watched). Reads local state only. */
  isEligibleParticipant(userId: string): boolean {
    const u = userId.toLowerCase();
    return this.view.has(u) && !!this.peers.get(u)?.eligible;
  }

  /** `userId` is a member of the current R_g (REQ-51: whose keyframe requests count). */
  isCurrentRecipient(userId: string): boolean {
    return this.inCurrentRecipients(userId.toLowerCase());
  }

  /** A video key is installed for the current instance of `userId` (REQ-50). */
  hasVideoKey(userId: string): boolean {
    const rec = this.peers.get(userId.toLowerCase())?.current;
    if (!rec) return false;
    for (const e of rec.epochs.keys()) if (rec.store.has(keyOf(MEDIA_KIND_VIDEO, e))) return true;
    return false;
  }

  // -------------------------------------------------------------------------
  // Epochs and rotation (REQ-7, REQ-16, REQ-17)
  // -------------------------------------------------------------------------

  private inCurrentRecipients(u: string): boolean {
    return !!(this.newest?.recipients.has(u) || this.active?.recipients.has(u));
  }

  /** REQ-16 (a), (d), (f): coalesced for up to `JOIN_COALESCE`. */
  private requestRotation(): void {
    if (!this.joined || this.ended || this.coalesceTimer !== null) return;
    this.coalesceTimer = this.after(this.t.joinCoalesceMs, () => {
      this.coalesceTimer = null;
      this.createEpoch();
    });
  }

  /**
   * REQ-16 (b), (c) and (e), and a local error: a new epoch in this turn.
   * For (b) and (c) nothing is sealed or handed off under the older epochs
   * from now on (REQ-17).
   */
  private rotateNow(cause: 'leave' | 'ineligible' | 'timer' | 'error'): void {
    if (!this.joined || this.ended) return;
    if (cause !== 'timer') {
      this.suspended = true;
      this.invalidBelow = (this.newest?.epoch ?? -1) + 1;
      // No fragment of these epochs can be handed off any more: their video
      // keys go now, even while a frame under them is still being sealed.
      for (const ep of [...this.heldVideo]) if (ep.epoch < this.invalidBelow) this.dropKeys(ep);
    }
    this.cancel(this.coalesceTimer);
    this.coalesceTimer = null;
    this.createEpoch();
  }

  private createEpoch(): void {
    if (!this.joined || this.ended) return;
    const g = (this.newest?.epoch ?? -1) + 1;
    if (g >= KID_LIMIT) {
      this.suspended = true;
      this.hooks.onRejoinNeeded?.('epoch_exhausted');
      return;
    }
    // A created epoch that never became current is abandoned: never switch back to it.
    if (this.newest && this.newest !== this.active) this.retireEpoch(this.newest, true);
    const previous = this.newest;
    let recipients = [...this.view].filter(u => this.peers.get(u)!.eligible);
    // REQ-8: while the audience is withheld, R may only shrink.
    if (this.bridge.rule() === 'final' && previous && this.bridge.audienceWithheld(this.nodeId)) {
      recipients = recipients.filter(u => previous.recipients.has(u));
    }
    const now = this.clock.now();
    const secret = Uint8Array.from(this.random(SECRET_LEN));
    if (secret.length !== SECRET_LEN) throw new RangeError('secret length');
    const ep: SenderEpoch = {
      epoch: g,
      secret,
      recipients: new Set(recipients),
      createdAt: now,
      deadline: now + this.t.switchDeadlineMs,
      keys: null,
      videoUsers: 0,
      retired: false,
    };
    this.newest = ep;
    this.cancel(this.rotationTimer);
    this.rotationTimer = this.after(this.t.rotationIntervalMs, () => {
      this.rotationTimer = null;
      // REQ-16 (e): whether or not frames were sent, while R_g is not empty.
      if (this.newest === ep && ep.recipients.size > 0) this.rotateNow('timer');
    });
    this.cancel(this.switchTimer);
    this.switchTimer = this.after(this.t.switchDeadlineMs, () => {
      this.switchTimer = null;
      this.maybeSwitch();
    });
    const derive = (async () => deriveEpochKeys(await importHkdfKey(ep.secret), g, 'encrypt'))();
    this.track(derive.then(
      keys => {
        if (this.ended || ep.retired) {
          keys.audio.salt.fill(0);
          keys.video.salt.fill(0);
          return;
        }
        ep.keys = keys;
        this.maybeSwitch();
      },
      () => {
        if (!this.ended && !ep.retired) this.localFailure();
      },
    ));
    for (const u of ep.recipients) this.pumpCkm(this.peers.get(u)!);
    this.changed();
  }

  /**
   * REQ-17: switch to the newest epoch once its keys are derived and its CKM
   * was handed off to every member of R that has a usable session, a known
   * current instance and no REQ-21 block; in any case by the deadline.
   */
  private maybeSwitch(): void {
    const ep = this.newest;
    if (!ep || ep === this.active || !ep.keys || this.ended) return;
    if (this.clock.now() < ep.deadline) {
      for (const u of ep.recipients) {
        const p = this.peers.get(u)!;
        if (this.reachable(p, ep) && !this.handedOffTo(p, ep)) return;
      }
    }
    this.switchTo(ep);
  }

  private reachable(p: Peer, ep: SenderEpoch): boolean {
    if (!this.view.has(p.id) || !p.eligible || !p.current || p.out.instFloor > ep.epoch) return false;
    if (!this.bridge.hasUsableSession(p.id)) return false;
    const len = this.bridge.sendingChainLength(p.id);
    return !(len !== null && len >= this.t.chainLimit && !p.out.credit);
  }

  private handedOffTo(p: Peer, ep: SenderEpoch): boolean {
    if (p.out.acked >= ep.epoch) return true;
    const st = p.out.ckm;
    return !!st && st.epoch === ep.epoch && st.inst === p.current?.id && st.txCount > 0;
  }

  private switchTo(ep: SenderEpoch): void {
    const old = this.active;
    this.active = ep;
    this.suspended = false;
    this.cancel(this.switchTimer);
    this.switchTimer = null;
    if (old) this.retireEpoch(old, false);
    this.hooks.onEpochSwitch?.(ep.epoch);
    this.changed();
  }

  /**
   * REQ-17, REQ-27: zero-fill the epoch's secret and drop its audio key; its
   * video key goes too unless a frame under it is still being sealed and may
   * still be handed off. Such an epoch is kept in `heldVideo` until then.
   */
  private retireEpoch(ep: SenderEpoch, everything: boolean): void {
    ep.retired = true;
    ep.secret.fill(0);
    if (!ep.keys) return;
    ep.keys.audio.salt.fill(0);
    if (everything || ep.videoUsers === 0 || ep.epoch < this.invalidBelow) this.dropKeys(ep);
    else this.heldVideo.add(ep);
  }

  /** Zero-fill both salts of a sender epoch and drop its keys (REQ-17, REQ-18, REQ-27). */
  private dropKeys(ep: SenderEpoch): void {
    this.heldVideo.delete(ep);
    if (!ep.keys) return;
    ep.keys.audio.salt.fill(0);
    ep.keys.video.salt.fill(0);
    ep.keys = null;
  }

  /** §8.3: stop sending (fail closed) and retry once with a new epoch. */
  private localFailure(): void {
    if (this.ended) return;
    this.localFailures++;
    if (this.localFailures === 1) {
      this.rotateNow('error');
    } else {
      this.localError = true;
      this.suspended = true;
      this.changed();
    }
  }

  // -------------------------------------------------------------------------
  // Eligibility (§6.4)
  // -------------------------------------------------------------------------

  private evalEligible(u: string): boolean {
    if (u === this.self || !this.view.has(u)) return false;
    return this.bridge.eligibility(this.nodeId, this.channelId, u).eligible;
  }

  /** After any eligibility change for N (REQ-9, REQ-16 (c), (d), REQ-18). */
  private reevaluate(): void {
    if (this.ended) return;
    let rotate = false;
    if (this.joined) {
      for (const u of this.view) {
        const p = this.peers.get(u)!;
        const e = this.evalEligible(u);
        if (p.eligible && !e) {
          p.eligible = false;
          this.eraseReceiveKeys(p);
          this.stopOutbound(p);
          if (this.inCurrentRecipients(u)) rotate = true;
        } else if (!p.eligible && e) {
          p.eligible = true;
          p.t0 = this.clock.now();
          this.restartHello(p);
          this.requestRotation(); // REQ-16 (d)
        }
      }
      if (rotate) this.rotateNow('ineligible'); // REQ-16 (c), in this turn
    }
    this.processHeld();
    this.changed();
  }

  private fetchAtStart(attempt: number): void {
    const run = this.bridge.refreshMembership(this.nodeId, 'call_start');
    if (attempt === 0) this.startFetch = run.then(() => undefined, () => undefined);
    this.track(run.then(
      () => {
        if (this.ended) return;
        this.membershipState = 'ok';
        this.changed();
      },
      () => {
        if (this.ended || this.membershipState === 'ok') return;
        this.membershipState = 'failed';
        this.changed();
        const delay = this.t.retryBackoffMs[attempt];
        // A call-start fetch makes the bridge forget its lists until it completes,
        // so it is retried only while no later fetch has succeeded.
        if (delay !== undefined) {
          this.after(delay, () => {
            if (this.membershipState !== 'ok') this.fetchAtStart(attempt + 1);
          });
        }
      },
    ));
  }

  private scheduleRefresh(): void {
    this.after(this.t.memberRefreshMs, () => {
      if (this.ended) return;
      this.track(this.bridge.refreshMembership(this.nodeId, 'timer').then(
        () => {
          if (this.ended) return;
          this.membershipState = 'ok';
          this.changed();
        },
        () => undefined,
      ));
      this.scheduleRefresh();
    });
  }

  private sessionUsable(u: string): void {
    const p = this.peers.get(u);
    if (!p || this.ended || !this.view.has(u)) return;
    p.out.held = false;
    if (!p.out.confirmed && p.eligible) {
      p.out.hello.requested = true;
      this.pumpHello(p);
    }
    if (p.out.ckm) p.out.ckm.immediate = true;
    this.pumpCkm(p);
  }

  // -------------------------------------------------------------------------
  // Call messages out (REQ-10, REQ-19 to REQ-21, REQ-36)
  // -------------------------------------------------------------------------

  private common(type: 'call_hello' | 'call_key' | 'call_key_ack', toInst: string | null): Record<string, string | number | null> {
    return { type, v: CALL_VERSION, from: this.self, ch: this.channelId, inst: this.instId, to_inst: toInst };
  }

  private withHead(body: Record<string, string | number | null>): ControlBody {
    if (this.bridge.rule() === 'final') {
      const gh = this.bridge.governanceHead(this.nodeId);
      if (gh) return { ...body, gh: { ...gh } } as unknown as ControlBody;
    }
    return body as unknown as ControlBody;
  }

  /**
   * Encrypt one call message for `peer` and hand it off (§6.4 `deliver`).
   * Deliveries to one peer run one at a time, so the chain check of REQ-21
   * sees every earlier message. `build` runs at the delivery's turn and
   * returns null when the message is no longer current.
   *
   * The encryption may yield, so every check is made again after it, right
   * before the hand-off (REQ-1, REQ-11, REQ-19): `peer` is still in V and
   * eligible, and `stillValid` (the message's own conditions, those `build`
   * checked) still holds. Otherwise the envelope is dropped unsent; the
   * Double Ratchet message it used is simply never delivered.
   */
  private deliver(peer: Peer, build: () => ControlBody | null, stillValid: () => boolean = () => true): Promise<DeliveryOutcome> {
    const run = async (): Promise<DeliveryOutcome> => {
      if (this.ended || !this.view.has(peer.id) || !peer.eligible) return 'stale';
      const out = peer.out;
      let useCredit = false;
      const len = this.bridge.sendingChainLength(peer.id);
      if (len !== null && len >= this.t.chainLimit) {
        if (!out.credit) {
          if (!out.capped) {
            out.capped = true;
            this.changed();
          }
          return 'capped';
        }
        useCredit = true;
      }
      const body = build();
      if (!body) return 'stale';
      let plaintext: string;
      try {
        plaintext = encodeControlPayloadFor('voice', body);
      } catch {
        return 'failed';
      }
      const r = await this.bridge.encryptFor(peer.id, plaintext, useCredit);
      if (this.ended || !this.view.has(peer.id)) return 'stale';
      if (!r.ok) {
        switch (r.error) {
          case 'await_peer':
            out.held = true;
            this.changed();
            return 'held';
          case 'chain_limit':
            out.capped = true;
            this.changed();
            return 'capped';
          case 'bundle_unavailable':
            return 'bundle';
          default:
            return 'failed';
        }
      }
      if (useCredit) out.credit = false; // the chain grew either way
      if (out.capped || out.held) {
        out.capped = false;
        out.held = false;
        this.changed();
      }
      if (!peer.eligible || !stillValid()) return 'stale';
      const wire = CALL_ENVELOPE_PREFIX + encodeBase64(utf8.encode(r.envelope));
      return this.transport.sendCallMessage(this.channelId, peer.id, wire) ? 'sent' : 'not_handed_off';
    };
    const p = peer.out.sendChain.then(run, run);
    peer.out.sendChain = p.catch(() => undefined);
    return this.track(p.catch((): DeliveryOutcome => 'failed'));
  }

  /** The delay before retrying after an outcome that sent nothing. */
  private failDelay(peer: Peer, outcome: DeliveryOutcome): number {
    if (outcome === 'bundle') {
      peer.out.bundleFailures++;
      const d = this.t.retryBackoffMs[peer.out.bundleFailures - 1];
      return d ?? this.t.helloRecoveryMs;
    }
    return this.t.sendMinGapMs;
  }

  private restartHello(peer: Peer): void {
    const h = peer.out.hello;
    this.cancel(h.timer);
    Object.assign(h, { seriesStart: null, sent: 0, requested: true, timer: null });
    this.pumpHello(peer);
  }

  /**
   * REQ-36 case 3, and REQ-33 (b): one hello in reply, also to a peer that
   * confirmed the local instance before (retransmissions stay stopped).
   */
  private replyHello(peer: Peer): void {
    if (!peer.eligible) return;
    peer.out.hello.requested = true;
    this.pumpHello(peer);
  }

  /** REQ-36: send or schedule the next hello to `peer`. */
  private pumpHello(peer: Peer): void {
    const h = peer.out.hello;
    this.cancel(h.timer);
    h.timer = null;
    if (!this.joined || this.ended || !this.view.has(peer.id) || !peer.eligible) return;
    if (peer.out.confirmed && !h.requested) return; // retransmit only while unconfirmed
    if (h.inFlight) return;
    const now = this.clock.now();
    let due: number;
    if (h.requested) {
      due = now;
    } else if (h.sent === 0 || h.seriesStart === null) {
      return;
    } else if (h.sent <= this.t.helloRetryMs.length) {
      due = h.seriesStart + this.t.helloRetryMs[h.sent - 1];
    } else {
      due = h.lastSentAt + this.t.helloRecoveryMs;
    }
    due = Math.max(due, h.lastSentAt + this.t.sendMinGapMs, h.lastFailedAt + h.failDelay);
    if (due > now) {
      h.timer = this.after(due - now, () => {
        h.timer = null;
        this.pumpHello(peer);
      });
      return;
    }
    h.inFlight = true;
    const wasRequested = h.requested;
    h.requested = false;
    void this.deliver(peer, () => {
      if (peer.out.confirmed && !wasRequested) return null;
      // REQ-36: name P's current instance when it is known.
      const cur = peer.current;
      return this.withHead(this.common('call_hello', cur ? cur.id : null));
    }).then(outcome => {
      h.inFlight = false;
      if (this.ended) return;
      if (outcome === 'sent') {
        const t = this.clock.now();
        if (h.seriesStart === null) h.seriesStart = t;
        h.sent++;
        h.lastSentAt = t;
        peer.out.bundleFailures = 0;
      } else if (outcome !== 'stale') {
        h.lastFailedAt = this.clock.now();
        h.failDelay = this.failDelay(peer, outcome);
        if (h.sent === 0 || wasRequested) h.requested = true;
      }
      this.pumpHello(peer);
    });
  }

  private ensureCkmState(peer: Peer): CkmState | null {
    const ep = this.newest;
    const rec = peer.current;
    if (!ep || !rec) return null;
    const st = peer.out.ckm;
    if (!st || st.epoch !== ep.epoch || st.inst !== rec.id) {
      peer.out.ckm = { epoch: ep.epoch, inst: rec.id, txCount: 0, firstTxAt: null, lastTxAt: -Infinity, immediate: false };
    }
    return peer.out.ckm;
  }

  /** REQ-19, REQ-20: send or schedule the current CKM to `peer`. */
  private pumpCkm(peer: Peer): void {
    const out = peer.out;
    this.cancel(out.ckmTimer);
    out.ckmTimer = null;
    const ep = this.newest;
    if (!this.joined || this.ended || !ep || ep.retired || !ep.recipients.has(peer.id)) return;
    if (!this.view.has(peer.id) || !peer.eligible || !peer.current) return;
    if (out.instFloor > ep.epoch || (out.acked >= ep.epoch && !out.resend)) return;
    const st = this.ensureCkmState(peer)!;
    if (out.ckmInFlight) return;
    const now = this.clock.now();
    let due: number;
    if (st.txCount === 0 || st.immediate) due = now;
    else if (st.txCount <= this.t.maxRetx) due = st.lastTxAt + this.t.ackTimeoutMs;
    else due = st.lastTxAt + this.t.recoveryIntervalMs;
    due = Math.max(due, out.lastCkmAt + this.t.sendMinGapMs, out.ckmFailedAt + out.ckmFailDelay);
    if (due > now) {
      out.ckmTimer = this.after(due - now, () => {
        out.ckmTimer = null;
        this.pumpCkm(peer);
      });
      return;
    }
    st.immediate = false;
    out.ckmInFlight = true;
    const rec = peer.current;
    const resend = out.resend;
    // REQ-1, REQ-19: the current epoch, to the recipient's current instance,
    // members of R only; checked when the CKM is built and again at hand-off.
    const current = () => this.newest === ep && !ep.retired && peer.current === rec
      && ep.recipients.has(peer.id) && out.instFloor <= ep.epoch;
    void this.deliver(peer, () => {
      if (!current() || (out.acked >= ep.epoch && !resend)) return null;
      return this.withHead({
        ...this.common('call_key', rec.id),
        suite: CALL_SUITE,
        epoch: ep.epoch,
        key: encodeBase64(ep.secret),
      });
    }, current).then(outcome => {
      out.ckmInFlight = false;
      if (this.ended) return;
      // The granted re-send is spent once handed off, or moot once its epoch or instance is not current.
      if (resend && (outcome === 'sent' || outcome === 'stale')) out.resend = false;
      if (outcome === 'sent') {
        const t = this.clock.now();
        if (out.ckm === st) {
          st.txCount++;
          st.lastTxAt = t;
          if (st.firstTxAt === null) st.firstTxAt = t;
        }
        out.lastCkmAt = t;
        out.bundleFailures = 0;
        this.maybeSwitch();
      } else if (outcome !== 'stale') {
        out.ckmFailedAt = this.clock.now();
        out.ckmFailDelay = this.failDelay(peer, outcome);
      }
      this.pumpCkm(peer);
      this.changed();
    });
  }

  /** REQ-20: acknowledge (`inst`, `epoch`) to the key sender's instance. */
  private sendAck(peer: Peer, rec: InstanceRecord, epoch: number): void {
    const current = () => peer.current === rec;
    void this.deliver(peer, () => {
      if (!current()) return null;
      return { ...this.common('call_key_ack', rec.id), epoch } as unknown as ControlBody;
    }, current);
  }

  private stopOutbound(peer: Peer): void {
    this.cancel(peer.out.hello.timer);
    peer.out.hello.timer = null;
    this.cancel(peer.out.ckmTimer);
    peer.out.ckmTimer = null;
    peer.out.resend = false;
  }

  // -------------------------------------------------------------------------
  // States (§8.1, §8.2; REQ-31)
  // -------------------------------------------------------------------------

  private outboundOf(p: Peer, eligible: boolean): OutboundState {
    if (!eligible) return 'blocked';
    if (this.isSecure(p)) return 'secure';
    if (p.out.capped) return 'capped';
    if (!this.bridge.hasUsableSession(p.id)) return 'session';
    if (!p.current) return 'hello';
    return 'keying';
  }

  private isSecure(p: Peer): boolean {
    const ep = this.newest;
    if (!ep || !p.current || !ep.recipients.has(p.id)) return false;
    if (p.out.acked >= ep.epoch) return true;
    if (p.out.acked < 0 || p.out.acked !== ep.epoch - 1) return false;
    const st = p.out.ckm;
    const ref = st && st.epoch === ep.epoch && st.inst === p.current.id && st.firstTxAt !== null ? st.firstTxAt : ep.createdAt;
    return this.clock.now() - ref < this.t.ackGraceMs;
  }

  private inboundOf(p: Peer, eligible: boolean): InboundState {
    if (!eligible) return 'blocked';
    return p.current && p.current.epochs.size > 0 ? 'keyed' : 'waiting';
  }

  /** The panel's view: §8.1's indicator and §8.2's per-participant states. */
  snapshot(): CallKeySnapshot {
    const now = this.clock.now();
    const participants: ParticipantView[] = [];
    for (const u of this.view) {
      const p = this.peers.get(u)!;
      const e = this.bridge.eligibility(this.nodeId, this.channelId, u);
      const outbound = this.outboundOf(p, e.eligible);
      const inbound = this.inboundOf(p, e.eligible);
      let label: ParticipantLabel;
      if (!e.eligible) {
        label = e.reason === 'identity_changed' ? 'identity_changed' : e.reason === 'membership_unknown' ? 'checking_membership' : 'not_verified_member';
      } else if (outbound === 'secure' && inbound === 'keyed') {
        label = 'secure';
      } else if (now - p.t0 < this.t.connectGraceMs || (outbound === 'keying' && this.firstTxWithin(p, now))) {
        label = 'connecting';
      } else if (outbound !== 'secure' && inbound === 'waiting') {
        label = 'cant_connect';
      } else if (outbound !== 'secure') {
        label = 'they_cant_hear_you';
      } else {
        label = 'cant_hear_them';
      }
      const id = this.bridge.identityLabel(u);
      participants.push({
        userId: u,
        shortId: id.shortId || shortIdOf(u),
        ...(id.fingerprintGroup !== undefined ? { fingerprintGroup: id.fingerprintGroup } : {}),
        verified: id.verified,
        recipient: !!this.newest?.recipients.has(u),
        outbound,
        inbound,
        label,
        ineligibleReason: e.eligible ? null : e.reason,
        notes: {
          sessionProblem: p.sessionProblem,
          outdatedApp: p.legacyEvidence,
          olderAppP2p: this.p2pReportAt !== null && p.lastAcceptedAt < this.p2pReportAt,
          audioUnverifiable: p.aeadFails.audio >= this.t.aeadFailNotice,
        },
      });
    }
    return {
      indicator: this.indicatorFor(participants),
      participants,
      sendingEpoch: this.sendingEpoch(),
      newestEpoch: this.newest?.epoch ?? null,
    };
  }

  private firstTxWithin(p: Peer, now: number): boolean {
    const st = p.out.ckm;
    const ep = this.newest;
    return !!st && !!ep && st.epoch === ep.epoch && st.firstTxAt !== null && now - st.firstTxAt < this.t.connectGraceMs;
  }

  private indicatorFor(participants: readonly ParticipantView[]): IndicatorState {
    if (!this.bridge.isReady() || this.localError) return 'unavailable';
    if (participants.length === 0) return 'waiting_for_others';
    if (this.membershipState === 'checking') return 'checking_membership';
    if (this.membershipState === 'failed') return 'cant_verify_members';
    const secure = participants.filter(p => p.label === 'secure');
    if (secure.length === 0) return 'connecting';
    if (this.bridge.rule() === 'interim' || secure.some(p => !p.verified)) return 'e2ee_not_verified';
    return 'e2ee_verified';
  }

  /** Notify, and schedule a notification for the next time-driven state change. */
  private changed(): void {
    if (this.ended) return;
    this.hooks.onStateChange?.();
    if (!this.hooks.onStateChange) return;
    const now = this.clock.now();
    let next = Infinity;
    const consider = (t: number) => {
      if (t > now && t < next) next = t;
    };
    for (const u of this.view) {
      const p = this.peers.get(u)!;
      consider(p.t0 + this.t.connectGraceMs);
      const st = p.out.ckm;
      if (st?.firstTxAt != null) {
        consider(st.firstTxAt + this.t.connectGraceMs);
        consider(st.firstTxAt + this.t.ackGraceMs);
      }
    }
    if (this.newest) consider(this.newest.createdAt + this.t.ackGraceMs);
    this.cancel(this.stateTimer);
    this.stateTimer = next === Infinity ? null : this.after(next - now, () => {
      this.stateTimer = null;
      this.changed();
    });
  }

  // -------------------------------------------------------------------------
  // Inspection (tests and the panel)
  // -------------------------------------------------------------------------

  /** V, the participant view. */
  participants(): string[] {
    return [...this.view];
  }

  /** The newest epoch's recipient set R_g. */
  currentRecipients(): string[] {
    return this.newest ? [...this.newest.recipients] : [];
  }

  /** A remote user's retained record (REQ-34), or null if none exists. */
  retainedRecord(userId: string): RetainedRecordView | null {
    const p = this.peers.get(userId.toLowerCase());
    if (!p) return null;
    const rec = p.current;
    const keys: { kind: MediaKind; kid: number }[] = [];
    if (rec) {
      for (const k of rec.store.keys()) {
        const [kind, kid] = k.split(':').map(Number);
        keys.push({ kind: kind as MediaKind, kid });
      }
    }
    const replayWindows = rec
      ? [...rec.windows].sort(([x], [y]) => x - y).map(([kid, w]) => ({ kid, audio: w.audio.highest, video: w.video.highest }))
      : [];
    return {
      currentInst: rec?.id ?? null,
      replaced: [...p.replaced],
      maxEpoch: rec?.maxEpoch ?? -1,
      maxEpochFirstInstalledAt: rec && rec.maxEpoch >= 0 ? rec.maxEpochFirstInstalledAt : null,
      highestAuthEpoch: { audio: rec?.highestAuth.audio ?? -1, video: rec?.highestAuth.video ?? -1 },
      replayHighest: {
        audio: Math.max(-1, ...replayWindows.map(w => w.audio)),
        video: Math.max(-1, ...replayWindows.map(w => w.video)),
      },
      replayWindows,
      keys,
    };
  }

  /** The receiver key store's key for (kind, KID) of `userId`'s current instance (T-14). */
  receiverKey(userId: string, kind: MediaKind, kid: number): KindKeys | null {
    return this.peers.get(userId.toLowerCase())?.current?.store.get(keyOf(kind, kid)) ?? null;
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private normalizeList(list: readonly string[]): string[] {
    const out: string[] = [];
    for (const u of list) {
      if (typeof u !== 'string') continue;
      const l = u.toLowerCase();
      if (l !== this.self && !out.includes(l)) out.push(l);
    }
    return out;
  }

  private addToView(u: string): Peer {
    this.view.add(u);
    let p = this.peers.get(u);
    if (!p) {
      p = {
        id: u,
        eligible: false,
        t0: this.clock.now(),
        current: null,
        replaced: [],
        out: {
          hello: { seriesStart: null, sent: 0, lastSentAt: -Infinity, lastFailedAt: -Infinity, failDelay: 0, requested: false, inFlight: false, timer: null },
          ckm: null,
          ckmInFlight: false,
          ckmTimer: null,
          lastCkmAt: -Infinity,
          ckmFailedAt: -Infinity,
          ckmFailDelay: 0,
          confirmed: false,
          acked: -1,
          ackedAt: 0,
          instFloor: 0,
          resendFor: null,
          resend: false,
          credit: false,
          capped: false,
          held: false,
          bundleFailures: 0,
          sendChain: Promise.resolve(),
        },
        busy: 0,
        installFailed: false,
        pendingAudio: [],
        pendingVideo: [],
        msgChain: Promise.resolve(),
        audioChain: Promise.resolve(),
        videoChain: Promise.resolve(),
        held: [],
        holdTimer: null,
        legacyEvidence: false,
        sessionProblem: false,
        lastAcceptedAt: -Infinity,
        aeadFails: { audio: 0, video: 0 },
      };
      this.peers.set(u, p);
    }
    return p;
  }

  private after(ms: number, fn: () => void): unknown {
    const h = this.clock.setTimeout(() => {
      this.timers.delete(h);
      if (!this.ended) fn();
    }, ms);
    this.timers.add(h);
    return h;
  }

  private cancel(h: unknown): void {
    if (h === null || h === undefined) return;
    this.clock.clearTimeout(h);
    this.timers.delete(h);
  }

  private track<T>(p: Promise<T>): Promise<T> {
    this.inflight++;
    const done = () => {
      this.inflight--;
      if (this.inflight === 0) {
        const waiters = this.idleWaiters;
        this.idleWaiters = [];
        for (const w of waiters) w();
      }
    };
    p.then(done, done);
    return p;
  }
}
