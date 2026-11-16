/**
 * @module voice/relay
 * Relay-mode voice: the only call mode of current clients (SPEC-03 stage 0
 * with amendment A1, REQ-41). Audio goes through the relay as AMF1 frames:
 * SFrame (RFC 9605, AES-256-GCM) under a per-sender epoch key with
 * authenticated metadata binding channel, sender, instance, media kind,
 * epoch and counter (§6.2). Epoch keys travel only inside pairwise Double
 * Ratchet messages to the participants the sender considers eligible
 * (`CallKeyManager`, §6.3); the relay forwards the frames and call messages
 * but holds no key. Under the interim rule of REQ-9 the relay still decides
 * who is a member, so the call security indicator says "not verified".
 *
 * One `RelayVoiceConnection` serves one voice session: from the user
 * selecting a voice channel until leaving it or being evicted (§5.1). Each
 * call within it (first join, rejoin after a reconnect or a failed
 * self-check) has its own `CallKeyManager` and so its own instance (REQ-5).
 *
 * - Frames are sent only as `SrtpVoicePacket` through the non-queuing
 *   `sendMediaFrame`, and call messages only through `sendCallMessage`
 *   (REQ-2, REQ-37). There is no plaintext path and no raw key anywhere.
 * - Received frames are opened by the manager, which serializes each
 *   sender's call messages and frames in arrival order (REQ-35); only
 *   authenticated plaintext is decoded, and only Opus (0x01) or PCM (0x00):
 *   any other codec byte, or Opus without a decoder, is discarded (REQ-3).
 *   The authenticated CTR is the jitter buffer's only sequence (REQ-15);
 *   the first frame under a sender's newer epoch resets the buffer when
 *   its CTR is not above the highest received (A2).
 * - The mute and deafen state is passed at construction and applied before
 *   anything is captured (REQ-5, C028).
 * - Disconnects end the call and erase it; the next `authenticated` rejoins
 *   with a new instance (REQ-22). A self-check rejoins when the relay has
 *   silently dropped the local user (REQ-38). Only an exact eviction ends
 *   the session (REQ-40). Relay mode reports drive a note only (REQ-41).
 * - No peer connection, no P2P signaling and no mode switch exist (REQ-39).
 * - Screen sharing (A1): each call owns one `ScreenShareSender` and the
 *   `ScreenViewers` of `voice/screenShare.ts`, fed with the call's epoch keys
 *   by its `CallKeyManager` (REQ-45). They run only on a relay whose `hello`
 *   lists `screen/1` and where the probes of §6.13.1 pass, which run once per
 *   voice session; there is no other transport (REQ-42).
 *
 * Nothing here logs or stores key material, frames or call messages (REQ-27).
 */

import type { AccordWebSocket, ScreenLimits, SendResult } from '../ws';
import { decodeWireBase64 } from '../attachments/base64';
import {
  CallKeyManager,
  type CallKeySnapshot,
  type CallKeyTimings,
  type ReceivedAudioFrame,
} from './callKeys';
import {
  KEYS_WAIT_NOTICE_MS,
  STRAY_STOP_MIN_GAP_MS,
  ScreenShareSender,
  ScreenViewers,
  SentStops,
  VIDEO_STALL_NOTICE_MS,
  VIDEO_WAIT_NOTICE_MS,
  browserScreenPlatform,
  probeCapture,
  probeViewing,
  shareControlState,
  viewerTileState,
  type CaptureProbe,
  type LocalShareView,
  type RemoteShareView,
  type ScreenNotice,
  type ScreenPlatform,
  type ShareControlState,
  type ShareSurface,
  type ViewerTileState,
  type ViewingProbe,
} from './screenShare';
import { systemCallClock, type CallClock, type CallKeyBridge } from './callKeyBridge';
import { JitterBuffer } from './jitterBuffer';
import { CODEC_OPUS, CODEC_PCM, type AudioDecoderPort, type VoiceMediaInput, type VoiceMediaOutput } from './mediaIo';

export type SpeakingCallback = (userId: string, speaking: boolean) => void;

/** The parts of the relay WebSocket a voice connection uses. */
export type VoiceSocket = Pick<
  AccordWebSocket,
  | 'on'
  | 'off'
  | 'isSocketConnected'
  | 'joinVoiceChannel'
  | 'leaveVoiceChannel'
  | 'getVoiceParticipants'
  | 'sendVoiceSpeakingState'
  | 'sendCallMessage'
  | 'sendMediaFrame'
  | 'isScreenCapable'
  | 'screenLimits'
  | 'helloProcessed'
  | 'bufferedAmount'
  | 'sendScreenFragment'
  | 'screenShareStart'
  | 'screenShareStop'
  | 'screenWatch'
  | 'screenKeyframeRequest'
>;

/** Timings of the connection itself (§6.5); tests may shorten them. */
export interface RelayVoiceTimings {
  /** `JOIN_CONFIRM_TIMEOUT` (§8.3). */
  joinConfirmMs: number;
  /** `SELF_CHECK`: first check after `voice_channel_joined` (REQ-38). */
  selfCheckFirstMs: number;
  /** `SELF_CHECK`: then every (REQ-38). */
  selfCheckIntervalMs: number;
  /** At most one self-check rejoin per (REQ-38). */
  selfCheckRejoinGapMs: number;
  /** The longest the join waits for N's lists at call start (§6.6 step 1). */
  membershipWaitMs: number;
  /** Jitter-buffer playout tick. */
  playoutIntervalMs: number;
}

export const DEFAULT_RELAY_VOICE_TIMINGS: Readonly<RelayVoiceTimings> = Object.freeze({
  joinConfirmMs: 10_000,
  selfCheckFirstMs: 5000,
  selfCheckIntervalMs: 30_000,
  selfCheckRejoinGapMs: 30_000,
  membershipWaitMs: 5000,
  playoutIntervalMs: 20,
});

/** The longest `packet_data` of a 4096-byte frame (§6.2.1), in base64 characters. */
const PACKET_DATA_MAX = Math.ceil(4096 / 3) * 4;
/** Opus packets waiting for their decoder's output; beyond it the decoder is replaced. */
const PENDING_DECODES_MAX = 50;
/** One Opus frame's duration, for decoder timestamps only. */
const FRAME_US = 20_000;
/** Playout stops after this many ticks without a frame, and restarts on the next one. */
const PLAYOUT_IDLE_TICKS = 50;

export interface RelayVoiceOptions {
  ws: VoiceSocket;
  /** C, the voice channel. */
  channelId: string;
  /** N, the node recorded with C when the user selected it (REQ-9). */
  nodeId: string | null;
  /** The E2EE bridge (§6.10); without one, secure voice is unavailable (REQ-23). */
  bridge: CallKeyBridge | null;
  /** The user interface's mute and deafen state at construction (REQ-5). */
  muted: boolean;
  deafened: boolean;
  input: VoiceMediaInput;
  output: VoiceMediaOutput;
  clock?: CallClock;
  callTimings?: Partial<CallKeyTimings>;
  voiceTimings?: Partial<RelayVoiceTimings>;
  random?: (length: number) => Uint8Array;
  /** Capture, codecs and renderer of screen sharing (§10.1); the browser's by default. */
  screen?: ScreenPlatform;
}

/**
 * - `connecting`: a call was started and waits for its `voice_channel_joined`;
 * - `joined`: the call's instance is joined;
 * - `reconnecting`: the socket is down; the next `authenticated` rejoins (REQ-22);
 * - `unavailable`: the E2EE manager is not ready (REQ-23): no join was sent;
 * - `failed`: no `voice_channel_joined` within 10 s (§8.3);
 * - `removed`: the relay evicted the local user (REQ-40);
 * - `left`: the connection was disconnected locally.
 */
export type VoicePhase = 'connecting' | 'joined' | 'reconnecting' | 'unavailable' | 'failed' | 'removed' | 'left';

export interface VoiceConnectionState {
  readonly phase: VoicePhase;
  /** "Reconnecting secure voice…" (REQ-22, REQ-38): the socket is down, or a rejoin waits for its join. */
  readonly reconnecting: boolean;
  /** The microphone could not be opened: the call is listen-only (§8.3). */
  readonly listenOnly: boolean;
  /** Audio output is available. */
  readonly playback: boolean;
  /** The latest relay report for C says `p2p` (REQ-41): show the note of §8.3, nothing else. */
  readonly relayReportsP2p: boolean;
  /** §8.1 and §8.2, from the current call's local key state; null without a call. */
  readonly call: CallKeySnapshot | null;
  /** The current call's `inst` (standard base64), or null. */
  readonly instanceId: string | null;
  /** Screen sharing (§8.4), from local state only (REQ-54). */
  readonly screen: ScreenState;
}

/** A tile of the remote share list, with its §8.4 row. */
export interface RemoteTileView extends RemoteShareView {
  readonly eligible: boolean;
  readonly hasKey: boolean;
  readonly tile: ViewerTileState;
  /** Watch may be offered now (REQ-50). */
  readonly canWatch: boolean;
}

export interface ScreenState {
  /** The Share Screen control's row of §8.4. */
  readonly control: ShareControlState;
  /** The local share, or null before the first click of this call. */
  readonly local: LocalShareView | null;
  /** The latest message after an attempt (§8.4), until the next attempt. */
  readonly notice: ScreenNotice | null;
  readonly relayCapable: boolean;
  readonly limits: ScreenLimits | null;
  readonly capture: CaptureProbe | null;
  readonly viewing: ViewingProbe | null;
  /** The remote share list (REQ-53), in announcement order. */
  readonly remote: readonly RemoteTileView[];
  /** Shares being watched (at most `WATCH_MAX`). */
  readonly watching: number;
  readonly now: number;
}

interface ActiveCall {
  readonly mgr: CallKeyManager;
  readonly viewers: ScreenViewers;
  /** Created at the first Share Screen click of the call. */
  sender: ScreenShareSender | null;
  /** Every `ScreenShareStop` of this call, from the sender or from the paths below (REQ-52, A2). */
  readonly stops: SentStops;
  joinSent: boolean;
  joined: boolean;
  joinTimer: unknown;
  selfCheckTimer: unknown;
  selfCheckPending: boolean;
  /**
   * `voice_peer_joined` and `voice_peer_left` for C that arrived after this
   * call's JoinVoiceChannel but before its `voice_channel_joined`. The relay
   * takes the join reply's list when it adds the user, and handles each
   * connection's messages concurrently, so another participant's join or
   * departure that happened after that moment can reach this socket before
   * the reply. They are applied, in order, right after the reply (§5.1:
   * V is the reply's list, then updated by these events).
   */
  early: Array<{ readonly joined: boolean; readonly user: string }>;
}

/** At most this many early participant events are kept per call. */
const EARLY_EVENTS_MAX = 64;

interface RemotePipeline {
  readonly jitter: JitterBuffer;
  decoder: AudioDecoderPort | null;
  /** CTRs and epochs of Opus packets handed to the decoder, in order. */
  pending: Array<{ readonly ctr: number; readonly epoch: number }>;
  /**
   * The newest epoch of a frame pushed into `jitter` since the pipeline was
   * last reset, or −1 (REQ-15 as amended by A2). Kept here rather than on
   * the frame that opened the epoch, so that the check runs on the first
   * frame of a newer epoch that is actually pushed, whichever frames were
   * dropped before it (a decoder that was replaced, for example).
   */
  lastEpoch: number;
  /** Bumped on every reset, so outputs of a replaced decoder are dropped. */
  generation: number;
  timer: unknown;
  /** Playout ticks since the last frame played or arrived. */
  idleTicks: number;
}

const lower = (s: string) => s.toLowerCase();

/** The panel's 1 s refresh while screen sharing shows counters (§8.4). */
const SCREEN_TICK_MS = 1000;

function stringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

export class RelayVoiceConnection {
  readonly channelId: string;
  private readonly nodeId: string | null;
  private readonly ws: VoiceSocket;
  private readonly bridge: CallKeyBridge | null;
  private readonly input: VoiceMediaInput;
  private readonly output: VoiceMediaOutput;
  private readonly clock: CallClock;
  private readonly callTimings: Partial<CallKeyTimings> | undefined;
  private readonly t: RelayVoiceTimings;
  private readonly random: ((length: number) => Uint8Array) | undefined;
  private readonly self: string;
  private readonly screen: ScreenPlatform;
  private captureProbe: CaptureProbe | null = null;
  private viewingProbe: ViewingProbe | null = null;
  private screenNotice: ScreenNotice | null = null;
  private screenTick: unknown = null;
  /** When the pending panel refresh is due. */
  private screenTickAt = Infinity;
  /** The last `ScreenShareStop` answering a share this client never started (REQ-52). */
  private lastStrayStopAt = -Infinity;
  /** The tiles' canvases, by sharer, kept across the calls of the session. */
  private readonly surfaces = new Map<string, ShareSurface>();

  private muted: boolean;
  private deafened: boolean;
  private started = false;
  private destroyed = false;
  private phase: VoicePhase = 'connecting';
  private rejoining = false;
  private listenOnly = false;
  private playback = false;
  private joinEverSent = false;
  private lastMode: string | null = null;
  private lastSelfCheckRejoinAt = -Infinity;
  private localSpeaking = false;

  private call: ActiveCall | null = null;
  private readonly pipelines = new Map<string, RemotePipeline>();
  private inflight = 0;
  private idleWaiters: Array<() => void> = [];
  private readonly wsHandlers: Array<{ event: string; handler: (data: any) => void }> = [];

  /** The local speaking flag changed (relay-asserted for peers; local VAD for self). */
  onSpeaking: SpeakingCallback | null = null;
  /** Something `state` shows changed. */
  onStateChange: ((state: VoiceConnectionState) => void) | null = null;

  constructor(opts: RelayVoiceOptions) {
    this.ws = opts.ws;
    this.channelId = lower(opts.channelId);
    this.nodeId = opts.nodeId ? lower(opts.nodeId) : null;
    this.bridge = opts.bridge;
    this.input = opts.input;
    this.output = opts.output;
    this.clock = opts.clock ?? systemCallClock;
    this.callTimings = opts.callTimings;
    this.t = { ...DEFAULT_RELAY_VOICE_TIMINGS, ...(opts.voiceTimings ?? {}) };
    this.random = opts.random;
    this.self = lower(opts.bridge?.selfId() ?? '');
    this.screen = opts.screen ?? browserScreenPlatform();
    // REQ-5: the state the user interface shows now applies from the start.
    this.muted = opts.muted;
    this.deafened = opts.deafened;
    this.output.setDeafened(this.deafened);
    this.setupSignaling();
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /** Start the voice session: open playback, then start the first call. */
  async connect(): Promise<void> {
    if (this.started || this.destroyed) return;
    this.started = true;
    // §6.13.1: both probes run once per voice session, before any click.
    this.track(this.runProbes());
    const opening = this.output.open().catch(() => false);
    this.track(opening);
    this.playback = await opening;
    // A disconnect meanwhile leaves the start to the next `authenticated`.
    if (this.destroyed || this.call || this.phase !== 'connecting') return;
    this.startCall(false);
  }

  /**
   * Local leave, channel switch or unmount (§6.6 step 14): send
   * `LeaveVoiceChannel`, erase all call state and clear every timer and
   * listener.
   */
  disconnect(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    // §6.6 step 14: end any share and every watch, then leave.
    this.endScreen(null);
    // Not after an eviction, nor after a join timeout, which already left.
    if (this.joinEverSent && this.phase !== 'removed' && this.phase !== 'failed') this.ws.leaveVoiceChannel(this.channelId);
    this.endCall();
    this.clock.clearTimeout(this.screenTick);
    this.screenTick = null;
    this.screenTickAt = Infinity;
    this.surfaces.clear();
    this.output.close();
    for (const { event, handler } of this.wsHandlers.splice(0)) this.ws.off(event as any, handler);
    this.phase = 'left';
    this.rejoining = false;
    this.changed();
  }

  setMuted(muted: boolean): void {
    this.muted = muted;
    this.applyMute();
  }

  /** Deafened: nothing is played, and the microphone is muted too. */
  setDeafened(deafened: boolean): void {
    this.deafened = deafened;
    this.output.setDeafened(deafened);
    if (deafened) this.muted = true;
    this.applyMute();
  }

  get speaking(): boolean {
    return this.localSpeaking;
  }

  get state(): VoiceConnectionState {
    const call = this.call;
    return {
      phase: this.phase,
      reconnecting: this.phase === 'reconnecting' || (this.phase === 'connecting' && this.rejoining),
      listenOnly: this.listenOnly,
      playback: this.playback,
      relayReportsP2p: this.lastMode === 'p2p',
      call: call ? call.mgr.snapshot() : null,
      instanceId: call ? call.mgr.instanceId : null,
      screen: this.screenState(),
    };
  }

  // -------------------------------------------------------------------------
  // Screen sharing (§5.10, §8.4)
  // -------------------------------------------------------------------------

  /**
   * The Share Screen click (REQ-43). Everything before `getDisplayMedia` is
   * synchronous, so the call keeps the click's transient activation. Returns
   * false when the control is not in its enabled state (REQ-42).
   */
  startScreenShare(): boolean {
    const call = this.call;
    if (!call || this.destroyed) return false;
    if (this.controlState().kind !== 'idle') return false;
    const sender = this.ensureSender(call);
    if (!sender) return false;
    this.screenNotice = null;
    return sender.startFromClick();
  }

  /** The Share Screen control's row of §8.4, computed synchronously (for the click handler). */
  screenControl(): ShareControlState {
    return this.controlState();
  }

  /** Stop Sharing, or Cancel while starting (REQ-52). */
  stopScreenShare(): void {
    this.call?.sender?.stopFromUser();
  }

  /** Watch on a tile (REQ-50). */
  watchScreen(sharerId: string): boolean {
    return this.call?.viewers.watch(sharerId) ?? false;
  }

  unwatchScreen(sharerId: string): void {
    this.call?.viewers.unwatch(sharerId);
  }

  /** A tile's canvas mounted (or, with null, unmounted). */
  attachScreenSurface(sharerId: string, surface: ShareSurface | null): void {
    const u = lower(sharerId);
    if (surface) this.surfaces.set(u, surface);
    else this.surfaces.delete(u);
    this.call?.viewers.attachSurface(u, surface);
  }

  /** The current call's key manager, or null between calls (tests and inspection). */
  get callKeys(): CallKeyManager | null {
    return this.call?.mgr ?? null;
  }

  /** The current call's screen parts (tests). */
  get screenParts(): { sender: ScreenShareSender | null; viewers: ScreenViewers } | null {
    const call = this.call;
    return call ? { sender: call.sender, viewers: call.viewers } : null;
  }

  private async runProbes(): Promise<void> {
    const [capture, viewing] = await Promise.all([
      probeCapture(this.screen).catch((): CaptureProbe => ({ ok: false, reason: 'no_capture' })),
      probeViewing(this.screen).catch((): ViewingProbe => ({ ok: false })),
    ]);
    if (this.destroyed) return;
    this.captureProbe = capture;
    this.viewingProbe = viewing;
    this.changed();
  }

  private controlState(): ShareControlState {
    const call = this.call;
    const local = call?.sender ?? null;
    const limits = this.ws.screenLimits();
    return shareControlState({
      local: local?.state ?? 'idle',
      picking: local?.isPicking ?? false,
      joined: !!call?.joined,
      e2eeReady: !!this.bridge?.isReady(),
      socketOpen: this.ws.isSocketConnected(),
      helloProcessed: this.ws.helloProcessed(),
      relayCapable: this.ws.isScreenCapable(),
      capture: this.captureProbe,
      remoteShares: call ? call.viewers.snapshot().length : 0,
      maxSharers: limits?.maxSharers ?? null,
    });
  }

  private screenState(): ScreenState {
    const call = this.call;
    const relayCapable = this.ws.isScreenCapable();
    const now = this.clock.now();
    const remote: RemoteTileView[] = (call ? call.viewers.snapshot() : []).map(share => {
      const eligible = !!call?.mgr.isEligibleParticipant(share.sharerId);
      const hasKey = !!call?.mgr.hasVideoKey(share.sharerId);
      return {
        ...share,
        eligible,
        hasKey,
        tile: viewerTileState({ share, viewing: this.viewingProbe, relayCapable, eligible, hasKey, now }),
        canWatch: !!call?.viewers.canWatch(share.sharerId),
      };
    });
    return {
      control: this.controlState(),
      local: call?.sender ? call.sender.snapshot() : null,
      notice: this.screenNotice,
      relayCapable,
      limits: this.ws.screenLimits(),
      capture: this.captureProbe,
      viewing: this.viewingProbe,
      remote,
      watching: call ? call.viewers.watchingCount() : 0,
      now,
    };
  }

  private ensureSender(call: ActiveCall): ScreenShareSender | null {
    if (call.sender) return call.sender;
    const probe = this.captureProbe;
    if (!probe?.ok) return null;
    const current = () => this.call === call;
    const notHandedOff = (): SendResult => ({ handedOff: false, messageId: '' });
    call.sender = new ScreenShareSender({
      channelId: this.channelId,
      selfId: this.self,
      platform: this.screen,
      keys: call.mgr,
      transport: {
        isOpen: () => current() && this.ws.isSocketConnected(),
        bufferedAmount: () => this.ws.bufferedAmount(),
        sendScreenFragment: (ch, fragment) => current() && this.ws.sendScreenFragment(ch, fragment),
        screenShareStart: ch => (current() ? this.ws.screenShareStart(ch) : notHandedOff()),
        screenShareStop: ch => (current() ? this.ws.screenShareStop(ch) : notHandedOff()),
      },
      clock: this.clock,
      probe,
      limits: () => this.ws.screenLimits(),
      canStart: () => current() && call.joined && !!this.bridge?.isReady() && this.ws.isScreenCapable(),
      stops: call.stops,
      onChange: () => {
        if (current()) this.changed();
      },
      onNotice: n => {
        this.screenNotice = n;
      },
    });
    return call.sender;
  }

  /** End the local share and every watch of the current call (REQ-22, REQ-52). */
  private endScreen(notice: ScreenNotice | null): void {
    const call = this.call;
    if (!call) return;
    if (call.sender) call.sender.end(notice);
    call.viewers.end();
  }

  /** An E2EE lock ends a share (REQ-52). */
  private checkScreenLock(call: ActiveCall): void {
    if (call.sender?.busy && !this.bridge?.isReady()) call.sender.stopFromUser();
  }

  /**
   * The panel's timer (§8.4), armed only while a share is watched or the
   * local share is busy. A watched tile is refreshed exactly when its row
   * changes with time (10 s after the watch started or the last decoded
   * frame while awaiting a keyframe, 15 s after it while decoding, 12 s
   * without a key, §6.5) and every second while it shows an "N s" counter
   * (rows 7 and 8). While the local share is busy, an E2EE lock is checked
   * every second (REQ-52); that refreshes nothing by itself. Unwatched tiles
   * show nothing that changes with time.
   */
  private armScreenTick(): void {
    if (this.destroyed) return;
    const call = this.call;
    if (!call) return;
    const now = this.clock.now();
    let delay = call.sender?.busy ? SCREEN_TICK_MS : Infinity;
    for (const s of call.viewers.snapshot()) {
      const v = s.viewer;
      if (!v) continue;
      const ref = Math.max(v.watchStartedAt, v.lastDecodedAt ?? -Infinity);
      const rowChangeAt = ref + (v.state === 'awaiting_keyframe' ? VIDEO_WAIT_NOTICE_MS : VIDEO_STALL_NOTICE_MS);
      delay = Math.min(delay, rowChangeAt > now ? rowChangeAt - now : SCREEN_TICK_MS);
      const keysAt = (v.keylessSince ?? v.watchStartedAt) + KEYS_WAIT_NOTICE_MS;
      if (v.keylessSince !== null && keysAt > now) delay = Math.min(delay, keysAt - now);
    }
    if (delay === Infinity) return;
    const at = now + delay;
    if (this.screenTick !== null) {
      if (this.screenTickAt <= at) return;
      this.clock.clearTimeout(this.screenTick);
    }
    this.screenTickAt = at;
    this.screenTick = this.clock.setTimeout(() => {
      this.screenTick = null;
      this.screenTickAt = Infinity;
      const c = this.call;
      if (!c) return;
      this.checkScreenLock(c);
      if (c.viewers.watchingCount() > 0) this.changed();
      else this.armScreenTick();
    }, delay);
  }

  /** Resolves once no asynchronous work of this connection or its call is in flight (tests). */
  async whenIdle(): Promise<void> {
    for (;;) {
      const mgr = this.call?.mgr;
      if (mgr) await mgr.whenIdle();
      if (this.inflight === 0) return;
      await new Promise<void>(r => this.idleWaiters.push(r));
    }
  }

  // -------------------------------------------------------------------------
  // Calls
  // -------------------------------------------------------------------------

  private startCall(rejoin: boolean): void {
    if (this.destroyed) return;
    this.endCall();
    this.rejoining = rejoin;
    const bridge = this.bridge;
    // REQ-23: no call, and no JoinVoiceChannel, while the E2EE manager is not
    // initialized (or the call has no node to check members against).
    if (!bridge || !this.nodeId || !bridge.isReady()) {
      this.phase = 'unavailable';
      this.changed();
      return;
    }
    if (!this.ws.isSocketConnected()) {
      this.phase = 'reconnecting';
      this.rejoining = true;
      this.changed();
      return;
    }
    let call: ActiveCall | null = null;
    const current = () => call !== null && this.call === call;
    const notHandedOff = (): SendResult => ({ handedOff: false, messageId: '' });
    const mgr = new CallKeyManager({
      channelId: this.channelId,
      nodeId: this.nodeId,
      bridge,
      clock: this.clock,
      timings: this.callTimings,
      random: this.random,
      transport: {
        sendCallMessage: (channelId, target, wrappedKey) => current() && this.ws.sendCallMessage(channelId, target, wrappedKey),
        sendMediaFrame: (channelId, frame) => {
          const sent = current() && this.ws.sendMediaFrame(channelId, frame);
          // REQ-47: waiting fragments are checked again after each audio send.
          if (sent) call?.sender?.onAudioSent();
          return sent;
        },
      },
      hooks: {
        onAudioFrame: (from, frame) => {
          if (current()) this.receiveAudio(from, frame);
        },
        onRemoteReset: (from, cause) => {
          if (!current()) return;
          this.resetPipeline(from);
          call!.viewers.onRemoteReset(from, cause === 'new_instance');
        },
        isWatching: from => current() && call!.viewers.isWatching(from),
        takeVideoDecryption: from => current() && call!.viewers.takeDecryption(from),
        onVideoFragment: (from, kid, plaintext) => {
          if (current()) call!.viewers.onFragment(from, kid, plaintext);
        },
        onVideoAeadFailures: (from, consecutive) => {
          if (current()) call!.viewers.onAeadFailures(from, consecutive);
        },
        onRemoteKeyInstalled: from => {
          if (current()) call!.viewers.onKeyInstalled(from);
        },
        onEpochSwitch: () => {
          if (current()) call!.sender?.onEpochSwitch();
        },
        onRejoinNeeded: () => {
          // Counters or epochs exhausted (REQ-6): a new instance, after this turn.
          if (current()) this.clock.setTimeout(() => current() && this.rejoin(), 0);
        },
        onStateChange: () => {
          if (!current()) return;
          // V or eligibility may have changed (REQ-50, §8.4).
          call!.viewers.reconcileView();
          call!.viewers.reconcileEligibility();
          this.checkScreenLock(call!);
          this.changed();
        },
      },
    });
    const viewers = new ScreenViewers({
      channelId: this.channelId,
      selfId: this.self,
      platform: this.screen,
      clock: this.clock,
      keys: mgr,
      transport: {
        isScreenCapable: () => current() && this.ws.isScreenCapable(),
        screenWatch: (ch, sharer, watch) => (current() ? this.ws.screenWatch(ch, sharer, watch) : notHandedOff()),
        screenKeyframeRequest: (ch, sharer) => (current() ? this.ws.screenKeyframeRequest(ch, sharer) : notHandedOff()),
      },
      viewing: () => this.viewingProbe,
      onChange: () => {
        if (current()) this.changed();
      },
    });
    for (const [sharer, surface] of this.surfaces) viewers.attachSurface(sharer, surface);
    call = { mgr, viewers, sender: null, stops: new SentStops(), joinSent: false, joined: false, joinTimer: null, selfCheckTimer: null, selfCheckPending: false, early: [] };
    this.call = call;
    if (!mgr.start()) {
      this.call = null;
      mgr.end();
      this.phase = 'unavailable';
      this.changed();
      return;
    }
    if (this.lastMode !== null) mgr.noteRelayMode(this.lastMode);
    this.phase = 'connecting';
    this.listenOnly = false;
    this.changed();
    this.track(this.beginCall(call));
  }

  /** §6.6 step 1: capture with the current mute state, wait for N's lists, then join. */
  private async beginCall(call: ActiveCall): Promise<void> {
    const capturing = await this.input
      .start(this.captureMuted(), {
        frame: plaintext => this.captured(call, plaintext),
        speaking: speaking => this.capturedSpeaking(call, speaking),
      })
      .catch(() => false);
    if (this.call !== call) return;
    this.listenOnly = !capturing;
    this.changed();
    await this.waitMembership(call);
    if (this.call !== call || !this.ws.isSocketConnected()) return;
    call.joinSent = true;
    this.joinEverSent = true;
    this.ws.joinVoiceChannel(this.channelId);
    call.joinTimer = this.clock.setTimeout(() => {
      if (this.call !== call || call.joined) return;
      // §8.3: "Couldn't join voice". The relay may have processed the join
      // and only its reply was lost: leave, so it stops listing the user in
      // V (its reply, without a reason, is ignored under REQ-40).
      this.ws.leaveVoiceChannel(this.channelId);
      this.endCall();
      this.phase = 'failed';
      this.rejoining = false;
      this.changed();
    }, this.t.joinConfirmMs);
  }

  private waitMembership(call: ActiveCall): Promise<void> {
    return new Promise<void>(resolve => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        this.clock.clearTimeout(timer);
        resolve();
      };
      const timer = this.clock.setTimeout(finish, this.t.membershipWaitMs);
      call.mgr.whenMembershipChecked().then(finish, finish);
    });
  }

  /**
   * End the current call: end its share and watches, erase its keys and
   * state, stop capture and playback pipelines. `screenNotice` is shown if a
   * share was running (a reconnect, §8.4).
   */
  private endCall(screenNotice: ScreenNotice | null = null): void {
    const call = this.call;
    if (!call) return;
    this.endScreen(screenNotice);
    this.call = null;
    this.clock.clearTimeout(call.joinTimer);
    this.clock.clearTimeout(call.selfCheckTimer);
    call.mgr.end();
    this.input.stop();
    for (const user of [...this.pipelines.keys()]) this.dropPipeline(user);
    this.listenOnly = false;
    if (this.localSpeaking) {
      this.localSpeaking = false;
      this.onSpeaking?.(this.self, false);
    }
  }

  /** End the instance and start a new one (REQ-6, REQ-38). */
  private rejoin(): void {
    if (this.destroyed) return;
    this.endCall({ code: 'reconnected' });
    this.startCall(true);
  }

  // -------------------------------------------------------------------------
  // Capture and sending
  // -------------------------------------------------------------------------

  private captureMuted(): boolean {
    return this.muted || this.deafened;
  }

  private applyMute(): void {
    const muted = this.captureMuted();
    this.input.setMuted(muted);
    if (muted && this.localSpeaking) {
      this.localSpeaking = false;
      this.onSpeaking?.(this.self, false);
      if (this.call?.joined) this.ws.sendVoiceSpeakingState(this.channelId, this.self, false);
    }
  }

  /**
   * REQ-2: a captured frame is sealed and sent only once the instance is
   * joined, while the mute state allows it; the manager also discards it
   * while no epoch key is ready or sending is suspended.
   */
  private captured(call: ActiveCall, plaintext: Uint8Array): void {
    if (this.call !== call || !call.joined || this.captureMuted()) return;
    call.mgr.sendAudio(plaintext);
  }

  private capturedSpeaking(call: ActiveCall, speaking: boolean): void {
    if (this.call !== call) return;
    const s = speaking && !this.captureMuted();
    if (s === this.localSpeaking) return;
    this.localSpeaking = s;
    this.onSpeaking?.(this.self, s);
    // The plaintext speaking flag stays in stage 0 (OD-56); it never drives a security state (REQ-31).
    if (call.joined) this.ws.sendVoiceSpeakingState(this.channelId, this.self, s);
  }

  // -------------------------------------------------------------------------
  // Receiving and playback
  // -------------------------------------------------------------------------

  /** §6.2.6 step 9: decode an authenticated frame and push it with sequence = CTR. */
  private receiveAudio(from: string, frame: ReceivedAudioFrame): void {
    const user = lower(from);
    if (frame.codec === CODEC_PCM) {
      const bytes = frame.payload;
      if (bytes.length === 0 || bytes.length % 2 !== 0) return;
      const pcm = new Int16Array(bytes.length / 2);
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      for (let i = 0; i < pcm.length; i++) pcm[i] = view.getInt16(2 * i, true);
      this.push(user, this.pipeline(user), frame.ctr, frame.epoch, pcm);
      return;
    }
    if (frame.codec !== CODEC_OPUS) return; // REQ-3: never interpreted as PCM
    const p = this.pipeline(user);
    if (!p.decoder) {
      const generation = p.generation;
      p.decoder = this.output.createOpusDecoder(
        pcm => {
          if (p.generation !== generation || this.pipelines.get(user) !== p) return;
          const next = p.pending.shift();
          if (next !== undefined) this.push(user, p, next.ctr, next.epoch, pcm);
        },
        () => {
          if (p.generation === generation && this.pipelines.get(user) === p) this.replaceDecoder(p);
        },
      );
      if (!p.decoder) return; // no Opus decoder here: discarded (REQ-3)
    }
    if (p.pending.length >= PENDING_DECODES_MAX) {
      this.replaceDecoder(p);
      return;
    }
    p.pending.push({ ctr: frame.ctr, epoch: frame.epoch });
    try {
      p.decoder!.decode(frame.payload, frame.ctr * FRAME_US);
    } catch {
      this.replaceDecoder(p);
    }
  }

  private pipeline(user: string): RemotePipeline {
    let p = this.pipelines.get(user);
    if (!p) {
      // A lost frame is silence: no frame is ever played twice, not even as
      // concealment of a gap the relay made (§3.2 G2). The buffer is bounded
      // and skips gaps at once, so neither a sender's counter jumps nor relay
      // drops grow its memory or the playout latency.
      p = {
        jitter: new JitterBuffer({ maxConcealment: 0, now: () => this.clock.now() }),
        decoder: null,
        pending: [],
        lastEpoch: -1,
        generation: 0,
        timer: null,
        idleTicks: 0,
      };
      this.pipelines.set(user, p);
    }
    return p;
  }

  /**
   * Push an authenticated frame with sequence = CTR (§6.2.6 step 9). The
   * first frame under a newer epoch of the sender instance whose CTR is not
   * above the highest CTR the buffer has received resets the buffer first
   * (REQ-15 as amended by A2), so counters a holder of an older epoch's key
   * forged far ahead cannot hold back playout under the newer epoch. The
   * epoch is compared with the newest one pushed (`lastEpoch`), so the reset
   * also happens when the frame that opened the epoch never reached the
   * buffer (dropped with a replaced Opus decoder's pending outputs).
   */
  private push(user: string, p: RemotePipeline, ctr: number, epoch: number, pcm: Int16Array): void {
    if (epoch > p.lastEpoch) {
      if (ctr <= p.jitter.highestReceived) p.jitter.reset();
      p.lastEpoch = epoch;
    }
    p.jitter.push(ctr, pcm.buffer as ArrayBuffer);
    p.idleTicks = 0;
    if (p.timer === null) this.schedulePlayout(user, p);
  }

  private schedulePlayout(user: string, p: RemotePipeline): void {
    p.timer = this.clock.setTimeout(() => {
      p.timer = null;
      if (this.pipelines.get(user) !== p) return;
      const frame = p.jitter.pull();
      // A deafened user gets no playback; the buffer keeps its place.
      if (frame && frame.byteLength > 0 && !this.deafened) this.output.play(user, new Int16Array(frame));
      p.idleTicks = frame ? 0 : p.idleTicks + 1;
      if (frame || (p.jitter.buffered > 0 && p.idleTicks < PLAYOUT_IDLE_TICKS)) this.schedulePlayout(user, p);
    }, this.t.playoutIntervalMs);
  }

  private replaceDecoder(p: RemotePipeline): void {
    p.generation++;
    p.pending = [];
    p.decoder?.close();
    p.decoder = null;
  }

  /** REQ-35: S's keys were erased or a new instance of S was recorded. */
  private resetPipeline(from: string): void {
    const p = this.pipelines.get(lower(from));
    if (!p) return;
    p.jitter.reset();
    p.lastEpoch = -1;
    this.replaceDecoder(p);
  }

  private dropPipeline(user: string): void {
    const p = this.pipelines.get(user);
    if (!p) return;
    this.pipelines.delete(user);
    this.clock.clearTimeout(p.timer);
    p.timer = null;
    this.replaceDecoder(p);
    p.jitter.reset();
    this.output.removeUser(user);
  }

  // -------------------------------------------------------------------------
  // Relay events
  // -------------------------------------------------------------------------

  private isC(channelId: unknown): boolean {
    return typeof channelId === 'string' && lower(channelId) === this.channelId;
  }

  /** REQ-41: a relay mode report for C changes the note and nothing else. */
  private noteMode(mode: unknown): void {
    if (typeof mode !== 'string') return;
    this.lastMode = mode;
    this.call?.mgr.noteRelayMode(mode);
    this.changed();
  }

  private setupSignaling(): void {
    this.listen('voice_channel_joined', data => {
      const call = this.call;
      if (!call || !call.joinSent || !this.isC(data?.channel_id)) return;
      const participants = stringList(data.participants);
      if (!call.joined) {
        call.joined = true;
        this.clock.clearTimeout(call.joinTimer);
        call.joinTimer = null;
        this.phase = 'joined';
        this.rejoining = false;
        this.noteMode(data.voice_mode);
        call.mgr.onJoined(participants);
        for (const e of call.early.splice(0)) {
          if (e.joined) call.mgr.onPeerJoined(e.user);
          else call.mgr.onPeerLeft(e.user);
        }
        this.dropDeparted(call);
        this.scheduleSelfCheck(call, this.t.selfCheckFirstMs);
      } else {
        // REQ-5: a later one only reconciles V; it never creates an epoch.
        this.noteMode(data.voice_mode);
        call.mgr.onJoined(participants);
        this.dropDeparted(call);
      }
      // REQ-53: the remote share list from `screen_sharers` (screen-capable relays).
      if (Array.isArray(data.screen_sharers)) call.viewers.setAnnounced(stringList(data.screen_sharers));
      this.changed();
    });

    this.listen('voice_peer_joined', data => {
      const call = this.call;
      if (!call || !this.isC(data?.channel_id) || typeof data.user_id !== 'string') return;
      if (!call.joined) {
        if (call.joinSent && call.early.length < EARLY_EVENTS_MAX) call.early.push({ joined: true, user: data.user_id });
        return;
      }
      call.mgr.onPeerJoined(data.user_id);
    });

    this.listen('voice_peer_left', data => {
      const call = this.call;
      if (!call || !this.isC(data?.channel_id) || typeof data.user_id !== 'string') return;
      if (!call.joined) {
        if (call.joinSent && call.early.length < EARLY_EVENTS_MAX) call.early.push({ joined: false, user: data.user_id });
        return;
      }
      call.mgr.onPeerLeft(data.user_id);
      this.dropDeparted(call);
    });

    // §6.3.6: the decryption starts in this handler, before any await (§11.3).
    this.listen('voice_key_exchange', data => {
      if (data && typeof data === 'object') this.call?.mgr.handleKeyExchange(data);
    });

    this.listen('srtp_voice_packet', data => {
      const call = this.call;
      if (!call?.joined || !data || typeof data.from !== 'string' || !this.isC(data.channel_id)) return;
      const packet = data.packet_data;
      if (typeof packet !== 'string' || packet.length > PACKET_DATA_MAX) return;
      const bytes = decodeWireBase64(packet);
      if (!bytes) return;
      call.mgr.receiveAudioFrame(data.from, data.channel_id, bytes);
    });

    // REQ-3, REQ-4: legacy frames are discarded and only recorded as evidence.
    this.listen('voice_packet', data => {
      const call = this.call;
      if (!call?.joined || !data || typeof data.from !== 'string' || typeof data.channel_id !== 'string') return;
      call.mgr.noteLegacyVoicePacket(data.from, data.channel_id);
    });

    this.listen('voice_participants', data => {
      const call = this.call;
      if (!call?.joined || !this.isC(data?.channel_id)) return;
      this.noteMode(data.voice_mode);
      if (!call.selfCheckPending) return; // only the reply to this call's own self-check
      call.selfCheckPending = false;
      const listed = stringList(data.participants).map(lower);
      if (!listed.includes(this.self)) {
        this.selfCheckMissing();
        return;
      }
      call.mgr.reconcileParticipants(listed);
      this.dropDeparted(call);
      // REQ-38: reconcile the remote share list and the local share.
      if (Array.isArray(data.screen_sharers)) {
        const sharers = stringList(data.screen_sharers).map(lower);
        call.viewers.setAnnounced(sharers);
        if (!sharers.includes(this.self)) call.sender?.onNotListedAsSharer();
        // Recorded, so that its confirmation never ends a share started meanwhile (REQ-52, A2).
        else if (!call.sender || call.sender.state === 'idle') call.stops.record(this.ws.screenShareStop(this.channelId));
      }
    });

    this.listen('voice_channel_left', data => {
      const call = this.call;
      // REQ-40: only the exact eviction form, after this instance's join.
      if (!call?.joined || !data || !this.isC(data.channel_id)) return;
      if (typeof data.user_id !== 'string' || lower(data.user_id) !== this.self || data.reason !== 'removed') return;
      this.endCall(null);
      this.phase = 'removed';
      this.rejoining = false;
      this.changed();
    });

    this.listen('voice_mode_changed', data => {
      if (this.isC(data?.channel_id)) this.noteMode(data.voice_mode);
    });
    this.listen('voice_mode', data => {
      if (this.isC(data?.channel_id)) this.noteMode(data.voice_mode);
    });

    // REQ-22: a disconnect ends the call and erases it; `authenticated` rejoins.
    this.listen('disconnected', () => {
      if (this.destroyed || !this.started) return;
      if (this.phase !== 'connecting' && this.phase !== 'joined') return;
      this.endCall({ code: 'reconnected' });
      this.phase = 'reconnecting';
      this.rejoining = true;
      this.changed();
    });
    this.listen('authenticated', () => {
      if (this.destroyed || !this.started || this.phase !== 'reconnecting') return;
      this.startCall(true);
    });

    // SPEC-01 §6.8, SPEC-03 §6.1: the relay's features may have changed. A
    // relay that stops offering `screen/1` ends the share and every watch:
    // there is no other transport (REQ-42).
    this.listen('hello', () => {
      const call = this.call;
      if (call && !this.ws.isScreenCapable()) {
        call.sender?.onRelayIncapable();
        call.viewers.stopAllWatches();
      }
      this.changed();
    });

    // §6.12.1: the screen-sharing messages for C.
    this.listen('screen_share_started', data => {
      const call = this.call;
      if (!call?.joined || !this.isC(data?.channel_id) || typeof data.user_id !== 'string') return;
      const user = lower(data.user_id);
      if (user === this.self) {
        if (call.sender) {
          call.sender.onShareStarted(user, data.request_id);
        } else {
          // A share this client never started (REQ-52): stop it, at most once per second.
          const now = this.clock.now();
          if (now - this.lastStrayStopAt >= STRAY_STOP_MIN_GAP_MS) {
            this.lastStrayStopAt = now;
            call.stops.record(this.ws.screenShareStop(this.channelId));
          }
        }
      } else {
        call.viewers.onStarted(user);
      }
    });
    this.listen('screen_share_stopped', data => {
      const call = this.call;
      if (!call?.joined || !this.isC(data?.channel_id) || typeof data.user_id !== 'string') return;
      const user = lower(data.user_id);
      if (user === this.self) {
        if (call.sender) call.sender.onShareStopped(user, data.request_id);
        else call.stops.confirms(data.request_id);
      } else {
        call.viewers.onStopped(user);
      }
    });
    this.listen('screen_share_rejected', data => {
      const call = this.call;
      if (!call || !this.isC(data?.channel_id)) return;
      call.sender?.onShareRejected(data.request_id, data.reason);
    });
    this.listen('screen_watch_rejected', data => {
      const call = this.call;
      if (!call || !this.isC(data?.channel_id)) return;
      call.viewers.onWatchRejected(data.sharer_id, data.reason);
    });
    this.listen('screen_keyframe_request', data => {
      const call = this.call;
      if (!call?.joined || !this.isC(data?.channel_id)) return;
      call.sender?.onKeyframeRequest(data.from);
    });
    this.listen('screen_watchers', data => {
      const call = this.call;
      if (!call?.joined || !this.isC(data?.channel_id)) return;
      call.sender?.onWatchers(data.watchers);
    });
    // §6.12.2: a well-formed SCREEN_DOWN; §6.2.8 runs in the manager.
    this.listen('screen_fragment', data => {
      const call = this.call;
      if (!call?.joined || !data || typeof data.from !== 'string' || typeof data.channelId !== 'string') return;
      if (!(data.fragment instanceof Uint8Array)) return;
      call.mgr.receiveVideoFragment(data.from, data.channelId, data.fragment);
    });
  }

  private listen(event: string, handler: (data: any) => void): void {
    this.ws.on(event as any, handler);
    this.wsHandlers.push({ event, handler });
  }

  /** Users that left V lose their playback pipeline, and their shares disappear (§8.4). */
  private dropDeparted(call: ActiveCall): void {
    const view = new Set(call.mgr.participants());
    for (const user of [...this.pipelines.keys()]) if (!view.has(user)) this.dropPipeline(user);
    call.viewers.reconcileView();
  }

  // -------------------------------------------------------------------------
  // Self-check (REQ-38)
  // -------------------------------------------------------------------------

  private scheduleSelfCheck(call: ActiveCall, ms: number): void {
    call.selfCheckTimer = this.clock.setTimeout(() => {
      if (this.call !== call) return;
      const sent = this.ws.getVoiceParticipants(this.channelId);
      call.selfCheckPending = !sent || sent.handedOff !== false;
      this.scheduleSelfCheck(call, this.t.selfCheckIntervalMs);
    }, ms);
  }

  private selfCheckMissing(): void {
    const now = this.clock.now();
    if (now - this.lastSelfCheckRejoinAt < this.t.selfCheckRejoinGapMs) return;
    this.lastSelfCheckRejoinAt = now;
    this.rejoin(); // a local share ends with the instance (REQ-38)
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private changed(): void {
    const listener = this.onStateChange;
    if (listener) listener(this.state);
    this.armScreenTick();
  }

  private track(p: Promise<unknown>): void {
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
  }
}
