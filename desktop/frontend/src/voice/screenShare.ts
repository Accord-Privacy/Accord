/**
 * @module voice/screenShare
 * End-to-end-encrypted screen sharing over the relay (SPEC-03 amendment A1,
 * §5.10, §6.13; REQ-42 to REQ-54).
 *
 * - `ScreenShareSender` captures the screen from the Share Screen click
 *   (REQ-43), reads frames from the captured track (§6.13.3), scales them to
 *   the caps, encodes VP8 (§6.13.4, OD-110: at most 1920 × 1080 pixels,
 *   15 frames per second, 1.5 Mbit/s target), splits each encoded frame into
 *   fragments sealed under the call's current epoch (REQ-46, through
 *   `CallKeyManager`), and hands them to the relay paced by the socket's
 *   `bufferedAmount` so audio never waits behind much video (REQ-47).
 * - `ScreenShareViewer` is one watched share: the reassembly and decoding
 *   rules of §6.2.9 (`ShareReassembler`), a VP8 decoder, a canvas, and the
 *   keyframe-request schedule of REQ-50. `ScreenViewers` keeps the remote
 *   share list (REQ-53), at most two watches (REQ-49, REQ-50) and the tile
 *   states of §8.4.
 *
 * Video uses only the epoch keys of the call (REQ-45): nothing here creates,
 * selects or erases a key, and every screen signal travels as a relay
 * message, never as a call message (REQ-50). There is no other transport,
 * codec or mode to fall back to (REQ-42): without `screen/1`, or where a
 * probe fails, screen sharing is unavailable.
 *
 * The capture, codec, renderer, clock and transport are injected
 * (`ScreenPlatform`, §10.1); `browserScreenPlatform()` is the implementation
 * over the browser's APIs. Captured frames, encoded video, decrypted
 * fragments and decoded frames live in memory only, every video frame is
 * closed on every path, and nothing here logs or stores anything (REQ-27).
 */

import type { SendResult } from '../ws';
import type { CallClock } from './callKeyBridge';
import type { VideoAudience, VideoFrameTicket } from './callKeys';
import { vp8KeySize, vp8TagOk } from './vp8';
import {
  ShareNumbering,
  ShareReassembler,
  VIDEO_FRAME_MAX,
  VIDEO_PIXELS_MAX,
  VIDEO_SIDE_MAX,
  VIDEO_SIDE_MIN,
  WATCH_MAX,
  fragmentCount,
  parseFragment,
  withinCaps,
  type DecodedVideoFrame,
  type EncodedScreenFrame,
  type ShareDecodeState,
  type VideoDecoderPort,
  type Vp8DecoderConfig,
} from './screenFrame';

// ---------------------------------------------------------------------------
// Constants (§6.5, §6.13; OD-109, OD-110)
// ---------------------------------------------------------------------------

/** `VIDEO_FPS_MAX`: 15 frames per second; interval 66.7 ms, accepted up to 10 ms early. */
export const VIDEO_FPS_MAX = 15;
export const FRAME_INTERVAL_MS = 1000 / VIDEO_FPS_MAX;
export const FRAME_EARLY_MS = 10;
/** `ENCODE_QUEUE_MAX`. */
export const ENCODE_QUEUE_MAX = 2;
/** `ENCODER_RECONFIG_MIN_GAP`: between reconfigurations for a size change. */
export const ENCODER_RECONFIG_MIN_GAP_MS = 2000;
/** `KEYFRAME_INTERVAL`, also the refresh of a static screen. */
export const KEYFRAME_INTERVAL_MS = 10_000;
/** `STATIC_KEYFRAME_WAIT`. */
export const STATIC_KEYFRAME_WAIT_MS = 100;
/** `KEYFRAME_MIN_GAP`: between keyframes from relay-driven triggers. */
export const KEYFRAME_MIN_GAP_MS = 1000;
/** `KFR_PER_USER_GAP`: between requests acted on from one requesting user. */
export const KFR_PER_USER_GAP_MS = 5000;
/** `KFR_RETRY` offsets from the first request of an awaiting period, and `KFR_MIN_GAP`. */
export const KFR_SCHEDULE_MS: readonly number[] = Object.freeze([0, 2000, 4000, 8000]);
export const KFR_MIN_GAP_MS = 1000;
/** `SEND_BUFFER_HIGH`: bytes of `WebSocket.bufferedAmount`. */
export const SEND_BUFFER_HIGH = 65_536;
/** `PACING_CHECK`: at most this long between hand-off checks while fragments wait. */
export const PACING_CHECK_MS = 20;
/** `SHARE_START_TIMEOUT`. */
export const SHARE_START_TIMEOUT_MS = 10_000;
/**
 * The ids of the client's own `ScreenShareStop` messages kept to recognize
 * their confirmations (REQ-52): only the newest, since the relay answers a
 * stop only when it ended a share and never answers the others.
 */
export const SENT_STOPS_MAX = 8;

/**
 * REQ-52 "Stop", as amended by A2 (§14.3): every `ScreenShareStop` the client
 * sends is recorded, so that the `screen_share_stopped` confirming it (with
 * its `request_id`) is recognised and never ends a share started since. One
 * ledger per call is shared by the sender and the connection's other stop
 * paths: the self-check of REQ-38 and the answer to a stray acknowledgment
 * before any share was attempted.
 */
export class SentStops {
  private readonly ids = new Set<string>();

  /** Record a stop that was handed off (one that was not was never sent). */
  record(sent: SendResult): void {
    if (!sent.handedOff) return;
    this.ids.add(sent.messageId);
    // The relay never answers a stop that ended nothing: keep only the newest ids.
    for (const id of this.ids) {
      if (this.ids.size <= SENT_STOPS_MAX) break;
      this.ids.delete(id);
    }
  }

  /** Whether `requestId` names a recorded stop; a confirmation is consumed. */
  confirms(requestId: unknown): boolean {
    return typeof requestId === 'string' && this.ids.delete(requestId);
  }

  clear(): void {
    this.ids.clear();
  }

  get size(): number {
    return this.ids.size;
  }

  /** The recorded ids, oldest first (inspection). */
  recorded(): string[] {
    return [...this.ids];
  }
}
/**
 * A `screen_share_started` naming the local user while it is idle is
 * answered with `ScreenShareStop` (REQ-52) at most once per second, so a
 * relay cannot turn its own messages into a stream of stops (each counts
 * toward the relay's start-and-stop limit, §6.12.5). The self-check of
 * REQ-38 sends a stop for a share the relay still lists anyway.
 */
export const STRAY_STOP_MIN_GAP_MS = 1000;
/** `VIDEO_WAIT_NOTICE`, `VIDEO_STALL_NOTICE`, `KEYS_WAIT_NOTICE` (§8.4). */
export const VIDEO_WAIT_NOTICE_MS = 10_000;
export const VIDEO_STALL_NOTICE_MS = 15_000;
export const KEYS_WAIT_NOTICE_MS = 12_000;
/** `AEAD_FAIL_NOTICE` for video (REQ-48). */
export const VIDEO_AEAD_FAIL_NOTICE = 50;
/**
 * REQ-47 as amended by A2 (§14.2): more than this many backpressure skips
 * within the window halve the bitrate (target and maximum), and halve it
 * again after each further window with as many; each window without a skip
 * doubles it, back up to the values of §6.13.4.
 */
export const BACKPRESSURE_SKIPS_MAX = 15;
export const BACKPRESSURE_WINDOW_MS = 10_000;
/** REQ-47 (A2): the target bitrate the steps down stop at. */
export const VIDEO_BITRATE_FLOOR = 200_000;
/** How often a watched share's incomplete frames are checked for expiry (§6.2.9). */
export const REASSEMBLY_SWEEP_MS = 250;
/** Bitrate caps (§6.13.4). */
export const VIDEO_TARGET_BITRATE_MAX = 1_500_000;
export const VIDEO_MAX_BITRATE_MAX = 2_500_000;

/** §6.13.2: the only options `getDisplayMedia` is called with. */
export interface DisplayMediaOptions {
  readonly video: {
    readonly width: { readonly max: number };
    readonly height: { readonly max: number };
    readonly frameRate: { readonly max: number };
  };
  readonly audio: false;
}

export function displayMediaOptions(): DisplayMediaOptions {
  return {
    video: { width: { max: VIDEO_SIDE_MAX }, height: { max: VIDEO_SIDE_MAX }, frameRate: { max: VIDEO_FPS_MAX } },
    audio: false,
  };
}

/** §6.13.4: target min(1,500,000, 4.8 r) and maximum min(2,500,000, 6.4 r) bit/s. */
export function videoBitrates(maxBytesPerSecond: number): { target: number; maximum: number } {
  return {
    target: Math.floor(Math.min(VIDEO_TARGET_BITRATE_MAX, 4.8 * maxBytesPerSecond)),
    maximum: Math.floor(Math.min(VIDEO_MAX_BITRATE_MAX, 6.4 * maxBytesPerSecond)),
  };
}

export interface BitrateStep {
  readonly target: number;
  readonly maximum: number;
}

/**
 * REQ-47 (A2): one step down under backpressure: the target and the maximum
 * halved, the target not below `VIDEO_BITRATE_FLOOR` and the maximum not
 * below the target. Null at the floor.
 */
export function bitrateStepDown(cur: BitrateStep): BitrateStep | null {
  if (cur.target <= VIDEO_BITRATE_FLOOR) return null;
  const target = Math.max(VIDEO_BITRATE_FLOOR, Math.floor(cur.target / 2));
  return { target, maximum: Math.max(target, Math.floor(cur.maximum / 2)) };
}

/** REQ-47 (A2): one step up after a window without a skip: both doubled, up to `full` (§6.13.4). Null at `full`. */
export function bitrateStepUp(cur: BitrateStep, full: BitrateStep): BitrateStep | null {
  if (cur.target >= full.target && cur.maximum >= full.maximum) return null;
  return { target: Math.min(full.target, cur.target * 2), maximum: Math.min(full.maximum, cur.maximum * 2) };
}

/**
 * §6.13.3: s = min(1, √(2,073,600 / (w·h)), 1920 / max(w, h)); W = 2·⌊w·s / 2⌋
 * and H = 2·⌊h·s / 2⌋, each at least 16. Null for a frame without a size.
 */
export function scaledSize(w: number, h: number): { width: number; height: number } | null {
  if (!(w > 0) || !(h > 0) || !Number.isFinite(w) || !Number.isFinite(h)) return null;
  const s = Math.min(1, Math.sqrt(VIDEO_PIXELS_MAX / (w * h)), VIDEO_SIDE_MAX / Math.max(w, h));
  const width = Math.max(VIDEO_SIDE_MIN, 2 * Math.floor((w * s) / 2));
  const height = Math.max(VIDEO_SIDE_MIN, 2 * Math.floor((h * s) / 2));
  return { width, height };
}

/** §6.13.4 configuration A (with `latencyMode`) or B (without, only if A is rejected). */
export type EncoderVariant = 'A' | 'B';

export interface Vp8EncoderConfig {
  readonly codec: 'vp8';
  readonly width: number;
  readonly height: number;
  readonly bitrate: number;
  readonly framerate: number;
  readonly latencyMode?: 'realtime';
}

export function encoderConfig(variant: EncoderVariant, width: number, height: number, bitrate: number): Vp8EncoderConfig {
  const base = { codec: 'vp8' as const, width, height, bitrate, framerate: VIDEO_FPS_MAX };
  return variant === 'A' ? { ...base, latencyMode: 'realtime' } : base;
}

// ---------------------------------------------------------------------------
// The platform (capture, codecs, renderer), injected (§10.1)
// ---------------------------------------------------------------------------

/** The parts of a `MediaStreamTrack` used here. */
export interface CaptureTrack {
  readonly kind: string;
  contentHint: string;
  stop(): void;
  addEventListener(type: 'ended', listener: () => void): void;
  removeEventListener(type: 'ended', listener: () => void): void;
}

/** The parts of the `MediaStream` that `getDisplayMedia` returns. */
export interface CaptureStream {
  getTracks(): CaptureTrack[];
  getVideoTracks(): CaptureTrack[];
  getAudioTracks(): CaptureTrack[];
}

/** The parts of a WebCodecs `VideoFrame` the sender uses. */
export interface ScreenVideoFrame {
  readonly displayWidth: number;
  readonly displayHeight: number;
  /** Microseconds. */
  readonly timestamp: number;
  clone(): ScreenVideoFrame;
  close(): void;
}

/** The parts of an `EncodedVideoChunk` the sender uses. */
export interface EncodedChunkPort {
  readonly type: string;
  readonly byteLength: number;
  copyTo(destination: Uint8Array): void;
}

/** What the sender needs of a WebCodecs `VideoEncoder`. */
export interface VideoEncoderPort {
  readonly encodeQueueSize: number;
  readonly state: string;
  configure(config: Vp8EncoderConfig): void;
  encode(frame: ScreenVideoFrame, options: { keyFrame: boolean }): void;
  close(): void;
}

/** Source A reads the track through `MediaStreamTrackProcessor`; Source B copies the in-DOM preview (§6.13.3). */
export type FrameSourceKind = 'processor' | 'video';

export interface FrameSourceHandle {
  close(): void;
}

/** The decoder configuration the viewing probe checks (§6.13.1). */
export interface Vp8DecoderProbeConfig {
  readonly codec: 'vp8';
  readonly codedWidth: number;
  readonly codedHeight: number;
  readonly optimizeForLatency?: boolean;
}

/** A viewer's drawing surface: its tile's canvas. */
export interface ShareSurface {
  /** Draw the frame's visible rectangle at `width` × `height`. */
  draw(frame: DecodedVideoFrame, width: number, height: number): void;
  /** Clear the picture. */
  clear(): void;
}

export interface ScreenPlatform {
  /**
   * The desktop shell's `display_capture_supported` (REQ-57), run before the
   * capture probe and never from the click handler; null in the
   * relay-served web client, which has no shell.
   */
  shellDisplayCapture(): Promise<boolean> | null;
  hasGetDisplayMedia(): boolean;
  /** Called only as the first action of the Share Screen click handler (REQ-43). */
  getDisplayMedia(options: DisplayMediaOptions): Promise<CaptureStream>;
  hasVideoEncoder(): boolean;
  /** `VideoEncoder.isConfigSupported(config).supported`; false when it rejects. */
  encoderConfigSupported(config: Vp8EncoderConfig): Promise<boolean>;
  createEncoder(output: (chunk: EncodedChunkPort) => void, error: (e: unknown) => void): VideoEncoderPort;
  hasTrackProcessor(): boolean;
  hasVideoFrame(): boolean;
  /** The local preview of REQ-43: a muted video element playing the captured stream itself. */
  createPreview(stream: CaptureStream): HTMLVideoElement | null;
  /**
   * Start reading frames of `track` (§6.13.3). Throws when the source cannot
   * be opened; `onError` reports a source that stopped delivering frames
   * because of an error, never one stopped by `close()`.
   */
  openFrameSource(
    kind: FrameSourceKind,
    track: CaptureTrack,
    preview: HTMLVideoElement | null,
    onFrame: (frame: ScreenVideoFrame) => void,
    clock: CallClock,
    onError: (error: unknown) => void,
  ): FrameSourceHandle;
  /** A new frame of `width` × `height` drawn from `frame` (§6.13.3); the caller closes `frame`. */
  scaleFrame(frame: ScreenVideoFrame, width: number, height: number): ScreenVideoFrame;
  /** A new frame with the picture of `frame` and another timestamp; the caller keeps `frame`. */
  retimeFrame(frame: ScreenVideoFrame, timestampUs: number): ScreenVideoFrame;
  hasVideoDecoder(): boolean;
  /** `VideoDecoder.isConfigSupported(config).supported`; rejects when the dictionary is refused. */
  decoderConfigSupported(config: Vp8DecoderProbeConfig): Promise<boolean>;
  createDecoder(output: (frame: DecodedVideoFrame) => void, error: (e: unknown) => void, optimizeForLatency: boolean): VideoDecoderPort;
  /** A canvas 2D context can be created. */
  canDraw2d(): boolean;
  requestAnimationFrame(callback: () => void): void;
}

function safeClose(frame: { close(): void } | null | undefined): void {
  if (!frame) return;
  try {
    frame.close();
  } catch {
    // already closed
  }
}

function stopTracks(stream: CaptureStream | null): void {
  if (!stream) return;
  let tracks: CaptureTrack[] = [];
  try {
    tracks = stream.getTracks();
  } catch {
    tracks = [];
  }
  for (const t of tracks) {
    try {
      t.stop();
    } catch {
      // already stopped
    }
  }
}

/**
 * The browser implementation of `ScreenPlatform`. It reads the globals when
 * it is used, not when it is built, so a missing API simply fails its probe.
 */
export function browserScreenPlatform(): ScreenPlatform {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  let scaleCanvas: { width: number; height: number; getContext(type: '2d'): unknown } | null = null;
  const fn = (v: unknown): v is (...args: unknown[]) => unknown => typeof v === 'function';

  return {
    shellDisplayCapture() {
      const core = g.__TAURI__?.core;
      if (!core || !fn(core.invoke)) return null;
      return Promise.resolve()
        .then(() => core.invoke('display_capture_supported'))
        .then((v: unknown) => v === true, () => false);
    },
    hasGetDisplayMedia() {
      return fn(g.navigator?.mediaDevices?.getDisplayMedia);
    },
    getDisplayMedia(options) {
      return g.navigator.mediaDevices.getDisplayMedia(options) as Promise<CaptureStream>;
    },
    hasVideoEncoder() {
      return fn(g.VideoEncoder) && fn(g.VideoEncoder.isConfigSupported);
    },
    encoderConfigSupported(config) {
      return Promise.resolve()
        .then(() => g.VideoEncoder.isConfigSupported(config))
        .then((r: { supported?: boolean } | undefined) => r?.supported === true, () => false);
    },
    createEncoder(output, error) {
      const enc = new g.VideoEncoder({ output: (chunk: EncodedChunkPort) => output(chunk), error: (e: unknown) => error(e) });
      return {
        get encodeQueueSize() {
          return enc.encodeQueueSize as number;
        },
        get state() {
          return enc.state as string;
        },
        configure: config => enc.configure(config),
        encode: (frame, options) => enc.encode(frame, options),
        close: () => {
          if (enc.state !== 'closed') enc.close();
        },
      };
    },
    hasTrackProcessor() {
      return fn(g.MediaStreamTrackProcessor);
    },
    hasVideoFrame() {
      return fn(g.VideoFrame);
    },
    createPreview(stream) {
      if (typeof document === 'undefined') return null;
      const video = document.createElement('video');
      video.muted = true;
      video.autoplay = true;
      video.playsInline = true;
      try {
        (video as unknown as { srcObject: unknown }).srcObject = stream;
        const playing = video.play() as Promise<void> | undefined;
        if (playing && fn(playing.catch)) playing.catch(() => undefined);
      } catch {
        // the preview stays blank; capture continues
      }
      return video;
    },
    openFrameSource(kind, track, preview, onFrame, clock, onError) {
      if (kind === 'processor') {
        // Throws, and so fails the share's capture, when the processor or
        // its reader cannot be created.
        const processor = new g.MediaStreamTrackProcessor({ track });
        const reader = processor.readable.getReader();
        let closed = false;
        const pump = async (): Promise<void> => {
          for (;;) {
            const r: { done: boolean; value?: ScreenVideoFrame } = await reader.read();
            // The stream ends with the track; its `ended` event ends the share.
            if (r.done) return;
            if (closed) safeClose(r.value);
            else if (r.value) onFrame(r.value);
          }
        };
        pump().catch(e => {
          // A read that fails while the source is open: no frame will come.
          if (!closed) onError(e);
        });
        return {
          close() {
            closed = true;
            Promise.resolve().then(() => reader.cancel()).catch(() => undefined);
          },
        };
      }
      // Source B: copies of the in-DOM preview, driven by
      // requestVideoFrameCallback with a 66 ms watchdog (§6.13.3).
      if (!preview) throw new Error('no preview element to read frames from');
      const video = preview;
      let closed = false;
      let lastCallbackAt = -Infinity;
      let lastTs = 0;
      let timer: unknown = null;
      const grab = () => {
        if (closed) return;
        const ts = Math.max(lastTs + 1, Math.round(clock.now() * 1000));
        let frame: ScreenVideoFrame | null = null;
        try {
          frame = new g.VideoFrame(video, { timestamp: ts }) as ScreenVideoFrame;
        } catch {
          frame = null; // no picture yet
        }
        if (frame) {
          lastTs = ts;
          onFrame(frame);
        }
      };
      const hasCallback = fn((video as unknown as { requestVideoFrameCallback?: unknown }).requestVideoFrameCallback);
      const onVideoFrame = () => {
        if (closed) return;
        lastCallbackAt = clock.now();
        grab();
        video.requestVideoFrameCallback(onVideoFrame);
      };
      if (hasCallback) video.requestVideoFrameCallback(onVideoFrame);
      const watchdog = () => {
        timer = clock.setTimeout(() => {
          if (closed) return;
          if (!hasCallback || clock.now() - lastCallbackAt >= 100) grab();
          watchdog();
        }, Math.round(FRAME_INTERVAL_MS - 0.7));
      };
      watchdog();
      return {
        close() {
          closed = true;
          clock.clearTimeout(timer);
        },
      };
    },
    scaleFrame(frame, width, height) {
      if (!scaleCanvas) {
        scaleCanvas = fn(g.OffscreenCanvas) ? new g.OffscreenCanvas(width, height) : document.createElement('canvas');
      }
      const canvas = scaleCanvas!;
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d') as { drawImage(...args: unknown[]): void } | null;
      if (!ctx) throw new Error('no 2d context');
      ctx.drawImage(frame, 0, 0, width, height);
      return new g.VideoFrame(canvas, { timestamp: frame.timestamp }) as ScreenVideoFrame;
    },
    retimeFrame(frame, timestampUs) {
      return new g.VideoFrame(frame, { timestamp: timestampUs }) as ScreenVideoFrame;
    },
    hasVideoDecoder() {
      return fn(g.VideoDecoder) && fn(g.VideoDecoder.isConfigSupported);
    },
    decoderConfigSupported(config) {
      return Promise.resolve()
        .then(() => g.VideoDecoder.isConfigSupported(config))
        .then((r: { supported?: boolean } | undefined) => r?.supported === true);
    },
    createDecoder(output, error, optimizeForLatency) {
      const dec = new g.VideoDecoder({ output: (f: DecodedVideoFrame) => output(f), error: (e: unknown) => error(e) });
      return {
        get decodeQueueSize() {
          return dec.decodeQueueSize as number;
        },
        get state() {
          return dec.state as string;
        },
        configure: (c: Vp8DecoderConfig) =>
          dec.configure(optimizeForLatency ? c : { codec: c.codec, codedWidth: c.codedWidth, codedHeight: c.codedHeight }),
        decode: chunk => dec.decode(new g.EncodedVideoChunk({ type: chunk.type, timestamp: chunk.timestamp, data: chunk.data })),
        close: () => {
          if (dec.state !== 'closed') dec.close();
        },
      };
    },
    canDraw2d() {
      if (typeof document === 'undefined') return false;
      try {
        return document.createElement('canvas').getContext('2d') != null;
      } catch {
        return false;
      }
    },
    requestAnimationFrame(callback) {
      if (fn(g.requestAnimationFrame)) g.requestAnimationFrame(() => callback());
      else setTimeout(callback, 16);
    },
  };
}

/** The canvas of a viewer tile as a `ShareSurface`: draws only the visible rectangle (§6.2.9). */
export function canvasSurface(canvas: HTMLCanvasElement): ShareSurface {
  return {
    draw(frame, width, height) {
      if (canvas.width !== width) canvas.width = width;
      if (canvas.height !== height) canvas.height = height;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      // A VideoFrame as an image is its visible rectangle (W3C WebCodecs).
      ctx.drawImage(frame as unknown as CanvasImageSource, 0, 0, width, height, 0, 0, width, height);
    },
    clear() {
      const ctx = canvas.getContext('2d');
      ctx?.clearRect(0, 0, canvas.width, canvas.height);
    },
  };
}

// ---------------------------------------------------------------------------
// Probes (§6.13.1)
// ---------------------------------------------------------------------------

/** Why the capture probe failed (§8.4 row 5). */
export type CaptureUnavailableReason = 'no_capture' | 'no_encoder' | 'no_frame_source';

export type CaptureProbe =
  | { readonly ok: true; readonly config: EncoderVariant; readonly source: FrameSourceKind }
  | { readonly ok: false; readonly reason: CaptureUnavailableReason };

export type ViewingProbe = { readonly ok: true; readonly optimizeForLatency: boolean } | { readonly ok: false };

/**
 * The capture probe, run once per voice session before any click: the shell
 * reports display capture (desktop app), `getDisplayMedia` exists, a VP8
 * encoder supports configuration A or B at 1920 × 1080, and a frame source
 * exists. Nothing here calls `getDisplayMedia`.
 */
export async function probeCapture(p: ScreenPlatform): Promise<CaptureProbe> {
  const shell = p.shellDisplayCapture();
  if (shell !== null) {
    const supported = await shell.catch(() => false);
    if (supported !== true) return { ok: false, reason: 'no_capture' };
  }
  if (!p.hasGetDisplayMedia()) return { ok: false, reason: 'no_capture' };
  if (!p.hasVideoEncoder()) return { ok: false, reason: 'no_encoder' };
  const { target } = videoBitrates(500_000);
  let config: EncoderVariant | null = null;
  if (await p.encoderConfigSupported(encoderConfig('A', 1920, 1080, target)).catch(() => false)) config = 'A';
  else if (await p.encoderConfigSupported(encoderConfig('B', 1920, 1080, target)).catch(() => false)) config = 'B';
  if (!config) return { ok: false, reason: 'no_encoder' };
  if (p.hasTrackProcessor()) return { ok: true, config, source: 'processor' };
  if (p.hasVideoFrame()) return { ok: true, config, source: 'video' };
  return { ok: false, reason: 'no_frame_source' };
}

/**
 * The viewing probe, run once per voice session: `VideoDecoder` supports VP8
 * at 1920 × 1080 (asked with `optimizeForLatency`, and again without it if
 * the first call rejects the dictionary), and a canvas 2D context exists.
 */
export async function probeViewing(p: ScreenPlatform): Promise<ViewingProbe> {
  if (!p.hasVideoDecoder()) return { ok: false };
  const base = { codec: 'vp8' as const, codedWidth: 1920, codedHeight: 1080 };
  let supported: boolean;
  let optimizeForLatency = true;
  try {
    supported = await p.decoderConfigSupported({ ...base, optimizeForLatency: true });
  } catch {
    optimizeForLatency = false;
    supported = await p.decoderConfigSupported(base).catch(() => false);
  }
  if (!supported || !p.canDraw2d()) return { ok: false };
  return { ok: true, optimizeForLatency };
}

// ---------------------------------------------------------------------------
// Sender (REQ-43, REQ-44, REQ-46, REQ-47, REQ-51, REQ-52)
// ---------------------------------------------------------------------------

/** The messages shown after an attempt (§8.4). */
export type ScreenNoticeCode =
  | 'cancelled'
  | 'capture_failed'
  | 'rejected_limit'
  | 'relay_didnt_start'
  | 'stopped_by_relay'
  | 'encoder_failed'
  | 'reconnected';

export interface ScreenNotice {
  readonly code: ScreenNoticeCode;
  /** For `rejected_limit`: the relay's `max_sharers`. */
  readonly limit?: number;
}

export type LocalShareState = 'idle' | 'starting' | 'sharing';

/** What the sender needs of `CallKeyManager` (REQ-45, REQ-46, REQ-51, REQ-54). */
export interface ScreenSenderKeys {
  beginVideoFrame(fragments: number): VideoFrameTicket | null;
  sealVideoFrame(ticket: VideoFrameTicket, frame: EncodedScreenFrame): Promise<Uint8Array[] | null>;
  mayHandOff(ticket: VideoFrameTicket): boolean;
  sendingEpoch(): number | null;
  videoAudience(): VideoAudience | null;
  participants(): string[];
  isCurrentRecipient(userId: string): boolean;
}

/** The relay transport of the sender (REQ-37, §6.12). */
export interface ScreenSenderTransport {
  /** The socket is open and authenticated. */
  isOpen(): boolean;
  bufferedAmount(): number;
  sendScreenFragment(channelId: string, fragment: Uint8Array): boolean;
  screenShareStart(channelId: string): SendResult;
  screenShareStop(channelId: string): SendResult;
}

export interface ScreenShareSenderOptions {
  /** C. */
  channelId: string;
  /** The local user id. */
  selfId: string;
  platform: ScreenPlatform;
  keys: ScreenSenderKeys;
  transport: ScreenSenderTransport;
  clock: CallClock;
  /** A passed capture probe (REQ-42). */
  probe: Extract<CaptureProbe, { ok: true }>;
  /** The relay's `max_bytes_per_second` and `max_sharers` from the current socket's `hello`, or null. */
  limits: () => { maxBytesPerSecond: number; maxSharers: number } | null;
  /** Whether a share may start now: the call is joined, the E2EE manager is ready and the relay is screen-capable. */
  canStart: () => boolean;
  /** The call's record of sent stops, shared with the connection's own stop paths (REQ-52, A2). */
  stops?: SentStops;
  /** Something the panel shows changed. */
  onChange?: () => void;
  /** A message of §8.4 to show after an attempt. */
  onNotice?: (notice: ScreenNotice) => void;
}

/** The panel's view of the local share (§8.4 rows 1 and 2, REQ-54). */
export interface LocalShareView {
  readonly state: LocalShareState;
  /** The platform picker is open (§8.4 row 2). */
  readonly picking: boolean;
  readonly shareSeq: number;
  /** The relay's latest `screen_watchers` (0 until the first). */
  readonly watchers: number;
  readonly source: FrameSourceKind | null;
  readonly audience: VideoAudience | null;
  readonly preview: HTMLVideoElement | null;
  /** The bitrate the encoder is configured with, or null before the first configuration. */
  readonly bitrate: number | null;
}

interface EncodedOutput {
  readonly key: boolean;
  readonly data: Uint8Array;
}

interface SendingFrame {
  readonly ticket: VideoFrameTicket;
  readonly frags: Uint8Array[];
  index: number;
  any: boolean;
}

/**
 * The local share of one call (one instance): `{ state: idle | starting |
 * sharing, startRequestId, shareSeq, frameNo, track, preview, source,
 * encoder, encW, encH, lastReconfigAt, target, maximum, bitrate, lastKeyAt,
 * scheduledKey, forceKey, discardDeltas, lastSourceFrame, nextFrameAt,
 * waitingFragments, skipTimes, lastActedRequest, watchers, startTimer }`
 * (§6.7). `share_seq` counts this instance's shares (REQ-46).
 */
export class ScreenShareSender {
  readonly channelId: string;
  private readonly self: string;
  private readonly platform: ScreenPlatform;
  private readonly keys: ScreenSenderKeys;
  private readonly transport: ScreenSenderTransport;
  private readonly clock: CallClock;
  private readonly probe: Extract<CaptureProbe, { ok: true }>;
  private readonly opts: ScreenShareSenderOptions;

  private st: LocalShareState = 'idle';
  private picking = false;
  private attempt = 0;
  private ended = false;
  private stream: CaptureStream | null = null;
  private track: CaptureTrack | null = null;
  private trackEnded: (() => void) | null = null;
  private previewEl: HTMLVideoElement | null = null;
  private source: FrameSourceHandle | null = null;
  private sourceLive: { live: boolean } | null = null;
  private outstanding: string | null = null;
  /** The newest `SENT_STOPS_MAX` stops this client sent (REQ-52). */
  private readonly sentStops: SentStops;
  private lastStrayStopAt = -Infinity;
  private startTimer: unknown = null;
  private readonly numbering = new ShareNumbering();
  /** Bumped whenever a share ends: late callbacks of the old one are ignored. */
  private generation = 0;

  private encoder: VideoEncoderPort | null = null;
  /** The encoder has a configuration: `encW` × `encH` at `configuredBitrate`. */
  private configured = false;
  private encW = 0;
  private encH = 0;
  /** The scaled size the encoder is to be configured for (§6.13.3); 0 before the first frame. */
  private wantW = 0;
  private wantH = 0;
  /** An `isConfigSupported` check is in flight (REQ-44). */
  private checking = false;
  /** This share's configurations that `isConfigSupported` accepted, by size and bitrate. */
  private readonly supportedConfigs = new Map<string, Vp8EncoderConfig>();
  private lastSizeConfigAt = -Infinity;
  /** §6.13.4's values for the relay's byte rate. */
  private rates: BitrateStep = { target: 0, maximum: 0 };
  private configuredBitrate: number | null = null;
  /** REQ-47 (A2): the current step, from `rates` down to the floor. */
  private step: BitrateStep = { target: 0, maximum: 0 };
  /** Backpressure skips within the last `BACKPRESSURE_WINDOW_MS`. */
  private skipTimes: number[] = [];
  private lastStepDownAt = -Infinity;
  /** Steps up once a window passes without a skip. */
  private stepUpTimer: unknown = null;

  private lastKeyAt = -Infinity;
  private forceKey = false;
  private relayKeyAt: number | null = null;
  private relayKeyBase = -Infinity;
  private keyTimer: unknown = null;
  private copyRetryAt = -Infinity;
  private discardDeltas = false;
  private lastCopy: ScreenVideoFrame | null = null;
  private lastSourceAt = -Infinity;
  private nextFrameAt = -Infinity;
  private lastEncodedTs = 0;

  private outputs: EncodedOutput[] = [];
  private current: SendingFrame | null = null;
  private sealing = false;
  private pacingTimer: unknown = null;
  private streamW = 0;
  private streamH = 0;

  private watchers = 0;
  private readonly lastActed = new Map<string, number>();
  /** The audience of the latest epoch fragments were sealed under, kept across a brief suspension (REQ-54). */
  private lastAudience: VideoAudience | null = null;

  /** Counters for the panel and tests. */
  readonly stats = { encoded: 0, keyframes: 0, fragmentsSent: 0, framesSent: 0, discards: 0, skips: 0 };

  constructor(opts: ScreenShareSenderOptions) {
    this.opts = opts;
    this.channelId = opts.channelId.toLowerCase();
    this.self = opts.selfId.toLowerCase();
    this.platform = opts.platform;
    this.keys = opts.keys;
    this.transport = opts.transport;
    this.clock = opts.clock;
    this.probe = opts.probe;
    this.sentStops = opts.stops ?? new SentStops();
  }

  get state(): LocalShareState {
    return this.st;
  }

  get isPicking(): boolean {
    return this.picking;
  }

  /** The share is starting, sharing, or the picker is open. */
  get busy(): boolean {
    return this.picking || this.st !== 'idle';
  }

  snapshot(): LocalShareView {
    return {
      state: this.st,
      picking: this.picking,
      shareSeq: this.numbering.shareSeq,
      watchers: this.st === 'sharing' ? this.watchers : 0,
      source: this.st === 'idle' ? null : this.probe.source,
      audience: this.st === 'sharing' ? this.audience() : null,
      preview: this.previewEl,
      bitrate: this.st === 'sharing' ? this.configuredBitrate : null,
    };
  }

  /**
   * REQ-54: the members of R_e for the epoch fragments are sealed under. While
   * sending is briefly suspended for a new epoch (REQ-17) there is no such
   * epoch; the last one is shown until the new one is ready, so the number is
   * 0 only when R_e is empty.
   */
  private audience(): VideoAudience | null {
    const a = this.keys.videoAudience();
    if (a) this.lastAudience = a;
    return a ?? this.lastAudience;
  }

  // -------------------------------------------------------------------------
  // Start (REQ-43, REQ-52)
  // -------------------------------------------------------------------------

  /**
   * The Share Screen click (REQ-43). `getDisplayMedia` is the first call,
   * before any await, so it runs during the click's transient activation,
   * with exactly the options of §6.13.2. Returns false when nothing was
   * started (a share or the picker is already open).
   */
  startFromClick(): boolean {
    if (this.ended || this.st !== 'idle' || this.picking) return false;
    let pending: Promise<CaptureStream>;
    try {
      pending = this.platform.getDisplayMedia(displayMediaOptions());
    } catch (e) {
      pending = Promise.reject(e);
    }
    const attempt = ++this.attempt;
    this.picking = true;
    pending.then(
      stream => this.onCaptured(attempt, stream),
      err => this.onCaptureError(attempt, err),
    );
    this.changed();
    return true;
  }

  private onCaptured(attempt: number, stream: CaptureStream): void {
    if (attempt !== this.attempt || this.ended || !this.picking) {
      stopTracks(stream); // cancelled while the picker was open
      return;
    }
    this.picking = false;
    // REQ-43: an audio track is stopped at once and never read (D30).
    let audio: CaptureTrack[] = [];
    let video: CaptureTrack[] = [];
    try {
      audio = stream.getAudioTracks();
      video = stream.getVideoTracks();
    } catch {
      video = [];
    }
    for (const t of audio) {
      try {
        t.stop();
      } catch {
        // already stopped
      }
    }
    const track = video[0];
    if (!track) {
      stopTracks(stream);
      this.notice({ code: 'capture_failed' });
      this.changed();
      return;
    }
    if (!this.opts.canStart()) {
      stopTracks(stream);
      this.notice({ code: 'relay_didnt_start' });
      this.changed();
      return;
    }
    try {
      track.contentHint = 'detail';
    } catch {
      // optional (W3C MediaStreamTrack Content Hints)
    }
    this.stream = stream;
    this.track = track;
    this.trackEnded = () => this.onTrackEnded();
    try {
      track.addEventListener('ended', this.trackEnded);
    } catch {
      // no ended event: the user stops with the panel's control
    }
    this.previewEl = this.platform.createPreview(stream);
    // A frame source that cannot be opened is a capture failure (REQ-43):
    // the share would send nothing at all.
    if (!this.openSource(track)) {
      this.teardownCapture();
      this.notice({ code: 'capture_failed' });
      this.changed();
      return;
    }
    const sent = this.transport.screenShareStart(this.channelId);
    if (!sent.handedOff) {
      this.teardownCapture();
      this.notice({ code: 'relay_didnt_start' });
      this.changed();
      return;
    }
    this.outstanding = sent.messageId;
    this.st = 'starting';
    const gen = this.generation;
    this.startTimer = this.clock.setTimeout(() => {
      this.startTimer = null;
      if (gen === this.generation && this.st === 'starting') this.endShare({ code: 'relay_didnt_start' });
    }, SHARE_START_TIMEOUT_MS);
    this.changed();
  }

  private onCaptureError(attempt: number, err: unknown): void {
    if (attempt !== this.attempt || !this.picking) return;
    this.picking = false;
    const name = typeof err === 'object' && err !== null ? (err as { name?: unknown }).name : undefined;
    // §6.13.2: NotAllowedError is a cancel or a denial; the rest mean capture is unavailable.
    this.notice({ code: name === 'NotAllowedError' ? 'cancelled' : 'capture_failed' });
    this.changed();
  }

  /** The panel's Stop, or Cancel while starting or while the picker is open (REQ-52). */
  stopFromUser(): void {
    if (this.picking) {
      this.picking = false;
      this.attempt++; // the stream, if it still comes, is stopped at once
      this.changed();
      return;
    }
    if (this.st !== 'idle') this.endShare(null);
  }

  /**
   * The call ends (leave, eviction, disconnect, rejoin, channel switch,
   * unmount): end the share, sending `ScreenShareStop` if the socket is still
   * open (REQ-22, REQ-52). The sender is unusable afterwards.
   */
  end(notice: ScreenNotice | null = null): void {
    if (this.ended) return;
    if (this.picking) {
      this.picking = false;
      this.attempt++;
    }
    if (this.st !== 'idle') this.endShare(notice);
    this.ended = true;
    this.sentStops.clear();
    this.lastActed.clear();
  }

  // -------------------------------------------------------------------------
  // Relay messages (§6.12.1)
  // -------------------------------------------------------------------------

  /** `screen_share_started` for C (REQ-52). */
  onShareStarted(userId: string, requestId: unknown): void {
    if (this.ended || userId.toLowerCase() !== this.self) return;
    if (this.st === 'starting' && typeof requestId === 'string' && requestId === this.outstanding) {
      this.beginSharing();
      return;
    }
    // A late or stray answer while idle: the relay may hold a share this
    // client abandoned. A stop from a connection without a share is ignored
    // by the relay, so this is always safe; at most one per second.
    if (this.st !== 'idle') return;
    const now = this.clock.now();
    if (now - this.lastStrayStopAt < STRAY_STOP_MIN_GAP_MS) return;
    this.lastStrayStopAt = now;
    this.sendStop();
  }

  /** `screen_share_rejected` for C, answering the outstanding start only (REQ-52). */
  onShareRejected(requestId: unknown, reason: unknown): void {
    if (this.ended || this.st !== 'starting' || typeof requestId !== 'string' || requestId !== this.outstanding) return;
    const limit = this.opts.limits()?.maxSharers;
    const notice: ScreenNotice = reason === 'limit' ? { code: 'rejected_limit', ...(limit ? { limit } : {}) } : { code: 'relay_didnt_start' };
    this.outstanding = null; // answered: nothing to stop at the relay
    this.endShare(notice, false);
  }

  /** `screen_share_stopped` for C naming the local user (REQ-52). */
  onShareStopped(userId: string, requestId: unknown): void {
    if (this.ended || userId.toLowerCase() !== this.self) return;
    if (this.sentStops.confirms(requestId)) return; // confirms our own stop
    if (this.st !== 'idle') this.endShare({ code: 'stopped_by_relay' });
  }

  /** A self-check reply that does not list the local user as a sharer (REQ-38). */
  onNotListedAsSharer(): void {
    if (!this.ended && this.st === 'sharing') this.endShare({ code: 'stopped_by_relay' });
  }

  /** The relay no longer offers `screen/1` on this socket: nothing can be sent, so the share ends. */
  onRelayIncapable(): void {
    if (this.ended) return;
    if (this.picking) {
      this.picking = false;
      this.attempt++;
      this.changed();
    }
    if (this.st !== 'idle') this.endShare({ code: 'stopped_by_relay' });
  }

  /** `screen_watchers` for C (REQ-47). */
  onWatchers(count: unknown): void {
    if (this.ended || this.st !== 'sharing') return;
    if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) return;
    const before = this.watchers;
    this.watchers = count;
    if (before === 0 && count > 0) this.relayKeyTrigger();
    if (count === 0) {
      // Nothing is sent without a watcher; a frame partly sent is discarded,
      // as a relay-driven discard (coalesced, REQ-44).
      if (this.current) this.finishFrame(true, true);
    }
    this.armKeyTimer();
    this.changed();
  }

  /** `screen_keyframe_request` for C from `from` (REQ-51). */
  onKeyframeRequest(from: unknown): void {
    if (this.ended || this.st !== 'sharing' || typeof from !== 'string') return;
    const u = from.toLowerCase();
    if (!this.keys.participants().includes(u) || !this.keys.isCurrentRecipient(u)) return;
    const now = this.clock.now();
    const last = this.lastActed.get(u);
    if (last !== undefined && now - last < KFR_PER_USER_GAP_MS) return;
    this.lastActed.set(u, now);
    this.relayKeyTrigger();
  }

  /** The local sender switched epoch: the first frame under it is a keyframe (REQ-17, REQ-44). */
  onEpochSwitch(): void {
    if (this.ended || this.st !== 'sharing') return;
    this.discardDeltas = true;
    this.setKeyDue();
  }

  /** An audio frame was just handed off: check the waiting fragments again (REQ-47). */
  onAudioSent(): void {
    if (this.current && this.pacingTimer !== null) this.pump();
  }

  // -------------------------------------------------------------------------
  // Share lifecycle
  // -------------------------------------------------------------------------

  private beginSharing(): void {
    this.clock.clearTimeout(this.startTimer);
    this.startTimer = null;
    this.outstanding = null;
    const limits = this.opts.limits();
    try {
      this.numbering.startShare();
    } catch {
      this.endShare(null);
      return;
    }
    this.st = 'sharing';
    this.rates = videoBitrates(limits?.maxBytesPerSecond ?? 200_000);
    this.watchers = 0;
    this.lastKeyAt = -Infinity;
    this.forceKey = true; // the first frame of a share
    this.discardDeltas = false;
    this.nextFrameAt = -Infinity;
    this.streamW = 0;
    this.streamH = 0;
    this.configured = false;
    this.configuredBitrate = null;
    this.wantW = 0;
    this.wantH = 0;
    this.checking = false;
    this.supportedConfigs.clear();
    this.step = this.rates;
    this.skipTimes = [];
    this.lastStepDownAt = -Infinity;
    this.clock.clearTimeout(this.stepUpTimer);
    this.stepUpTimer = null;
    this.lastSizeConfigAt = -Infinity;
    const gen = this.generation;
    try {
      this.encoder = this.platform.createEncoder(
        chunk => this.onEncoderOutput(gen, chunk),
        () => {
          if (gen === this.generation) this.endShare({ code: 'encoder_failed' });
        },
      );
    } catch {
      this.endShare({ code: 'encoder_failed' });
      return;
    }
    this.armKeyTimer();
    this.changed();
  }

  private onTrackEnded(): void {
    // The platform's own stop control (REQ-52).
    if (this.st !== 'idle') this.endShare(null);
  }

  /**
   * End the share (REQ-52): stop every captured track, close the frame
   * source and the encoder, discard queued fragments and return to idle;
   * send `ScreenShareStop` when the share was starting or sharing and the
   * socket is open.
   */
  private endShare(notice: ScreenNotice | null, sendStop = true): void {
    const was = this.st;
    this.generation++;
    this.teardownCapture();
    try {
      this.encoder?.close();
    } catch {
      // already closed
    }
    this.encoder = null;
    this.configured = false;
    this.configuredBitrate = null;
    this.checking = false;
    this.outputs = [];
    this.current = null;
    this.sealing = false;
    for (const t of [this.startTimer, this.keyTimer, this.pacingTimer, this.stepUpTimer]) this.clock.clearTimeout(t);
    this.startTimer = this.keyTimer = this.pacingTimer = this.stepUpTimer = null;
    safeClose(this.lastCopy);
    this.lastCopy = null;
    this.relayKeyAt = null;
    this.forceKey = false;
    this.discardDeltas = false;
    this.watchers = 0;
    this.lastAudience = null;
    this.st = 'idle';
    const outstanding = this.outstanding;
    this.outstanding = null;
    if (sendStop && (was === 'starting' || was === 'sharing' || outstanding !== null)) this.sendStop();
    if (notice) this.notice(notice);
    this.changed();
  }

  private sendStop(): void {
    if (!this.transport.isOpen()) return;
    this.sentStops.record(this.transport.screenShareStop(this.channelId));
  }

  private teardownCapture(): void {
    if (this.sourceLive) this.sourceLive.live = false;
    this.sourceLive = null;
    try {
      this.source?.close();
    } catch {
      // already closed
    }
    this.source = null;
    if (this.track && this.trackEnded) {
      try {
        this.track.removeEventListener('ended', this.trackEnded);
      } catch {
        // ignore
      }
    }
    stopTracks(this.stream);
    this.stream = null;
    this.track = null;
    this.trackEnded = null;
    if (this.previewEl) {
      try {
        (this.previewEl as unknown as { srcObject: unknown }).srcObject = null;
      } catch {
        // ignore
      }
    }
    this.previewEl = null;
    safeClose(this.lastCopy);
    this.lastCopy = null;
  }

  /**
   * Open the frame source of the probe (§6.13.3). Returns false when it
   * cannot be opened. A source that fails later ends the share as a capture
   * failure (REQ-43, REQ-52): no further frame would come, and the share
   * must not look active while sending nothing.
   */
  private openSource(track: CaptureTrack): boolean {
    const token = { live: true };
    this.sourceLive = token;
    try {
      this.source = this.platform.openFrameSource(
        this.probe.source,
        track,
        this.previewEl,
        f => {
          if (!token.live) {
            safeClose(f);
            return;
          }
          this.onSourceFrame(f);
        },
        this.clock,
        () => {
          if (token.live && this.st !== 'idle') this.endShare({ code: 'capture_failed' });
        },
      );
      return true;
    } catch {
      token.live = false;
      this.sourceLive = null;
      this.source = null;
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // Frames to the encoder (REQ-44, REQ-47, §6.13.3)
  // -------------------------------------------------------------------------

  private onSourceFrame(frame: ScreenVideoFrame): void {
    if (this.ended || !this.track) {
      safeClose(frame);
      return;
    }
    const now = this.clock.now();
    this.lastSourceAt = now;
    // REQ-44: keep a copy of the newest source frame, also while nothing is encoded.
    let copy: ScreenVideoFrame | null = null;
    try {
      copy = frame.clone();
    } catch {
      copy = null;
    }
    if (copy) {
      safeClose(this.lastCopy);
      this.lastCopy = copy;
    }
    this.tryEncode(frame, now, false);
  }

  /** Frames go to the encoder only while fragments could be sent (REQ-47). */
  private feeding(): boolean {
    return this.st === 'sharing' && this.encoder !== null && this.watchers > 0 && this.transport.isOpen() && this.keys.sendingEpoch() !== null;
  }

  private canSendVideo(): boolean {
    return this.st === 'sharing' && this.watchers > 0 && this.transport.isOpen();
  }

  private videoBusy(): boolean {
    return this.outputs.length > 0 || this.current !== null || this.sealing;
  }

  /** Pass `frame` to the encoder, or close it. Takes ownership of `frame`. */
  private tryEncode(frame: ScreenVideoFrame, now: number, fromCopy: boolean): boolean {
    if (!this.feeding()) {
      safeClose(frame);
      return false;
    }
    // §6.13.3 rate rule.
    if (now < this.nextFrameAt - FRAME_EARLY_MS) {
      safeClose(frame);
      return false;
    }
    // REQ-47 pacing: no new frame while the socket is backed up or fragments wait.
    if (this.transport.bufferedAmount() > SEND_BUFFER_HIGH || this.videoBusy()) {
      if (!fromCopy) this.noteSkip(now);
      safeClose(frame);
      return false;
    }
    const enc = this.encoder!;
    if (enc.encodeQueueSize > ENCODE_QUEUE_MAX) {
      safeClose(frame);
      return false;
    }
    const size = scaledSize(frame.displayWidth, frame.displayHeight);
    if (!size) {
      safeClose(frame);
      return false;
    }
    // §6.13.3: a new scaled size reconfigures the encoder at most once per
    // 2 s; until then frames are scaled to the encoder's current size.
    if (this.wantW === 0 || ((size.width !== this.wantW || size.height !== this.wantH) && now - this.lastSizeConfigAt >= ENCODER_RECONFIG_MIN_GAP_MS)) {
      this.wantW = size.width;
      this.wantH = size.height;
      this.lastSizeConfigAt = now;
    }
    // REQ-44: while the configuration for the wanted size and bitrate is
    // being checked with isConfigSupported, input frames are closed; the
    // newest one is encoded from the kept copy once the check passes.
    if (!this.syncConfig()) {
      safeClose(frame);
      return false;
    }
    this.nextFrameAt = Math.max(this.nextFrameAt + FRAME_INTERVAL_MS, now + FRAME_INTERVAL_MS - FRAME_EARLY_MS);
    const width = this.encW;
    const height = this.encH;
    let input = frame;
    if (width !== frame.displayWidth || height !== frame.displayHeight) {
      try {
        input = this.platform.scaleFrame(frame, width, height);
      } catch {
        safeClose(frame);
        return false;
      } finally {
        if (input !== frame) safeClose(frame);
      }
    }
    const key = this.forceKey || now - this.lastKeyAt >= KEYFRAME_INTERVAL_MS;
    try {
      enc.encode(input, { keyFrame: key });
    } catch {
      safeClose(input);
      this.endShare({ code: 'encoder_failed' });
      return false;
    }
    this.lastEncodedTs = Math.max(this.lastEncodedTs, input.timestamp);
    safeClose(input); // encode() keeps its own reference (W3C WebCodecs)
    this.stats.encoded++;
    if (key) {
      this.stats.keyframes++;
      this.lastKeyAt = now;
      this.forceKey = false;
    }
    this.armKeyTimer();
    return true;
  }

  /** §6.13.4 and REQ-47: the current step's target, never above its maximum or §6.13.4's. */
  private wantedBitrate(): number {
    return Math.min(this.step.target, this.step.maximum, this.rates.maximum);
  }

  /**
   * REQ-44: bring the encoder to the wanted size and bitrate, with a
   * configuration of §6.13.4 that `VideoEncoder.isConfigSupported` accepted
   * first. Returns whether the encoder is configured as wanted now;
   * otherwise a check is in flight, or the share has ended.
   */
  private syncConfig(): boolean {
    const enc = this.encoder;
    if (!enc || this.st !== 'sharing' || this.wantW === 0) return false;
    const bitrate = this.wantedBitrate();
    if (this.configured && this.encW === this.wantW && this.encH === this.wantH && this.configuredBitrate === bitrate) return true;
    const key = `${this.wantW}x${this.wantH}@${bitrate}`;
    const config = this.supportedConfigs.get(key);
    if (config) return this.applyConfig(enc, config);
    if (!this.checking) this.checkConfig(this.wantW, this.wantH, bitrate, key);
    return false;
  }

  /**
   * Ask `isConfigSupported` for the probe's configuration at this size and
   * bitrate, and for configuration B where A is rejected (§6.13.4). An
   * unsupported configuration ends the share as an encoder failure, without
   * calling `configure` (REQ-44, §8.4).
   */
  private checkConfig(width: number, height: number, bitrate: number, key: string): void {
    this.checking = true;
    const gen = this.generation;
    const ask = (variant: EncoderVariant): Promise<Vp8EncoderConfig | null> => {
      const config = encoderConfig(variant, width, height, bitrate);
      let asked: Promise<boolean>;
      try {
        asked = this.platform.encoderConfigSupported(config);
      } catch {
        asked = Promise.resolve(false);
      }
      return Promise.resolve(asked).then(ok => (ok === true ? config : null), () => null);
    };
    ask(this.probe.config)
      .then(config => (config || this.probe.config === 'B' ? config : ask('B')))
      .then(config => {
        if (gen !== this.generation) return;
        this.checking = false;
        if (this.st !== 'sharing') return;
        if (!config) {
          this.endShare({ code: 'encoder_failed' });
          return;
        }
        this.supportedConfigs.set(key, config);
        // The wanted size or bitrate may have changed meanwhile: that is checked next.
        if (this.syncConfig()) this.encodeKeptCopy();
      })
      .catch(() => {
        if (gen === this.generation && this.st !== 'idle') this.endShare({ code: 'encoder_failed' });
      });
  }

  private applyConfig(enc: VideoEncoderPort, config: Vp8EncoderConfig): boolean {
    try {
      enc.configure(config);
    } catch {
      this.endShare({ code: 'encoder_failed' });
      return false;
    }
    this.configured = true;
    this.configuredBitrate = config.bitrate;
    this.encW = config.width;
    this.encH = config.height;
    // REQ-44: the first frame after a (re)configuration is a keyframe.
    this.forceKey = true;
    this.armKeyTimer();
    return true;
  }

  /** A new frame with the picture of the kept copy and a later timestamp, or null. */
  private retimedCopy(): ScreenVideoFrame | null {
    const copy = this.lastCopy;
    if (!copy) return null;
    try {
      return this.platform.retimeFrame(copy, Math.max(copy.timestamp, this.lastEncodedTs) + 1000);
    } catch {
      return null;
    }
  }

  /**
   * After a configuration check passed: the source frames that arrived
   * during the check were closed, so the newest one, the kept copy, is
   * encoded now as the keyframe that follows the configuration (REQ-44).
   */
  private encodeKeptCopy(): void {
    if (!this.lastCopy || !this.feeding()) return;
    const frame = this.retimedCopy();
    if (frame) this.tryEncode(frame, this.clock.now(), true);
  }

  /**
   * REQ-47 as amended by A2: a source frame skipped for backpressure. More
   * than 15 skips within 10 s halve the target and the maximum; after each
   * further 10 s with more than 15 skips they halve again, down to a target
   * of 200,000 bit/s. Only skips after the previous halving count, since a
   * halving needs 10 s since the last one and the window is 10 s long.
   */
  private noteSkip(now: number): void {
    this.stats.skips++;
    this.skipTimes.push(now);
    while (this.skipTimes.length > 0 && now - this.skipTimes[0] >= BACKPRESSURE_WINDOW_MS) this.skipTimes.shift();
    if (this.skipTimes.length > BACKPRESSURE_SKIPS_MAX && now - this.lastStepDownAt >= BACKPRESSURE_WINDOW_MS) {
      const down = bitrateStepDown(this.step);
      if (down) {
        this.lastStepDownAt = now;
        this.setStep(down);
      }
    }
    // Every skip restarts the 10 s that a step up waits for.
    this.armStepUp();
  }

  /** REQ-47 (A2): after each 10 s without a skip, double the bitrate, up to §6.13.4's values. */
  private armStepUp(): void {
    this.clock.clearTimeout(this.stepUpTimer);
    this.stepUpTimer = null;
    if (this.st !== 'sharing' || !bitrateStepUp(this.step, this.rates)) return;
    const gen = this.generation;
    this.stepUpTimer = this.clock.setTimeout(() => {
      this.stepUpTimer = null;
      if (gen !== this.generation || this.st !== 'sharing') return;
      const up = bitrateStepUp(this.step, this.rates);
      if (!up) return;
      this.setStep(up);
      this.armStepUp();
    }, BACKPRESSURE_WINDOW_MS);
  }

  /** Apply a bitrate step: reconfigure (a reconfiguration is followed by a keyframe, §6.13.4). */
  private setStep(step: BitrateStep): void {
    this.step = step;
    if (this.configured) this.syncConfig();
    this.armKeyTimer();
    this.changed();
  }

  // -------------------------------------------------------------------------
  // Keyframes (REQ-44, REQ-51)
  // -------------------------------------------------------------------------

  private setKeyDue(): void {
    this.forceKey = true;
    this.armKeyTimer();
  }

  /**
   * The watcher count rising from 0 and acted-on requests, which the relay
   * can produce at will: at most one keyframe per `KEYFRAME_MIN_GAP` results
   * from them. Within 1 s of the last keyframe a trigger schedules one
   * keyframe 1 s after it, and further triggers before then add nothing.
   */
  private relayKeyTrigger(): void {
    if (this.st !== 'sharing' || this.forceKey || this.relayKeyAt !== null) return;
    const now = this.clock.now();
    if (now - this.lastKeyAt >= KEYFRAME_MIN_GAP_MS) {
      this.setKeyDue();
      return;
    }
    this.relayKeyAt = this.lastKeyAt + KEYFRAME_MIN_GAP_MS;
    this.relayKeyBase = this.lastKeyAt;
    this.armKeyTimer();
  }

  private armKeyTimer(): void {
    this.clock.clearTimeout(this.keyTimer);
    this.keyTimer = null;
    if (this.st !== 'sharing' || this.ended) return;
    const now = this.clock.now();
    let at = Infinity;
    if (this.relayKeyAt !== null) at = Math.min(at, this.relayKeyAt);
    if (this.feeding()) {
      if (!this.forceKey) at = Math.min(at, this.lastKeyAt + KEYFRAME_INTERVAL_MS);
      else if (this.lastCopy) at = Math.min(at, Math.max(this.lastSourceAt + STATIC_KEYFRAME_WAIT_MS, this.copyRetryAt));
    }
    if (at === Infinity) return;
    const delay = Number.isFinite(at) ? Math.max(0, at - now) : 0;
    this.keyTimer = this.clock.setTimeout(() => {
      this.keyTimer = null;
      this.onKeyTimer();
    }, delay);
  }

  private onKeyTimer(): void {
    if (this.st !== 'sharing' || this.ended) return;
    const now = this.clock.now();
    if (this.relayKeyAt !== null && now >= this.relayKeyAt) {
      this.relayKeyAt = null;
      // Satisfied already if a keyframe was requested since it was scheduled.
      if (this.lastKeyAt <= this.relayKeyBase) this.forceKey = true;
    }
    if (this.feeding()) {
      if (now - this.lastKeyAt >= KEYFRAME_INTERVAL_MS) this.forceKey = true;
      // A static screen delivers no frames: encode the kept copy (REQ-44).
      if (this.forceKey && this.lastCopy && now - this.lastSourceAt >= STATIC_KEYFRAME_WAIT_MS && now >= this.copyRetryAt) {
        const frame = this.retimedCopy();
        if (!frame || !this.tryEncode(frame, now, true)) this.copyRetryAt = now + PACING_CHECK_MS;
      }
    }
    this.armKeyTimer();
  }

  // -------------------------------------------------------------------------
  // Encoder outputs to fragments (REQ-44, REQ-46, REQ-47)
  // -------------------------------------------------------------------------

  private onEncoderOutput(gen: number, chunk: EncodedChunkPort): void {
    if (gen !== this.generation || this.st !== 'sharing') return;
    const n = chunk.byteLength;
    // REQ-44: an output above 1,024,000 bytes is discarded, which counts as a discard.
    if (!Number.isSafeInteger(n) || n < 1 || n > VIDEO_FRAME_MAX) {
      this.markDiscard(false);
      return;
    }
    const data = new Uint8Array(n);
    try {
      chunk.copyTo(data);
    } catch {
      this.markDiscard(false);
      return;
    }
    this.outputs.push({ key: chunk.type === 'key', data });
    this.processQueue();
  }

  /**
   * After a discard the next frame is a keyframe and deltas are dropped
   * until a key output (REQ-44). A discard the relay caused (no watcher)
   * asks for the keyframe through the coalesced relay-driven path.
   */
  private markDiscard(relayDriven: boolean): void {
    this.stats.discards++;
    this.discardDeltas = true;
    if (relayDriven) this.relayKeyTrigger();
    else this.setKeyDue();
  }

  /** Start the next encoded frame: number it, fix its epoch and VCTR range, seal it (REQ-46). */
  private processQueue(): void {
    while (!this.current && !this.sealing && this.outputs.length > 0 && this.st === 'sharing') {
      const out = this.outputs.shift()!;
      if (!out.key && this.discardDeltas) continue;
      let width: number;
      let height: number;
      if (out.key) {
        const size = vp8KeySize(out.data);
        if (!size || !withinCaps(size.width, size.height) || !vp8TagOk(out.data, true)) {
          this.markDiscard(false);
          continue;
        }
        width = size.width;
        height = size.height;
        this.streamW = width;
        this.streamH = height;
        this.discardDeltas = false;
      } else {
        if (this.streamW === 0 || !vp8TagOk(out.data, false)) {
          this.markDiscard(false);
          continue;
        }
        width = this.streamW;
        height = this.streamH;
      }
      if (!this.canSendVideo()) {
        this.markDiscard(true);
        continue;
      }
      if (!this.numbering.canNumberFrame) {
        this.endShare(null); // frame_no would exceed 2^32 − 1 (REQ-46)
        return;
      }
      const ticket = this.keys.beginVideoFrame(fragmentCount(out.data.length));
      if (!ticket) {
        this.markDiscard(false);
        continue;
      }
      const frame: EncodedScreenFrame = {
        data: out.data,
        key: out.key,
        shareSeq: this.numbering.shareSeq,
        frameNo: this.numbering.frameNo,
        width,
        height,
      };
      this.sealing = true;
      const gen = this.generation;
      let sealing: Promise<Uint8Array[] | null>;
      try {
        sealing = this.keys.sealVideoFrame(ticket, frame);
      } catch (e) {
        sealing = Promise.reject(e);
      }
      sealing
        .then(f => f, () => null)
        .then(frags => this.onSealed(gen, ticket, frags));
      return;
    }
  }

  private onSealed(gen: number, ticket: VideoFrameTicket, frags: Uint8Array[] | null): void {
    if (gen !== this.generation) return;
    this.sealing = false;
    if (!frags || frags.length === 0) {
      this.numbering.frameDone(false);
      this.markDiscard(false);
      this.processQueue();
      this.armKeyTimer();
      return;
    }
    this.current = { ticket, frags, index: 0, any: false };
    this.pump();
  }

  /**
   * Hand off the waiting fragments in VCTR order while `bufferedAmount` is at
   * most `SEND_BUFFER_HIGH`, checking again every 20 ms and after each audio
   * send (REQ-47). A fragment not handed off discards the rest of the frame.
   */
  private pump(): void {
    const cur = this.current;
    if (!cur) return;
    this.clock.clearTimeout(this.pacingTimer);
    this.pacingTimer = null;
    while (cur.index < cur.frags.length) {
      if (!this.canSendVideo()) {
        this.finishFrame(true, true);
        return;
      }
      if (!this.keys.mayHandOff(cur.ticket)) {
        this.finishFrame(true, false);
        return;
      }
      if (this.transport.bufferedAmount() > SEND_BUFFER_HIGH) {
        const gen = this.generation;
        this.pacingTimer = this.clock.setTimeout(() => {
          this.pacingTimer = null;
          if (gen === this.generation) this.pump();
        }, PACING_CHECK_MS);
        return;
      }
      if (!this.transport.sendScreenFragment(this.channelId, cur.frags[cur.index])) {
        this.finishFrame(true, false);
        return;
      }
      cur.any = true;
      cur.index++;
      this.stats.fragmentsSent++;
    }
    this.finishFrame(false, false);
  }

  private finishFrame(discarded: boolean, relayDriven: boolean): void {
    const cur = this.current;
    if (!cur) return;
    this.current = null;
    this.clock.clearTimeout(this.pacingTimer);
    this.pacingTimer = null;
    // REQ-46: frame_no advances only for a frame with a handed-off fragment.
    this.numbering.frameDone(cur.any);
    if (cur.any && !discarded) this.stats.framesSent++;
    if (discarded) this.markDiscard(relayDriven);
    this.processQueue();
    this.armKeyTimer();
  }

  private notice(n: ScreenNotice): void {
    this.opts.onNotice?.(n);
  }

  private changed(): void {
    this.opts.onChange?.();
  }
}

// ---------------------------------------------------------------------------
// Viewer (REQ-48 to REQ-50, §6.2.8, §6.2.9)
// ---------------------------------------------------------------------------

export interface ScreenShareViewerOptions {
  sharerId: string;
  platform: ScreenPlatform;
  clock: CallClock;
  /** From the viewing probe: whether the decoder takes `optimizeForLatency`. */
  optimizeForLatency: boolean;
  /** A video key is installed for the sharer's current instance. */
  hasVideoKey: () => boolean;
  /** Send `ScreenKeyframeRequest` for the share; returns whether it was handed off. */
  sendKeyframeRequest: () => boolean;
  /** Decoder setups were refused 3 times within 30 s: stop watching (REQ-49). */
  onCantDisplay: () => void;
  onChange: () => void;
}

/** One watched share's state for the panel (§8.4). */
export interface ViewerView {
  readonly state: ShareDecodeState;
  readonly watchStartedAt: number;
  readonly lastDecodedAt: number | null;
  readonly aeadFailures: number;
  readonly keylessSince: number | null;
  readonly requestsSent: number;
}

/**
 * One watched share (REQ-50): `ShareReassembler` with a VP8 decoder and the
 * tile's canvas, the keyframe-request schedule, and the consecutive AEAD
 * failures of REQ-48. Watching starts in `awaiting_keyframe`.
 */
export class ScreenShareViewer {
  readonly sharerId: string;
  readonly watchStartedAt: number;
  private readonly opts: ScreenShareViewerOptions;
  private readonly clock: CallClock;
  private readonly r: ShareReassembler<DecodedVideoFrame>;
  private surface: ShareSurface | null = null;
  private aead = 0;
  private closedFlag = false;
  private sweepTimer: unknown = null;
  private keyless: number | null;
  /**
   * The panel was last told this share is live (§8.4 row 9), and when the
   * last picture was drawn. A draw notifies only when it can change the
   * tile's row; the "N s" counters of rows 7 and 8 are the panel's timer's.
   */
  private shownLive = false;
  private lastDrawAt = -Infinity;
  // REQ-50 keyframe-request schedule.
  private kfrActive = false;
  private kfrAwaitKey = false;
  private kfrFirstAt = 0;
  private kfrStepIndex = 0;
  private kfrTimer: unknown = null;
  private lastKfrAt = -Infinity;
  private requests = 0;
  private awaitingFired = false;

  constructor(opts: ScreenShareViewerOptions) {
    this.opts = opts;
    this.sharerId = opts.sharerId;
    this.clock = opts.clock;
    this.watchStartedAt = this.clock.now();
    this.keyless = opts.hasVideoKey() ? null : this.watchStartedAt;
    this.r = new ShareReassembler<DecodedVideoFrame>({
      now: () => this.clock.now(),
      createDecoder: (output, error) => opts.platform.createDecoder(output, error, opts.optimizeForLatency),
      requestAnimationFrame: cb => opts.platform.requestAnimationFrame(cb),
      draw: (frame, width, height) => {
        if (this.surface) this.surface.draw(frame, width, height);
        // Up to 15 draws a second: only the first after a wait or a stall
        // changes the tile (rows 6 to 8 to row 9).
        const now = this.clock.now();
        const stalled = now - this.lastDrawAt >= VIDEO_STALL_NOTICE_MS;
        this.lastDrawAt = now;
        if (!this.shownLive || stalled) {
          this.shownLive = true;
          this.opts.onChange();
        }
      },
      onAwaitingKeyframe: () => {
        this.awaitingFired = true;
        this.shownLive = false;
        this.startSchedule();
        this.opts.onChange();
      },
      onCantDisplay: () => {
        this.close();
        this.opts.onCantDisplay();
      },
    });
    this.armSweep();
    // The watch starts awaiting a keyframe: its first request (REQ-50).
    this.startSchedule();
  }

  get closed(): boolean {
    return this.closedFlag;
  }

  get decodeState(): ShareDecodeState {
    return this.r.state;
  }

  /** The reassembler, for inspection in tests. */
  get reassembler(): ShareReassembler<DecodedVideoFrame> {
    return this.r;
  }

  snapshot(): ViewerView {
    return {
      state: this.r.state,
      watchStartedAt: this.watchStartedAt,
      lastDecodedAt: this.r.lastDecodedAt,
      aeadFailures: this.aead,
      keylessSince: this.keyless,
      requestsSent: this.requests,
    };
  }

  attachSurface(surface: ShareSurface | null): void {
    if (this.surface && this.surface !== surface) this.surface.clear();
    this.surface = surface;
  }

  /** §6.2.8 step 7: a token of the decryption budget. */
  takeDecryption(): boolean {
    return !this.closedFlag && this.r.takeDecryption();
  }

  /** §6.2.8 steps 10 and 11: an authenticated fragment plaintext under epoch `kid`. */
  onFragment(kid: number, plaintext: Uint8Array): void {
    if (this.closedFlag) return;
    const f = parseFragment(plaintext);
    if (!f) return;
    this.r.onFragment(kid, f.header, f.payload);
  }

  /** REQ-48: consecutive AEAD failures from the sharer; 50 clear the picture. */
  onAeadFailures(consecutive: number): void {
    if (this.closedFlag) return;
    const before = this.aead;
    this.aead = consecutive;
    if (before < VIDEO_AEAD_FAIL_NOTICE && consecutive >= VIDEO_AEAD_FAIL_NOTICE) this.surface?.clear();
    if ((before >= VIDEO_AEAD_FAIL_NOTICE) !== (consecutive >= VIDEO_AEAD_FAIL_NOTICE)) this.opts.onChange();
  }

  /** REQ-35: the sharer's keys were erased, or a new instance of the sharer was recorded. */
  onRemoteReset(newInstance: boolean): void {
    if (this.closedFlag) return;
    if (!this.opts.hasVideoKey() && this.keyless === null) this.keyless = this.clock.now();
    if (newInstance) this.aead = 0;
    this.awaitingFired = false;
    this.shownLive = false;
    this.r.reset(newInstance);
    // A new sharer instance starts a new awaiting period (REQ-50).
    if (newInstance && !this.awaitingFired) this.startSchedule();
    this.opts.onChange();
  }

  /** A key for the sharer's current instance was installed (REQ-50). */
  onKeyInstalled(): void {
    if (this.closedFlag) return;
    this.keyless = null;
    if (this.kfrActive && this.kfrAwaitKey && this.r.state === 'awaiting_keyframe') this.sendFirstRequest();
    this.opts.onChange();
  }

  /** Watching ended: close the decoder, clear the canvas, stop every timer. */
  close(): void {
    if (this.closedFlag) return;
    this.closedFlag = true;
    this.r.close();
    this.cancelSchedule();
    this.clock.clearTimeout(this.sweepTimer);
    this.sweepTimer = null;
    this.surface?.clear();
    this.surface = null;
  }

  private armSweep(): void {
    this.sweepTimer = this.clock.setTimeout(() => {
      this.sweepTimer = null;
      if (this.closedFlag) return;
      this.r.sweep();
      this.armSweep();
    }, REASSEMBLY_SWEEP_MS);
  }

  // REQ-50: on entering awaiting_keyframe with a key installed, a request now
  // and 2, 4 and 8 s later; without a key, one as soon as a key is installed.
  private startSchedule(): void {
    this.cancelSchedule();
    this.kfrActive = true;
    if (this.opts.hasVideoKey()) this.sendFirstRequest();
    else this.kfrAwaitKey = true;
  }

  private sendFirstRequest(): void {
    this.kfrAwaitKey = false;
    this.kfrFirstAt = Math.max(this.clock.now(), this.lastKfrAt + KFR_MIN_GAP_MS);
    this.kfrStepIndex = 0;
    this.armStep();
  }

  private armStep(): void {
    this.clock.clearTimeout(this.kfrTimer);
    const at = Math.max(this.kfrFirstAt + KFR_SCHEDULE_MS[this.kfrStepIndex], this.lastKfrAt + KFR_MIN_GAP_MS);
    const delay = Math.max(0, at - this.clock.now());
    if (delay === 0) {
      this.kfrTimer = null;
      this.kfrStep();
      return;
    }
    this.kfrTimer = this.clock.setTimeout(() => {
      this.kfrTimer = null;
      this.kfrStep();
    }, delay);
  }

  private kfrStep(): void {
    if (!this.kfrActive || this.closedFlag) return;
    // A keyframe reached the decoder: this awaiting period is over.
    if (this.r.state !== 'awaiting_keyframe') {
      this.kfrActive = false;
      return;
    }
    if (this.opts.hasVideoKey() && this.clock.now() - this.lastKfrAt >= KFR_MIN_GAP_MS) {
      if (this.opts.sendKeyframeRequest()) {
        this.lastKfrAt = this.clock.now();
        this.requests++;
      }
    }
    this.kfrStepIndex++;
    if (this.kfrStepIndex >= KFR_SCHEDULE_MS.length) {
      this.kfrActive = false; // no more until a frame decodes and a new period starts
      return;
    }
    this.armStep();
  }

  private cancelSchedule(): void {
    this.clock.clearTimeout(this.kfrTimer);
    this.kfrTimer = null;
    this.kfrActive = false;
    this.kfrAwaitKey = false;
  }
}

// ---------------------------------------------------------------------------
// The remote share list and the watches (REQ-49, REQ-50, REQ-53)
// ---------------------------------------------------------------------------

/** What the viewers need of `CallKeyManager`. */
export interface ScreenViewerKeys {
  /** V. */
  participants(): string[];
  isEligibleParticipant(userId: string): boolean;
  hasVideoKey(userId: string): boolean;
}

export interface ScreenViewerTransport {
  isScreenCapable(): boolean;
  screenWatch(channelId: string, sharerId: string, watch: boolean): SendResult;
  screenKeyframeRequest(channelId: string, sharerId: string): SendResult;
}

export interface ScreenViewersOptions {
  channelId: string;
  selfId: string;
  platform: ScreenPlatform;
  clock: CallClock;
  keys: ScreenViewerKeys;
  transport: ScreenViewerTransport;
  /** The viewing probe's result, or null while it runs. */
  viewing: () => ViewingProbe | null;
  onChange: () => void;
}

/** One entry of the remote share list, for the panel (§8.4). */
export interface RemoteShareView {
  readonly sharerId: string;
  readonly watching: boolean;
  readonly viewer: ViewerView | null;
  /** The watch ended because decoder setups were refused (REQ-49). */
  readonly cantDisplay: boolean;
  /** The relay refused the last watch (REQ-50), with its reason. */
  readonly rejected: string | null;
}

interface ShareEntry {
  readonly sharerId: string;
  viewer: ScreenShareViewer | null;
  cantDisplay: boolean;
  rejected: string | null;
}

export class ScreenViewers {
  private readonly opts: ScreenViewersOptions;
  private readonly channelId: string;
  private readonly self: string;
  /** The remote share list, in announcement order. */
  private readonly shares = new Map<string, ShareEntry>();
  private readonly surfaces = new Map<string, ShareSurface>();
  private ended = false;

  constructor(opts: ScreenViewersOptions) {
    this.opts = opts;
    this.channelId = opts.channelId.toLowerCase();
    this.self = opts.selfId.toLowerCase();
  }

  // Announcements (REQ-53): hints that decide which tiles exist. They never
  // touch keys, eligibility or R_g, and never display anything.

  /** `screen_share_started` for C. */
  onStarted(userId: string): void {
    const u = userId.toLowerCase();
    if (this.ended || u === this.self || !this.inView(u) || this.shares.has(u)) return;
    this.shares.set(u, { sharerId: u, viewer: null, cantDisplay: false, rejected: null });
    this.opts.onChange();
  }

  /** `screen_share_stopped` for C. */
  onStopped(userId: string): void {
    const u = userId.toLowerCase();
    if (this.ended || !this.shares.has(u)) return;
    this.remove(u);
    this.opts.onChange();
  }

  /** `screen_sharers` of `voice_channel_joined` or `voice_participants` for C. */
  setAnnounced(list: readonly string[]): void {
    if (this.ended) return;
    const listed = new Set(list.filter((x): x is string => typeof x === 'string').map(x => x.toLowerCase()));
    for (const u of [...this.shares.keys()]) if (!listed.has(u)) this.remove(u);
    for (const u of listed) if (u !== this.self && this.inView(u) && !this.shares.has(u)) {
      this.shares.set(u, { sharerId: u, viewer: null, cantDisplay: false, rejected: null });
    }
    this.opts.onChange();
  }

  /** V changed: a share of a user who left V disappears with the user (§8.4). */
  reconcileView(): void {
    if (this.ended) return;
    let changed = false;
    for (const u of [...this.shares.keys()]) {
      if (!this.inView(u)) {
        this.remove(u);
        changed = true;
      }
    }
    if (changed) this.opts.onChange();
  }

  /** Eligibility changed: stop watching a sharer that is no longer eligible (REQ-50). */
  reconcileEligibility(): void {
    if (this.ended) return;
    for (const e of this.shares.values()) {
      if (e.viewer && !this.opts.keys.isEligibleParticipant(e.sharerId)) this.stopWatching(e, true);
    }
  }

  // Watching (REQ-50).

  watchingCount(): number {
    let n = 0;
    for (const e of this.shares.values()) if (e.viewer) n++;
    return n;
  }

  /** Whether Watch may be offered on `sharerId`'s tile now. */
  canWatch(sharerId: string): boolean {
    const u = sharerId.toLowerCase();
    const e = this.shares.get(u);
    const viewing = this.opts.viewing();
    return !this.ended && !!e && !e.viewer && !!viewing?.ok && this.opts.transport.isScreenCapable()
      && this.inView(u) && this.opts.keys.isEligibleParticipant(u) && this.watchingCount() < WATCH_MAX;
  }

  /** The user chose Watch on the tile (REQ-50). Refused locally beyond `WATCH_MAX`. */
  watch(sharerId: string): boolean {
    const u = sharerId.toLowerCase();
    if (!this.canWatch(u)) return false;
    const e = this.shares.get(u)!;
    const viewing = this.opts.viewing() as { ok: true; optimizeForLatency: boolean };
    const sent = this.opts.transport.screenWatch(this.channelId, u, true);
    if (!sent.handedOff) return false;
    e.cantDisplay = false;
    e.rejected = null;
    e.viewer = new ScreenShareViewer({
      sharerId: u,
      platform: this.opts.platform,
      clock: this.opts.clock,
      optimizeForLatency: viewing.optimizeForLatency,
      hasVideoKey: () => this.opts.keys.hasVideoKey(u),
      sendKeyframeRequest: () => this.opts.transport.screenKeyframeRequest(this.channelId, u).handedOff,
      onCantDisplay: () => {
        const cur = this.shares.get(u);
        if (!cur || cur.viewer !== e.viewer) return;
        this.stopWatching(cur, true);
        cur.cantDisplay = true;
        this.opts.onChange();
      },
      onChange: () => this.opts.onChange(),
    });
    const surface = this.surfaces.get(u);
    if (surface) e.viewer.attachSurface(surface);
    this.opts.onChange();
    return true;
  }

  /** The user stopped watching. */
  unwatch(sharerId: string): void {
    const e = this.shares.get(sharerId.toLowerCase());
    if (!e || !e.viewer) return;
    this.stopWatching(e, true);
    this.opts.onChange();
  }

  /** `screen_watch_rejected` for C (REQ-50): stop without `watch: false`; no retry. */
  onWatchRejected(sharerId: unknown, reason: unknown): void {
    if (this.ended || typeof sharerId !== 'string') return;
    const u = sharerId.toLowerCase();
    const e = this.shares.get(u);
    if (!e || !e.viewer) return;
    this.stopWatching(e, false);
    e.rejected = typeof reason === 'string' && /^[a-z_]{1,32}$/.test(reason) ? reason : 'error';
    if (reason === 'not_sharing') this.shares.delete(u);
    this.opts.onChange();
  }

  /** The tile's canvas mounted or unmounted. */
  attachSurface(sharerId: string, surface: ShareSurface | null): void {
    const u = sharerId.toLowerCase();
    if (surface) this.surfaces.set(u, surface);
    else this.surfaces.delete(u);
    this.shares.get(u)?.viewer?.attachSurface(surface);
  }

  // Hooks from CallKeyManager (§6.2.8).

  isWatching(from: string): boolean {
    return !this.ended && !!this.shares.get(from.toLowerCase())?.viewer;
  }

  takeDecryption(from: string): boolean {
    return this.shares.get(from.toLowerCase())?.viewer?.takeDecryption() ?? false;
  }

  onFragment(from: string, kid: number, plaintext: Uint8Array): void {
    this.shares.get(from.toLowerCase())?.viewer?.onFragment(kid, plaintext);
  }

  onAeadFailures(from: string, consecutive: number): void {
    this.shares.get(from.toLowerCase())?.viewer?.onAeadFailures(consecutive);
  }

  onRemoteReset(from: string, newInstance: boolean): void {
    this.shares.get(from.toLowerCase())?.viewer?.onRemoteReset(newInstance);
  }

  onKeyInstalled(from: string): void {
    this.shares.get(from.toLowerCase())?.viewer?.onKeyInstalled();
  }

  /** The relay no longer offers `screen/1` on this socket: every watch ends; nothing can be sent. */
  stopAllWatches(): void {
    if (this.ended) return;
    let changed = false;
    for (const e of this.shares.values()) {
      if (e.viewer) {
        this.stopWatching(e, false);
        changed = true;
      }
    }
    if (changed) this.opts.onChange();
  }

  /** The call ended: stop every watch (`watch: false` while the socket is open) and forget the list. */
  end(): void {
    if (this.ended) return;
    for (const e of this.shares.values()) if (e.viewer) this.stopWatching(e, true);
    this.shares.clear();
    this.surfaces.clear();
    this.ended = true;
  }

  snapshot(): RemoteShareView[] {
    return [...this.shares.values()].map(e => ({
      sharerId: e.sharerId,
      watching: !!e.viewer,
      viewer: e.viewer ? e.viewer.snapshot() : null,
      cantDisplay: e.cantDisplay,
      rejected: e.rejected,
    }));
  }

  /** The viewer of a watched share (tests). */
  viewerOf(sharerId: string): ScreenShareViewer | null {
    return this.shares.get(sharerId.toLowerCase())?.viewer ?? null;
  }

  private inView(u: string): boolean {
    return this.opts.keys.participants().includes(u);
  }

  private remove(u: string): void {
    const e = this.shares.get(u);
    if (!e) return;
    if (e.viewer) this.stopWatching(e, true);
    this.shares.delete(u);
  }

  private stopWatching(e: ShareEntry, sendFalse: boolean): void {
    const v = e.viewer;
    if (!v) return;
    e.viewer = null;
    v.close();
    if (sendFalse) this.opts.transport.screenWatch(this.channelId, e.sharerId, false);
  }
}

// ---------------------------------------------------------------------------
// The panel's states (§8.4), computed only from local state (REQ-54)
// ---------------------------------------------------------------------------

export type ShareControlState =
  | { readonly row: 1; readonly kind: 'sharing' }
  | { readonly row: 2; readonly kind: 'starting' }
  | { readonly row: 3; readonly kind: 'not_ready' }
  | { readonly row: 4; readonly kind: 'relay_unsupported' }
  | { readonly row: 5; readonly kind: 'app_unsupported'; readonly reason: CaptureUnavailableReason }
  | { readonly row: 6; readonly kind: 'limit'; readonly count: number }
  | { readonly row: 7; readonly kind: 'idle' };

export interface ShareControlInput {
  readonly local: LocalShareState;
  readonly picking: boolean;
  /** The instance's first `voice_channel_joined` was processed. */
  readonly joined: boolean;
  readonly e2eeReady: boolean;
  readonly socketOpen: boolean;
  readonly helloProcessed: boolean;
  readonly relayCapable: boolean;
  /** The capture probe's result, or null while it runs. */
  readonly capture: CaptureProbe | null;
  readonly remoteShares: number;
  readonly maxSharers: number | null;
}

/** The Share Screen control of §8.4: the first matching row. */
export function shareControlState(s: ShareControlInput): ShareControlState {
  if (s.local === 'sharing') return { row: 1, kind: 'sharing' };
  if (s.local === 'starting' || s.picking) return { row: 2, kind: 'starting' };
  if (!s.joined || !s.e2eeReady || !s.socketOpen || !s.helloProcessed || s.capture === null) return { row: 3, kind: 'not_ready' };
  if (!s.relayCapable) return { row: 4, kind: 'relay_unsupported' };
  if (!s.capture.ok) return { row: 5, kind: 'app_unsupported', reason: s.capture.reason };
  if (s.maxSharers !== null && s.remoteShares >= s.maxSharers) return { row: 6, kind: 'limit', count: s.remoteShares };
  return { row: 7, kind: 'idle' };
}

export type ViewerTileState =
  | { readonly row: 1; readonly kind: 'viewing_unavailable'; readonly cause: 'probe' | 'relay' }
  | { readonly row: 2; readonly kind: 'blocked' }
  | { readonly row: 3; readonly kind: 'not_watching' }
  | { readonly row: 4; readonly kind: 'cant_verify' }
  | { readonly row: 5; readonly kind: 'waiting_for_keys'; readonly long: boolean }
  | { readonly row: 6; readonly kind: 'waiting_for_video' }
  | { readonly row: 7; readonly kind: 'no_video'; readonly seconds: number }
  | { readonly row: 8; readonly kind: 'stalled'; readonly seconds: number }
  | { readonly row: 9; readonly kind: 'live' };

export interface ViewerTileInput {
  readonly share: RemoteShareView;
  /** The viewing probe's result, or null while it runs. */
  readonly viewing: ViewingProbe | null;
  readonly relayCapable: boolean;
  readonly eligible: boolean;
  readonly hasKey: boolean;
  readonly now: number;
}

/** A viewer tile of §8.4: the first matching row. */
export function viewerTileState(t: ViewerTileInput): ViewerTileState {
  if (t.viewing && !t.viewing.ok) return { row: 1, kind: 'viewing_unavailable', cause: 'probe' };
  if (!t.relayCapable) return { row: 1, kind: 'viewing_unavailable', cause: 'relay' };
  if (!t.eligible) return { row: 2, kind: 'blocked' };
  const v = t.share.viewer;
  if (!t.share.watching || !v) return { row: 3, kind: 'not_watching' };
  if (t.hasKey && v.aeadFailures >= VIDEO_AEAD_FAIL_NOTICE) return { row: 4, kind: 'cant_verify' };
  if (!t.hasKey) {
    const since = v.keylessSince ?? v.watchStartedAt;
    return { row: 5, kind: 'waiting_for_keys', long: t.now - since >= KEYS_WAIT_NOTICE_MS };
  }
  const ref = Math.max(v.watchStartedAt, v.lastDecodedAt ?? -Infinity);
  const seconds = Math.max(0, Math.floor((t.now - ref) / 1000));
  if (v.state === 'awaiting_keyframe') {
    return t.now - ref < VIDEO_WAIT_NOTICE_MS ? { row: 6, kind: 'waiting_for_video' } : { row: 7, kind: 'no_video', seconds };
  }
  return t.now - ref >= VIDEO_STALL_NOTICE_MS ? { row: 8, kind: 'stalled', seconds } : { row: 9, kind: 'live' };
}

const CAPTURE_REASON_TEXT: Readonly<Record<CaptureUnavailableReason, string>> = Object.freeze({
  no_capture: "this app can't capture the screen",
  no_encoder: 'no VP8 video encoder',
  no_frame_source: 'no way to read video frames',
});

/** §8.4: the status text of the Share Screen control. */
export function shareControlText(s: ShareControlState): string {
  switch (s.kind) {
    case 'sharing':
      return 'Sharing your screen';
    case 'starting':
      return 'Starting screen share…';
    case 'not_ready':
      return 'Connecting…';
    case 'relay_unsupported':
      return "Encrypted screen sharing isn't available on this relay yet.";
    case 'app_unsupported':
      return `Screen sharing isn't available here: ${CAPTURE_REASON_TEXT[s.reason]}`;
    case 'limit':
      return `${s.count} ${s.count === 1 ? 'person is' : 'people are'} already sharing.`;
    case 'idle':
      return 'Share Screen';
  }
}

/** §8.4: the messages after an attempt. `linux` adds the PipeWire note. */
export function screenNoticeText(n: ScreenNotice, linux: boolean): string {
  switch (n.code) {
    case 'cancelled':
      return 'Screen sharing was cancelled.';
    case 'capture_failed':
      return linux
        ? "Couldn't capture your screen. Screen capture needs PipeWire and the desktop portal."
        : "Couldn't capture your screen.";
    case 'rejected_limit': {
      const n2 = n.limit ?? 2;
      return n2 === 2 ? 'Two people are already sharing.' : `${n2} ${n2 === 1 ? 'person is' : 'people are'} already sharing.`;
    }
    case 'relay_didnt_start':
      return "The relay didn't start your screen share.";
    case 'stopped_by_relay':
      return 'Your screen share was stopped by the relay.';
    case 'encoder_failed':
      return 'Screen sharing stopped: the video encoder failed.';
    case 'reconnected':
      return 'Screen sharing stopped because the call reconnected.';
  }
}

/** §8.4: the viewer tile's text for `name`. */
export function viewerTileText(s: ViewerTileState, name: string): string {
  switch (s.kind) {
    case 'viewing_unavailable':
      return s.cause === 'probe'
        ? `${name} is sharing their screen. This app can't display screen shares (no VP8 video decoder).`
        : `${name} is sharing their screen. Encrypted screen sharing isn't available on this relay yet.`;
    case 'blocked':
      return `${name} is sharing their screen. Not a verified member, so the share is blocked.`;
    case 'not_watching':
      return `${name} is sharing their screen`;
    case 'cant_verify':
      return `Video from ${name} can't be verified.`;
    case 'waiting_for_keys':
      return s.long ? "Can't decrypt this screen share yet." : 'Waiting for encryption keys…';
    case 'waiting_for_video':
      return 'Waiting for video…';
    case 'no_video':
      return `No video received from ${name} for ${s.seconds} s.`;
    case 'stalled':
      return `No new video for ${s.seconds} s.`;
    case 'live':
      return '';
  }
}

const WATCH_REJECTED_TEXT: ReadonlyMap<string, string> = new Map([
  ['disabled', 'screen sharing is off on this relay'],
  ['not_participant', 'not in the call'],
  ['rate_limited', 'too many requests'],
  ['not_sharing', 'no longer sharing'],
  ['watch_limit', 'watching too many screens'],
]);

/**
 * The relay's rejection reasons as shown in "Couldn't start watching
 * ([reason])." The reason is relay-supplied: a reason without a text of its
 * own (`constructor` and `__proto__` included) is shown as it is.
 */
export function watchRejectedText(reason: string): string {
  return `Couldn't start watching (${WATCH_REJECTED_TEXT.get(reason) ?? reason}).`;
}
