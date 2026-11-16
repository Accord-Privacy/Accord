/**
 * @module voice/screenShare.testkit
 * The screen fakes of SPEC-03 §10.1 for U and F tests: a fake platform with
 * a capture stream whose frames the test pushes, a synthetic VP8 encoder
 * whose outputs carry valid frame tags and key-frame headers followed by a
 * marker (sender tag, encoder output number, source picture), a recording
 * decoder that checks each chunk's VP8 header, records the marker and
 * outputs frames whose visible rectangle is the key-frame size and whose
 * coded size is padded to a multiple of 16 by default, a drawing surface
 * that records draws, and a controllable animation-frame queue. No real
 * codec is needed. Imported by tests only; nothing in the app imports it.
 */

import type { CallClock } from './callKeyBridge';
import { vp8KeySize, vp8TagOk } from './vp8';
import type { DecodedVideoFrame, VideoDecoderPort, Vp8Chunk, Vp8DecoderConfig } from './screenFrame';
import type {
  CaptureStream,
  CaptureTrack,
  DisplayMediaOptions,
  EncodedChunkPort,
  FrameSourceHandle,
  FrameSourceKind,
  ScreenPlatform,
  ScreenVideoFrame,
  ShareSurface,
  VideoEncoderPort,
  Vp8DecoderProbeConfig,
  Vp8EncoderConfig,
} from './screenShare';

// ---------------------------------------------------------------------------
// Synthetic VP8 (§10.1)
// ---------------------------------------------------------------------------

export interface VideoMarker {
  /** The sender's tag. */
  readonly tag: number;
  /** The encoder's output number. */
  readonly seq: number;
  /** The source picture the frame was encoded from. */
  readonly picture: number;
  readonly key: boolean;
}

/** VP8 frame tag byte 0: show_frame set, version 0, first_part_size 0; bit 0 clear for a key frame. */
const TAG_KEY = 0x10;
const TAG_DELTA = 0x11;
/** Smallest synthetic frames: header plus the 12-byte marker. */
export const VP8_KEY_MIN = 22;
export const VP8_DELTA_MIN = 15;

/** A synthetic VP8 frame of `size` bytes: valid tag (and key-frame header), marker, padding. */
export function syntheticVp8(key: boolean, width: number, height: number, marker: { tag: number; seq: number; picture: number }, size: number): Uint8Array {
  const n = Math.max(size, key ? VP8_KEY_MIN : VP8_DELTA_MIN);
  const b = new Uint8Array(n);
  const v = new DataView(b.buffer);
  let o: number;
  if (key) {
    b.set([TAG_KEY, 0, 0, 0x9d, 0x01, 0x2a, width & 0xff, (width >> 8) & 0x3f, height & 0xff, (height >> 8) & 0x3f]);
    o = 10;
  } else {
    b.set([TAG_DELTA, 0, 0]);
    o = 3;
  }
  v.setUint32(o, marker.tag >>> 0);
  v.setUint32(o + 4, marker.seq >>> 0);
  v.setUint32(o + 8, marker.picture >>> 0);
  for (let i = o + 12; i < n; i++) b[i] = (i * 31 + marker.seq) & 0xff;
  return b;
}

/** The marker of a synthetic frame, or null if it is not one. */
export function readMarker(data: Uint8Array): VideoMarker | null {
  if (data.length < 3) return null;
  const key = (data[0] & 1) === 0;
  const o = key ? 10 : 3;
  if (data.length < o + 12) return null;
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return { tag: v.getUint32(o), seq: v.getUint32(o + 4), picture: v.getUint32(o + 8), key };
}

// ---------------------------------------------------------------------------
// Frames, tracks and the capture stream
// ---------------------------------------------------------------------------

/** Every fake video frame still open, to check that each one is closed (REQ-27). */
export class FrameRegistry {
  readonly open = new Set<FakeScreenFrame>();
  created = 0;
}

export class FakeScreenFrame implements ScreenVideoFrame {
  closed = false;
  constructor(
    private readonly registry: FrameRegistry,
    readonly displayWidth: number,
    readonly displayHeight: number,
    readonly timestamp: number,
    readonly picture: number,
  ) {
    registry.open.add(this);
    registry.created++;
  }

  clone(): FakeScreenFrame {
    if (this.closed) throw new Error('clone of a closed frame');
    return new FakeScreenFrame(this.registry, this.displayWidth, this.displayHeight, this.timestamp, this.picture);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.registry.open.delete(this);
  }
}

export class FakeTrack implements CaptureTrack {
  contentHint = '';
  stopped = false;
  /** Times anything read this track (an audio track must never be read, REQ-43). */
  reads = 0;
  private readonly endedListeners = new Set<() => void>();

  constructor(readonly kind: 'video' | 'audio') {}

  stop(): void {
    this.stopped = true;
  }

  addEventListener(_type: 'ended', listener: () => void): void {
    this.endedListeners.add(listener);
  }

  removeEventListener(_type: 'ended', listener: () => void): void {
    this.endedListeners.delete(listener);
  }

  /** The platform's own stop control. */
  end(): void {
    this.stopped = true;
    for (const l of [...this.endedListeners]) l();
  }
}

export class FakeStream implements CaptureStream {
  constructor(readonly tracks: FakeTrack[]) {}

  getTracks(): FakeTrack[] {
    return [...this.tracks];
  }

  getVideoTracks(): FakeTrack[] {
    return this.tracks.filter(t => t.kind === 'video');
  }

  getAudioTracks(): FakeTrack[] {
    return this.tracks.filter(t => t.kind === 'audio');
  }

  get allStopped(): boolean {
    return this.tracks.every(t => t.stopped);
  }
}

/** A frame source whose frames the test pushes (a captured screen). */
export class FakeFrameSource implements FrameSourceHandle {
  closed = false;
  private picture = 0;
  private ts = 0;

  constructor(
    readonly kind: FrameSourceKind,
    readonly track: CaptureTrack,
    private readonly registry: FrameRegistry,
    private readonly onFrame: (frame: ScreenVideoFrame) => void,
    private readonly clock: CallClock,
    private readonly onError: (error: unknown) => void = () => undefined,
  ) {}

  /** Deliver one source frame of `width` × `height`; returns it. */
  push(width = 1280, height = 720, picture?: number): FakeScreenFrame {
    this.picture = picture ?? this.picture + 1;
    this.ts = Math.max(this.ts + 1, Math.round(this.clock.now() * 1000));
    const f = new FakeScreenFrame(this.registry, width, height, this.ts, this.picture);
    if (this.closed) {
      f.close();
      return f;
    }
    this.onFrame(f);
    return f;
  }

  close(): void {
    this.closed = true;
  }

  /** The source fails while open (a rejected read of Source A): it delivers nothing more. */
  fail(): void {
    if (this.closed) return;
    this.closed = true;
    this.onError(new Error('frame source failed'));
  }
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

export interface EncodeInput {
  readonly picture: number;
  readonly keyFrame: boolean;
  readonly width: number;
  readonly height: number;
  readonly timestamp: number;
  readonly at: number;
}

export interface EncodedOutputRecord {
  readonly key: boolean;
  readonly size: number;
  readonly at: number;
}

export class FakeEncoder implements VideoEncoderPort {
  state = 'unconfigured';
  readonly configs: Vp8EncoderConfig[] = [];
  /** When each configuration was applied (the platform clock), in the order of `configs`. */
  readonly configuredAt: number[] = [];
  readonly inputs: EncodeInput[] = [];
  readonly outputs: EncodedOutputRecord[] = [];
  /** Keep outputs until `release()`. */
  hold = false;
  /** Report this `encodeQueueSize` instead of the outputs still pending. */
  forcedQueueSize: number | null = null;
  private pending: Array<() => void> = [];
  private seq = 0;
  private needKey = true;

  constructor(
    private readonly platform: FakeScreenPlatform,
    private readonly output: (chunk: EncodedChunkPort) => void,
    private readonly error: (e: unknown) => void,
  ) {}

  get encodeQueueSize(): number {
    return this.forcedQueueSize ?? this.pending.length;
  }

  configure(config: Vp8EncoderConfig): void {
    if (this.state === 'closed') throw new Error('closed');
    this.configs.push(config);
    this.configuredAt.push(this.platform.clock?.now() ?? 0);
    this.state = 'configured';
    this.needKey = true;
  }

  encode(frame: ScreenVideoFrame, options: { keyFrame: boolean }): void {
    if (this.state !== 'configured') throw new Error('encode before configure');
    const f = frame as FakeScreenFrame;
    if (f.closed) throw new Error('encode of a closed frame');
    const cfg = this.configs[this.configs.length - 1];
    if (f.displayWidth !== cfg.width || f.displayHeight !== cfg.height) throw new Error('frame size differs from the configured size');
    const key = options.keyFrame || this.needKey;
    this.needKey = false;
    const input: EncodeInput = { picture: f.picture, keyFrame: options.keyFrame, width: f.displayWidth, height: f.displayHeight, timestamp: f.timestamp, at: this.platform.clock?.now() ?? 0 };
    this.inputs.push(input);
    const seq = ++this.seq;
    const size = this.platform.outputSize({ key, seq, input });
    const type = key ? 'key' : 'delta';
    const emit = () => {
      if (this.state === 'closed') return;
      this.outputs.push({ key: type === 'key', size, at: this.platform.clock?.now() ?? 0 });
      const data = size <= 4_000_000 ? syntheticVp8(type === 'key', cfg.width, cfg.height, { tag: this.platform.tag, seq, picture: f.picture }, size) : null;
      const chunk: EncodedChunkPort = {
        type,
        byteLength: size,
        copyTo: dest => {
          if (data) dest.set(data);
        },
      };
      this.output(chunk);
    };
    if (this.hold) this.pending.push(emit);
    else {
      this.pending.push(emit);
      queueMicrotask(() => {
        const i = this.pending.indexOf(emit);
        if (i >= 0) {
          this.pending.splice(i, 1);
          emit();
        }
      });
    }
  }

  /** Deliver held outputs (all, or the first `n`). */
  release(n = Infinity): void {
    const out = this.pending.splice(0, Math.min(n, this.pending.length));
    for (const e of out) e();
  }

  /** The encoder reports an error. */
  fail(): void {
    this.error(new Error('encoder error'));
  }

  close(): void {
    this.state = 'closed';
    this.pending = [];
  }
}

// ---------------------------------------------------------------------------
// Decoder, frames and surface
// ---------------------------------------------------------------------------

export class FakeDecodedFrame implements DecodedVideoFrame {
  closed = false;
  constructor(
    private readonly registry: Set<FakeDecodedFrame>,
    readonly codedWidth: number,
    readonly codedHeight: number,
    readonly visibleRect: { readonly x: number; readonly y: number; readonly width: number; readonly height: number },
    readonly marker: VideoMarker | null,
  ) {
    registry.add(this);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.registry.delete(this);
  }
}

/** How the recording decoder sizes its outputs: padded to 16 (default), unpadded, or a chosen coded size. */
export type DecoderPadding = 'pad16' | 'none' | { readonly coded: readonly [number, number] };

export class RecordingDecoder implements VideoDecoderPort {
  state = 'unconfigured';
  config: Vp8DecoderConfig | null = null;
  readonly chunks: Vp8Chunk[] = [];
  readonly markers: VideoMarker[] = [];
  /** Report this `decodeQueueSize` instead of the outputs still pending. */
  forcedQueueSize: number | null = null;
  /** Keep outputs until `flush()`. */
  hold = false;
  private pending: Vp8Chunk[] = [];

  constructor(
    private readonly platform: FakeScreenPlatform,
    private readonly output: (frame: DecodedVideoFrame) => void,
    private readonly error: (e: unknown) => void,
  ) {}

  get decodeQueueSize(): number {
    return this.forcedQueueSize ?? this.pending.length;
  }

  configure(config: Vp8DecoderConfig): void {
    if (this.state === 'closed') throw new Error('closed');
    this.config = config;
    this.state = 'configured';
    this.platform.decoderSetups.push({ ...config, at: this.platform.clock?.now() ?? 0 });
  }

  decode(chunk: Vp8Chunk): void {
    if (this.state !== 'configured') throw new Error('decode before configure');
    this.platform.decodeQueueOnEntry.push(this.decodeQueueSize);
    const key = chunk.type === 'key';
    if (!vp8TagOk(chunk.data, key) || (key && !vp8KeySize(chunk.data))) {
      queueMicrotask(() => this.error(new Error('bad VP8')));
      return;
    }
    this.chunks.push(chunk);
    const m = readMarker(chunk.data);
    if (m) {
      this.markers.push(m);
      this.platform.decodedMarkers.push(m);
    }
    this.platform.decodedAt.push({ key, at: this.platform.clock?.now() ?? 0 });
    this.pending.push(chunk);
    if (!this.hold) queueMicrotask(() => this.flush());
  }

  /** Output every chunk decoded so far. */
  flush(): void {
    const p = this.pending;
    this.pending = [];
    for (const chunk of p) {
      if (this.state === 'closed') return;
      const w = this.config!.codedWidth;
      const h = this.config!.codedHeight;
      const pad = this.platform.padding;
      const coded: readonly [number, number] = pad === 'pad16' ? [Math.ceil(w / 16) * 16, Math.ceil(h / 16) * 16] : pad === 'none' ? [w, h] : pad.coded;
      const visible = this.platform.visibleOverride ?? { width: w, height: h };
      this.output(new FakeDecodedFrame(this.platform.decodedFrames, coded[0], coded[1], { x: 0, y: 0, ...visible }, readMarker(chunk.data)));
    }
  }

  fail(): void {
    this.error(new Error('decoder error'));
  }

  close(): void {
    this.state = 'closed';
    this.pending = [];
  }
}

export interface DrawRecord {
  readonly marker: VideoMarker | null;
  readonly width: number;
  readonly height: number;
  readonly codedWidth: number;
  readonly codedHeight: number;
}

/** A tile canvas that records what is drawn and when it is cleared. */
export class FakeSurface implements ShareSurface {
  readonly draws: DrawRecord[] = [];
  clears = 0;

  draw(frame: DecodedVideoFrame, width: number, height: number): void {
    const f = frame as FakeDecodedFrame;
    if (f.closed) throw new Error('draw of a closed frame');
    this.draws.push({ marker: f.marker, width, height, codedWidth: f.codedWidth, codedHeight: f.codedHeight });
  }

  clear(): void {
    this.clears++;
  }
}

// ---------------------------------------------------------------------------
// The platform
// ---------------------------------------------------------------------------

export interface CaptureBehaviour {
  /** Reject with an error of this name. */
  readonly error?: string;
  /** Add an audio track. */
  readonly audio?: boolean;
  /** No video track at all. */
  readonly noVideo?: boolean;
  /** Resolve only when `resolveCapture()` is called. */
  readonly manual?: boolean;
}

export class FakeScreenPlatform implements ScreenPlatform {
  /** The shell's `display_capture_supported`; null in the web client. */
  shell: boolean | null = null;
  displayMedia = true;
  encoder: 'ok' | 'missing' = 'ok';
  encoderSupport = { A: true, B: true };
  processor = true;
  videoFrame = true;
  /** `openFrameSource` throws (a `MediaStreamTrackProcessor` that cannot be built). */
  sourceThrows = false;
  /** Decide `isConfigSupported` for one configuration (later, with a promise); null leaves it to `encoderSupport`. */
  configSupport: ((config: Vp8EncoderConfig) => boolean | Promise<boolean>) | null = null;
  decoder: 'ok' | 'missing' | 'unsupported' | 'rejects_option' = 'ok';
  canvas = true;
  autoAnimationFrames = true;
  padding: DecoderPadding = 'pad16';
  visibleOverride: { width: number; height: number } | null = null;
  /** The encoder's output sizes. */
  outputSize: (o: { key: boolean; seq: number; input: EncodeInput }) => number = o => (o.key ? 4000 : 600);
  /** The sender tag in every marker. */
  tag: number;
  clock: CallClock | null = null;

  capture: CaptureBehaviour = {};
  readonly displayMediaCalls: DisplayMediaOptions[] = [];
  readonly streams: FakeStream[] = [];
  readonly encoderConfigsAsked: Vp8EncoderConfig[] = [];
  readonly decoderConfigsAsked: Vp8DecoderProbeConfig[] = [];
  readonly encoders: FakeEncoder[] = [];
  readonly decoders: RecordingDecoder[] = [];
  readonly decoderSetups: Array<Vp8DecoderConfig & { at: number }> = [];
  readonly decodedMarkers: VideoMarker[] = [];
  readonly decodedAt: Array<{ key: boolean; at: number }> = [];
  /** `decodeQueueSize` at each `decode()` call, before the chunk is queued (REQ-49: never above 4). */
  readonly decodeQueueOnEntry: number[] = [];
  /** New decoders keep their outputs until `flush()` (a slow decoder). */
  decoderHold = false;
  readonly decodedFrames = new Set<FakeDecodedFrame>();
  readonly sources: FakeFrameSource[] = [];
  readonly frames = new FrameRegistry();
  readonly scaled: Array<{ from: [number, number]; to: [number, number] }> = [];
  readonly raf: Array<() => void> = [];
  shellCalls = 0;
  private resolvers: Array<() => void> = [];

  constructor(tag = 1) {
    this.tag = tag;
  }

  shellDisplayCapture(): Promise<boolean> | null {
    if (this.shell === null) return null;
    this.shellCalls++;
    return Promise.resolve(this.shell);
  }

  hasGetDisplayMedia(): boolean {
    return this.displayMedia;
  }

  getDisplayMedia(options: DisplayMediaOptions): Promise<CaptureStream> {
    this.displayMediaCalls.push(options);
    const c = this.capture;
    if (c.error) {
      const e = new Error(c.error);
      e.name = c.error;
      return Promise.reject(e);
    }
    const tracks = [...(c.noVideo ? [] : [new FakeTrack('video')]), ...(c.audio ? [new FakeTrack('audio')] : [])];
    const stream = new FakeStream(tracks);
    this.streams.push(stream);
    if (c.manual) return new Promise(resolve => this.resolvers.push(() => resolve(stream)));
    return Promise.resolve(stream);
  }

  /** Resolve a manual capture (the user picked a surface). */
  resolveCapture(): void {
    for (const r of this.resolvers.splice(0)) r();
  }

  hasVideoEncoder(): boolean {
    return this.encoder === 'ok';
  }

  encoderConfigSupported(config: Vp8EncoderConfig): Promise<boolean> {
    this.encoderConfigsAsked.push(config);
    if (this.configSupport) return Promise.resolve(this.configSupport(config));
    return Promise.resolve(config.latencyMode === 'realtime' ? this.encoderSupport.A : this.encoderSupport.B);
  }

  createEncoder(output: (chunk: EncodedChunkPort) => void, error: (e: unknown) => void): VideoEncoderPort {
    const e = new FakeEncoder(this, output, error);
    this.encoders.push(e);
    return e;
  }

  hasTrackProcessor(): boolean {
    return this.processor;
  }

  hasVideoFrame(): boolean {
    return this.videoFrame;
  }

  createPreview(): HTMLVideoElement | null {
    return null;
  }

  openFrameSource(
    kind: FrameSourceKind,
    track: CaptureTrack,
    _preview: HTMLVideoElement | null,
    onFrame: (frame: ScreenVideoFrame) => void,
    clock: CallClock,
    onError: (error: unknown) => void,
  ): FrameSourceHandle {
    if (this.sourceThrows) throw new TypeError('MediaStreamTrackProcessor failed');
    if (track instanceof FakeTrack) track.reads++;
    const s = new FakeFrameSource(kind, track, this.frames, onFrame, clock, onError);
    this.sources.push(s);
    return s;
  }

  scaleFrame(frame: ScreenVideoFrame, width: number, height: number): ScreenVideoFrame {
    const f = frame as FakeScreenFrame;
    if (f.closed) throw new Error('scale of a closed frame');
    this.scaled.push({ from: [f.displayWidth, f.displayHeight], to: [width, height] });
    return new FakeScreenFrame(this.frames, width, height, f.timestamp, f.picture);
  }

  retimeFrame(frame: ScreenVideoFrame, timestampUs: number): ScreenVideoFrame {
    const f = frame as FakeScreenFrame;
    if (f.closed) throw new Error('retime of a closed frame');
    return new FakeScreenFrame(this.frames, f.displayWidth, f.displayHeight, timestampUs, f.picture);
  }

  hasVideoDecoder(): boolean {
    return this.decoder !== 'missing';
  }

  decoderConfigSupported(config: Vp8DecoderProbeConfig): Promise<boolean> {
    this.decoderConfigsAsked.push(config);
    if (this.decoder === 'rejects_option' && config.optimizeForLatency !== undefined) return Promise.reject(new TypeError('unknown member'));
    return Promise.resolve(this.decoder !== 'unsupported');
  }

  createDecoder(output: (frame: DecodedVideoFrame) => void, error: (e: unknown) => void): VideoDecoderPort {
    const d = new RecordingDecoder(this, output, error);
    d.hold = this.decoderHold;
    this.decoders.push(d);
    return d;
  }

  canDraw2d(): boolean {
    return this.canvas;
  }

  requestAnimationFrame(callback: () => void): void {
    if (this.autoAnimationFrames) queueMicrotask(callback);
    else this.raf.push(callback);
  }

  /** Run the queued animation-frame callbacks. */
  runAnimationFrames(): void {
    for (const cb of this.raf.splice(0)) cb();
  }

  /** The newest frame source. */
  get source(): FakeFrameSource {
    const s = this.sources[this.sources.length - 1];
    if (!s) throw new Error('no frame source');
    return s;
  }

  /** The newest encoder. */
  get enc(): FakeEncoder {
    const e = this.encoders[this.encoders.length - 1];
    if (!e) throw new Error('no encoder');
    return e;
  }

  /** The newest stream. */
  get stream(): FakeStream {
    const s = this.streams[this.streams.length - 1];
    if (!s) throw new Error('no stream');
    return s;
  }
}
