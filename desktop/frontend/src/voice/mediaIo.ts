/**
 * @module voice/mediaIo
 * The media input and output of a relay-mode voice connection (SPEC-03
 * §11.1: "the constructor takes ... injectable media input and output").
 *
 * - `VoiceMediaInput` captures the microphone and hands the call one
 *   plaintext per frame, `codec ‖ payload` (§6.2.1): codec 0x01 for an Opus
 *   packet (WebCodecs, 48 kHz, mono) or 0x00 for signed 16-bit little-endian
 *   PCM at 48 kHz, mono. It never encrypts or sends anything itself: the
 *   connection seals each frame under the current epoch key (REQ-2) or
 *   discards it.
 * - `VoiceMediaOutput` plays decoded PCM and offers an Opus decoder where the
 *   platform has one. It only ever receives audio that authenticated (REQ-3).
 *
 * `MicrophoneCapture` and `WebAudioPlayback` are the browser implementations;
 * tests inject their own (SPEC-03 §10.1). Captured and decoded audio lives
 * in memory only and is never logged (REQ-27).
 */

import type { AudioManager } from './audio';

/** 48 kHz, the sample rate of both codecs (§6.2.1). */
export const SAMPLE_RATE = 48_000;
/** Codec byte of an Opus packet (§6.2.1). */
export const CODEC_OPUS = 0x01;
/** Codec byte of signed 16-bit little-endian PCM (§6.2.1). */
export const CODEC_PCM = 0x00;

// ScriptProcessorNode requires a power-of-two buffer (256 to 16384); 1024
// samples is about 21.3 ms at 48 kHz.
const CAPTURE_BUFFER_SIZE = 1024;
const VAD_INTERVAL_MS = 50;
const VAD_THRESHOLD = 0.015;

/** Where a capture delivers its frames and its local speaking detection. */
export interface CaptureSink {
  /** One frame's plaintext, `codec ‖ payload`. */
  frame(plaintext: Uint8Array): void;
  /** The local voice-activity detector changed its mind. */
  speaking(speaking: boolean): void;
}

export interface VoiceMediaInput {
  /**
   * Acquire the microphone and start delivering frames to `sink`. The mute
   * state is applied before the first frame (SPEC-03 REQ-5). Resolves false
   * when no microphone is available (the call is then listen-only) or when
   * `stop()` was called meanwhile.
   */
  start(muted: boolean, sink: CaptureSink): Promise<boolean>;
  setMuted(muted: boolean): void;
  /** Stop capturing and release the microphone; also cancels a pending start. Idempotent. */
  stop(): void;
}

/** An audio decoder; outputs come back through the callbacks given at creation, in input order. */
export interface AudioDecoderPort {
  decode(data: Uint8Array, timestampUs: number): void;
  close(): void;
}

export interface VoiceMediaOutput {
  /** Prepare playback. Resolves false when no audio output is available. */
  open(): Promise<boolean>;
  /**
   * An Opus decoder, or null where the platform cannot decode Opus (no
   * WebCodecs). Frames the receiver cannot decode are discarded, never
   * played as PCM (REQ-3).
   */
  createOpusDecoder(onPcm: (pcm: Int16Array) => void, onError: () => void): AudioDecoderPort | null;
  /** Play one decoded frame of `userId` now. */
  play(userId: string, pcm: Int16Array): void;
  removeUser(userId: string): void;
  setDeafened(deafened: boolean): void;
  close(): void;
}

function hasOpusEncoder(): boolean {
  return typeof AudioEncoder !== 'undefined' && typeof AudioData !== 'undefined';
}

function floatToInt16(input: Float32Array): Int16Array {
  const out = new Int16Array(input.length);
  for (let i = 0; i < input.length; i++) {
    const s = Math.max(-1, Math.min(1, input[i]));
    out[i] = s < 0 ? s * 0x8000 : s * 0x7fff;
  }
  return out;
}

/** `codec ‖ payload` for PCM: signed 16-bit little-endian samples. */
function pcmFrame(samples: Int16Array): Uint8Array {
  const out = new Uint8Array(1 + samples.length * 2);
  out[0] = CODEC_PCM;
  const view = new DataView(out.buffer);
  for (let i = 0; i < samples.length; i++) view.setInt16(1 + 2 * i, samples[i], true);
  return out;
}

/**
 * The microphone through Web Audio: Opus through WebCodecs where available,
 * PCM otherwise, plus a simple voice-activity detector for the speaking flag.
 */
export class MicrophoneCapture implements VoiceMediaInput {
  private generation = 0;
  private muted = true;
  private sink: CaptureSink | null = null;
  private stream: MediaStream | null = null;
  private context: AudioContext | null = null;
  private processor: ScriptProcessorNode | null = null;
  private encoder: AudioEncoder | null = null;
  private analyser: AnalyserNode | null = null;
  private vadTimer: ReturnType<typeof setInterval> | null = null;
  private speaking = false;

  async start(muted: boolean, sink: CaptureSink): Promise<boolean> {
    this.stop();
    const gen = this.generation;
    this.muted = muted;
    let stream: MediaStream;
    try {
      if (!navigator.mediaDevices?.getUserMedia) return false;
      stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true, sampleRate: SAMPLE_RATE },
      });
    } catch {
      return false;
    }
    if (gen !== this.generation) {
      stream.getTracks().forEach(t => t.stop());
      return false;
    }
    this.stream = stream;
    this.sink = sink;
    // REQ-5: the mute state is applied before anything is captured.
    stream.getAudioTracks().forEach(t => {
      t.enabled = !this.muted;
    });
    try {
      this.setupPipeline(gen);
    } catch {
      this.stop();
      return false;
    }
    return true;
  }

  setMuted(muted: boolean): void {
    this.muted = muted;
    this.stream?.getAudioTracks().forEach(t => {
      t.enabled = !muted;
    });
    if (muted) this.setSpeaking(false);
  }

  stop(): void {
    this.generation++;
    if (this.vadTimer) clearInterval(this.vadTimer);
    this.vadTimer = null;
    this.analyser = null;
    if (this.processor) {
      this.processor.onaudioprocess = null;
      try {
        this.processor.disconnect();
      } catch { /* already disconnected */ }
    }
    this.processor = null;
    if (this.encoder) {
      try {
        if (this.encoder.state !== 'closed') this.encoder.close();
      } catch { /* already closed */ }
    }
    this.encoder = null;
    if (this.context && this.context.state !== 'closed') this.context.close().catch(() => undefined);
    this.context = null;
    this.stream?.getTracks().forEach(t => t.stop());
    this.stream = null;
    this.sink = null;
    this.speaking = false;
  }

  private emit(gen: number, plaintext: Uint8Array): void {
    if (gen !== this.generation || this.muted) return;
    this.sink?.frame(plaintext);
  }

  private setSpeaking(speaking: boolean): void {
    if (speaking === this.speaking) return;
    this.speaking = speaking;
    this.sink?.speaking(speaking);
  }

  private setupPipeline(gen: number): void {
    const stream = this.stream!;
    const context = new AudioContext({ sampleRate: SAMPLE_RATE });
    this.context = context;
    const source = context.createMediaStreamSource(stream);
    const processor = context.createScriptProcessor(CAPTURE_BUFFER_SIZE, 1, 1);
    this.processor = processor;

    if (hasOpusEncoder()) {
      try {
        const encoder = new AudioEncoder({
          output: (chunk: EncodedAudioChunk) => {
            const data = new Uint8Array(1 + chunk.byteLength);
            data[0] = CODEC_OPUS;
            chunk.copyTo(data.subarray(1));
            this.emit(gen, data);
          },
          error: () => {
            // No fallback codec is negotiated; the frame codec byte tells the
            // receiver which of the two defined codecs a frame carries.
            if (gen !== this.generation) return;
            try {
              if (this.encoder && this.encoder.state !== 'closed') this.encoder.close();
            } catch { /* already closed */ }
            this.encoder = null;
          },
        });
        encoder.configure({ codec: 'opus', sampleRate: SAMPLE_RATE, numberOfChannels: 1, bitrate: 64_000 });
        this.encoder = encoder;
      } catch {
        this.encoder = null;
      }
    }

    let timestamp = 0;
    processor.onaudioprocess = e => {
      if (gen !== this.generation || this.muted) return;
      const input = e.inputBuffer.getChannelData(0);
      const encoder = this.encoder;
      if (encoder && encoder.state === 'configured') {
        const audio = new AudioData({
          format: 'f32-planar',
          sampleRate: SAMPLE_RATE,
          numberOfFrames: input.length,
          numberOfChannels: 1,
          timestamp,
          data: Float32Array.from(input),
        });
        timestamp += (input.length / SAMPLE_RATE) * 1_000_000;
        try {
          encoder.encode(audio);
        } catch { /* the frame is dropped */ }
        audio.close();
        return;
      }
      this.emit(gen, pcmFrame(floatToInt16(input)));
    };
    source.connect(processor);
    processor.connect(context.destination);

    const analyser = context.createAnalyser();
    analyser.fftSize = 1024;
    analyser.smoothingTimeConstant = 0.5;
    source.connect(analyser);
    this.analyser = analyser;
    const bins = new Uint8Array(analyser.frequencyBinCount);
    this.vadTimer = setInterval(() => {
      if (gen !== this.generation || !this.analyser) return;
      if (this.muted) {
        this.setSpeaking(false);
        return;
      }
      this.analyser.getByteFrequencyData(bins);
      const level = bins.reduce((a, b) => a + b, 0) / bins.length / 255;
      this.setSpeaking(level > VAD_THRESHOLD);
    }, VAD_INTERVAL_MS);
  }
}

/** Playback through the shared Web Audio context of an `AudioManager`. */
export class WebAudioPlayback implements VoiceMediaOutput {
  private readonly audio: AudioManager;
  private context: AudioContext | null = null;

  constructor(audio: AudioManager) {
    this.audio = audio;
  }

  async open(): Promise<boolean> {
    try {
      this.context = await this.audio.getContext();
      return true;
    } catch {
      this.context = null;
      return false;
    }
  }

  createOpusDecoder(onPcm: (pcm: Int16Array) => void, onError: () => void): AudioDecoderPort | null {
    if (typeof AudioDecoder === 'undefined' || typeof EncodedAudioChunk === 'undefined') return null;
    let decoder: AudioDecoder;
    try {
      decoder = new AudioDecoder({
        output: (frame: AudioData) => {
          const samples = new Float32Array(frame.numberOfFrames);
          try {
            frame.copyTo(samples, { planeIndex: 0, format: 'f32-planar' });
          } catch {
            frame.close();
            onError();
            return;
          }
          frame.close();
          onPcm(floatToInt16(samples));
        },
        error: () => onError(),
      });
      decoder.configure({ codec: 'opus', sampleRate: SAMPLE_RATE, numberOfChannels: 1 });
    } catch {
      return null;
    }
    return {
      decode(data: Uint8Array, timestampUs: number): void {
        decoder.decode(new EncodedAudioChunk({ type: 'key', timestamp: timestampUs, data }));
      },
      close(): void {
        try {
          if (decoder.state !== 'closed') decoder.close();
        } catch { /* already closed */ }
      },
    };
  }

  play(userId: string, pcm: Int16Array): void {
    const ctx = this.context;
    if (!ctx || ctx.state === 'closed' || pcm.length === 0) return;
    const gain = this.audio.getUserGainNode(userId) ?? this.audio.createRelayUserGain(userId);
    if (!gain) return;
    const samples = new Float32Array(pcm.length);
    for (let i = 0; i < pcm.length; i++) samples[i] = pcm[i] / (pcm[i] < 0 ? 0x8000 : 0x7fff);
    const buffer = ctx.createBuffer(1, samples.length, SAMPLE_RATE);
    buffer.getChannelData(0).set(samples);
    const source = ctx.createBufferSource();
    source.buffer = buffer;
    source.connect(gain);
    source.start();
  }

  removeUser(userId: string): void {
    this.audio.removeUser(userId);
  }

  setDeafened(deafened: boolean): void {
    this.audio.setDeafened(deafened);
  }

  close(): void {
    this.context = null;
  }
}
