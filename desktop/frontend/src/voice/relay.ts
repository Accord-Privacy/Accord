/**
 * Relay voice connection — audio routed through the server.
 *
 * Prevents IP address exposure by never establishing direct P2P connections.
 * Audio is captured via getUserMedia, optionally Opus-encoded (WebCodecs),
 * encrypted with AES-256-GCM, buffered through an adaptive jitter buffer,
 * and played via a single shared AudioContext.
 */

import { AccordWebSocket } from '../ws';
import { AudioManager } from './audio';
import { JitterBuffer } from './jitterBuffer';
import {
  generateVoiceKey,
  exportKey,
  importKey,
  encryptVoiceFrame,
  decryptVoiceFrame,
} from './voiceCrypto';

export type SpeakingCallback = (userId: string, speaking: boolean) => void;
export type PeerStateCallback = (userId: string, state: 'connected' | 'disconnected') => void;

/** PCM frame size: 960 samples @ 48kHz = 20ms */
const FRAME_SIZE = 960;
const SAMPLE_RATE = 48000;
const PLAYOUT_INTERVAL_MS = 20;

/** Check if WebCodecs AudioEncoder/AudioDecoder are available. */
function hasWebCodecs(): boolean {
  return typeof AudioEncoder !== 'undefined' && typeof AudioDecoder !== 'undefined';
}

export class RelayVoiceConnection {
  private channelId: string;
  private userId: string;
  private ws: AccordWebSocket;
  private audioManager: AudioManager;
  private localStream: MediaStream | null = null;
  private destroyed = false;
  private isMuted = false;
  private sequence = 0;

  // Capture pipeline
  private captureContext: AudioContext | null = null;
  private scriptProcessor: ScriptProcessorNode | null = null;

  // Opus encoding (WebCodecs)
  private opusEncoder: AudioEncoder | null = null;
  private opusDecoders: Map<string, { decoder: AudioDecoder; resolveQueue: Array<(buf: ArrayBuffer) => void> }> = new Map();
  private useOpus = false;

  // Encryption
  private localKey: CryptoKey | null = null;
  private peerKeys: Map<string, CryptoKey> = new Map(); // fromUserId → their key
  private keyGeneration = 0;

  // Playback pipeline — single shared context, per-user gain via AudioManager
  private playbackContext: AudioContext | null = null;
  private jitterBuffers: Map<string, JitterBuffer> = new Map();
  private playoutTimers: Map<string, ReturnType<typeof setInterval>> = new Map();

  // VAD
  private analyser: AnalyserNode | null = null;
  private vadInterval: ReturnType<typeof setInterval> | null = null;
  private _isSpeaking = false;
  private vadThreshold = 0.015;

  // Callbacks
  onSpeaking: SpeakingCallback | null = null;
  onPeerState: PeerStateCallback | null = null;

  // WS handlers for cleanup
  private wsHandlers: { event: string; handler: (data: any) => void }[] = [];

  constructor(
    ws: AccordWebSocket,
    channelId: string,
    userId: string,
    audioManager: AudioManager,
  ) {
    this.ws = ws;
    this.channelId = channelId;
    this.userId = userId;
    this.audioManager = audioManager;
    this.useOpus = hasWebCodecs();
    this.setupSignaling();
  }

  async connect(): Promise<void> {
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error('Microphone access requires HTTPS or localhost. Voice is not available on plain HTTP.');
    }
    this.localStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
        sampleRate: SAMPLE_RATE,
      },
    });

    // Initialize shared playback context
    this.playbackContext = await this.audioManager.getContext();

    // Generate encryption key
    this.localKey = await generateVoiceKey();

    this.setupCapture();
    this.setupVAD();

    this.ws.joinVoiceChannel(this.channelId);
  }

  disconnect(): void {
    if (this.destroyed) return;
    this.destroyed = true;

    this.ws.leaveVoiceChannel(this.channelId);

    this.stopVAD();
    this.stopCapture();

    // Clean up Opus encoder
    if (this.opusEncoder) {
      try { this.opusEncoder.close(); } catch {}
      this.opusEncoder = null;
    }

    // Clean up playout timers
    this.playoutTimers.forEach((timer) => clearInterval(timer));
    this.playoutTimers.clear();

    // Clean up per-user gain nodes via AudioManager
    this.jitterBuffers.forEach((_, userId) => {
      this.audioManager.removeUser(userId);
    });
    this.jitterBuffers.clear();

    // Clean up Opus decoders
    this.opusDecoders.forEach(({ decoder }) => {
      try { decoder.close(); } catch {}
    });
    this.opusDecoders.clear();

    this.playbackContext = null;

    if (this.localStream) {
      this.localStream.getTracks().forEach(t => t.stop());
      this.localStream = null;
    }

    this.wsHandlers.forEach(({ event, handler }) => {
      this.ws.off(event as any, handler);
    });
    this.wsHandlers = [];
  }

  setMuted(muted: boolean): void {
    this.isMuted = muted;
    if (this.localStream) {
      this.localStream.getAudioTracks().forEach(t => {
        t.enabled = !muted;
      });
    }
    if (muted && this._isSpeaking) {
      this._isSpeaking = false;
      this.onSpeaking?.(this.userId, false);
      this.sendSpeakingState(false);
    }
  }

  setDeafened(deafened: boolean): void {
    this.audioManager.setDeafened(deafened);
    if (deafened) this.setMuted(true);
  }

  get speaking(): boolean {
    return this._isSpeaking;
  }

  // ── Capture: mic → encode → encrypt → WS ──

  private setupCapture(): void {
    if (!this.localStream) return;

    this.captureContext = new AudioContext({ sampleRate: SAMPLE_RATE });
    const source = this.captureContext.createMediaStreamSource(this.localStream);

    if (this.useOpus) {
      this.setupOpusCapture(source);
    } else {
      this.setupPcmCapture(source);
    }
  }

  private setupOpusCapture(source: MediaStreamAudioSourceNode): void {
    if (!this.captureContext) return;

    // Use ScriptProcessorNode to feed AudioEncoder
    this.scriptProcessor = this.captureContext.createScriptProcessor(FRAME_SIZE, 1, 1);

    this.opusEncoder = new AudioEncoder({
      output: (chunk: EncodedAudioChunk) => {
        if (this.isMuted || this.destroyed) return;
        const data = new Uint8Array(chunk.byteLength);
        chunk.copyTo(data);
        this.sendEncryptedPacket(data);
      },
      error: (e: Error) => {
        console.error('Opus encoder error:', e);
        // Fall back to PCM
        this.useOpus = false;
        if (this.opusEncoder) {
          try { this.opusEncoder.close(); } catch {}
          this.opusEncoder = null;
        }
        if (this.captureContext && this.localStream) {
          const src = this.captureContext.createMediaStreamSource(this.localStream);
          this.setupPcmCapture(src);
        }
      },
    });

    this.opusEncoder.configure({
      codec: 'opus',
      sampleRate: SAMPLE_RATE,
      numberOfChannels: 1,
      bitrate: 64000,
    });

    let timestamp = 0;
    this.scriptProcessor.onaudioprocess = (e) => {
      if (this.isMuted || this.destroyed || !this.opusEncoder) return;
      if (this.opusEncoder.state !== 'configured') return;

      const input = e.inputBuffer.getChannelData(0);
      const audioData = new AudioData({
        format: 'f32-planar',
        sampleRate: SAMPLE_RATE,
        numberOfFrames: input.length,
        numberOfChannels: 1,
        timestamp,
        data: input.buffer,
      });
      timestamp += (input.length / SAMPLE_RATE) * 1_000_000; // microseconds

      try {
        this.opusEncoder.encode(audioData);
      } catch {}
      audioData.close();
    };

    source.connect(this.scriptProcessor);
    this.scriptProcessor.connect(this.captureContext.destination);
  }

  private setupPcmCapture(source: MediaStreamAudioSourceNode): void {
    if (!this.captureContext) return;

    this.scriptProcessor = this.captureContext.createScriptProcessor(FRAME_SIZE, 1, 1);
    this.scriptProcessor.onaudioprocess = (e) => {
      if (this.isMuted || this.destroyed) return;

      const input = e.inputBuffer.getChannelData(0);
      // Float32 PCM → Int16
      const int16 = new Int16Array(input.length);
      for (let i = 0; i < input.length; i++) {
        const s = Math.max(-1, Math.min(1, input[i]));
        int16[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
      }
      this.sendEncryptedPacket(new Uint8Array(int16.buffer));
    };

    source.connect(this.scriptProcessor);
    this.scriptProcessor.connect(this.captureContext.destination);
  }

  private async sendEncryptedPacket(payload: Uint8Array): Promise<void> {
    const seq = this.sequence++;

    // Prepend 1-byte codec flag: 0x01 = Opus, 0x00 = raw PCM
    const flagged = new Uint8Array(1 + payload.length);
    flagged[0] = this.useOpus && this.opusEncoder ? 0x01 : 0x00;
    flagged.set(payload, 1);

    if (this.localKey) {
      const encrypted = await encryptVoiceFrame(this.localKey, flagged, seq);
      this.ws.sendVoicePacket(this.channelId, Array.from(encrypted), seq);
    } else {
      this.ws.sendVoicePacket(this.channelId, Array.from(flagged), seq);
    }
  }

  private stopCapture(): void {
    if (this.scriptProcessor) {
      this.scriptProcessor.disconnect();
      this.scriptProcessor = null;
    }
    if (this.captureContext && this.captureContext.state !== 'closed') {
      this.captureContext.close();
      this.captureContext = null;
    }
  }

  // ── Playback: WS → decrypt → decode → jitter buffer → speakers ──

  private async receivePacket(fromUserId: string, audioData: number[], sequence: number): Promise<void> {
    if (this.destroyed) return;

    const raw = new Uint8Array(audioData);

    // Decrypt if we have the peer's key
    let payload: Uint8Array;
    const peerKey = this.peerKeys.get(fromUserId);
    if (peerKey) {
      const decrypted = await decryptVoiceFrame(peerKey, raw);
      if (!decrypted) return; // decryption failed, drop
      payload = decrypted;
    } else {
      // No key yet — try as plaintext (backward compat)
      payload = raw;
    }

    // Parse codec flag
    if (payload.length < 2) return;
    const codec = payload[0]; // 0x00 = PCM, 0x01 = Opus
    const audioPayload = payload.subarray(1);

    // Decode Opus if needed, or pass through PCM
    let pcmBuffer: ArrayBuffer;
    if (codec === 0x01 && this.useOpus) {
      pcmBuffer = await this.decodeOpusPacket(fromUserId, audioPayload);
    } else {
      pcmBuffer = audioPayload.buffer.slice(audioPayload.byteOffset, audioPayload.byteOffset + audioPayload.byteLength) as ArrayBuffer;
    }

    // Push into jitter buffer
    let jb = this.jitterBuffers.get(fromUserId);
    if (!jb) {
      jb = new JitterBuffer();
      this.jitterBuffers.set(fromUserId, jb);
      this.startPlayout(fromUserId);
    }
    jb.push(sequence, pcmBuffer);
  }

  private async decodeOpusPacket(fromUserId: string, encoded: Uint8Array): Promise<ArrayBuffer> {
    let entry = this.opusDecoders.get(fromUserId);
    if (!entry || entry.decoder.state === 'closed') {
      const resolveQueue: Array<(buf: ArrayBuffer) => void> = [];
      const decoder = new AudioDecoder({
        output: (frame: AudioData) => {
          const pcm = new Float32Array(frame.numberOfFrames);
          frame.copyTo(pcm, { planeIndex: 0 });
          frame.close();
          // Float32 → Int16
          const int16 = new Int16Array(pcm.length);
          for (let i = 0; i < pcm.length; i++) {
            const s = Math.max(-1, Math.min(1, pcm[i]));
            int16[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
          }
          const resolve = resolveQueue.shift();
          if (resolve) resolve(int16.buffer);
        },
        error: (e: Error) => {
          console.error('Opus decoder error:', e);
          const resolve = resolveQueue.shift();
          if (resolve) resolve(new ArrayBuffer(0));
        },
      });
      decoder.configure({ codec: 'opus', sampleRate: SAMPLE_RATE, numberOfChannels: 1 });
      entry = { decoder, resolveQueue };
      this.opusDecoders.set(fromUserId, entry);
    }

    return new Promise((resolve) => {
      entry!.resolveQueue.push(resolve);
      const chunk = new EncodedAudioChunk({
        type: 'key',
        timestamp: 0,
        data: encoded,
      });
      try {
        entry!.decoder.decode(chunk);
      } catch {
        // Remove from queue since decode won't fire callback
        const idx = entry!.resolveQueue.indexOf(resolve);
        if (idx >= 0) entry!.resolveQueue.splice(idx, 1);
        resolve(new ArrayBuffer(0));
      }
    });
  }

  private startPlayout(fromUserId: string): void {
    const ctx = this.playbackContext;
    if (!ctx) return;

    // Ensure AudioManager has a gain node for this user
    if (!this.audioManager.hasUser(fromUserId)) {
      this.audioManager.createRelayUserGain(fromUserId);
      this.onPeerState?.(fromUserId, 'connected');
    }

    const timer = setInterval(() => {
      const jb = this.jitterBuffers.get(fromUserId);
      if (!jb || this.destroyed) return;

      const frame = jb.pull();
      if (!frame || frame.byteLength === 0) return;

      this.playPcmFrame(fromUserId, frame);
    }, PLAYOUT_INTERVAL_MS);

    this.playoutTimers.set(fromUserId, timer);
  }

  private playPcmFrame(fromUserId: string, pcmData: ArrayBuffer): void {
    const ctx = this.playbackContext;
    if (!ctx || ctx.state === 'closed') return;

    // Int16 → Float32
    const int16 = new Int16Array(pcmData);
    const float32 = new Float32Array(int16.length);
    for (let i = 0; i < int16.length; i++) {
      float32[i] = int16[i] / (int16[i] < 0 ? 0x8000 : 0x7FFF);
    }

    const buffer = ctx.createBuffer(1, float32.length, SAMPLE_RATE);
    buffer.getChannelData(0).set(float32);

    const source = ctx.createBufferSource();
    source.buffer = buffer;

    const gainNode = this.audioManager.getUserGainNode(fromUserId);
    if (gainNode) {
      source.connect(gainNode);
    } else {
      source.connect(ctx.destination);
    }

    source.start();
  }

  // ── Key Exchange ──

  private async broadcastKey(): Promise<void> {
    if (!this.localKey) return;
    const raw = await exportKey(this.localKey);
    const b64 = btoa(String.fromCharCode(...raw));
    this.ws.sendVoiceKeyExchange(
      this.channelId,
      b64,
      null, // broadcast to all
      0,
      this.keyGeneration,
    );
  }

  private async sendKeyTo(targetUserId: string): Promise<void> {
    if (!this.localKey) return;
    const raw = await exportKey(this.localKey);
    const b64 = btoa(String.fromCharCode(...raw));
    this.ws.sendVoiceKeyExchange(
      this.channelId,
      b64,
      targetUserId,
      0,
      this.keyGeneration,
    );
  }

  private async handleKeyExchange(data: any): Promise<void> {
    if (data.channel_id !== this.channelId) return;
    const fromUserId = data.from;
    if (fromUserId === this.userId) return;

    try {
      const rawStr = atob(data.wrapped_key);
      const raw = new Uint8Array(rawStr.length);
      for (let i = 0; i < rawStr.length; i++) raw[i] = rawStr.charCodeAt(i);
      const key = await importKey(raw);
      this.peerKeys.set(fromUserId, key);
    } catch (e) {
      console.warn('Failed to import peer voice key:', e);
    }
  }

  // ── Signaling ──

  private setupSignaling(): void {
    const onJoined = (data: any) => {
      if (data.channel_id !== this.channelId) return;
      const participants: string[] = data.participants || [];
      for (const pid of participants) {
        if (pid !== this.userId) {
          this.onPeerState?.(pid, 'connected');
        }
      }
      // Broadcast our encryption key to all existing participants
      this.broadcastKey();
    };

    const onPeerJoined = (data: any) => {
      if (data.channel_id !== this.channelId || data.user_id === this.userId) return;
      this.onPeerState?.(data.user_id, 'connected');
      // Send our key to the new peer
      this.sendKeyTo(data.user_id);
    };

    const onPeerLeft = (data: any) => {
      if (data.channel_id !== this.channelId || data.user_id === this.userId) return;
      // Clean up jitter buffer and playout
      const timer = this.playoutTimers.get(data.user_id);
      if (timer) {
        clearInterval(timer);
        this.playoutTimers.delete(data.user_id);
      }
      this.jitterBuffers.delete(data.user_id);
      this.peerKeys.delete(data.user_id);
      // Clean up Opus decoder
      const decEntry = this.opusDecoders.get(data.user_id);
      if (decEntry) {
        try { decEntry.decoder.close(); } catch {}
        this.opusDecoders.delete(data.user_id);
      }
      this.audioManager.removeUser(data.user_id);
      this.onPeerState?.(data.user_id, 'disconnected');
    };

    const onVoicePacket = (data: any) => {
      if (data.channel_id !== this.channelId || data.from === this.userId) return;
      this.receivePacket(data.from, data.encrypted_audio, data.sequence);
    };

    const onKeyExchange = (data: any) => {
      this.handleKeyExchange(data);
    };

    this.addWsListener('voice_channel_joined', onJoined);
    this.addWsListener('voice_peer_joined', onPeerJoined);
    this.addWsListener('voice_peer_left', onPeerLeft);
    this.addWsListener('voice_packet', onVoicePacket);
    this.addWsListener('voice_key_exchange', onKeyExchange);
  }

  private addWsListener(event: string, handler: (data: any) => void): void {
    this.ws.on(event as any, handler);
    this.wsHandlers.push({ event, handler });
  }

  private sendSpeakingState(speaking: boolean): void {
    this.ws.sendVoiceSpeakingState(this.channelId, this.userId, speaking);
  }

  // ── VAD ──

  private setupVAD(): void {
    if (!this.localStream || !this.captureContext) return;

    const source = this.captureContext.createMediaStreamSource(this.localStream);
    this.analyser = this.captureContext.createAnalyser();
    this.analyser.fftSize = 1024;
    this.analyser.smoothingTimeConstant = 0.5;
    source.connect(this.analyser);

    const dataArray = new Uint8Array(this.analyser.frequencyBinCount);

    this.vadInterval = setInterval(() => {
      if (!this.analyser || this.isMuted) {
        if (this._isSpeaking) {
          this._isSpeaking = false;
          this.onSpeaking?.(this.userId, false);
          this.sendSpeakingState(false);
        }
        return;
      }

      this.analyser.getByteFrequencyData(dataArray);
      const avg = dataArray.reduce((a, b) => a + b, 0) / dataArray.length / 255;
      const speaking = avg > this.vadThreshold;

      if (speaking !== this._isSpeaking) {
        this._isSpeaking = speaking;
        this.onSpeaking?.(this.userId, speaking);
        this.sendSpeakingState(speaking);
      }
    }, 50);
  }

  private stopVAD(): void {
    if (this.vadInterval) {
      clearInterval(this.vadInterval);
      this.vadInterval = null;
    }
  }
}
