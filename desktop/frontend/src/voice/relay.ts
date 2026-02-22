/**
 * Relay voice connection — audio routed through the server.
 * 
 * Prevents IP address exposure by never establishing direct P2P connections.
 * Audio is captured via getUserMedia, encoded to PCM chunks via AudioWorklet/ScriptProcessor,
 * and sent as JSON-wrapped VoicePacket messages through the WebSocket.
 * Incoming audio packets are decoded and played via AudioContext.
 */

import { AccordWebSocket } from '../ws';
import { AudioManager } from './audio';

export type SpeakingCallback = (userId: string, speaking: boolean) => void;
export type PeerStateCallback = (userId: string, state: 'connected' | 'disconnected') => void;

/** PCM frame size: 960 samples @ 48kHz = 20ms (Opus frame size) */
const FRAME_SIZE = 960;
const SAMPLE_RATE = 48000;

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

  // Playback pipeline - per user
  private playbackContexts: Map<string, {
    ctx: AudioContext;
    nextPlayTime: number;
  }> = new Map();

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

    this.setMuted(true);
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

    // Clean up playback contexts
    this.playbackContexts.forEach(({ ctx }) => {
      if (ctx.state !== 'closed') ctx.close();
    });
    this.playbackContexts.clear();

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

  // ── Capture: mic → PCM → WS ──

  private setupCapture(): void {
    if (!this.localStream) return;

    this.captureContext = new AudioContext({ sampleRate: SAMPLE_RATE });
    const source = this.captureContext.createMediaStreamSource(this.localStream);

    // Use ScriptProcessorNode (deprecated but widely supported; AudioWorklet needs separate file)
    this.scriptProcessor = this.captureContext.createScriptProcessor(FRAME_SIZE, 1, 1);
    this.scriptProcessor.onaudioprocess = (e) => {
      if (this.isMuted || this.destroyed) return;

      const input = e.inputBuffer.getChannelData(0);
      // Convert Float32 PCM to Int16 for compact transmission
      const int16 = new Int16Array(input.length);
      for (let i = 0; i < input.length; i++) {
        const s = Math.max(-1, Math.min(1, input[i]));
        int16[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
      }

      // Send as base64-encoded VoicePacket
      const bytes = new Uint8Array(int16.buffer);

      this.ws.sendVoicePacket(this.channelId, Array.from(bytes), this.sequence++);
    };

    source.connect(this.scriptProcessor);
    this.scriptProcessor.connect(this.captureContext.destination); // needed for processing to run
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

  // ── Playback: WS → PCM → speakers ──

  private async playAudioPacket(fromUserId: string, audioData: number[], _sequence: number): Promise<void> {
    if (this.destroyed) return;

    let entry = this.playbackContexts.get(fromUserId);
    if (!entry) {
      const ctx = new AudioContext({ sampleRate: SAMPLE_RATE });
      entry = { ctx, nextPlayTime: ctx.currentTime };
      this.playbackContexts.set(fromUserId, entry);
      this.onPeerState?.(fromUserId, 'connected');
    }

    const { ctx } = entry;
    if (ctx.state === 'suspended') await ctx.resume();

    // Convert Int16 back to Float32
    const int16 = new Int16Array(new Uint8Array(audioData).buffer);
    const float32 = new Float32Array(int16.length);
    for (let i = 0; i < int16.length; i++) {
      float32[i] = int16[i] / (int16[i] < 0 ? 0x8000 : 0x7FFF);
    }

    const buffer = ctx.createBuffer(1, float32.length, SAMPLE_RATE);
    buffer.getChannelData(0).set(float32);

    const source = ctx.createBufferSource();
    source.buffer = buffer;

    // Get gain from audio manager
    const gainNode = ctx.createGain();
    gainNode.gain.value = this.audioManager.getMasterVolume();
    source.connect(gainNode);
    gainNode.connect(ctx.destination);

    // Schedule playback for gapless audio
    const now = ctx.currentTime;
    if (entry.nextPlayTime < now) {
      entry.nextPlayTime = now;
    }
    source.start(entry.nextPlayTime);
    entry.nextPlayTime += buffer.duration;
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
    };

    const onPeerJoined = (data: any) => {
      if (data.channel_id !== this.channelId || data.user_id === this.userId) return;
      this.onPeerState?.(data.user_id, 'connected');
    };

    const onPeerLeft = (data: any) => {
      if (data.channel_id !== this.channelId || data.user_id === this.userId) return;
      const entry = this.playbackContexts.get(data.user_id);
      if (entry) {
        if (entry.ctx.state !== 'closed') entry.ctx.close();
        this.playbackContexts.delete(data.user_id);
      }
      this.audioManager.removeUser(data.user_id);
      this.onPeerState?.(data.user_id, 'disconnected');
    };

    const onVoicePacket = (data: any) => {
      if (data.channel_id !== this.channelId || data.from === this.userId) return;
      this.playAudioPacket(data.from, data.encrypted_audio, data.sequence);
    };

    this.addWsListener('voice_channel_joined', onJoined);
    this.addWsListener('voice_peer_joined', onPeerJoined);
    this.addWsListener('voice_peer_left', onPeerLeft);
    this.addWsListener('voice_packet', onVoicePacket);
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
