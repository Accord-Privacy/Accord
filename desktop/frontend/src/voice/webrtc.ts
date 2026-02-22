/**
 * WebRTC peer connection manager for Accord voice chat.
 *
 * Uses server-relayed signaling via WebSocket (P2PSignal messages).
 * Each pair of users in a voice channel establishes an RTCPeerConnection.
 * Audio is sent peer-to-peer with SRTP/DTLS encryption (WebRTC default).
 *
 * The "polite peer" pattern is used: the user with the lexicographically
 * smaller ID is the polite peer (yields on collision).
 */

import { AccordWebSocket } from '../ws';
import { AudioManager } from './audio';

export type SpeakingCallback = (userId: string, speaking: boolean) => void;
export type PeerStateCallback = (userId: string, state: 'connected' | 'disconnected') => void;

interface PeerConnection {
  pc: RTCPeerConnection;
  audioElement?: HTMLAudioElement;
  makingOffer: boolean;
  ignoreOffer: boolean;
}

const ICE_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

export class VoiceConnection {
  private peers: Map<string, PeerConnection> = new Map();
  private localStream: MediaStream | null = null;
  private channelId: string;
  private userId: string;
  private ws: AccordWebSocket;
  private audioManager: AudioManager;
  private isMuted = false;
  private destroyed = false;

  // VAD
  private audioContext: AudioContext | null = null;
  private analyser: AnalyserNode | null = null;
  private vadInterval: ReturnType<typeof setInterval> | null = null;
  private _isSpeaking = false;
  private vadThreshold = 0.015;

  // Callbacks
  onSpeaking: SpeakingCallback | null = null;
  onPeerState: PeerStateCallback | null = null;

  // WS event handler references for cleanup
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

  /** Start: acquire mic and join voice channel via WS. */
  async connect(): Promise<void> {
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error('Microphone access requires HTTPS or localhost. Voice is not available on plain HTTP.');
    }
    // Acquire microphone
    this.localStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
        sampleRate: 48000,
      },
    });

    // Start muted by default
    this.setMuted(true);

    // Setup VAD
    this.setupVAD();

    // Join voice channel — server will respond with participant list
    this.ws.joinVoiceChannel(this.channelId);
  }

  /** Disconnect from voice and clean up all peers. */
  disconnect(): void {
    if (this.destroyed) return;
    this.destroyed = true;

    // Leave voice channel
    this.ws.leaveVoiceChannel(this.channelId);

    this.stopVAD();

    // Close all peer connections
    this.peers.forEach((peer, peerId) => {
      peer.pc.close();
      if (peer.audioElement) {
        peer.audioElement.pause();
        peer.audioElement.srcObject = null;
      }
      this.audioManager.removeUser(peerId);
    });
    this.peers.clear();

    // Stop local tracks
    if (this.localStream) {
      this.localStream.getTracks().forEach(t => t.stop());
      this.localStream = null;
    }

    // Remove WS listeners
    this.wsHandlers.forEach(({ event, handler }) => {
      this.ws.off(event as any, handler);
    });
    this.wsHandlers = [];

    if (this.audioContext && this.audioContext.state !== 'closed') {
      this.audioContext.close();
    }
  }

  /** Mute/unmute local mic. */
  setMuted(muted: boolean): void {
    this.isMuted = muted;
    if (this.localStream) {
      this.localStream.getAudioTracks().forEach(t => {
        t.enabled = !muted;
      });
    }
    // Broadcast speaking=false when muted
    if (muted && this._isSpeaking) {
      this._isSpeaking = false;
      this.onSpeaking?.(this.userId, false);
      this.sendSpeakingState(false);
    }
  }

  /** Deafen — also mutes. */
  setDeafened(deafened: boolean): void {
    this.audioManager.setDeafened(deafened);
    if (deafened) {
      this.setMuted(true);
    }
  }

  get speaking(): boolean {
    return this._isSpeaking;
  }

  // ── Private: Signaling ──

  private setupSignaling(): void {
    // When we successfully join, server sends participant list
    const onJoined = (data: any) => {
      if (data.channel_id !== this.channelId) return;
      // Create peer connections to all existing participants
      const participants: string[] = data.participants || [];
      for (const peerId of participants) {
        if (peerId !== this.userId) {
          this.createPeerConnection(peerId, true); // we are the offerer
        }
      }
    };

    // When a new peer joins our channel
    const onPeerJoined = (data: any) => {
      if (data.channel_id !== this.channelId || data.user_id === this.userId) return;
      // New peer will send us an offer, so we just wait
      // (they get the participant list and create offers to us)
    };

    // When a peer leaves
    const onPeerLeft = (data: any) => {
      if (data.channel_id !== this.channelId || data.user_id === this.userId) return;
      this.removePeer(data.user_id);
    };

    // P2P signaling messages (SDP offers/answers, ICE candidates)
    const onP2PSignal = (data: any) => {
      if (data.channel_id !== this.channelId) return;
      this.handleSignalingMessage(data.from, JSON.parse(data.signal_data));
    };

    this.addWsListener('voice_channel_joined', onJoined);
    this.addWsListener('voice_peer_joined', onPeerJoined);
    this.addWsListener('voice_peer_left', onPeerLeft);
    this.addWsListener('p2p_signal', onP2PSignal);
  }

  private addWsListener(event: string, handler: (data: any) => void): void {
    this.ws.on(event as any, handler);
    this.wsHandlers.push({ event, handler });
  }

  private sendSignal(targetUserId: string, signalData: any): void {
    this.ws.sendP2PSignal(this.channelId, targetUserId, JSON.stringify(signalData));
  }

  private sendSpeakingState(speaking: boolean): void {
    this.ws.sendVoiceSpeakingState(this.channelId, this.userId, speaking);
  }

  // ── Private: Peer Connection Management ──

  private createPeerConnection(peerId: string, createOffer: boolean): PeerConnection {
    // Close existing if any
    const existing = this.peers.get(peerId);
    if (existing) {
      existing.pc.close();
    }

    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    const peerConn: PeerConnection = { pc, makingOffer: false, ignoreOffer: false };
    this.peers.set(peerId, peerConn);

    // Add local tracks
    if (this.localStream) {
      this.localStream.getTracks().forEach(track => {
        pc.addTrack(track, this.localStream!);
      });
    }

    // ICE candidates
    pc.onicecandidate = ({ candidate }) => {
      if (candidate) {
        this.sendSignal(peerId, { type: 'ice-candidate', candidate });
      }
    };

    // Remote tracks
    pc.ontrack = async (event) => {
      const [remoteStream] = event.streams;
      if (remoteStream) {
        const audioEl = await this.audioManager.createUserOutput(peerId, remoteStream);
        peerConn.audioElement = audioEl;
      }
    };

    // Connection state
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'connected') {
        this.onPeerState?.(peerId, 'connected');
      } else if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected' || pc.connectionState === 'closed') {
        this.onPeerState?.(peerId, 'disconnected');
      }
    };

    // Negotiation needed (polite peer pattern)
    pc.onnegotiationneeded = async () => {
      try {
        peerConn.makingOffer = true;
        await pc.setLocalDescription();
        this.sendSignal(peerId, { type: 'sdp', sdp: pc.localDescription });
      } catch (e) {
        console.error('Negotiation error:', e);
      } finally {
        peerConn.makingOffer = false;
      }
    };

    // If we should initiate, trigger negotiation
    if (createOffer) {
      // onnegotiationneeded will fire because we added tracks above
    }

    return peerConn;
  }

  private async handleSignalingMessage(fromUserId: string, signal: any): Promise<void> {
    if (this.destroyed) return;

    let peerConn = this.peers.get(fromUserId);
    if (!peerConn) {
      // Create a new connection for this unknown peer
      peerConn = this.createPeerConnection(fromUserId, false);
    }

    const pc = peerConn.pc;
    const polite = this.userId < fromUserId; // lexicographic comparison for polite peer

    if (signal.type === 'sdp') {
      const description = signal.sdp as RTCSessionDescriptionInit;
      const offerCollision =
        description.type === 'offer' &&
        (peerConn.makingOffer || pc.signalingState !== 'stable');

      peerConn.ignoreOffer = !polite && offerCollision;
      if (peerConn.ignoreOffer) return;

      await pc.setRemoteDescription(description);
      if (description.type === 'offer') {
        await pc.setLocalDescription();
        this.sendSignal(fromUserId, { type: 'sdp', sdp: pc.localDescription });
      }
    } else if (signal.type === 'ice-candidate') {
      try {
        await pc.addIceCandidate(signal.candidate);
      } catch (e) {
        if (!peerConn.ignoreOffer) {
          console.error('ICE candidate error:', e);
        }
      }
    }
  }

  private removePeer(peerId: string): void {
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.pc.close();
      if (peer.audioElement) {
        peer.audioElement.pause();
        peer.audioElement.srcObject = null;
      }
      this.audioManager.removeUser(peerId);
      this.peers.delete(peerId);
      this.onPeerState?.(peerId, 'disconnected');
    }
  }

  // ── Private: Voice Activity Detection ──

  private setupVAD(): void {
    if (!this.localStream) return;

    this.audioContext = new AudioContext({ sampleRate: 48000 });
    const source = this.audioContext.createMediaStreamSource(this.localStream);
    this.analyser = this.audioContext.createAnalyser();
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
