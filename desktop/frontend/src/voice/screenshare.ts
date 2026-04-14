/**
 * Screen sharing via WebRTC.
 *
 * Uses P2P connections (same signaling as voice P2P mode) to send a
 * screen capture track to all voice channel participants. The server
 * only relays signaling messages — actual video is peer-to-peer.
 */

import { AccordWebSocket } from '../ws';

export type ScreenShareStateCallback = (active: boolean) => void;
export type RemoteStreamCallback = (userId: string, stream: MediaStream | null) => void;

const ICE_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

interface ScreenPeer {
  pc: RTCPeerConnection;
  makingOffer: boolean;
  ignoreOffer: boolean;
}

export class ScreenShareManager {
  private ws: AccordWebSocket;
  private channelId: string;
  private userId: string;
  private destroyed = false;

  // Local screen capture
  private localStream: MediaStream | null = null;

  // Outbound peers (we're sharing → sending to them)
  private outboundPeers: Map<string, ScreenPeer> = new Map();

  // Inbound streams (someone else is sharing → we're viewing)
  private inboundStreams: Map<string, { pc: RTCPeerConnection; stream: MediaStream }> = new Map();

  // WS handlers
  private wsHandlers: { event: string; handler: (data: any) => void }[] = [];

  // Callbacks
  onLocalStateChange: ScreenShareStateCallback | null = null;
  onRemoteStream: RemoteStreamCallback | null = null;

  constructor(ws: AccordWebSocket, channelId: string, userId: string) {
    this.ws = ws;
    this.channelId = channelId;
    this.userId = userId;
    this.setupSignaling();
  }

  get isSharing(): boolean {
    return this.localStream !== null;
  }

  /** Start sharing your screen to all voice channel participants. */
  async startSharing(participants: string[]): Promise<void> {
    if (this.localStream) return; // already sharing

    this.localStream = await navigator.mediaDevices.getDisplayMedia({
      video: { cursor: 'always' } as any,
      audio: true,
    });

    // Listen for user stopping via browser's built-in "Stop sharing" button
    const videoTrack = this.localStream.getVideoTracks()[0];
    if (videoTrack) {
      videoTrack.onended = () => {
        this.stopSharing();
      };
    }

    // Create outbound peer connections to all participants
    for (const peerId of participants) {
      if (peerId !== this.userId) {
        this.createOutboundPeer(peerId);
      }
    }

    // Broadcast that we started sharing
    this.ws.sendP2PSignal(
      this.channelId,
      '', // broadcast (empty target = all)
      JSON.stringify({ type: 'screen-share-start', userId: this.userId }),
    );

    this.onLocalStateChange?.(true);
  }

  /** Stop sharing your screen. */
  stopSharing(): void {
    if (!this.localStream) return;

    this.localStream.getTracks().forEach(t => t.stop());
    this.localStream = null;

    // Close all outbound peers
    this.outboundPeers.forEach((peer) => peer.pc.close());
    this.outboundPeers.clear();

    // Broadcast stop
    this.ws.sendP2PSignal(
      this.channelId,
      '',
      JSON.stringify({ type: 'screen-share-stop', userId: this.userId }),
    );

    this.onLocalStateChange?.(false);
  }

  /** Clean up everything. */
  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;

    this.stopSharing();

    this.inboundStreams.forEach(({ pc }) => pc.close());
    this.inboundStreams.clear();

    this.wsHandlers.forEach(({ event, handler }) => {
      this.ws.off(event as any, handler);
    });
    this.wsHandlers = [];
  }

  /** Called when a new peer joins the voice channel while we're sharing. */
  addParticipant(peerId: string): void {
    if (!this.localStream || peerId === this.userId) return;
    if (this.outboundPeers.has(peerId)) return;
    this.createOutboundPeer(peerId);
  }

  /** Called when a peer leaves the voice channel. */
  removeParticipant(peerId: string): void {
    const outbound = this.outboundPeers.get(peerId);
    if (outbound) {
      outbound.pc.close();
      this.outboundPeers.delete(peerId);
    }

    const inbound = this.inboundStreams.get(peerId);
    if (inbound) {
      inbound.pc.close();
      this.inboundStreams.delete(peerId);
      this.onRemoteStream?.(peerId, null);
    }
  }

  // ── Outbound (we share → peer receives) ──

  private createOutboundPeer(peerId: string): void {
    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    const peer: ScreenPeer = { pc, makingOffer: false, ignoreOffer: false };
    this.outboundPeers.set(peerId, peer);

    // Add screen tracks
    if (this.localStream) {
      this.localStream.getTracks().forEach(track => {
        pc.addTrack(track, this.localStream!);
      });
    }

    pc.onicecandidate = ({ candidate }) => {
      if (candidate) {
        this.ws.sendP2PSignal(
          this.channelId,
          peerId,
          JSON.stringify({ type: 'screen-ice', candidate }),
        );
      }
    };

    pc.onnegotiationneeded = async () => {
      try {
        peer.makingOffer = true;
        await pc.setLocalDescription();
        this.ws.sendP2PSignal(
          this.channelId,
          peerId,
          JSON.stringify({ type: 'screen-sdp', sdp: pc.localDescription }),
        );
      } catch (e) {
        console.error('Screen share negotiation error:', e);
      } finally {
        peer.makingOffer = false;
      }
    };
  }

  // ── Inbound (peer shares → we receive) ──

  private createInboundPeer(fromUserId: string): RTCPeerConnection {
    const existing = this.inboundStreams.get(fromUserId);
    if (existing) existing.pc.close();

    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

    pc.onicecandidate = ({ candidate }) => {
      if (candidate) {
        this.ws.sendP2PSignal(
          this.channelId,
          fromUserId,
          JSON.stringify({ type: 'screen-ice', candidate }),
        );
      }
    };

    pc.ontrack = (event) => {
      const [remoteStream] = event.streams;
      if (remoteStream) {
        this.inboundStreams.set(fromUserId, { pc, stream: remoteStream });
        this.onRemoteStream?.(fromUserId, remoteStream);
      }
    };

    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
        this.inboundStreams.delete(fromUserId);
        this.onRemoteStream?.(fromUserId, null);
      }
    };

    return pc;
  }

  // ── Signaling ──

  private setupSignaling(): void {
    const onP2PSignal = (data: any) => {
      if (data.channel_id !== this.channelId) return;
      try {
        const signal = JSON.parse(data.signal_data);
        this.handleSignal(data.from, signal);
      } catch {}
    };

    this.addWsListener('p2p_signal', onP2PSignal);
  }

  private async handleSignal(fromUserId: string, signal: any): Promise<void> {
    if (this.destroyed) return;

    // Screen share start/stop broadcasts
    if (signal.type === 'screen-share-start') {
      // Remote user started sharing — we'll receive their SDP offer next
      return;
    }
    if (signal.type === 'screen-share-stop') {
      const inbound = this.inboundStreams.get(signal.userId || fromUserId);
      if (inbound) {
        inbound.pc.close();
        this.inboundStreams.delete(signal.userId || fromUserId);
        this.onRemoteStream?.(signal.userId || fromUserId, null);
      }
      return;
    }

    // Screen SDP/ICE (separate from voice SDP/ICE)
    if (signal.type === 'screen-sdp') {
      const desc = signal.sdp as RTCSessionDescriptionInit;

      if (desc.type === 'offer') {
        // Inbound: someone is sharing their screen to us
        const pc = this.createInboundPeer(fromUserId);
        await pc.setRemoteDescription(desc);
        await pc.setLocalDescription();
        this.ws.sendP2PSignal(
          this.channelId,
          fromUserId,
          JSON.stringify({ type: 'screen-sdp', sdp: pc.localDescription }),
        );
      } else if (desc.type === 'answer') {
        // Outbound: peer accepted our screen share
        const outbound = this.outboundPeers.get(fromUserId);
        if (outbound) {
          await outbound.pc.setRemoteDescription(desc);
        }
      }
      return;
    }

    if (signal.type === 'screen-ice') {
      // Try outbound first, then inbound
      const outbound = this.outboundPeers.get(fromUserId);
      if (outbound) {
        try { await outbound.pc.addIceCandidate(signal.candidate); } catch {}
        return;
      }
      const inbound = this.inboundStreams.get(fromUserId);
      if (inbound) {
        try { await inbound.pc.addIceCandidate(signal.candidate); } catch {}
      }
    }
  }

  private addWsListener(event: string, handler: (data: any) => void): void {
    this.ws.on(event as any, handler);
    this.wsHandlers.push({ event, handler });
  }
}
