/**
 * VoiceChat — Real WebRTC voice chat component.
 *
 * Uses RTCPeerConnection for audio (SRTP/DTLS encrypted by default).
 * Signaling is relayed through the server's WebSocket via P2PSignal messages.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { AccordWebSocket } from './ws';
import { VoiceConnection } from './voice/webrtc';
import { AudioManager } from './voice/audio';

interface VoiceChatProps {
  ws: AccordWebSocket | null;
  currentUserId: string | null;
  channelId: string;
  channelName: string;
  onLeave: () => void;
  privateKey?: CryptoKey | null;
}

interface PeerInfo {
  userId: string;
  isSpeaking: boolean;
  isConnected: boolean;
}

export const VoiceChat: React.FC<VoiceChatProps> = ({
  ws,
  currentUserId,
  channelId,
  channelName,
  onLeave,
}) => {
  const [isMuted, setIsMuted] = useState(true);
  const [isDeafened, setIsDeafened] = useState(false);
  const [outputVolume, setOutputVolume] = useState(100);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [peers, setPeers] = useState<Map<string, PeerInfo>>(new Map());
  const [connectionError, setConnectionError] = useState<string | null>(null);

  const voiceConnRef = useRef<VoiceConnection | null>(null);
  const audioManagerRef = useRef<AudioManager | null>(null);

  // Connect to voice on mount
  useEffect(() => {
    if (!ws || !currentUserId) return;

    const audioManager = new AudioManager();
    audioManagerRef.current = audioManager;

    const vc = new VoiceConnection(ws, channelId, currentUserId, audioManager);
    voiceConnRef.current = vc;

    // Speaking callback
    vc.onSpeaking = (userId, speaking) => {
      if (userId === currentUserId) {
        setIsSpeaking(speaking);
      } else {
        setPeers(prev => {
          const next = new Map(prev);
          const existing = next.get(userId);
          if (existing) {
            next.set(userId, { ...existing, isSpeaking: speaking });
          }
          return next;
        });
      }
    };

    // Peer connection state
    vc.onPeerState = (userId, state) => {
      setPeers(prev => {
        const next = new Map(prev);
        if (state === 'connected') {
          const existing = next.get(userId);
          next.set(userId, {
            userId,
            isSpeaking: existing?.isSpeaking ?? false,
            isConnected: true,
          });
        } else {
          next.delete(userId);
        }
        return next;
      });
    };

    // Also listen for voice_speaking_state from WS (for users we have peer connections with)
    const onSpeakingState = (data: any) => {
      if (data.channel_id !== channelId || data.user_id === currentUserId) return;
      setPeers(prev => {
        const next = new Map(prev);
        const existing = next.get(data.user_id);
        if (existing) {
          next.set(data.user_id, { ...existing, isSpeaking: data.speaking });
        }
        return next;
      });
    };
    ws.on('voice_speaking_state' as any, onSpeakingState);

    // Track peers as they join (before WebRTC connects)
    const onPeerJoined = (data: any) => {
      if (data.channel_id !== channelId || data.user_id === currentUserId) return;
      setPeers(prev => {
        const next = new Map(prev);
        if (!next.has(data.user_id)) {
          next.set(data.user_id, { userId: data.user_id, isSpeaking: false, isConnected: false });
        }
        return next;
      });
    };
    ws.on('voice_peer_joined' as any, onPeerJoined);

    // On voice_channel_joined, populate initial peers
    const onChannelJoined = (data: any) => {
      if (data.channel_id !== channelId) return;
      const participants: string[] = data.participants || [];
      setPeers(prev => {
        const next = new Map(prev);
        for (const pid of participants) {
          if (pid !== currentUserId && !next.has(pid)) {
            next.set(pid, { userId: pid, isSpeaking: false, isConnected: false });
          }
        }
        return next;
      });
    };
    ws.on('voice_channel_joined' as any, onChannelJoined);

    // Connect
    vc.connect().catch(err => {
      console.error('Voice connection failed:', err);
      setConnectionError(err.message || 'Failed to connect to voice');
    });

    return () => {
      vc.disconnect();
      audioManager.destroy();
      voiceConnRef.current = null;
      audioManagerRef.current = null;
      ws.off('voice_speaking_state' as any, onSpeakingState);
      ws.off('voice_peer_joined' as any, onPeerJoined);
      ws.off('voice_channel_joined' as any, onChannelJoined);
    };
  }, [ws, channelId, currentUserId]);

  // Sync mute state
  useEffect(() => {
    voiceConnRef.current?.setMuted(isMuted);
  }, [isMuted]);

  // Sync deafen state
  useEffect(() => {
    voiceConnRef.current?.setDeafened(isDeafened);
    if (isDeafened) setIsMuted(true);
  }, [isDeafened]);

  // Sync volume
  useEffect(() => {
    audioManagerRef.current?.setMasterVolume(outputVolume / 100);
  }, [outputVolume]);

  const toggleMute = useCallback(() => {
    // Resume audio context on user gesture
    audioManagerRef.current?.resume();
    setIsMuted(prev => !prev);
  }, []);

  const toggleDeafen = useCallback(() => {
    audioManagerRef.current?.resume();
    setIsDeafened(prev => !prev);
  }, []);

  const handleDisconnect = useCallback(() => {
    voiceConnRef.current?.disconnect();
    onLeave();
  }, [onLeave]);

  const peerList = Array.from(peers.values());

  return (
    <div style={{
      position: 'fixed',
      bottom: 0,
      left: '312px',
      right: '240px',
      height: '120px',
      background: '#2f3136',
      borderTop: '1px solid #202225',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 1000,
    }}>
      {/* Header */}
      <div style={{
        padding: '12px 16px',
        borderBottom: '1px solid #202225',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '14px', fontWeight: 600, color: connectionError ? '#f04747' : '#43b581' }}>
            {connectionError ? '⚠️ Voice Error' : '🔊 Voice Connected'}
          </span>
          <span style={{ fontSize: '13px', color: '#b9bbbe' }}>
            {connectionError || channelName}
          </span>
        </div>
        <button
          onClick={handleDisconnect}
          style={{
            background: '#f04747',
            border: 'none',
            color: '#ffffff',
            padding: '6px 12px',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '12px',
          }}
        >
          Disconnect
        </button>
      </div>

      {/* Controls */}
      <div style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px',
      }}>
        {/* Users */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, overflow: 'auto' }}>
          <span style={{ fontSize: '12px', color: '#8e9297', marginRight: '8px' }}>
            Users ({peerList.length + 1}):
          </span>

          {/* Current user */}
          <UserAvatar
            label="You"
            isSpeaking={isSpeaking}
            isMuted={isMuted}
          />

          {/* Remote peers */}
          {peerList.map(peer => (
            <UserAvatar
              key={peer.userId}
              label={peer.userId.slice(0, 8)}
              isSpeaking={peer.isSpeaking}
              isConnecting={!peer.isConnected}
            />
          ))}
        </div>

        {/* Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            onClick={toggleMute}
            style={{
              width: '36px', height: '36px', borderRadius: '50%', border: 'none',
              background: isMuted ? '#f04747' : '#3ba55d',
              color: '#fff', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px',
            }}
            title={isMuted ? 'Unmute' : 'Mute'}
          >
            {isMuted ? '🔇' : '🎤'}
          </button>

          <button
            onClick={toggleDeafen}
            style={{
              width: '36px', height: '36px', borderRadius: '50%', border: 'none',
              background: isDeafened ? '#f04747' : '#4f545c',
              color: '#fff', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px',
            }}
            title={isDeafened ? 'Undeafen' : 'Deafen'}
          >
            {isDeafened ? '🔇' : '🔊'}
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '120px' }}>
            <span style={{ fontSize: '12px', color: '#8e9297' }}>Vol:</span>
            <input
              type="range" min="0" max="100"
              value={outputVolume}
              onChange={(e) => setOutputVolume(parseInt(e.target.value))}
              style={{ flex: 1, height: '4px', borderRadius: '2px', background: '#4f545c', outline: 'none', cursor: 'pointer' }}
            />
            <span style={{ fontSize: '11px', color: '#8e9297', minWidth: '25px' }}>
              {outputVolume}%
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

/** Small user avatar with speaking indicator. */
const UserAvatar: React.FC<{
  label: string;
  isSpeaking?: boolean;
  isMuted?: boolean;
  isConnecting?: boolean;
}> = ({ label, isSpeaking, isMuted, isConnecting }) => (
  <div style={{
    display: 'flex', alignItems: 'center', gap: '6px',
    padding: '4px 8px', borderRadius: '4px',
    background: isSpeaking ? 'rgba(67, 181, 129, 0.3)' : 'transparent',
    border: isSpeaking ? '2px solid #43b581' : '2px solid transparent',
    transition: 'all 0.15s',
    opacity: isConnecting ? 0.5 : 1,
  }}>
    <div style={{
      width: '24px', height: '24px', borderRadius: '50%',
      background: '#5865f2',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: '12px', color: '#fff',
    }}>
      {label[0]?.toUpperCase()}
    </div>
    <span style={{ fontSize: '12px', color: '#dcddde' }}>{label}</span>
    {isMuted && <span style={{ fontSize: '10px', color: '#f04747' }}>🔇</span>}
    {isConnecting && <span style={{ fontSize: '10px', color: '#faa61a' }}>⋯</span>}
  </div>
);
