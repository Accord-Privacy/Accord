/**
 * VoiceChat — Voice chat component supporting relay and P2P modes.
 *
 * Relay mode (default): Audio routed through server, preventing IP exposure.
 * P2P mode (opt-in): Direct WebRTC connections for lower latency.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useAppContext } from './components/AppContext';
import { Icon } from './components/Icon';
import { AccordWebSocket } from './ws';
import { VoiceConnection } from './voice/webrtc';
import { RelayVoiceConnection } from './voice/relay';
import { AudioManager } from './voice/audio';
import { ScreenShareManager } from './voice/screenshare';

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

type VoiceMode = 'relay' | 'p2p';

export const VoiceChat: React.FC<VoiceChatProps> = ({
  ws,
  currentUserId,
  channelId,
  channelName,
  onLeave,
}) => {
  const ctx = useAppContext();
  const isMuted = ctx.voiceMuted;
  const setIsMuted = ctx.setVoiceMuted;
  const isDeafened = ctx.voiceDeafened;
  const setIsDeafened = ctx.setVoiceDeafened;
  const [outputVolume, setOutputVolume] = useState(100);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [peers, setPeers] = useState<Map<string, PeerInfo>>(new Map());
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [voiceMode, setVoiceMode] = useState<VoiceMode>('relay');
  const [isScreenSharing, setIsScreenSharing] = useState(false);
  const [remoteScreenStreams, setRemoteScreenStreams] = useState<Map<string, MediaStream>>(new Map());

  const voiceConnRef = useRef<VoiceConnection | RelayVoiceConnection | null>(null);
  const audioManagerRef = useRef<AudioManager | null>(null);
  const screenShareRef = useRef<ScreenShareManager | null>(null);

  // Connect to voice on mount
  useEffect(() => {
    if (!ws || !currentUserId) return;

    const audioManager = new AudioManager();
    audioManagerRef.current = audioManager;

    // Listen for server-sent voice mode
    const onModeChanged = (data: any) => {
      if (data.channel_id !== channelId) return;
      setVoiceMode(data.voice_mode === 'p2p' ? 'p2p' : 'relay');
    };
    ws.on('voice_mode_changed' as any, onModeChanged);
    ws.on('voice_mode' as any, onModeChanged);

    // Create appropriate connection based on mode
    const createConnection = (mode: VoiceMode) => {
      if (mode === 'p2p') {
        return new VoiceConnection(ws, channelId, currentUserId, audioManager);
      } else {
        return new RelayVoiceConnection(ws, channelId, currentUserId, audioManager);
      }
    };

    const vc = createConnection(voiceMode);
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

    // Also listen for voice_speaking_state from WS
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

    // Track peers as they join
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

    // On voice_channel_joined, populate initial peers and mode
    const onChannelJoined = (data: any) => {
      if (data.channel_id !== channelId) return;
      // Server sends voice_mode in join response
      if (data.voice_mode) {
        setVoiceMode(data.voice_mode === 'p2p' ? 'p2p' : 'relay');
      }
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

    // Screen share manager
    const sm = new ScreenShareManager(ws, channelId, currentUserId);
    screenShareRef.current = sm;
    sm.onLocalStateChange = (active) => setIsScreenSharing(active);
    sm.onRemoteStream = (userId, stream) => {
      setRemoteScreenStreams(prev => {
        const next = new Map(prev);
        if (stream) {
          next.set(userId, stream);
        } else {
          next.delete(userId);
        }
        return next;
      });
    };

    // Forward peer join/leave to screen share manager
    const onPeerJoinedScreen = (data: any) => {
      if (data.channel_id !== channelId || data.user_id === currentUserId) return;
      sm.addParticipant(data.user_id);
    };
    const onPeerLeftScreen = (data: any) => {
      if (data.channel_id !== channelId || data.user_id === currentUserId) return;
      sm.removeParticipant(data.user_id);
    };
    ws.on('voice_peer_joined' as any, onPeerJoinedScreen);
    ws.on('voice_peer_left' as any, onPeerLeftScreen);

    // Connect
    vc.connect().catch(err => {
      console.error('Voice connection failed:', err);
      setConnectionError(err.message || 'Failed to connect to voice');
    });

    return () => {
      sm.destroy();
      screenShareRef.current = null;
      setIsScreenSharing(false);
      setRemoteScreenStreams(new Map());
      vc.disconnect();
      audioManager.destroy();
      voiceConnRef.current = null;
      audioManagerRef.current = null;
      ws.off('voice_speaking_state' as any, onSpeakingState);
      ws.off('voice_peer_joined' as any, onPeerJoined);
      ws.off('voice_channel_joined' as any, onChannelJoined);
      ws.off('voice_mode_changed' as any, onModeChanged);
      ws.off('voice_mode' as any, onModeChanged);
      ws.off('voice_peer_joined' as any, onPeerJoinedScreen);
      ws.off('voice_peer_left' as any, onPeerLeftScreen);
    };
  }, [ws, channelId, currentUserId, voiceMode]);

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

  const toggleVoiceMode = useCallback(() => {
    if (!ws) return;
    const newMode: VoiceMode = voiceMode === 'relay' ? 'p2p' : 'relay';
    ws.setVoiceMode(channelId, newMode);
    // Mode will update via voice_mode_changed event, which triggers reconnect via useEffect
  }, [ws, channelId, voiceMode]);

  const toggleScreenShare = useCallback(() => {
    const sm = screenShareRef.current;
    if (!sm) return;
    if (sm.isSharing) {
      sm.stopSharing();
    } else {
      const participantIds = Array.from(peers.keys());
      sm.startSharing(participantIds).catch(err => {
        console.error('Screen share failed:', err);
      });
    }
  }, [peers]);

  const peerList = Array.from(peers.values());

  // Sync voice channel users to app context for sidebar display
  useEffect(() => {
    const users: import('./hooks/useVoice').VoiceChannelUser[] = [
      {
        userId: currentUserId || '',
        displayName: ctx.appState.user?.display_name || 'You',
        isSpeaking,
        isMuted,
      },
      ...peerList.map(p => ({
        userId: p.userId,
        displayName: p.userId.slice(0, 8),
        isSpeaking: p.isSpeaking,
      })),
    ];
    ctx.setVoiceChannelUsers(users);
  }, [peers, isSpeaking, isMuted, currentUserId]);

  // Clear users on unmount
  useEffect(() => {
    return () => { ctx.setVoiceChannelUsers([]); };
  }, []);

  return (
    <div className="voice-panel">
      {/* Header */}
      <div className="voice-panel-header">
        <div className="voice-panel-status">
          <span className={`voice-panel-status-label ${connectionError ? 'error' : 'connected'}`}>
            {connectionError ? 'Voice Error' : 'Voice Connected'}
          </span>
          <span className="voice-panel-channel">
            {connectionError || channelName}
          </span>
          <span
            onClick={toggleVoiceMode}
            className={`voice-mode-badge ${voiceMode}`}
            title={voiceMode === 'relay'
              ? 'Relay mode — IP protected. Click to switch to P2P (lower latency, exposes IP).'
              : 'P2P mode — direct connection. Click to switch to Relay (IP protected).'}
          >
            {voiceMode === 'relay' ? 'Relay' : 'P2P'}
          </span>
        </div>
        <button onClick={handleDisconnect} className="voice-panel-disconnect">
          Disconnect
        </button>
      </div>

      {/* Body */}
      <div className="voice-panel-body">
        {/* Users */}
        <div className="voice-panel-users">
          <span className="voice-panel-users-label">
            Users ({peerList.length + 1}):
          </span>

          <UserAvatar label="You" isSpeaking={isSpeaking} isMuted={isMuted} />

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
        <div className="voice-panel-controls">
          <button
            onClick={toggleMute}
            className={`voice-ctrl-round ${isMuted ? 'muted' : 'active'}`}
            title={isMuted ? 'Unmute' : 'Mute'}
          >
            <Icon name={isMuted ? 'mic-off' : 'mic'} size={16} />
          </button>

          <button
            onClick={toggleDeafen}
            className={`voice-ctrl-round ${isDeafened ? 'muted' : 'neutral'}`}
            title={isDeafened ? 'Undeafen' : 'Deafen'}
          >
            <Icon name={isDeafened ? 'speaker-off' : 'speaker'} size={16} />
          </button>

          <button
            onClick={toggleScreenShare}
            className={`voice-ctrl-round ${isScreenSharing ? 'active' : 'neutral'}`}
            title={isScreenSharing ? 'Stop Sharing' : 'Share Screen'}
          >
            <Icon name={isScreenSharing ? 'screen-off' : 'screen-share'} size={16} />
          </button>

          <div className="voice-volume-control">
            <span className="voice-volume-label">Vol</span>
            <input
              type="range" min="0" max="100"
              value={outputVolume}
              onChange={(e) => setOutputVolume(parseInt(e.target.value))}
              className="voice-volume-slider"
            />
            <span className="voice-volume-value">{outputVolume}%</span>
          </div>
        </div>
      </div>

      {/* Screen share viewers */}
      {remoteScreenStreams.size > 0 && (
        <div className="voice-screenshare-viewers">
          {Array.from(remoteScreenStreams.entries()).map(([userId, stream]) => (
            <ScreenShareViewer key={userId} userId={userId} stream={stream} />
          ))}
        </div>
      )}
    </div>
  );
};

/** Remote screen share video element. */
const ScreenShareViewer: React.FC<{ userId: string; stream: MediaStream }> = ({ userId, stream }) => {
  const videoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const el = videoRef.current;
    if (el) {
      el.srcObject = stream;
      el.play().catch(() => {});
    }
    return () => {
      if (el) el.srcObject = null;
    };
  }, [stream]);

  return (
    <div className="voice-screenshare-viewer">
      <div className="voice-screenshare-label">{userId.slice(0, 8)}'s screen</div>
      <video ref={videoRef} autoPlay playsInline muted className="voice-screenshare-video" />
    </div>
  );
};

/** Small user avatar with speaking indicator (green ring). */
const UserAvatar: React.FC<{
  label: string;
  isSpeaking?: boolean;
  isMuted?: boolean;
  isConnecting?: boolean;
}> = ({ label, isSpeaking, isMuted, isConnecting }) => {
  const cls = ['voice-user-pill'];
  if (isSpeaking) cls.push('speaking');
  if (isConnecting) cls.push('connecting');

  return (
    <div className={cls.join(' ')}>
      <div className="voice-user-pill-avatar">
        {label[0]?.toUpperCase()}
      </div>
      <span className="voice-user-pill-name">{label}</span>
      {isMuted && <span className="voice-user-pill-icon"><Icon name="mic-off" size={12} /></span>}
      {isConnecting && <span className="voice-user-pill-connecting">⋯</span>}
    </div>
  );
};
