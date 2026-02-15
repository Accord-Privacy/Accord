import React, { useState, useEffect, useCallback, useRef } from 'react';
import { AccordWebSocket } from './ws';
import { VoiceState, VoiceJoinMessage, VoiceLeaveMessage, VoicePacketMessage, VoiceSpeakingMessage } from './types';

interface VoiceChatProps {
  ws: AccordWebSocket | null;
  currentUserId: string | null;
  channelId: string;
  channelName: string;
  onLeave: () => void;
}

export const VoiceChat: React.FC<VoiceChatProps> = ({
  ws,
  currentUserId,
  channelId,
  channelName,
  onLeave
}) => {
  const [voiceState, setVoiceState] = useState<VoiceState>({
    channelId: null,
    isConnected: false,
    isMuted: true,
    isDeafened: false,
    outputVolume: 100,
    connectedUsers: [],
    isCapturingAudio: false,
    vadThreshold: 0.01,
    isSpeaking: false
  });

  // Audio context and stream refs
  const audioContextRef = useRef<AudioContext | null>(null);
  const mediaStreamRef = useRef<MediaStream | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const microphoneRef = useRef<MediaStreamAudioSourceNode | null>(null);
  const processorRef = useRef<ScriptProcessorNode | null>(null);
  const audioBuffersRef = useRef<Map<string, { context: AudioContext; gainNode: GainNode }>>(new Map());
  
  // Voice Activity Detection
  const vadIntervalRef = useRef<number | null>(null);
  const speakingTimeoutRef = useRef<number | null>(null);

  // Initialize audio context and setup
  const initializeAudio = useCallback(async () => {
    try {
      // Create audio context
      audioContextRef.current = new (window.AudioContext || (window as any).webkitAudioContext)();
      
      // Get user media
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
          sampleRate: 44100
        }
      });
      
      mediaStreamRef.current = stream;

      // Create analyser for VAD
      analyserRef.current = audioContextRef.current.createAnalyser();
      analyserRef.current.fftSize = 2048;
      analyserRef.current.smoothingTimeConstant = 0.8;

      // Create microphone input
      microphoneRef.current = audioContextRef.current.createMediaStreamSource(stream);

      // Create script processor for audio processing
      processorRef.current = audioContextRef.current.createScriptProcessor(4096, 1, 1);
      
      // Connect audio chain
      microphoneRef.current.connect(analyserRef.current);
      analyserRef.current.connect(processorRef.current);
      processorRef.current.connect(audioContextRef.current.destination);

      // Set up audio processing
      processorRef.current.onaudioprocess = (event) => {
        if (voiceState.isMuted) return;

        const inputData = event.inputBuffer.getChannelData(0);
        
        // Convert to 16-bit PCM and encode as base64
        const audioData = new Int16Array(inputData.length);
        for (let i = 0; i < inputData.length; i++) {
          audioData[i] = Math.max(-1, Math.min(1, inputData[i])) * 0x7FFF;
        }
        
        // Convert to base64
        const arrayBuffer = audioData.buffer;
        const base64Data = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));

        // Send voice packet
        if (ws && ws.isSocketConnected()) {
          ws.send(JSON.stringify({
            type: 'voice_packet',
            channel_id: channelId,
            user_id: currentUserId,
            data: base64Data
          }));
        }
      };

      setVoiceState(prev => ({ ...prev, isCapturingAudio: true }));
      startVAD();

      console.log('Audio initialized successfully');
    } catch (error) {
      console.error('Failed to initialize audio:', error);
      alert('Failed to access microphone. Please check permissions.');
    }
  }, [ws, channelId, currentUserId, voiceState.isMuted]);

  // Voice Activity Detection
  const startVAD = useCallback(() => {
    if (vadIntervalRef.current) return;

    vadIntervalRef.current = setInterval(() => {
      if (!analyserRef.current || voiceState.isMuted) return;

      const dataArray = new Uint8Array(analyserRef.current.frequencyBinCount);
      analyserRef.current.getByteFrequencyData(dataArray);

      // Calculate average volume
      const average = dataArray.reduce((acc, value) => acc + value, 0) / dataArray.length;
      const normalizedVolume = average / 255;

      const isSpeaking = normalizedVolume > voiceState.vadThreshold;
      
      if (isSpeaking !== voiceState.isSpeaking) {
        setVoiceState(prev => ({ ...prev, isSpeaking }));
        
        // Send speaking status
        if (ws && ws.isSocketConnected()) {
          ws.send(JSON.stringify({
            type: 'voice_speaking',
            channel_id: channelId,
            user_id: currentUserId,
            speaking: isSpeaking
          }));
        }

        // Clear existing timeout
        if (speakingTimeoutRef.current) {
          clearTimeout(speakingTimeoutRef.current);
        }

        // If user stopped speaking, set a timeout to confirm
        if (!isSpeaking) {
          speakingTimeoutRef.current = setTimeout(() => {
            setVoiceState(prev => ({ ...prev, isSpeaking: false }));
            if (ws && ws.isSocketConnected()) {
              ws.send(JSON.stringify({
                type: 'voice_speaking',
                channel_id: channelId,
                user_id: currentUserId,
                speaking: false
              }));
            }
          }, 500);
        }
      }
    }, 100);
  }, [analyserRef, voiceState.isMuted, voiceState.vadThreshold, voiceState.isSpeaking, ws, channelId, currentUserId]);

  const stopVAD = useCallback(() => {
    if (vadIntervalRef.current) {
      clearInterval(vadIntervalRef.current);
      vadIntervalRef.current = null;
    }
    if (speakingTimeoutRef.current) {
      clearTimeout(speakingTimeoutRef.current);
      speakingTimeoutRef.current = null;
    }
  }, []);

  // Play received audio
  const playAudio = useCallback(async (userId: string, audioData: string) => {
    if (voiceState.isDeafened) return;

    try {
      // Decode base64 audio data
      const binaryString = atob(audioData);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      // Convert to Float32Array
      const audioArray = new Int16Array(bytes.buffer);
      const floatArray = new Float32Array(audioArray.length);
      for (let i = 0; i < audioArray.length; i++) {
        floatArray[i] = audioArray[i] / 0x7FFF;
      }

      // Get or create audio context for this user
      let userAudio = audioBuffersRef.current.get(userId);
      if (!userAudio) {
        const context = new (window.AudioContext || (window as any).webkitAudioContext)();
        const gainNode = context.createGain();
        gainNode.connect(context.destination);
        gainNode.gain.value = voiceState.outputVolume / 100;
        
        userAudio = { context, gainNode };
        audioBuffersRef.current.set(userId, userAudio);
      }

      // Create audio buffer and play
      const audioBuffer = userAudio.context.createBuffer(1, floatArray.length, 44100);
      audioBuffer.copyToChannel(floatArray, 0);

      const source = userAudio.context.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(userAudio.gainNode);
      source.start();

    } catch (error) {
      console.error('Failed to play audio:', error);
    }
  }, [voiceState.isDeafened, voiceState.outputVolume]);

  // Connect to voice channel
  const connectToVoice = useCallback(async () => {
    if (voiceState.isConnected) return;

    try {
      await initializeAudio();
      
      // Send voice join message
      if (ws && ws.isSocketConnected()) {
        ws.send(JSON.stringify({
          type: 'voice_join',
          channel_id: channelId,
          user_id: currentUserId
        }));
      }

      setVoiceState(prev => ({
        ...prev,
        channelId,
        isConnected: true
      }));

    } catch (error) {
      console.error('Failed to connect to voice:', error);
    }
  }, [initializeAudio, ws, channelId, currentUserId, voiceState.isConnected]);

  // Disconnect from voice channel
  const disconnectFromVoice = useCallback(() => {
    // Send voice leave message
    if (ws && ws.isSocketConnected()) {
      ws.send(JSON.stringify({
        type: 'voice_leave',
        channel_id: channelId,
        user_id: currentUserId
      }));
    }

    // Clean up audio
    stopVAD();
    
    if (processorRef.current) {
      processorRef.current.disconnect();
      processorRef.current = null;
    }
    
    if (microphoneRef.current) {
      microphoneRef.current.disconnect();
      microphoneRef.current = null;
    }

    if (analyserRef.current) {
      analyserRef.current.disconnect();
      analyserRef.current = null;
    }

    if (mediaStreamRef.current) {
      mediaStreamRef.current.getTracks().forEach(track => track.stop());
      mediaStreamRef.current = null;
    }

    if (audioContextRef.current) {
      audioContextRef.current.close();
      audioContextRef.current = null;
    }

    // Clean up user audio contexts
    audioBuffersRef.current.forEach(userAudio => {
      userAudio.context.close();
    });
    audioBuffersRef.current.clear();

    setVoiceState(prev => ({
      ...prev,
      channelId: null,
      isConnected: false,
      connectedUsers: [],
      isCapturingAudio: false,
      isSpeaking: false
    }));

    onLeave();
  }, [ws, channelId, currentUserId, stopVAD, onLeave]);

  // Toggle mute
  const toggleMute = useCallback(() => {
    setVoiceState(prev => ({ ...prev, isMuted: !prev.isMuted }));
  }, []);

  // Toggle deafen
  const toggleDeafen = useCallback(() => {
    setVoiceState(prev => ({ 
      ...prev, 
      isDeafened: !prev.isDeafened,
      isMuted: prev.isDeafened ? prev.isMuted : true // Auto-mute when deafening
    }));
  }, []);

  // Set output volume
  const setOutputVolume = useCallback((volume: number) => {
    setVoiceState(prev => ({ ...prev, outputVolume: Math.max(0, Math.min(100, volume)) }));
    
    // Update all user audio contexts
    audioBuffersRef.current.forEach(userAudio => {
      userAudio.gainNode.gain.value = volume / 100;
    });
  }, []);

  // WebSocket event handlers
  useEffect(() => {
    if (!ws) return;

    const handleVoiceJoin = (message: VoiceJoinMessage) => {
      if (message.channel_id !== channelId) return;
      
      setVoiceState(prev => ({
        ...prev,
        connectedUsers: [
          ...prev.connectedUsers.filter(u => u.userId !== message.user_id),
          {
            userId: message.user_id,
            username: message.username || `User ${message.user_id}`,
            isSpeaking: false,
            audioLevel: 0
          }
        ]
      }));
    };

    const handleVoiceLeave = (message: VoiceLeaveMessage) => {
      if (message.channel_id !== channelId) return;
      
      setVoiceState(prev => ({
        ...prev,
        connectedUsers: prev.connectedUsers.filter(u => u.userId !== message.user_id)
      }));

      // Clean up user's audio context
      const userAudio = audioBuffersRef.current.get(message.user_id);
      if (userAudio) {
        userAudio.context.close();
        audioBuffersRef.current.delete(message.user_id);
      }
    };

    const handleVoicePacket = (message: VoicePacketMessage) => {
      if (message.channel_id !== channelId || message.user_id === currentUserId) return;
      
      playAudio(message.user_id, message.data);
    };

    const handleVoiceSpeaking = (message: VoiceSpeakingMessage) => {
      if (message.channel_id !== channelId) return;
      
      setVoiceState(prev => ({
        ...prev,
        connectedUsers: prev.connectedUsers.map(user =>
          user.userId === message.user_id
            ? { ...user, isSpeaking: message.speaking }
            : user
        )
      }));
    };

    // Add event listeners
    ws.on('voice_join', handleVoiceJoin);
    ws.on('voice_leave', handleVoiceLeave);
    ws.on('voice_packet', handleVoicePacket);
    ws.on('voice_speaking', handleVoiceSpeaking);

    return () => {
      // Remove event listeners
      ws.off('voice_join', handleVoiceJoin);
      ws.off('voice_leave', handleVoiceLeave);
      ws.off('voice_packet', handleVoicePacket);
      ws.off('voice_speaking', handleVoiceSpeaking);
    };
  }, [ws, channelId, currentUserId, playAudio]);

  // Auto-connect when component mounts
  useEffect(() => {
    connectToVoice();
    return () => {
      disconnectFromVoice();
    };
  }, []);

  return (
    <div style={{
      position: 'fixed',
      bottom: 0,
      left: '312px', // Account for server list + channel sidebar
      right: '240px', // Account for member sidebar
      height: '120px',
      background: '#2f3136',
      borderTop: '1px solid #202225',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 1000
    }}>
      {/* Voice Channel Header */}
      <div style={{
        padding: '12px 16px',
        borderBottom: '1px solid #202225',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '14px', fontWeight: 600, color: '#43b581' }}>
            🔊 Voice Connected
          </span>
          <span style={{ fontSize: '13px', color: '#b9bbbe' }}>
            {channelName}
          </span>
        </div>
        <button
          onClick={disconnectFromVoice}
          style={{
            background: '#f04747',
            border: 'none',
            color: '#ffffff',
            padding: '6px 12px',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '12px'
          }}
        >
          Disconnect
        </button>
      </div>

      {/* Voice Controls */}
      <div style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px'
      }}>
        {/* Connected Users */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
          <span style={{ fontSize: '12px', color: '#8e9297', marginRight: '8px' }}>
            Users ({voiceState.connectedUsers.length + 1}):
          </span>
          
          {/* Current user */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 8px',
            borderRadius: '4px',
            background: voiceState.isSpeaking ? 'rgba(67, 181, 129, 0.3)' : 'transparent',
            border: voiceState.isSpeaking ? '2px solid #43b581' : '2px solid transparent',
            transition: 'all 0.2s'
          }}>
            <div style={{
              width: '24px',
              height: '24px',
              borderRadius: '50%',
              background: '#5865f2',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '12px',
              color: '#fff'
            }}>
              U
            </div>
            <span style={{ fontSize: '12px', color: '#dcddde' }}>You</span>
            {voiceState.isMuted && <span style={{ fontSize: '10px', color: '#f04747' }}>🔇</span>}
          </div>

          {/* Other users */}
          {voiceState.connectedUsers.map(user => (
            <div
              key={user.userId}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 8px',
                borderRadius: '4px',
                background: user.isSpeaking ? 'rgba(67, 181, 129, 0.3)' : 'transparent',
                border: user.isSpeaking ? '2px solid #43b581' : '2px solid transparent',
                transition: 'all 0.2s'
              }}
            >
              <div style={{
                width: '24px',
                height: '24px',
                borderRadius: '50%',
                background: '#5865f2',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '12px',
                color: '#fff'
              }}>
                {user.username[0]?.toUpperCase()}
              </div>
              <span style={{ fontSize: '12px', color: '#dcddde' }}>{user.username}</span>
            </div>
          ))}
        </div>

        {/* Voice Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {/* Mute Button */}
          <button
            onClick={toggleMute}
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '50%',
              border: 'none',
              background: voiceState.isMuted ? '#f04747' : '#3ba55d',
              color: '#fff',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '14px'
            }}
            title={voiceState.isMuted ? 'Unmute' : 'Mute'}
          >
            {voiceState.isMuted ? '🔇' : '🎤'}
          </button>

          {/* Deafen Button */}
          <button
            onClick={toggleDeafen}
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '50%',
              border: 'none',
              background: voiceState.isDeafened ? '#f04747' : '#4f545c',
              color: '#fff',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '14px'
            }}
            title={voiceState.isDeafened ? 'Undeafen' : 'Deafen'}
          >
            {voiceState.isDeafened ? '🔇' : '🔊'}
          </button>

          {/* Volume Control */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '120px' }}>
            <span style={{ fontSize: '12px', color: '#8e9297' }}>Vol:</span>
            <input
              type="range"
              min="0"
              max="100"
              value={voiceState.outputVolume}
              onChange={(e) => setOutputVolume(parseInt(e.target.value))}
              style={{
                flex: 1,
                height: '4px',
                borderRadius: '2px',
                background: '#4f545c',
                outline: 'none',
                cursor: 'pointer'
              }}
            />
            <span style={{ fontSize: '11px', color: '#8e9297', minWidth: '25px' }}>
              {voiceState.outputVolume}%
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};