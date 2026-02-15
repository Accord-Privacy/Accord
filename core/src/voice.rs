//! # Accord Voice System
//!
//! Real-time encrypted voice communication with low latency.
//! Supports both P2P and server-relayed voice channels.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::crypto::{CryptoManager, VoiceKey};

/// Voice channel configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceChannel {
    pub channel_id: Uuid,
    pub name: String,
    pub max_participants: Option<u32>,
    pub quality_settings: AudioQuality,
    pub channel_type: VoiceChannelType,
    pub participants: HashMap<Uuid, VoiceParticipant>,
    pub encryption_mode: EncryptionMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VoiceChannelType {
    /// Lobby voice channel - anyone can join
    Lobby,
    /// Private voice channel - requires permission
    Private,
    /// Direct call between specific users
    DirectCall { participants: Vec<Uuid> },
}

/// Audio quality settings for voice channels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AudioQuality {
    pub sample_rate: u32,    // Hz (8000, 16000, 24000, 48000)
    pub bitrate: u32,        // bits per second (8000-128000)
    pub channels: u8,        // 1 = mono, 2 = stereo
    pub frame_duration: u16, // milliseconds (10, 20, 40, 60)
}

/// Voice participant information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceParticipant {
    pub user_id: Uuid,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub is_speaking: bool,
    pub is_muted: bool,
    pub is_deafened: bool,
    pub volume: f32,                // 0.0 to 1.0
    pub voice_key: Option<Vec<u8>>, // Encrypted voice key for this participant
}

/// Voice encryption modes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EncryptionMode {
    /// End-to-end encrypted (keys shared between clients)
    EndToEnd,
    /// Server-assisted encryption (server relays but can't decrypt)
    ServerAssisted,
    /// Group encryption (shared key for all participants)
    Group,
}

/// Voice packet for transmission
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoicePacket {
    pub packet_id: u64,
    pub user_id: Uuid,
    pub channel_id: Uuid,
    pub timestamp: u64,
    pub sequence: u64,
    pub encrypted_audio: Vec<u8>,
    pub packet_type: VoicePacketType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VoicePacketType {
    /// Regular audio data
    Audio,
    /// Silence detection packet
    Silence,
    /// Speaking state change
    SpeakingState { is_speaking: bool },
    /// Connection test packet
    Ping,
}

/// Voice activity detection
#[derive(Debug, Clone)]
pub struct VoiceActivityDetector {
    threshold: f32,
    hangover_frames: u32,
    current_hangover: u32,
    is_speaking: bool,
}

/// Real-time voice processor
pub struct VoiceProcessor {
    crypto: CryptoManager,
    channels: HashMap<Uuid, VoiceChannel>,
    voice_keys: HashMap<(Uuid, Uuid), VoiceKey>, // (channel_id, user_id) -> key
    vad: VoiceActivityDetector,
    local_user_id: Uuid,
}

impl AudioQuality {
    /// High quality settings for music/broadcast
    pub fn high_quality() -> Self {
        Self {
            sample_rate: 48000,
            bitrate: 128000,
            channels: 2,
            frame_duration: 20,
        }
    }

    /// Standard quality for voice chat
    pub fn standard() -> Self {
        Self {
            sample_rate: 48000,
            bitrate: 64000,
            channels: 1,
            frame_duration: 20,
        }
    }

    /// Low bandwidth settings
    pub fn low_bandwidth() -> Self {
        Self {
            sample_rate: 16000,
            bitrate: 32000,
            channels: 1,
            frame_duration: 40,
        }
    }

    /// Get frame size in bytes
    pub fn frame_size_bytes(&self) -> usize {
        (self.sample_rate as usize * self.channels as usize * self.frame_duration as usize) / 1000
            * 2 // 16-bit samples
    }
}

impl VoiceActivityDetector {
    pub fn new() -> Self {
        Self {
            threshold: 0.01,     // Adjust based on testing
            hangover_frames: 20, // ~400ms at 20ms frames
            current_hangover: 0,
            is_speaking: false,
        }
    }

    /// Analyze audio frame and determine if user is speaking
    pub fn detect_activity(&mut self, audio_samples: &[i16]) -> bool {
        let energy = self.calculate_energy(audio_samples);

        if energy > self.threshold {
            self.is_speaking = true;
            self.current_hangover = self.hangover_frames;
        } else if self.current_hangover > 0 {
            self.current_hangover -= 1;
        } else {
            self.is_speaking = false;
        }

        self.is_speaking
    }

    fn calculate_energy(&self, samples: &[i16]) -> f32 {
        let sum_squares: f64 = samples.iter().map(|&sample| (sample as f64).powi(2)).sum();

        (sum_squares / samples.len() as f64).sqrt() as f32 / i16::MAX as f32
    }
}

impl VoiceProcessor {
    pub fn new(local_user_id: Uuid) -> Self {
        Self {
            crypto: CryptoManager::new(),
            channels: HashMap::new(),
            voice_keys: HashMap::new(),
            vad: VoiceActivityDetector::new(),
            local_user_id,
        }
    }

    /// Join a voice channel
    pub fn join_channel(&mut self, channel_id: Uuid) -> Result<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("Voice channel not found"))?;

        // Check max participants
        if let Some(max) = channel.max_participants {
            if channel.participants.len() >= max as usize {
                return Err(anyhow::anyhow!("Voice channel is full"));
            }
        }

        // Generate voice key for this user in this channel
        let voice_key = self.crypto.generate_voice_key()?;
        self.voice_keys
            .insert((channel_id, self.local_user_id), voice_key);

        // Add participant
        channel.participants.insert(
            self.local_user_id,
            VoiceParticipant {
                user_id: self.local_user_id,
                joined_at: chrono::Utc::now(),
                is_speaking: false,
                is_muted: false,
                is_deafened: false,
                volume: 1.0,
                voice_key: None, // Would be exchanged securely
            },
        );

        Ok(())
    }

    /// Leave a voice channel
    pub fn leave_channel(&mut self, channel_id: Uuid) -> Result<()> {
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.participants.remove(&self.local_user_id);
            self.voice_keys.remove(&(channel_id, self.local_user_id));
        }
        Ok(())
    }

    /// Process and encrypt outgoing audio
    pub fn process_outgoing_audio(
        &mut self,
        channel_id: Uuid,
        audio_samples: &[i16],
    ) -> Result<VoicePacket> {
        let is_speaking = self.vad.detect_activity(audio_samples);

        // Get voice key
        let voice_key = self
            .voice_keys
            .get_mut(&(channel_id, self.local_user_id))
            .ok_or_else(|| anyhow::anyhow!("No voice key for channel"))?;

        // Convert samples to bytes
        let audio_bytes: Vec<u8> = audio_samples
            .iter()
            .flat_map(|&sample| sample.to_le_bytes().to_vec())
            .collect();

        // Encrypt audio data
        let encrypted_audio = if is_speaking {
            self.crypto.encrypt_voice_packet(voice_key, &audio_bytes)?
        } else {
            Vec::new() // Don't send silence packets with audio data
        };

        let packet_type = if is_speaking {
            VoicePacketType::Audio
        } else {
            VoicePacketType::SpeakingState { is_speaking: false }
        };

        Ok(VoicePacket {
            packet_id: voice_key.sequence,
            user_id: self.local_user_id,
            channel_id,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: voice_key.sequence,
            encrypted_audio,
            packet_type,
        })
    }

    /// Process incoming encrypted voice packet
    pub fn process_incoming_packet(&mut self, packet: VoicePacket) -> Result<Option<Vec<i16>>> {
        // Get the voice key for the sender
        let voice_key = self
            .voice_keys
            .get(&(packet.channel_id, packet.user_id))
            .ok_or_else(|| anyhow::anyhow!("No voice key for sender"))?;

        match packet.packet_type {
            VoicePacketType::Audio => {
                // Decrypt audio data
                let audio_bytes = self
                    .crypto
                    .decrypt_voice_packet(voice_key, &packet.encrypted_audio)?;

                // Convert bytes back to samples
                let samples: Vec<i16> = audio_bytes
                    .chunks_exact(2)
                    .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();

                // Update participant speaking state
                if let Some(channel) = self.channels.get_mut(&packet.channel_id) {
                    if let Some(participant) = channel.participants.get_mut(&packet.user_id) {
                        participant.is_speaking = true;
                    }
                }

                Ok(Some(samples))
            }
            VoicePacketType::SpeakingState { is_speaking } => {
                // Update speaking state
                if let Some(channel) = self.channels.get_mut(&packet.channel_id) {
                    if let Some(participant) = channel.participants.get_mut(&packet.user_id) {
                        participant.is_speaking = is_speaking;
                    }
                }
                Ok(None) // No audio data to return
            }
            VoicePacketType::Silence | VoicePacketType::Ping => {
                Ok(None) // No audio data
            }
        }
    }

    /// Mix multiple audio streams for output
    pub fn mix_audio_streams(&self, streams: Vec<Vec<i16>>) -> Vec<i16> {
        if streams.is_empty() {
            return Vec::new();
        }

        let max_length = streams.iter().map(|s| s.len()).max().unwrap_or(0);
        let mut mixed = vec![0i32; max_length];

        // Sum all streams
        for stream in streams {
            for (i, &sample) in stream.iter().enumerate() {
                mixed[i] += sample as i32;
            }
        }

        // Apply soft clipping and convert back to i16
        mixed
            .into_iter()
            .map(|sample| {
                let clamped = sample.clamp(i16::MIN as i32, i16::MAX as i32);
                clamped as i16
            })
            .collect()
    }

    /// Create a new voice channel
    pub fn create_voice_channel(
        &mut self,
        name: String,
        channel_type: VoiceChannelType,
        quality: AudioQuality,
    ) -> Uuid {
        let channel_id = Uuid::new_v4();

        let channel = VoiceChannel {
            channel_id,
            name,
            max_participants: None,
            quality_settings: quality,
            channel_type,
            participants: HashMap::new(),
            encryption_mode: EncryptionMode::EndToEnd,
        };

        self.channels.insert(channel_id, channel);
        channel_id
    }

    /// Get channel information
    pub fn get_channel(&self, channel_id: Uuid) -> Option<&VoiceChannel> {
        self.channels.get(&channel_id)
    }

    /// Mute/unmute local microphone
    pub fn set_muted(&mut self, channel_id: Uuid, muted: bool) -> Result<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("Voice channel not found"))?;

        if let Some(participant) = channel.participants.get_mut(&self.local_user_id) {
            participant.is_muted = muted;
        }

        Ok(())
    }

    /// Deafen (mute all incoming audio)
    pub fn set_deafened(&mut self, channel_id: Uuid, deafened: bool) -> Result<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("Voice channel not found"))?;

        if let Some(participant) = channel.participants.get_mut(&self.local_user_id) {
            participant.is_deafened = deafened;
        }

        Ok(())
    }

    /// Set volume for specific user
    pub fn set_user_volume(&mut self, channel_id: Uuid, user_id: Uuid, volume: f32) -> Result<()> {
        let volume = volume.clamp(0.0, 2.0); // Allow up to 200% volume

        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("Voice channel not found"))?;

        if let Some(participant) = channel.participants.get_mut(&user_id) {
            participant.volume = volume;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_quality_frame_size() {
        let quality = AudioQuality::standard();
        let frame_size = quality.frame_size_bytes();

        // Standard: 48kHz, mono, 20ms = 48000 * 1 * 0.02 * 2 = 1920 bytes
        assert_eq!(frame_size, 1920);
    }

    #[test]
    fn test_voice_activity_detection() {
        let mut vad = VoiceActivityDetector::new();

        // Silent audio (should not trigger)
        let silence = vec![0i16; 960]; // 20ms at 48kHz mono
        assert!(!vad.detect_activity(&silence));

        // Loud audio (should trigger)
        let loud = vec![1000i16; 960];
        assert!(vad.detect_activity(&loud));
    }

    #[test]
    fn test_voice_channel_creation() {
        let mut processor = VoiceProcessor::new(Uuid::new_v4());

        let channel_id = processor.create_voice_channel(
            "Test Channel".to_string(),
            VoiceChannelType::Lobby,
            AudioQuality::standard(),
        );

        let channel = processor.get_channel(channel_id).unwrap();
        assert_eq!(channel.name, "Test Channel");
        assert!(channel.participants.is_empty());
    }

    #[test]
    fn test_audio_mixing() {
        let processor = VoiceProcessor::new(Uuid::new_v4());

        let stream1 = vec![100i16, 200i16, 300i16];
        let stream2 = vec![50i16, 100i16, 150i16];

        let mixed = processor.mix_audio_streams(vec![stream1, stream2]);
        assert_eq!(mixed, vec![150i16, 300i16, 450i16]);
    }
}
