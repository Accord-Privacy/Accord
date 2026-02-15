//! # Accord Network Protocol
//! 
//! Message formats and network protocol for secure communication
//! between clients and relay servers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::voice::VoicePacket;
use crate::bots::{BotCommand, BotResponse};

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum message size in bytes (10MB)
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Network message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    pub message_id: Uuid,
    pub message_type: MessageType,
    pub sender_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub channel_id: Option<Uuid>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub payload: MessagePayload,
    pub signature: Option<Vec<u8>>, // Message authentication
}

/// Types of network messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    // Authentication & Connection
    Handshake,
    Authentication,
    Heartbeat,
    Disconnect,
    
    // Text Messaging
    TextMessage,
    TypingIndicator,
    MessageAck,
    MessageEdit,
    MessageDelete,
    
    // Voice Communication
    VoiceJoin,
    VoiceLeave,
    VoicePacket,
    VoiceSpeaking,
    
    // Channel Management
    ChannelJoin,
    ChannelLeave,
    ChannelUpdate,
    ChannelInvite,
    
    // Bot Integration
    BotCommand,
    BotResponse,
    
    // File Sharing
    FileUpload,
    FileDownload,
    FileChunk,
    
    // Server Management
    ServerInfo,
    UserList,
    PermissionUpdate,
    
    // Error Handling
    Error,
}

/// Message payload containing the actual data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    // Connection Messages
    Handshake(HandshakePayload),
    Authentication(AuthPayload),
    Heartbeat(HeartbeatPayload),
    
    // Text Messages
    TextMessage(TextMessagePayload),
    TypingIndicator(TypingPayload),
    MessageEdit(EditPayload),
    MessageDelete(DeletePayload),
    
    // Voice Messages
    VoiceJoin(VoiceJoinPayload),
    VoiceLeave(VoiceLeavePayload),
    VoicePacket(VoicePacketPayload),
    VoiceSpeaking(VoiceSpeakingPayload),
    
    // Channel Messages
    ChannelJoin(ChannelJoinPayload),
    ChannelLeave(ChannelLeavePayload),
    ChannelUpdate(ChannelUpdatePayload),
    
    // Bot Messages
    BotCommand(BotCommandPayload),
    BotResponse(BotResponsePayload),
    
    // File Messages
    FileUpload(FileUploadPayload),
    FileChunk(FileChunkPayload),
    
    // Server Messages
    ServerInfo(ServerInfoPayload),
    UserList(UserListPayload),
    
    // Error Messages
    Error(ErrorPayload),
    
    // Generic encrypted payload
    Encrypted(EncryptedPayload),
}

// Payload Definitions

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePayload {
    pub protocol_version: u8,
    pub client_version: String,
    pub supported_features: Vec<String>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    pub user_id: Uuid,
    pub token: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub latency_check: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextMessagePayload {
    pub content: Vec<u8>, // Encrypted message content
    pub message_type: TextMessageType,
    pub reply_to: Option<Uuid>,
    pub mentions: Vec<Uuid>,
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TextMessageType {
    Regular,
    System,
    Reply,
    Edit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub file_id: Uuid,
    pub filename: String,
    pub file_size: u64,
    pub content_type: String,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingPayload {
    pub is_typing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditPayload {
    pub original_message_id: Uuid,
    pub new_content: Vec<u8>, // Encrypted
    pub edit_timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePayload {
    pub message_id: Uuid,
    pub delete_timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceJoinPayload {
    pub channel_id: Uuid,
    pub audio_codec: String,
    pub encryption_key: Vec<u8>, // Encrypted voice key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceLeavePayload {
    pub channel_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoicePacketPayload {
    pub packet: VoicePacket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceSpeakingPayload {
    pub is_speaking: bool,
    pub channel_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelJoinPayload {
    pub channel_id: Uuid,
    pub channel_key: Option<Vec<u8>>, // For private channels
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelLeavePayload {
    pub channel_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelUpdatePayload {
    pub channel_id: Uuid,
    pub update_type: ChannelUpdateType,
    pub data: Vec<u8>, // Encrypted update data
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelUpdateType {
    NameChange,
    TopicChange,
    PermissionChange,
    UserJoined,
    UserLeft,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotCommandPayload {
    pub command: BotCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotResponsePayload {
    pub response: BotResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileUploadPayload {
    pub file_id: Uuid,
    pub filename: String,
    pub file_size: u64,
    pub content_type: String,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub encrypted_metadata: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunkPayload {
    pub file_id: Uuid,
    pub chunk_number: u32,
    pub is_last_chunk: bool,
    pub encrypted_data: Vec<u8>,
    pub checksum: [u8; 32], // SHA-256 of unencrypted chunk
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoPayload {
    pub server_id: Uuid,
    pub server_name: String,
    pub member_count: u32,
    pub channel_count: u32,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListPayload {
    pub users: Vec<UserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: Uuid,
    pub username: String,
    pub status: UserStatus,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserStatus {
    Online,
    Away,
    DoNotDisturb,
    Invisible,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub error_code: ErrorCode,
    pub error_message: String,
    pub details: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorCode {
    // Authentication Errors
    InvalidCredentials,
    TokenExpired,
    Unauthorized,
    
    // Channel Errors
    ChannelNotFound,
    ChannelFull,
    InsufficientPermissions,
    
    // Message Errors
    MessageTooLarge,
    MessageNotFound,
    DecryptionFailed,
    
    // Voice Errors
    VoiceChannelFull,
    CodecNotSupported,
    
    // File Errors
    FileTooLarge,
    UnsupportedFileType,
    UploadFailed,
    
    // Server Errors
    ServerOverloaded,
    RateLimited,
    InternalError,
    
    // Protocol Errors
    InvalidMessage,
    UnsupportedVersion,
    MalformedPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub encrypted_data: Vec<u8>,
    pub encryption_info: EncryptionInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub algorithm: String,
    pub key_version: u32,
    pub nonce: Vec<u8>,
}

/// Message builder for creating network messages
pub struct MessageBuilder {
    sender_id: Option<Uuid>,
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self { sender_id: None }
    }

    pub fn with_sender(mut self, sender_id: Uuid) -> Self {
        self.sender_id = Some(sender_id);
        self
    }

    pub fn build_text_message(
        &self,
        channel_id: Uuid,
        encrypted_content: Vec<u8>,
        reply_to: Option<Uuid>,
    ) -> NetworkMessage {
        NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender_id: self.sender_id,
            target_id: None,
            channel_id: Some(channel_id),
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::TextMessage(TextMessagePayload {
                content: encrypted_content,
                message_type: TextMessageType::Regular,
                reply_to,
                mentions: Vec::new(),
                attachments: Vec::new(),
            }),
            signature: None,
        }
    }

    pub fn build_voice_packet(&self, voice_packet: VoicePacket) -> NetworkMessage {
        NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::VoicePacket,
            sender_id: self.sender_id,
            target_id: None,
            channel_id: Some(voice_packet.channel_id),
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::VoicePacket(VoicePacketPayload {
                packet: voice_packet,
            }),
            signature: None,
        }
    }

    pub fn build_heartbeat(&self) -> NetworkMessage {
        NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::Heartbeat,
            sender_id: self.sender_id,
            target_id: None,
            channel_id: None,
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::Heartbeat(HeartbeatPayload {
                timestamp: chrono::Utc::now(),
                latency_check: None,
            }),
            signature: None,
        }
    }

    pub fn build_error(&self, error_code: ErrorCode, message: String) -> NetworkMessage {
        NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::Error,
            sender_id: self.sender_id,
            target_id: None,
            channel_id: None,
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::Error(ErrorPayload {
                error_code,
                error_message: message,
                details: None,
            }),
            signature: None,
        }
    }
}

/// Message validator for checking message integrity and format
pub struct MessageValidator;

impl MessageValidator {
    /// Validate a network message
    pub fn validate_message(message: &NetworkMessage) -> Result<()> {
        // Check protocol compatibility
        if let MessagePayload::Handshake(handshake) = &message.payload {
            if handshake.protocol_version != PROTOCOL_VERSION {
                return Err(anyhow::anyhow!(
                    "Unsupported protocol version: {}",
                    handshake.protocol_version
                ));
            }
        }

        // Check message size
        let serialized = bincode::serialize(message)
            .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?;
        
        if serialized.len() > MAX_MESSAGE_SIZE {
            return Err(anyhow::anyhow!(
                "Message too large: {} bytes (max: {})",
                serialized.len(),
                MAX_MESSAGE_SIZE
            ));
        }

        // Validate payload-specific constraints
        match &message.payload {
            MessagePayload::TextMessage(text) => {
                if text.content.is_empty() {
                    return Err(anyhow::anyhow!("Empty text message"));
                }
            }
            MessagePayload::FileChunk(chunk) => {
                if chunk.encrypted_data.is_empty() {
                    return Err(anyhow::anyhow!("Empty file chunk"));
                }
            }
            _ => {} // Other message types don't need special validation
        }

        Ok(())
    }

    /// Validate message ordering and sequence
    pub fn validate_sequence(
        &self,
        previous_message: Option<&NetworkMessage>,
        current_message: &NetworkMessage,
    ) -> Result<()> {
        if let Some(prev) = previous_message {
            if current_message.timestamp < prev.timestamp {
                return Err(anyhow::anyhow!("Message timestamp is out of order"));
            }
        }
        Ok(())
    }
}

/// Message serialization utilities
pub struct MessageSerializer;

impl MessageSerializer {
    /// Serialize message to bytes for network transmission
    pub fn serialize(message: &NetworkMessage) -> Result<Vec<u8>> {
        bincode::serialize(message)
            .map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))
    }

    /// Deserialize bytes to network message
    pub fn deserialize(data: &[u8]) -> Result<NetworkMessage> {
        bincode::deserialize(data)
            .map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))
    }

    /// Serialize with compression for large messages
    pub fn serialize_compressed(message: &NetworkMessage) -> Result<Vec<u8>> {
        let serialized = Self::serialize(message)?;
        
        // Only compress if message is large enough to benefit
        if serialized.len() > 1024 {
            use std::io::Write;
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(&serialized)
                .map_err(|e| anyhow::anyhow!("Compression failed: {}", e))?;
            encoder.finish()
                .map_err(|e| anyhow::anyhow!("Compression finalization failed: {}", e))
        } else {
            Ok(serialized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_building() {
        let builder = MessageBuilder::new().with_sender(Uuid::new_v4());
        
        let message = builder.build_text_message(
            Uuid::new_v4(),
            b"encrypted content".to_vec(),
            None,
        );
        
        assert_eq!(message.message_type, MessageType::TextMessage);
        assert!(message.sender_id.is_some());
    }

    #[test]
    fn test_message_validation() {
        let builder = MessageBuilder::new();
        let message = builder.build_heartbeat();
        
        assert!(MessageValidator::validate_message(&message).is_ok());
    }

    #[test]
    fn test_message_serialization() {
        let builder = MessageBuilder::new();
        let message = builder.build_heartbeat();
        
        let serialized = MessageSerializer::serialize(&message).unwrap();
        let deserialized = MessageSerializer::deserialize(&serialized).unwrap();
        
        assert_eq!(message.message_id, deserialized.message_id);
        assert_eq!(message.message_type, deserialized.message_type);
    }

    #[test]
    fn test_error_message_creation() {
        let builder = MessageBuilder::new();
        let error_msg = builder.build_error(
            ErrorCode::ChannelNotFound,
            "The requested channel does not exist".to_string(),
        );
        
        assert_eq!(error_msg.message_type, MessageType::Error);
        
        if let MessagePayload::Error(error) = error_msg.payload {
            assert_eq!(error.error_code, ErrorCode::ChannelNotFound);
        } else {
            panic!("Expected error payload");
        }
    }
}