//! # Accord Network Protocol
//!
//! Message formats and network protocol for secure communication
//! between clients and relay servers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::bots::{BotCommand, BotResponse};
use crate::session_manager::{PublishableKeyBundle, X3DHInitialMessage};
use crate::srtp::SrtpPacket;
use crate::voice::VoicePacket;

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum message size in bytes (10MB)
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Network message envelope
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    VoiceKeyExchange,
    EncryptedVoicePacket,

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

    // Key Exchange (Double Ratchet / X3DH)
    KeyBundlePublish,
    KeyBundleFetch,
    X3DHInitial,

    // Error Handling
    Error,
}

/// Message payload containing the actual data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

    // SRTP Voice Messages
    VoiceKeyExchange(VoiceKeyExchangePayload),
    EncryptedVoicePacket(EncryptedVoicePacketPayload),

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

    // Key exchange payloads
    KeyBundlePublish(KeyBundlePublishPayload),
    KeyBundleFetch(KeyBundleFetchPayload),
    KeyBundleResponse(KeyBundleResponsePayload),
    X3DHInitial(X3DHInitialPayload),

    // Generic encrypted payload
    Encrypted(EncryptedPayload),

    // Double Ratchet encrypted message
    DoubleRatchetEncrypted(DoubleRatchetPayload),
}

// Payload Definitions

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandshakePayload {
    pub protocol_version: u8,
    pub client_version: String,
    pub supported_features: Vec<String>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthPayload {
    pub user_id: Uuid,
    pub token: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub latency_check: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextMessagePayload {
    pub content: Vec<u8>, // Encrypted message content
    pub message_type: TextMessageType,
    pub reply_to: Option<Uuid>,
    pub mentions: Vec<Uuid>,
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TextMessageType {
    Regular,
    System,
    Reply,
    Edit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub file_id: Uuid,
    pub filename: String,
    pub file_size: u64,
    pub content_type: String,
    pub encrypted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypingPayload {
    pub is_typing: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditPayload {
    pub original_message_id: Uuid,
    pub new_content: Vec<u8>, // Encrypted
    pub edit_timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeletePayload {
    pub message_id: Uuid,
    pub delete_timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceJoinPayload {
    pub channel_id: Uuid,
    pub audio_codec: String,
    pub encryption_key: Vec<u8>, // Encrypted voice key
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceLeavePayload {
    pub channel_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoicePacketPayload {
    pub packet: VoicePacket,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceSpeakingPayload {
    pub is_speaking: bool,
    pub channel_id: Uuid,
}

/// Voice key exchange for SRTP session establishment
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceKeyExchangePayload {
    pub channel_id: Uuid,
    /// The encrypted voice session key (wrapped for each recipient)
    pub wrapped_key: Vec<u8>,
    /// Target user ID (for 1:1) or None (broadcast to channel)
    pub target_user_id: Option<Uuid>,
    /// SSRC the sender will use
    pub sender_ssrc: u32,
    /// Key generation number
    pub key_generation: u32,
}

/// An SRTP-encrypted voice packet with full header fields
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedVoicePacketPayload {
    pub channel_id: Uuid,
    pub packet: SrtpPacket,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelJoinPayload {
    pub channel_id: Uuid,
    pub channel_key: Option<Vec<u8>>, // For private channels
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelLeavePayload {
    pub channel_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelUpdatePayload {
    pub channel_id: Uuid,
    pub update_type: ChannelUpdateType,
    pub data: Vec<u8>, // Encrypted update data
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelUpdateType {
    NameChange,
    TopicChange,
    PermissionChange,
    UserJoined,
    UserLeft,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BotCommandPayload {
    pub command: BotCommand,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BotResponsePayload {
    pub response: BotResponse,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileUploadPayload {
    pub file_id: Uuid,
    pub filename: String,
    pub file_size: u64,
    pub content_type: String,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub encrypted_metadata: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileChunkPayload {
    pub file_id: Uuid,
    pub chunk_number: u32,
    pub is_last_chunk: bool,
    pub encrypted_data: Vec<u8>,
    pub checksum: [u8; 32], // SHA-256 of unencrypted chunk
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerInfoPayload {
    pub server_id: Uuid,
    pub server_name: String,
    pub member_count: u32,
    pub channel_count: u32,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserListPayload {
    pub users: Vec<UserInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: Uuid,
    pub username: String,
    pub status: UserStatus,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UserStatus {
    Online,
    Away,
    DoNotDisturb,
    Invisible,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub error_code: ErrorCode,
    pub error_message: String,
    pub details: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

// ── Key exchange payloads ──

/// Publish a prekey bundle to the server
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyBundlePublishPayload {
    pub bundle: PublishableKeyBundle,
}

/// Request another user's prekey bundle
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyBundleFetchPayload {
    pub target_user_id: Uuid,
}

/// Server response with a user's prekey bundle
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyBundleResponsePayload {
    pub user_id: Uuid,
    pub identity_key: [u8; 32],
    pub signed_prekey: [u8; 32],
    pub one_time_prekey: Option<[u8; 32]>,
}

/// X3DH initial message to establish a Double Ratchet session
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X3DHInitialPayload {
    pub initial_message: X3DHInitialMessage,
}

/// Double Ratchet encrypted message with header
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DoubleRatchetPayload {
    /// Sender's current DH ratchet public key
    pub sender_ratchet_key: [u8; 32],
    /// Number of messages in the previous sending chain
    pub previous_chain_length: u32,
    /// Message number in the current sending chain
    pub message_number: u32,
    /// The encrypted ciphertext (nonce + AES-GCM ciphertext)
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub encrypted_data: Vec<u8>,
    pub encryption_info: EncryptionInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub algorithm: String,
    pub key_version: u32,
    pub nonce: Vec<u8>,
}

/// Message builder for creating network messages
pub struct MessageBuilder {
    sender_id: Option<Uuid>,
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
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
        bincode::serialize(message).map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))
    }

    /// Deserialize bytes to network message
    pub fn deserialize(data: &[u8]) -> Result<NetworkMessage> {
        bincode::deserialize(data).map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))
    }

    /// Serialize with compression for large messages
    pub fn serialize_compressed(message: &NetworkMessage) -> Result<Vec<u8>> {
        let serialized = Self::serialize(message)?;

        // Only compress if message is large enough to benefit
        if serialized.len() > 1024 {
            use std::io::Write;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder
                .write_all(&serialized)
                .map_err(|e| anyhow::anyhow!("Compression failed: {}", e))?;
            encoder
                .finish()
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

        let message =
            builder.build_text_message(Uuid::new_v4(), b"encrypted content".to_vec(), None);

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

    // ── Message Type Tests ──

    #[test]
    fn test_all_message_types_serialization() {
        let types = vec![
            MessageType::Handshake,
            MessageType::Authentication,
            MessageType::Heartbeat,
            MessageType::Disconnect,
            MessageType::TextMessage,
            MessageType::TypingIndicator,
            MessageType::MessageAck,
            MessageType::MessageEdit,
            MessageType::MessageDelete,
            MessageType::VoiceJoin,
            MessageType::VoiceLeave,
            MessageType::VoicePacket,
            MessageType::VoiceSpeaking,
            MessageType::VoiceKeyExchange,
            MessageType::EncryptedVoicePacket,
            MessageType::ChannelJoin,
            MessageType::ChannelLeave,
            MessageType::ChannelUpdate,
            MessageType::ChannelInvite,
            MessageType::BotCommand,
            MessageType::BotResponse,
            MessageType::FileUpload,
            MessageType::FileDownload,
            MessageType::FileChunk,
            MessageType::ServerInfo,
            MessageType::UserList,
            MessageType::PermissionUpdate,
            MessageType::KeyBundlePublish,
            MessageType::KeyBundleFetch,
            MessageType::X3DHInitial,
            MessageType::Error,
        ];

        for msg_type in types {
            let serialized = bincode::serialize(&msg_type).unwrap();
            let deserialized: MessageType = bincode::deserialize(&serialized).unwrap();
            assert_eq!(msg_type, deserialized);
        }
    }

    #[test]
    fn test_text_message_type_variants() {
        let variants = vec![
            TextMessageType::Regular,
            TextMessageType::System,
            TextMessageType::Reply,
            TextMessageType::Edit,
        ];

        for variant in variants {
            let serialized = bincode::serialize(&variant).unwrap();
            let deserialized: TextMessageType = bincode::deserialize(&serialized).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn test_user_status_variants() {
        let statuses = vec![
            UserStatus::Online,
            UserStatus::Away,
            UserStatus::DoNotDisturb,
            UserStatus::Invisible,
            UserStatus::Offline,
        ];

        for status in statuses {
            let serialized = bincode::serialize(&status).unwrap();
            let deserialized: UserStatus = bincode::deserialize(&serialized).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_channel_update_type_variants() {
        let variants = vec![
            ChannelUpdateType::NameChange,
            ChannelUpdateType::TopicChange,
            ChannelUpdateType::PermissionChange,
            ChannelUpdateType::UserJoined,
            ChannelUpdateType::UserLeft,
        ];

        for variant in variants {
            let serialized = bincode::serialize(&variant).unwrap();
            let deserialized: ChannelUpdateType = bincode::deserialize(&serialized).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn test_all_error_code_variants() {
        let error_codes = vec![
            ErrorCode::InvalidCredentials,
            ErrorCode::TokenExpired,
            ErrorCode::Unauthorized,
            ErrorCode::ChannelNotFound,
            ErrorCode::ChannelFull,
            ErrorCode::InsufficientPermissions,
            ErrorCode::MessageTooLarge,
            ErrorCode::MessageNotFound,
            ErrorCode::DecryptionFailed,
            ErrorCode::VoiceChannelFull,
            ErrorCode::CodecNotSupported,
            ErrorCode::FileTooLarge,
            ErrorCode::UnsupportedFileType,
            ErrorCode::UploadFailed,
            ErrorCode::ServerOverloaded,
            ErrorCode::RateLimited,
            ErrorCode::InternalError,
            ErrorCode::InvalidMessage,
            ErrorCode::UnsupportedVersion,
            ErrorCode::MalformedPayload,
        ];

        for code in error_codes {
            let serialized = bincode::serialize(&code).unwrap();
            let deserialized: ErrorCode = bincode::deserialize(&serialized).unwrap();
            assert_eq!(code, deserialized);
        }
    }

    // ── Payload Tests ──

    #[test]
    fn test_handshake_payload_serialization() {
        let payload = HandshakePayload {
            protocol_version: PROTOCOL_VERSION,
            client_version: "1.0.0".to_string(),
            supported_features: vec!["encryption".to_string(), "voice".to_string()],
            public_key: vec![1, 2, 3, 4],
        };

        let serialized = bincode::serialize(&payload).unwrap();
        let deserialized: HandshakePayload = bincode::deserialize(&serialized).unwrap();
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_auth_payload_serialization() {
        let payload = AuthPayload {
            user_id: Uuid::new_v4(),
            token: "test_token_12345".to_string(),
            signature: vec![5, 6, 7, 8],
        };

        let serialized = bincode::serialize(&payload).unwrap();
        let deserialized: AuthPayload = bincode::deserialize(&serialized).unwrap();
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_text_message_payload_with_attachments() {
        let attachment = AttachmentInfo {
            file_id: Uuid::new_v4(),
            filename: "test.pdf".to_string(),
            file_size: 1024,
            content_type: "application/pdf".to_string(),
            encrypted: true,
        };

        let payload = TextMessagePayload {
            content: b"encrypted content".to_vec(),
            message_type: TextMessageType::Regular,
            reply_to: Some(Uuid::new_v4()),
            mentions: vec![Uuid::new_v4(), Uuid::new_v4()],
            attachments: vec![attachment],
        };

        let serialized = bincode::serialize(&payload).unwrap();
        let deserialized: TextMessagePayload = bincode::deserialize(&serialized).unwrap();
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_voice_key_exchange_payload() {
        let payload = VoiceKeyExchangePayload {
            channel_id: Uuid::new_v4(),
            wrapped_key: vec![1, 2, 3, 4, 5],
            target_user_id: Some(Uuid::new_v4()),
            sender_ssrc: 12345,
            key_generation: 1,
        };

        let serialized = bincode::serialize(&payload).unwrap();
        let deserialized: VoiceKeyExchangePayload = bincode::deserialize(&serialized).unwrap();
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_file_chunk_payload_with_checksum() {
        let payload = FileChunkPayload {
            file_id: Uuid::new_v4(),
            chunk_number: 5,
            is_last_chunk: false,
            encrypted_data: vec![9, 8, 7, 6, 5],
            checksum: [0u8; 32],
        };

        let serialized = bincode::serialize(&payload).unwrap();
        let deserialized: FileChunkPayload = bincode::deserialize(&serialized).unwrap();
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_double_ratchet_payload() {
        let payload = DoubleRatchetPayload {
            sender_ratchet_key: [1u8; 32],
            previous_chain_length: 10,
            message_number: 5,
            ciphertext: vec![1, 2, 3, 4, 5],
        };

        let serialized = bincode::serialize(&payload).unwrap();
        let deserialized: DoubleRatchetPayload = bincode::deserialize(&serialized).unwrap();
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_error_payload_with_details() {
        let mut details = HashMap::new();
        details.insert("field".to_string(), "value".to_string());
        details.insert("reason".to_string(), "invalid input".to_string());

        let payload = ErrorPayload {
            error_code: ErrorCode::InvalidMessage,
            error_message: "Test error".to_string(),
            details: Some(details),
        };

        let serialized = bincode::serialize(&payload).unwrap();
        let deserialized: ErrorPayload = bincode::deserialize(&serialized).unwrap();
        assert_eq!(payload, deserialized);
    }

    // ── NetworkMessage Tests ──

    #[test]
    fn test_network_message_complete_structure() {
        let msg = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender_id: Some(Uuid::new_v4()),
            target_id: Some(Uuid::new_v4()),
            channel_id: Some(Uuid::new_v4()),
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::TextMessage(TextMessagePayload {
                content: b"test".to_vec(),
                message_type: TextMessageType::Regular,
                reply_to: None,
                mentions: vec![],
                attachments: vec![],
            }),
            signature: Some(vec![1, 2, 3, 4]),
        };

        let serialized = MessageSerializer::serialize(&msg).unwrap();
        let deserialized = MessageSerializer::deserialize(&serialized).unwrap();
        assert_eq!(msg.message_id, deserialized.message_id);
        assert_eq!(msg.message_type, deserialized.message_type);
    }

    #[test]
    fn test_network_message_without_optional_fields() {
        let msg = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::Heartbeat,
            sender_id: None,
            target_id: None,
            channel_id: None,
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::Heartbeat(HeartbeatPayload {
                timestamp: chrono::Utc::now(),
                latency_check: None,
            }),
            signature: None,
        };

        let serialized = MessageSerializer::serialize(&msg).unwrap();
        let deserialized = MessageSerializer::deserialize(&serialized).unwrap();
        assert_eq!(msg.message_id, deserialized.message_id);
        assert!(deserialized.sender_id.is_none());
        assert!(deserialized.signature.is_none());
    }

    // ── MessageBuilder Tests ──

    #[test]
    fn test_message_builder_default() {
        let builder = MessageBuilder::default();
        let msg = builder.build_heartbeat();
        assert!(msg.sender_id.is_none());
    }

    #[test]
    fn test_message_builder_with_sender() {
        let sender = Uuid::new_v4();
        let builder = MessageBuilder::new().with_sender(sender);
        let msg = builder.build_heartbeat();
        assert_eq!(msg.sender_id, Some(sender));
    }

    #[test]
    fn test_build_text_message_with_reply() {
        let builder = MessageBuilder::new().with_sender(Uuid::new_v4());
        let channel_id = Uuid::new_v4();
        let reply_to = Uuid::new_v4();

        let msg = builder.build_text_message(channel_id, b"reply content".to_vec(), Some(reply_to));

        assert_eq!(msg.message_type, MessageType::TextMessage);
        assert_eq!(msg.channel_id, Some(channel_id));

        if let MessagePayload::TextMessage(text) = msg.payload {
            assert_eq!(text.reply_to, Some(reply_to));
            assert_eq!(text.content, b"reply content");
        } else {
            panic!("Expected text message payload");
        }
    }

    #[test]
    fn test_build_error_with_all_error_codes() {
        let builder = MessageBuilder::new();

        let error_codes = vec![
            ErrorCode::InvalidCredentials,
            ErrorCode::ChannelNotFound,
            ErrorCode::MessageTooLarge,
        ];

        for code in error_codes {
            let msg = builder.build_error(code.clone(), "Test error".to_string());
            assert_eq!(msg.message_type, MessageType::Error);

            if let MessagePayload::Error(error) = msg.payload {
                assert_eq!(error.error_code, code);
            } else {
                panic!("Expected error payload");
            }
        }
    }

    // ── MessageValidator Tests ──

    #[test]
    fn test_validate_message_with_correct_protocol_version() {
        let msg = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::Handshake,
            sender_id: None,
            target_id: None,
            channel_id: None,
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::Handshake(HandshakePayload {
                protocol_version: PROTOCOL_VERSION,
                client_version: "1.0".to_string(),
                supported_features: vec![],
                public_key: vec![1, 2, 3],
            }),
            signature: None,
        };

        assert!(MessageValidator::validate_message(&msg).is_ok());
    }

    #[test]
    fn test_validate_message_with_incorrect_protocol_version() {
        let msg = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::Handshake,
            sender_id: None,
            target_id: None,
            channel_id: None,
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::Handshake(HandshakePayload {
                protocol_version: 99,
                client_version: "1.0".to_string(),
                supported_features: vec![],
                public_key: vec![1, 2, 3],
            }),
            signature: None,
        };

        assert!(MessageValidator::validate_message(&msg).is_err());
    }

    #[test]
    fn test_validate_empty_text_message() {
        let msg = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender_id: Some(Uuid::new_v4()),
            target_id: None,
            channel_id: Some(Uuid::new_v4()),
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::TextMessage(TextMessagePayload {
                content: vec![],
                message_type: TextMessageType::Regular,
                reply_to: None,
                mentions: vec![],
                attachments: vec![],
            }),
            signature: None,
        };

        let result = MessageValidator::validate_message(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_empty_file_chunk() {
        let msg = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::FileChunk,
            sender_id: Some(Uuid::new_v4()),
            target_id: None,
            channel_id: None,
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::FileChunk(FileChunkPayload {
                file_id: Uuid::new_v4(),
                chunk_number: 1,
                is_last_chunk: false,
                encrypted_data: vec![],
                checksum: [0u8; 32],
            }),
            signature: None,
        };

        assert!(MessageValidator::validate_message(&msg).is_err());
    }

    #[test]
    fn test_validate_sequence_in_order() {
        let validator = MessageValidator;

        let msg1 = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender_id: Some(Uuid::new_v4()),
            target_id: None,
            channel_id: Some(Uuid::new_v4()),
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::TextMessage(TextMessagePayload {
                content: b"first".to_vec(),
                message_type: TextMessageType::Regular,
                reply_to: None,
                mentions: vec![],
                attachments: vec![],
            }),
            signature: None,
        };

        std::thread::sleep(std::time::Duration::from_millis(10));

        let msg2 = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender_id: Some(Uuid::new_v4()),
            target_id: None,
            channel_id: Some(Uuid::new_v4()),
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::TextMessage(TextMessagePayload {
                content: b"second".to_vec(),
                message_type: TextMessageType::Regular,
                reply_to: None,
                mentions: vec![],
                attachments: vec![],
            }),
            signature: None,
        };

        assert!(validator.validate_sequence(Some(&msg1), &msg2).is_ok());
    }

    #[test]
    fn test_validate_sequence_out_of_order() {
        let validator = MessageValidator;

        let timestamp_future = chrono::Utc::now() + chrono::Duration::hours(1);
        let timestamp_past = chrono::Utc::now() - chrono::Duration::hours(1);

        let msg1 = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender_id: Some(Uuid::new_v4()),
            target_id: None,
            channel_id: Some(Uuid::new_v4()),
            timestamp: timestamp_future,
            payload: MessagePayload::TextMessage(TextMessagePayload {
                content: b"first".to_vec(),
                message_type: TextMessageType::Regular,
                reply_to: None,
                mentions: vec![],
                attachments: vec![],
            }),
            signature: None,
        };

        let msg2 = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender_id: Some(Uuid::new_v4()),
            target_id: None,
            channel_id: Some(Uuid::new_v4()),
            timestamp: timestamp_past,
            payload: MessagePayload::TextMessage(TextMessagePayload {
                content: b"second".to_vec(),
                message_type: TextMessageType::Regular,
                reply_to: None,
                mentions: vec![],
                attachments: vec![],
            }),
            signature: None,
        };

        assert!(validator.validate_sequence(Some(&msg1), &msg2).is_err());
    }

    #[test]
    fn test_validate_sequence_no_previous() {
        let validator = MessageValidator;
        let msg = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::Heartbeat,
            sender_id: None,
            target_id: None,
            channel_id: None,
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::Heartbeat(HeartbeatPayload {
                timestamp: chrono::Utc::now(),
                latency_check: None,
            }),
            signature: None,
        };

        assert!(validator.validate_sequence(None, &msg).is_ok());
    }

    // ── MessageSerializer Tests ──

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let original = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender_id: Some(Uuid::new_v4()),
            target_id: Some(Uuid::new_v4()),
            channel_id: Some(Uuid::new_v4()),
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::TextMessage(TextMessagePayload {
                content: b"test message".to_vec(),
                message_type: TextMessageType::Regular,
                reply_to: None,
                mentions: vec![],
                attachments: vec![],
            }),
            signature: Some(vec![1, 2, 3, 4]),
        };

        let serialized = MessageSerializer::serialize(&original).unwrap();
        let deserialized = MessageSerializer::deserialize(&serialized).unwrap();

        assert_eq!(original.message_id, deserialized.message_id);
        assert_eq!(original.message_type, deserialized.message_type);
        assert_eq!(original.sender_id, deserialized.sender_id);
    }

    #[test]
    fn test_deserialize_invalid_data() {
        let invalid_data = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let result = MessageSerializer::deserialize(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_compressed_small_message() {
        let msg = MessageBuilder::new().build_heartbeat();
        let compressed = MessageSerializer::serialize_compressed(&msg).unwrap();

        // Small messages should not be compressed
        let normal = MessageSerializer::serialize(&msg).unwrap();
        assert_eq!(compressed, normal);
    }

    #[test]
    fn test_serialize_compressed_large_message() {
        let large_content = vec![0u8; 2048];
        let msg = NetworkMessage {
            message_id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender_id: Some(Uuid::new_v4()),
            target_id: None,
            channel_id: Some(Uuid::new_v4()),
            timestamp: chrono::Utc::now(),
            payload: MessagePayload::TextMessage(TextMessagePayload {
                content: large_content,
                message_type: TextMessageType::Regular,
                reply_to: None,
                mentions: vec![],
                attachments: vec![],
            }),
            signature: None,
        };

        let compressed = MessageSerializer::serialize_compressed(&msg).unwrap();
        let normal = MessageSerializer::serialize(&msg).unwrap();

        // Compressed should be smaller for large messages with repetitive data
        assert!(compressed.len() < normal.len());
    }

    // ── Edge Cases and Additional Tests ──

    #[test]
    fn test_attachment_info_encryption_flag() {
        let encrypted_attachment = AttachmentInfo {
            file_id: Uuid::new_v4(),
            filename: "secret.txt".to_string(),
            file_size: 100,
            content_type: "text/plain".to_string(),
            encrypted: true,
        };

        let unencrypted_attachment = AttachmentInfo {
            file_id: Uuid::new_v4(),
            filename: "public.txt".to_string(),
            file_size: 100,
            content_type: "text/plain".to_string(),
            encrypted: false,
        };

        assert!(encrypted_attachment.encrypted);
        assert!(!unencrypted_attachment.encrypted);
    }

    #[test]
    fn test_file_upload_payload_metadata() {
        let payload = FileUploadPayload {
            file_id: Uuid::new_v4(),
            filename: "document.pdf".to_string(),
            file_size: 1024 * 1024,
            content_type: "application/pdf".to_string(),
            chunk_size: 4096,
            total_chunks: 256,
            encrypted_metadata: vec![1, 2, 3, 4],
        };

        assert_eq!(payload.chunk_size, 4096);
        assert_eq!(payload.total_chunks, 256);
    }

    #[test]
    fn test_server_info_payload() {
        let payload = ServerInfoPayload {
            server_id: Uuid::new_v4(),
            server_name: "Test Server".to_string(),
            member_count: 100,
            channel_count: 10,
            features: vec!["voice".to_string(), "encryption".to_string()],
        };

        assert_eq!(payload.member_count, 100);
        assert_eq!(payload.features.len(), 2);
    }

    #[test]
    fn test_user_info_structure() {
        let user = UserInfo {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            status: UserStatus::Online,
            public_key: vec![1, 2, 3, 4],
        };

        assert_eq!(user.username, "testuser");
        assert_eq!(user.status, UserStatus::Online);
    }

    #[test]
    fn test_encryption_info() {
        let info = EncryptionInfo {
            algorithm: "AES-256-GCM".to_string(),
            key_version: 1,
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        assert_eq!(info.algorithm, "AES-256-GCM");
        assert_eq!(info.nonce.len(), 12);
    }

    #[test]
    fn test_typing_indicator_payload() {
        let typing = TypingPayload { is_typing: true };
        let not_typing = TypingPayload { is_typing: false };

        assert!(typing.is_typing);
        assert!(!not_typing.is_typing);
    }

    #[test]
    fn test_voice_speaking_payload() {
        let channel_id = Uuid::new_v4();
        let payload = VoiceSpeakingPayload {
            is_speaking: true,
            channel_id,
        };

        assert!(payload.is_speaking);
        assert_eq!(payload.channel_id, channel_id);
    }

    #[test]
    fn test_key_bundle_publish_payload() {
        use crate::session_manager::PublishableKeyBundle;

        let bundle = PublishableKeyBundle {
            identity_key: [1u8; 32],
            signed_prekey: [2u8; 32],
            one_time_prekeys: vec![[3u8; 32], [4u8; 32]],
        };

        let payload = KeyBundlePublishPayload { bundle };
        assert_eq!(payload.bundle.one_time_prekeys.len(), 2);
    }

    #[test]
    fn test_key_bundle_fetch_payload() {
        let target_user = Uuid::new_v4();
        let payload = KeyBundleFetchPayload {
            target_user_id: target_user,
        };

        assert_eq!(payload.target_user_id, target_user);
    }

    #[test]
    fn test_key_bundle_response_payload() {
        let payload = KeyBundleResponsePayload {
            user_id: Uuid::new_v4(),
            identity_key: [1u8; 32],
            signed_prekey: [2u8; 32],
            one_time_prekey: Some([3u8; 32]),
        };

        assert!(payload.one_time_prekey.is_some());
    }

    #[test]
    fn test_key_bundle_response_without_one_time_prekey() {
        let payload = KeyBundleResponsePayload {
            user_id: Uuid::new_v4(),
            identity_key: [1u8; 32],
            signed_prekey: [2u8; 32],
            one_time_prekey: None,
        };

        assert!(payload.one_time_prekey.is_none());
    }

    #[test]
    fn test_edit_payload() {
        let payload = EditPayload {
            original_message_id: Uuid::new_v4(),
            new_content: b"edited content".to_vec(),
            edit_timestamp: chrono::Utc::now(),
        };

        assert_eq!(payload.new_content, b"edited content");
    }

    #[test]
    fn test_delete_payload() {
        let msg_id = Uuid::new_v4();
        let payload = DeletePayload {
            message_id: msg_id,
            delete_timestamp: chrono::Utc::now(),
        };

        assert_eq!(payload.message_id, msg_id);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(MAX_MESSAGE_SIZE, 10 * 1024 * 1024);
    }
}
