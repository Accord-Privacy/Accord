//! # Accord Core (Minimal Implementation)
//!
//! Simplified implementation for testing and demonstration purposes.
//! Production version will use proper cryptographic libraries.

pub mod channel_types;
pub mod crypto_minimal;
pub mod demo;
pub mod network_protocol;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Accord protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Initialize the minimal Accord implementation
pub fn init() -> Result<(), String> {
    println!("🔒 Accord Core (Minimal) v{}", env!("CARGO_PKG_VERSION"));
    println!("⚠️  Using simplified crypto for demonstration");
    println!("🎯 Full cryptography in production build");
    Ok(())
}

/// Message types in the Accord system
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    TextMessage,
    VoicePacket,
    ChannelJoin,
    ChannelLeave,
    BotCommand,
    InviteCreate,
    Heartbeat,
}

/// Core message structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccordMessage {
    pub id: Uuid,
    pub message_type: MessageType,
    pub sender: Option<Uuid>,
    pub channel: Option<Uuid>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub encrypted_payload: Vec<u8>,
}

/// User identity in the system
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub public_key_fingerprint: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Server information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Server {
    pub id: Uuid,
    pub name: String,
    pub member_count: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }

    #[test]
    fn test_message_creation() {
        let msg = AccordMessage {
            id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender: Some(Uuid::new_v4()),
            channel: Some(Uuid::new_v4()),
            timestamp: chrono::Utc::now(),
            encrypted_payload: b"test message".to_vec(),
        };

        assert_eq!(msg.message_type, MessageType::TextMessage);
    }
}
