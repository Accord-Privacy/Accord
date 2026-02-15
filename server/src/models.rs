//! Data models for the Accord relay server

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// User information stored on the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub public_key: String, // Base64-encoded public identity key
    pub created_at: u64,    // Unix timestamp
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub token: String,
    pub user_id: Uuid,
    pub expires_at: u64, // Unix timestamp
}

/// Channel information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<Uuid>,
    pub created_at: u64,
}

/// WebSocket message types that the server understands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsMessageType {
    /// Join a channel
    JoinChannel { channel_id: Uuid },
    /// Leave a channel
    LeaveChannel { channel_id: Uuid },
    /// Direct message to a user (encrypted blob)
    DirectMessage { 
        to_user: Uuid, 
        encrypted_data: String, // Base64-encoded encrypted blob
    },
    /// Channel message (encrypted blob)
    ChannelMessage { 
        channel_id: Uuid, 
        encrypted_data: String, // Base64-encoded encrypted blob
    },
    /// Heartbeat/keepalive
    Ping,
    /// Response to ping
    Pong,
}

/// WebSocket message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub message_type: WsMessageType,
    pub message_id: Uuid,
    pub timestamp: u64,
}

/// Registration request
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub public_key: String, // Base64-encoded public identity key
}

/// Registration response
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub message: String,
}

/// Authentication request
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    // For now, simple password or token-based auth
    pub password: String,
}

/// Authentication response
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: Uuid,
    pub expires_at: u64,
}

/// Generic error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}