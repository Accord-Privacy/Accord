//! Data models for the Accord relay server

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User information stored on the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub public_key: String,
    pub created_at: u64,
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub token: String,
    pub user_id: Uuid,
    pub expires_at: u64,
}

/// Channel information (now scoped to a Node)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: Uuid,
    pub name: String,
    pub node_id: Uuid,
    pub members: Vec<Uuid>,
    pub created_at: u64,
}

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsMessageType {
    // ── Node operations ──
    /// Create a new Node
    CreateNode { name: String, description: Option<String> },
    /// Join an existing Node
    JoinNode { node_id: Uuid },
    /// Leave a Node
    LeaveNode { node_id: Uuid },
    /// Request Node info
    GetNodeInfo { node_id: Uuid },

    // ── Channel operations (scoped to Node) ──
    /// Join a channel within a Node
    JoinChannel { channel_id: Uuid },
    /// Leave a channel
    LeaveChannel { channel_id: Uuid },
    /// Create a channel in a Node
    CreateChannel { node_id: Uuid, name: String },

    // ── Messaging ──
    /// Direct message to a user (encrypted blob)
    DirectMessage {
        to_user: Uuid,
        encrypted_data: String,
    },
    /// Channel message (encrypted blob)
    ChannelMessage {
        channel_id: Uuid,
        encrypted_data: String,
    },

    // ── Voice operations ──
    /// Join a voice channel
    JoinVoiceChannel { channel_id: Uuid },
    /// Leave a voice channel
    LeaveVoiceChannel { channel_id: Uuid },
    /// Voice packet (encrypted audio data)
    VoicePacket {
        channel_id: Uuid,
        encrypted_audio: Vec<u8>,
        sequence: u64,
    },
    /// Voice speaking state change
    VoiceSpeakingState {
        channel_id: Uuid,
        user_id: Uuid,
        speaking: bool,
    },

    /// Heartbeat
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
    pub public_key: String,
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
    pub password: String,
}

/// Authentication response
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: Uuid,
    pub expires_at: u64,
}

/// Create Node request (REST)
#[derive(Debug, Deserialize)]
pub struct CreateNodeRequest {
    pub name: String,
    pub description: Option<String>,
}

/// Node invite information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInvite {
    pub id: Uuid,
    pub node_id: Uuid,
    pub created_by: Uuid,
    pub invite_code: String,
    pub max_uses: Option<u32>,
    pub current_uses: u32,
    pub expires_at: Option<u64>,
    pub created_at: u64,
}

/// Create Node invite request
#[derive(Debug, Deserialize)]
pub struct CreateInviteRequest {
    pub max_uses: Option<u32>,
    pub expires_in_hours: Option<u32>,
}

/// Create Node invite response
#[derive(Debug, Serialize)]
pub struct CreateInviteResponse {
    pub id: Uuid,
    pub invite_code: String,
    pub max_uses: Option<u32>,
    pub expires_at: Option<u64>,
    pub created_at: u64,
}

/// Use invite response
#[derive(Debug, Serialize)]
pub struct UseInviteResponse {
    pub status: String,
    pub node_id: Uuid,
    pub node_name: String,
}

/// Generic error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

/// Permission denied error response
#[derive(Debug, Serialize)]
pub struct PermissionDeniedResponse {
    pub error: String,
    pub code: u16,
    pub required_permission: String,
    pub user_role: String,
}

impl PermissionDeniedResponse {
    pub fn new(required_permission: &str, user_role: &str) -> Self {
        Self {
            error: format!("Permission denied. Required: {}, Your role: {}", required_permission, user_role),
            code: 403,
            required_permission: required_permission.to_string(),
            user_role: user_role.to_string(),
        }
    }
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}
