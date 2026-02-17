//! Data models for the Accord relay server

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User information stored on the server
///
/// The relay identifies users by UUID and public_key_hash only.
/// Usernames are a Node-level concept — the relay does not store human-readable names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    /// SHA-256 hash of the user's public key (hex-encoded). Primary relay-level identifier.
    pub public_key_hash: String,
    pub public_key: String,
    pub created_at: u64,
}

/// Per-Node user profile (encrypted, stored on the relay but opaque to it)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeUserProfile {
    pub node_id: Uuid,
    pub user_id: Uuid,
    /// Encrypted with the Node metadata key — relay cannot read this
    pub encrypted_display_name: Option<Vec<u8>>,
    /// Encrypted with the Node metadata key — relay cannot read this
    pub encrypted_avatar_url: Option<Vec<u8>>,
    pub joined_at: u64,
}

/// Ban entry for a Node (keyed on public_key_hash for identity-based bans)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeBan {
    pub node_id: Uuid,
    pub public_key_hash: String,
    pub banned_by: Uuid,
    pub banned_at: u64,
    /// Encrypted with the Node metadata key — relay cannot read the reason
    pub reason_encrypted: Option<Vec<u8>>,
    pub expires_at: Option<u64>,
    /// Optional device fingerprint hash (for device-level ban enforcement)
    #[serde(default)]
    pub device_fingerprint_hash: Option<String>,
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

/// Channel category information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCategory {
    pub id: Uuid,
    pub node_id: Uuid,
    pub name: String,
    pub position: u32,
    pub created_at: u64,
}

/// Channel information with category details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelWithCategory {
    pub id: Uuid,
    pub name: String,
    pub node_id: Uuid,
    pub members: Vec<Uuid>,
    pub created_at: u64,
    pub category_id: Option<Uuid>,
    pub category_name: Option<String>,
    pub position: u32,
}

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsMessageType {
    // ── Node operations ──
    /// Create a new Node
    CreateNode {
        name: String,
        description: Option<String>,
    },
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
    /// Update a channel's category and position
    UpdateChannel {
        channel_id: Uuid,
        category_id: Option<Uuid>,
        position: Option<u32>,
    },

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
        #[serde(default)]
        reply_to: Option<Uuid>,
    },
    /// Edit a message (author only)
    EditMessage {
        message_id: Uuid,
        encrypted_data: String,
    },
    /// Delete a message (author or admin/mod)
    DeleteMessage { message_id: Uuid },

    // ── Reaction operations ──
    /// Add a reaction to a message
    AddReaction { message_id: Uuid, emoji: String },
    /// Remove a reaction from a message
    RemoveReaction { message_id: Uuid, emoji: String },

    /// Pin a message (admin/mod only)
    PinMessage { message_id: Uuid },
    /// Unpin a message (admin/mod only)
    UnpinMessage { message_id: Uuid },

    // ── Typing operations ──
    /// User started typing in a channel
    TypingStart { channel_id: Uuid },

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
    /// SRTP voice key exchange (opaque to server)
    VoiceKeyExchange {
        channel_id: Uuid,
        /// Base64-encoded wrapped key data
        wrapped_key: String,
        target_user_id: Option<Uuid>,
        sender_ssrc: u32,
        key_generation: u32,
    },
    /// SRTP encrypted voice packet (opaque to server)
    SrtpVoicePacket {
        channel_id: Uuid,
        /// Base64-encoded SrtpPacket
        packet_data: String,
    },

    // ── Key exchange operations (Double Ratchet / X3DH) ──
    /// Publish prekey bundle
    PublishKeyBundle {
        identity_key: String,
        signed_prekey: String,
        one_time_prekeys: Vec<String>,
    },
    /// Fetch another user's prekey bundle
    FetchKeyBundle { target_user_id: Uuid },
    /// Store a prekey message for offline user
    StorePrekeyMessage {
        recipient_id: Uuid,
        message_data: String,
    },
    /// Retrieve pending prekey messages
    GetPrekeyMessages,

    // ── P2P Voice Signaling ──
    /// P2P voice signaling: relay ICE candidates and offer/answer between peers.
    /// The server forwards this opaquely — it cannot interpret the content.
    P2PSignal {
        channel_id: Uuid,
        target_user_id: Uuid,
        /// JSON-serialized P2PSignal from accord_core::p2p_voice
        signal_data: String,
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

/// Registration request — keypair-only, no username at relay level
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Deprecated: ignored by the relay. Kept for backward API compat.
    #[serde(default)]
    pub username: String,
    pub public_key: String,
    #[serde(default)]
    pub password: String,
}

/// Registration response
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub message: String,
}

/// Authentication request — authenticate by public_key (or public_key_hash) + password
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    /// Deprecated: use public_key or public_key_hash instead. Kept for backward compat.
    #[serde(default)]
    pub username: String,
    pub password: String,
    /// The user's public key — relay will compute SHA-256 hash to look up the user.
    #[serde(default)]
    pub public_key: Option<String>,
    /// Alternatively, provide the hex-encoded SHA-256 hash directly.
    #[serde(default)]
    pub public_key_hash: Option<String>,
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

/// Create channel category request (REST)
#[derive(Debug, Deserialize)]
pub struct CreateChannelCategoryRequest {
    pub name: String,
}

/// Create channel category response (REST)
#[derive(Debug, Serialize)]
pub struct CreateChannelCategoryResponse {
    pub id: Uuid,
    pub name: String,
    pub position: u32,
    pub created_at: u64,
}

/// Update channel category request (REST)
#[derive(Debug, Deserialize)]
pub struct UpdateChannelCategoryRequest {
    pub name: Option<String>,
    pub position: Option<u32>,
}

/// Update channel request (REST)
#[derive(Debug, Deserialize)]
pub struct UpdateChannelRequest {
    pub category_id: Option<Uuid>,
    pub position: Option<u32>,
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

/// Edit message request
#[derive(Debug, Deserialize)]
pub struct EditMessageRequest {
    pub encrypted_data: String,
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
            error: format!(
                "Permission denied. Required: {}, Your role: {}",
                required_permission, user_role
            ),
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

/// User profile information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: Uuid,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub status: String, // online, idle, dnd, offline
    pub custom_status: Option<String>,
    pub updated_at: u64,
}

/// Request to update user profile
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub status: Option<String>,
    pub custom_status: Option<String>,
}

/// User presence information for broadcasting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPresence {
    pub user_id: Uuid,
    pub status: String,
    pub custom_status: Option<String>,
    pub updated_at: u64,
}

/// Node member with profile information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberWithProfile {
    pub user_id: Uuid,
    /// Public key hash (hex). No username at relay level.
    pub public_key_hash: String,
    pub role: crate::node::NodeRole,
    pub joined_at: u64,
    pub profile: UserProfile,
}

/// Message metadata for history (encrypted content is opaque to server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub sender_id: Uuid,
    /// Sender's public_key_hash (hex). Display name comes from Node-level profile.
    pub sender_public_key_hash: String,
    pub encrypted_payload: String, // Base64 encoded encrypted content
    pub created_at: u64,
    pub edited_at: Option<u64>,
    pub pinned_at: Option<u64>,
    pub pinned_by: Option<Uuid>,
    pub reply_to: Option<Uuid>,
    pub replied_message: Option<RepliedMessage>, // Preview of the message being replied to
}

/// Preview of a replied-to message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepliedMessage {
    pub id: Uuid,
    pub sender_id: Uuid,
    /// Sender's public_key_hash (hex). Display name comes from Node-level profile.
    pub sender_public_key_hash: String,
    pub encrypted_payload: String, // Base64 encoded encrypted content (snippet)
    pub created_at: u64,
}

/// File metadata for encrypted file sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub uploader_id: Uuid,
    pub encrypted_filename: Vec<u8>, // Encrypted filename (server can't read)
    pub file_size_bytes: i64,
    pub content_hash: String, // SHA-256 of encrypted content
    pub storage_path: String,
    pub created_at: u64,
}

/// Response for paginated message history
#[derive(Debug, Serialize)]
pub struct MessageHistoryResponse {
    pub messages: Vec<MessageMetadata>,
    pub has_more: bool,
    pub next_cursor: Option<Uuid>, // message_id for pagination
}

/// Search result containing message metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub message_id: Uuid,
    pub channel_id: Uuid,
    pub channel_name: String,
    pub sender_id: Uuid,
    pub sender_public_key_hash: String,
    pub created_at: u64,
    pub encrypted_payload: String, // Base64 encoded - content search must happen client-side
}

/// Response for search messages
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
    pub total_count: u32,
    pub search_query: String,
    pub note: String, // Explains that content search requires client-side decryption
}

/// Message reaction with count and user list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReaction {
    pub emoji: String,
    pub count: u32,
    pub users: Vec<Uuid>, // List of user IDs who reacted with this emoji
    pub created_at: u64,  // When the first reaction with this emoji was added
}

/// Response for get message reactions
#[derive(Debug, Serialize)]
pub struct MessageReactionsResponse {
    pub reactions: Vec<MessageReaction>,
}

/// Direct Message channel between two users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmChannel {
    pub id: Uuid,
    pub user1_id: Uuid,
    pub user2_id: Uuid,
    pub created_at: u64,
}

/// DM channel with last message preview and user info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmChannelWithInfo {
    pub id: Uuid,
    pub user1_id: Uuid,
    pub user2_id: Uuid,
    pub other_user: User,
    pub other_user_profile: UserProfile,
    pub last_message: Option<MessageMetadata>,
    pub unread_count: u32,
    pub created_at: u64,
}

/// Response for list user DM channels
#[derive(Debug, Serialize)]
pub struct DmChannelsResponse {
    pub dm_channels: Vec<DmChannelWithInfo>,
}

/// Audit log entry for Node management actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub node_id: Uuid,
    pub actor_id: Uuid,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<Uuid>,
    pub details: Option<String>, // JSON string with additional context
    pub created_at: u64,
}

/// Response for paginated audit log
#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditLogWithActor>,
    pub has_more: bool,
    pub next_cursor: Option<Uuid>, // entry_id for pagination
}

// ── Key Bundle models (Double Ratchet / X3DH) ──

/// Request to publish a prekey bundle
#[derive(Debug, Deserialize)]
pub struct PublishKeyBundleRequest {
    pub identity_key: String,          // base64
    pub signed_prekey: String,         // base64
    pub one_time_prekeys: Vec<String>, // base64
}

/// Response after publishing a prekey bundle
#[derive(Debug, Serialize)]
pub struct PublishKeyBundleResponse {
    pub status: String,
    pub one_time_prekeys_stored: usize,
}

/// Response for fetching a user's prekey bundle
#[derive(Debug, Serialize)]
pub struct FetchKeyBundleResponse {
    pub user_id: Uuid,
    pub identity_key: String,            // base64
    pub signed_prekey: String,           // base64
    pub one_time_prekey: Option<String>, // base64 (consumed)
}

/// Request to store a prekey message (X3DH initial message)
#[derive(Debug, Deserialize)]
pub struct StorePrekeyMessageRequest {
    pub recipient_id: Uuid,
    pub message_data: String, // base64
}

/// Prekey message retrieved by recipient
#[derive(Debug, Serialize)]
pub struct PrekeyMessageResponse {
    pub id: Uuid,
    pub sender_id: Uuid,
    pub message_data: String, // base64
    pub created_at: u64,
}

// ── Push notification models ──

/// Platform for push notifications
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    Ios,
    Android,
}

impl PushPlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            PushPlatform::Ios => "ios",
            PushPlatform::Android => "android",
        }
    }
}

impl std::str::FromStr for PushPlatform {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ios" => Ok(PushPlatform::Ios),
            "android" => Ok(PushPlatform::Android),
            _ => Err(format!("unknown platform: {}", s)),
        }
    }
}

/// User preference for how much info appears in push notifications
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotificationPrivacy {
    /// Show sender display name and channel
    Full,
    /// Show "New message" only
    #[default]
    Partial,
    /// Silent background wake — no visible notification
    Stealth,
}

impl NotificationPrivacy {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationPrivacy::Full => "full",
            NotificationPrivacy::Partial => "partial",
            NotificationPrivacy::Stealth => "stealth",
        }
    }
}

impl std::str::FromStr for NotificationPrivacy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "full" => Ok(NotificationPrivacy::Full),
            "partial" => Ok(NotificationPrivacy::Partial),
            "stealth" => Ok(NotificationPrivacy::Stealth),
            _ => Err(format!("unknown privacy level: {}", s)),
        }
    }
}

/// A registered device token for push notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub platform: PushPlatform,
    pub token: String,
    pub privacy_level: NotificationPrivacy,
    pub created_at: u64,
}

/// Request to register a device token
#[derive(Debug, Deserialize)]
pub struct RegisterDeviceTokenRequest {
    pub platform: PushPlatform,
    pub token: String,
    #[serde(default)]
    pub privacy_level: Option<NotificationPrivacy>,
}

/// Response after registering a device token
#[derive(Debug, Serialize)]
pub struct RegisterDeviceTokenResponse {
    pub id: Uuid,
    pub status: String,
}

/// Request to deregister a device token
#[derive(Debug, Deserialize)]
pub struct DeregisterDeviceTokenRequest {
    pub token: String,
}

/// Request to update push notification preferences
#[derive(Debug, Deserialize)]
pub struct UpdatePushPreferencesRequest {
    pub privacy_level: NotificationPrivacy,
    /// Optional: only update for a specific token
    pub token: Option<String>,
}

/// Audit log entry with actor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogWithActor {
    pub id: Uuid,
    pub node_id: Uuid,
    pub actor_id: Uuid,
    pub actor_public_key_hash: String,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<Uuid>,
    pub details: Option<String>,
    pub created_at: u64,
}

/// Request to ban a user from a Node
#[derive(Debug, Deserialize)]
pub struct BanUserRequest {
    /// The hex-encoded SHA-256 hash of the public key to ban
    pub public_key_hash: String,
    /// Encrypted reason (opaque to relay)
    #[serde(default)]
    pub reason_encrypted: Option<String>,
    /// Optional expiration timestamp (Unix seconds)
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Optional device fingerprint hash to also ban the device
    #[serde(default)]
    pub device_fingerprint_hash: Option<String>,
}

/// Request to unban a user from a Node
#[derive(Debug, Deserialize)]
pub struct UnbanUserRequest {
    /// The hex-encoded SHA-256 hash of the public key to unban
    pub public_key_hash: String,
}

/// Response for listing bans
#[derive(Debug, Serialize)]
pub struct NodeBansResponse {
    pub bans: Vec<NodeBan>,
}

/// Friend request between two users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendRequest {
    pub id: Uuid,
    pub from_user_id: Uuid,
    pub to_user_id: Uuid,
    pub node_id: Uuid,
    pub dm_key_bundle: Option<Vec<u8>>,
    pub created_at: u64,
    pub status: String, // pending, accepted, rejected
}

/// Friendship record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Friendship {
    pub user_a_hash: String,
    pub user_b_hash: String,
    pub friendship_proof: Option<Vec<u8>>,
    pub established_at: u64,
}

/// Request to send a friend request
#[derive(Debug, Deserialize)]
pub struct SendFriendRequestRequest {
    pub to_user_id: Uuid,
    pub node_id: Uuid,
    #[serde(default)]
    pub dm_key_bundle: Option<String>, // base64
}

/// Request to accept a friend request
#[derive(Debug, Deserialize)]
pub struct AcceptFriendRequestRequest {
    pub request_id: Uuid,
    #[serde(default)]
    pub friendship_proof: Option<String>, // base64
}

/// Request to reject a friend request
#[derive(Debug, Deserialize)]
pub struct RejectFriendRequestRequest {
    pub request_id: Uuid,
}

// ── Raw types for per-Node DB layer (without relay-level joins) ──

/// Raw message metadata from per-Node DB (no public_key_hash — needs relay lookup)
#[derive(Debug, Clone)]
pub struct MessageMetadataRaw {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub sender_id: Uuid,
    pub encrypted_payload: Vec<u8>,
    pub created_at: u64,
    pub edited_at: Option<u64>,
    pub pinned_at: Option<u64>,
    pub pinned_by: Option<Uuid>,
    pub reply_to: Option<Uuid>,
    pub replied_message: Option<RepliedMessageRaw>,
    pub _node_id: Uuid,
}

/// Raw replied message (no public_key_hash)
#[derive(Debug, Clone)]
pub struct RepliedMessageRaw {
    pub id: Uuid,
    pub sender_id: Uuid,
    pub encrypted_payload: Vec<u8>,
    pub created_at: u64,
}

/// Raw search result from per-Node DB
#[derive(Debug, Clone)]
pub struct SearchResultRaw {
    pub message_id: Uuid,
    pub channel_id: Uuid,
    pub channel_name: String,
    pub sender_id: Uuid,
    pub created_at: u64,
    pub encrypted_payload: Vec<u8>,
}

/// Raw audit log entry from per-Node DB (no actor public_key_hash)
#[derive(Debug, Clone)]
pub struct AuditLogRaw {
    pub id: Uuid,
    pub node_id: Uuid,
    pub actor_id: Uuid,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<Uuid>,
    pub details: Option<String>,
    pub created_at: u64,
}

/// Request to set a per-Node user profile
#[derive(Debug, Deserialize)]
pub struct SetNodeUserProfileRequest {
    /// Encrypted display name (base64, encrypted with Node metadata key)
    #[serde(default)]
    pub encrypted_display_name: Option<String>,
    /// Encrypted avatar URL (base64, encrypted with Node metadata key)
    #[serde(default)]
    pub encrypted_avatar_url: Option<String>,
}
