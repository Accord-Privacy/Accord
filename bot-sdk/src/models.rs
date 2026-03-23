use serde::{Deserialize, Serialize};

/// Payload for a member joining a node.
///
/// Emitted when a user joins a node (via invite or direct join).
/// Maps to the server-side `member_joined` WebSocket event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemberJoin {
    /// The node the user joined.
    pub node_id: String,
    /// The user who joined.
    pub user_id: String,
    /// Display name of the user at join time.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Unix timestamp (seconds) of when the join occurred.
    #[serde(default)]
    pub timestamp: Option<u64>,
}

/// Payload for a member leaving a node.
///
/// Emitted when a user voluntarily leaves a node.
/// Maps to the server-side `member_left` WebSocket event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemberLeave {
    /// The node the user left.
    pub node_id: String,
    /// The user who left.
    pub user_id: String,
    /// Display name of the user (may be absent if profile was purged).
    #[serde(default)]
    pub display_name: Option<String>,
    /// Unix timestamp (seconds) of when the leave occurred.
    #[serde(default)]
    pub timestamp: Option<u64>,
}

/// A user on the Accord platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub custom_status: Option<String>,
}

/// A channel within a Node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<u64>,
}

/// A message in a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub channel_id: String,
    pub sender_id: String,
    #[serde(default)]
    pub sender_public_key_hash: Option<String>,
    /// For bots, this is the plaintext content (via `encrypted_data` field).
    #[serde(default)]
    pub content: Option<String>,
    /// Raw encrypted payload from the API.
    #[serde(default)]
    pub encrypted_payload: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub edited_at: Option<u64>,
    #[serde(default)]
    pub reply_to: Option<String>,
}

/// A role within a Node.
///
/// Roles define permission sets and can be assigned to node members.
/// They are ordered by `position` — higher values grant more authority.
/// The built-in `@everyone` role always has position `0`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Role {
    /// Unique role identifier (UUID).
    pub id: String,
    /// The node this role belongs to.
    pub node_id: String,
    /// Human-readable role name (e.g. `"Moderator"`).
    pub name: String,
    /// RGB color encoded as an integer (`0` = no color / default).
    #[serde(default)]
    pub color: u32,
    /// Permission bitmask. Each set bit enables a specific permission.
    #[serde(default)]
    pub permissions: u64,
    /// Hierarchy position — higher number = more authority. `@everyone` is always 0.
    #[serde(default)]
    pub position: i32,
    /// Whether members with this role appear separately in the member list.
    #[serde(default)]
    pub hoist: bool,
    /// Whether this role can be @mentioned by anyone.
    #[serde(default)]
    pub mentionable: bool,
    /// Optional Unicode emoji shown as the role icon.
    #[serde(default)]
    pub icon_emoji: Option<String>,
    /// Unix timestamp (seconds) when the role was created.
    #[serde(default)]
    pub created_at: Option<u64>,
}

/// A reaction on a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    #[serde(default)]
    pub count: u32,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub created_at: Option<u64>,
}

/// Events received from the WebSocket.
#[derive(Debug, Clone)]
pub enum Event {
    /// A new message was received in a channel.
    MessageCreate(Message),
    /// A message was edited.
    MessageEdit {
        message_id: String,
        channel_id: String,
        content: String,
        edited_at: u64,
    },
    /// A message was deleted.
    MessageDelete {
        message_id: String,
        channel_id: String,
    },
    /// A reaction was added.
    ReactionAdd {
        message_id: String,
        channel_id: String,
        user_id: String,
        emoji: String,
    },
    /// A reaction was removed.
    ReactionRemove {
        message_id: String,
        channel_id: String,
        user_id: String,
        emoji: String,
    },
    /// A user started typing.
    TypingStart { channel_id: String, user_id: String },
    /// A user joined a node.
    ///
    /// Fired when any member joins the node this bot is connected to.
    MemberJoin(MemberJoin),
    /// A user left a node.
    ///
    /// Fired when any member voluntarily leaves a node.
    MemberLeave(MemberLeave),
    /// Unknown/unhandled event.
    Unknown(serde_json::Value),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MemberJoin deserialization ──

    #[test]
    fn test_member_join_deserialize_full() {
        let json = r#"{
            "node_id": "node-abc",
            "user_id": "user-123",
            "display_name": "Alice",
            "timestamp": 1700000000
        }"#;
        let ev: MemberJoin = serde_json::from_str(json).unwrap();
        assert_eq!(ev.node_id, "node-abc");
        assert_eq!(ev.user_id, "user-123");
        assert_eq!(ev.display_name, Some("Alice".to_string()));
        assert_eq!(ev.timestamp, Some(1700000000));
    }

    #[test]
    fn test_member_join_deserialize_minimal() {
        // display_name and timestamp are optional
        let json = r#"{"node_id": "node-abc", "user_id": "user-123"}"#;
        let ev: MemberJoin = serde_json::from_str(json).unwrap();
        assert_eq!(ev.node_id, "node-abc");
        assert_eq!(ev.user_id, "user-123");
        assert!(ev.display_name.is_none());
        assert!(ev.timestamp.is_none());
    }

    #[test]
    fn test_member_join_roundtrip() {
        let orig = MemberJoin {
            node_id: "n1".to_string(),
            user_id: "u1".to_string(),
            display_name: Some("Bob".to_string()),
            timestamp: Some(999),
        };
        let json = serde_json::to_string(&orig).unwrap();
        let back: MemberJoin = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    // ── MemberLeave deserialization ──

    #[test]
    fn test_member_leave_deserialize_full() {
        let json = r#"{
            "node_id": "node-xyz",
            "user_id": "user-456",
            "display_name": "Bob",
            "timestamp": 1700000001
        }"#;
        let ev: MemberLeave = serde_json::from_str(json).unwrap();
        assert_eq!(ev.node_id, "node-xyz");
        assert_eq!(ev.user_id, "user-456");
        assert_eq!(ev.display_name, Some("Bob".to_string()));
        assert_eq!(ev.timestamp, Some(1700000001));
    }

    #[test]
    fn test_member_leave_deserialize_minimal() {
        let json = r#"{"node_id": "node-xyz", "user_id": "user-456"}"#;
        let ev: MemberLeave = serde_json::from_str(json).unwrap();
        assert_eq!(ev.node_id, "node-xyz");
        assert_eq!(ev.user_id, "user-456");
        assert!(ev.display_name.is_none());
        assert!(ev.timestamp.is_none());
    }

    #[test]
    fn test_member_leave_roundtrip() {
        let orig = MemberLeave {
            node_id: "n2".to_string(),
            user_id: "u2".to_string(),
            display_name: None,
            timestamp: Some(42),
        };
        let json = serde_json::to_string(&orig).unwrap();
        let back: MemberLeave = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    // ── User serde ──────────────────────────────────────────────────────

    #[test]
    fn test_user_deserialize_full() {
        let json = r#"{
            "user_id": "u-1",
            "display_name": "Alice",
            "avatar_url": "https://example.com/a.png",
            "bio": "Hello",
            "status": "online",
            "custom_status": "Working"
        }"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.user_id, "u-1");
        assert_eq!(user.display_name.as_deref(), Some("Alice"));
        assert_eq!(
            user.avatar_url.as_deref(),
            Some("https://example.com/a.png")
        );
        assert_eq!(user.bio.as_deref(), Some("Hello"));
        assert_eq!(user.status.as_deref(), Some("online"));
        assert_eq!(user.custom_status.as_deref(), Some("Working"));
    }

    #[test]
    fn test_user_deserialize_minimal() {
        let json = r#"{"user_id": "u-2"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.user_id, "u-2");
        assert!(user.display_name.is_none());
        assert!(user.avatar_url.is_none());
        assert!(user.bio.is_none());
        assert!(user.status.is_none());
        assert!(user.custom_status.is_none());
    }

    #[test]
    fn test_user_roundtrip() {
        let user = User {
            user_id: "u-3".to_string(),
            display_name: Some("Bob".to_string()),
            avatar_url: None,
            bio: Some("".to_string()),
            status: None,
            custom_status: None,
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.user_id, "u-3");
        assert_eq!(back.bio.as_deref(), Some(""));
    }

    // ── Channel serde ───────────────────────────────────────────────────

    #[test]
    fn test_channel_deserialize_full() {
        let json = r#"{
            "id": "ch-1",
            "name": "general",
            "node_id": "node-1",
            "created_at": 1700000000
        }"#;
        let ch: Channel = serde_json::from_str(json).unwrap();
        assert_eq!(ch.id, "ch-1");
        assert_eq!(ch.name, "general");
        assert_eq!(ch.node_id.as_deref(), Some("node-1"));
        assert_eq!(ch.created_at, Some(1700000000));
    }

    #[test]
    fn test_channel_deserialize_minimal() {
        let json = r#"{"id": "ch-2", "name": "random"}"#;
        let ch: Channel = serde_json::from_str(json).unwrap();
        assert_eq!(ch.id, "ch-2");
        assert_eq!(ch.name, "random");
        assert!(ch.node_id.is_none());
        assert!(ch.created_at.is_none());
    }

    #[test]
    fn test_channel_empty_name() {
        let json = r#"{"id": "ch-3", "name": ""}"#;
        let ch: Channel = serde_json::from_str(json).unwrap();
        assert_eq!(ch.name, "");
    }

    // ── Message serde ───────────────────────────────────────────────────

    #[test]
    fn test_message_deserialize_full() {
        let json = r#"{
            "id": "msg-1",
            "channel_id": "ch-1",
            "sender_id": "u-1",
            "sender_public_key_hash": "abcdef",
            "content": "Hello world",
            "encrypted_payload": "enc123",
            "display_name": "Alice",
            "created_at": 1700000000,
            "edited_at": 1700000100,
            "reply_to": "msg-0"
        }"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "msg-1");
        assert_eq!(msg.channel_id, "ch-1");
        assert_eq!(msg.sender_id, "u-1");
        assert_eq!(msg.sender_public_key_hash.as_deref(), Some("abcdef"));
        assert_eq!(msg.content.as_deref(), Some("Hello world"));
        assert_eq!(msg.encrypted_payload.as_deref(), Some("enc123"));
        assert_eq!(msg.display_name.as_deref(), Some("Alice"));
        assert_eq!(msg.created_at, Some(1700000000));
        assert_eq!(msg.edited_at, Some(1700000100));
        assert_eq!(msg.reply_to.as_deref(), Some("msg-0"));
    }

    #[test]
    fn test_message_deserialize_minimal() {
        let json = r#"{"id": "msg-2", "channel_id": "ch-1", "sender_id": "u-1"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.id, "msg-2");
        assert!(msg.content.is_none());
        assert!(msg.encrypted_payload.is_none());
        assert!(msg.display_name.is_none());
        assert!(msg.created_at.is_none());
        assert!(msg.edited_at.is_none());
        assert!(msg.reply_to.is_none());
    }

    #[test]
    fn test_message_roundtrip() {
        let msg = Message {
            id: "msg-3".to_string(),
            channel_id: "ch-1".to_string(),
            sender_id: "u-2".to_string(),
            sender_public_key_hash: None,
            content: Some("test content".to_string()),
            encrypted_payload: None,
            display_name: None,
            created_at: Some(99),
            edited_at: None,
            reply_to: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "msg-3");
        assert_eq!(back.content.as_deref(), Some("test content"));
        assert_eq!(back.created_at, Some(99));
    }

    // ── Role serde ──────────────────────────────────────────────────────

    #[test]
    fn test_role_deserialize_full() {
        let json = r#"{
            "id": "role-1",
            "node_id": "node-1",
            "name": "Admin",
            "color": 16711680,
            "permissions": 8,
            "position": 10,
            "hoist": true,
            "mentionable": true,
            "icon_emoji": "⭐",
            "created_at": 1700000000
        }"#;
        let role: Role = serde_json::from_str(json).unwrap();
        assert_eq!(role.id, "role-1");
        assert_eq!(role.name, "Admin");
        assert_eq!(role.color, 16711680);
        assert_eq!(role.permissions, 8);
        assert_eq!(role.position, 10);
        assert!(role.hoist);
        assert!(role.mentionable);
        assert_eq!(role.icon_emoji.as_deref(), Some("⭐"));
        assert_eq!(role.created_at, Some(1700000000));
    }

    #[test]
    fn test_role_deserialize_defaults() {
        let json = r#"{"id": "role-2", "node_id": "node-1", "name": "@everyone"}"#;
        let role: Role = serde_json::from_str(json).unwrap();
        assert_eq!(role.color, 0);
        assert_eq!(role.permissions, 0);
        assert_eq!(role.position, 0);
        assert!(!role.hoist);
        assert!(!role.mentionable);
        assert!(role.icon_emoji.is_none());
        assert!(role.created_at.is_none());
    }

    #[test]
    fn test_role_roundtrip() {
        let orig = Role {
            id: "role-3".to_string(),
            node_id: "node-1".to_string(),
            name: "Mod".to_string(),
            color: 255,
            permissions: 0xF,
            position: 5,
            hoist: true,
            mentionable: false,
            icon_emoji: Some("🔧".to_string()),
            created_at: Some(42),
        };
        let json = serde_json::to_string(&orig).unwrap();
        let back: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(orig, back);
    }

    // ── Reaction serde ──────────────────────────────────────────────────

    #[test]
    fn test_reaction_deserialize_full() {
        let json = r#"{
            "emoji": "👍",
            "count": 3,
            "users": ["u-1", "u-2", "u-3"],
            "created_at": 1700000000
        }"#;
        let r: Reaction = serde_json::from_str(json).unwrap();
        assert_eq!(r.emoji, "👍");
        assert_eq!(r.count, 3);
        assert_eq!(r.users.len(), 3);
        assert_eq!(r.created_at, Some(1700000000));
    }

    #[test]
    fn test_reaction_deserialize_minimal() {
        let json = r#"{"emoji": "❤️"}"#;
        let r: Reaction = serde_json::from_str(json).unwrap();
        assert_eq!(r.emoji, "❤️");
        assert_eq!(r.count, 0);
        assert!(r.users.is_empty());
        assert!(r.created_at.is_none());
    }

    #[test]
    fn test_reaction_empty_users_vec() {
        let json = r#"{"emoji": "🎉", "count": 0, "users": []}"#;
        let r: Reaction = serde_json::from_str(json).unwrap();
        assert!(r.users.is_empty());
        assert_eq!(r.count, 0);
    }

    // ── Missing required fields → error ─────────────────────────────────

    #[test]
    fn test_message_missing_required_fails() {
        // Missing sender_id — should fail
        let json = r#"{"id": "msg-x", "channel_id": "ch-1"}"#;
        assert!(serde_json::from_str::<Message>(json).is_err());
    }

    #[test]
    fn test_role_missing_name_fails() {
        let json = r#"{"id": "r-x", "node_id": "n-1"}"#;
        assert!(serde_json::from_str::<Role>(json).is_err());
    }

    #[test]
    fn test_channel_missing_name_fails() {
        let json = r#"{"id": "ch-x"}"#;
        assert!(serde_json::from_str::<Channel>(json).is_err());
    }

    #[test]
    fn test_user_missing_user_id_fails() {
        let json = r#"{"display_name": "Alice"}"#;
        assert!(serde_json::from_str::<User>(json).is_err());
    }
}
