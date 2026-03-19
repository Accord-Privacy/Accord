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
}
