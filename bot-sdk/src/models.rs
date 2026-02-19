use serde::{Deserialize, Serialize};

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
    /// Unknown/unhandled event.
    Unknown(serde_json::Value),
}
