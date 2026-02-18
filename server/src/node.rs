//! Node model and management for multi-tenant architecture
//!
//! A Node is a community space (like a Discord server). Users join Nodes,
//! each Node has its own channels, members, and admins.
//! Server admin ≠ Node admin — they are independent.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Role of a user within a Node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Admin,
    Moderator,
    Member,
}

impl NodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeRole::Admin => "admin",
            NodeRole::Moderator => "moderator",
            NodeRole::Member => "member",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(NodeRole::Admin),
            "moderator" => Some(NodeRole::Moderator),
            "member" => Some(NodeRole::Member),
            _ => None,
        }
    }
}

/// Policy for who can create Nodes on this server
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeCreationPolicy {
    /// Only server admin can create Nodes
    AdminOnly,
    /// Anyone can create a Node
    #[default]
    Open,
    /// Nodes require approval from server admin
    Approval,
    /// Nodes can only be created via invite
    Invite,
}

/// A Node (community space)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub description: Option<String>,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_hash: Option<String>,
}

/// Node membership info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMember {
    pub node_id: Uuid,
    pub user_id: Uuid,
    pub role: NodeRole,
    pub joined_at: u64,
}

/// Full Node info with member list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    #[serde(flatten)]
    pub node: Node,
    pub members: Vec<NodeMember>,
    pub channel_count: u64,
}
