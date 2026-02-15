//! State management for the Accord relay server with SQLite persistence

use crate::db::Database;
use crate::models::{AuthToken, Channel};
use crate::node::{Node, NodeCreationPolicy, NodeInfo, NodeRole};
use crate::permissions::{Permission, has_permission};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

/// Application state shared across handlers
pub struct AppState {
    /// Database connection for persistent storage
    pub db: Database,
    /// Active authentication tokens (in-memory for performance)
    pub auth_tokens: RwLock<HashMap<String, AuthToken>>,
    /// Active WebSocket connections indexed by user ID
    pub connections: RwLock<HashMap<Uuid, broadcast::Sender<String>>>,
    /// Voice channels state (channel_id -> set of user_ids)
    pub voice_channels: RwLock<HashMap<Uuid, HashSet<Uuid>>>,
    /// Server start time
    pub start_time: u64,
    /// Node creation policy
    pub node_creation_policy: NodeCreationPolicy,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db", &"<Database>")
            .field("start_time", &self.start_time)
            .field("node_creation_policy", &self.node_creation_policy)
            .finish()
    }
}

impl AppState {
    /// Create new application state with database connection
    pub async fn new(db_path: &str) -> Result<Self> {
        let db = Database::new(db_path).await?;
        Ok(Self {
            db,
            auth_tokens: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
            voice_channels: RwLock::new(HashMap::new()),
            start_time: now(),
            node_creation_policy: NodeCreationPolicy::default(),
        })
    }

    /// Create new application state with in-memory database (for testing)
    pub async fn new_in_memory() -> Result<Self> {
        Self::new(":memory:").await
    }

    // ── User operations ──

    pub async fn register_user(&self, username: String, public_key: String) -> Result<Uuid, String> {
        match self.db.username_exists(&username).await {
            Ok(true) => return Err("Username already exists".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
            _ => {}
        }
        match self.db.create_user(&username, &public_key).await {
            Ok(user) => Ok(user.id),
            Err(e) => Err(format!("Failed to create user: {}", e)),
        }
    }

    pub async fn authenticate_user(&self, username: String, _password: String) -> Result<AuthToken, String> {
        let user = match self.db.get_user_by_username(&username).await {
            Ok(Some(user)) => user,
            Ok(None) => return Err("User not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        };

        let token = format!("tok_{}", Uuid::new_v4().simple());
        let expires_at = now() + 86400;

        let auth_token = AuthToken {
            token: token.clone(),
            user_id: user.id,
            expires_at,
        };

        self.auth_tokens.write().await.insert(token, auth_token.clone());
        Ok(auth_token)
    }

    pub async fn validate_token(&self, token: &str) -> Option<Uuid> {
        let auth_tokens = self.auth_tokens.read().await;
        let auth_token = auth_tokens.get(token)?;
        if auth_token.expires_at > now() {
            Some(auth_token.user_id)
        } else {
            None
        }
    }

    // ── Node operations ──

    pub async fn create_node(&self, name: String, owner_id: Uuid, description: Option<String>) -> Result<Node, String> {
        match self.node_creation_policy {
            NodeCreationPolicy::Open => {}
            NodeCreationPolicy::AdminOnly => {
                return Err("Only server admin can create nodes".to_string());
            }
            NodeCreationPolicy::Approval => {
                return Err("Node creation requires approval (not yet implemented)".to_string());
            }
            NodeCreationPolicy::Invite => {
                return Err("Node creation requires an invite (not yet implemented)".to_string());
            }
        }

        match self.db.create_node(&name, owner_id, description.as_deref()).await {
            Ok(node) => Ok(node),
            Err(e) => Err(format!("Failed to create node: {}", e)),
        }
    }

    pub async fn get_node_info(&self, node_id: Uuid) -> Result<NodeInfo, String> {
        let node = match self.db.get_node(node_id).await {
            Ok(Some(n)) => n,
            Ok(None) => return Err("Node not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        };
        let members = self.db.get_node_members(node_id).await.map_err(|e| e.to_string())?;
        let channel_count = self.db.count_node_channels(node_id).await.map_err(|e| e.to_string())?;

        Ok(NodeInfo { node, members, channel_count })
    }

    pub async fn get_node_member(&self, node_id: Uuid, user_id: Uuid) -> Result<Option<crate::node::NodeMember>, String> {
        self.db.get_node_member(node_id, user_id).await.map_err(|e| e.to_string())
    }

    pub async fn join_node(&self, user_id: Uuid, node_id: Uuid) -> Result<(), String> {
        // Check node exists
        match self.db.get_node(node_id).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err("Node not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        }
        // Check not already member
        if self.db.is_node_member(node_id, user_id).await.unwrap_or(false) {
            return Err("Already a member of this node".to_string());
        }
        self.db.add_node_member(node_id, user_id, NodeRole::Member).await.map_err(|e| e.to_string())
    }

    pub async fn leave_node(&self, user_id: Uuid, node_id: Uuid) -> Result<(), String> {
        // Check node exists
        let node = match self.db.get_node(node_id).await {
            Ok(Some(n)) => n,
            Ok(None) => return Err("Node not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        };
        if node.owner_id == user_id {
            return Err("Node owner cannot leave their own node".to_string());
        }
        self.db.remove_node_member(node_id, user_id).await.map_err(|e| e.to_string())
    }

    pub async fn kick_from_node(&self, admin_id: Uuid, target_id: Uuid, node_id: Uuid) -> Result<(), String> {
        // Check if user has permission to kick members
        let member = self.db.get_node_member(node_id, admin_id).await.map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::KickMembers) {
                    return Err("Insufficient permissions to kick members".to_string());
                }
            }
            None => return Err("Must be a member of the node".to_string()),
        }
        // Can't kick the owner
        let node = self.db.get_node(node_id).await.map_err(|e| e.to_string())?.ok_or("Node not found")?;
        if node.owner_id == target_id {
            return Err("Cannot kick the node owner".to_string());
        }
        self.db.remove_node_member(node_id, target_id).await.map_err(|e| e.to_string())
    }

    // ── Node invite operations ──

    pub async fn create_invite(&self, node_id: Uuid, created_by: Uuid, max_uses: Option<u32>, expires_in_hours: Option<u32>) -> Result<(Uuid, String), String> {
        // Check if user has permission to manage invites
        let member = self.db.get_node_member(node_id, created_by).await.map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::ManageInvites) {
                    return Err("Insufficient permissions to create invites".to_string());
                }
            }
            None => return Err("Must be a member of the node".to_string()),
        }

        // Generate invite code (8 character alphanumeric)
        let invite_code = generate_invite_code();
        
        // Calculate expiration timestamp
        let expires_at = expires_in_hours.map(|hours| now() + (hours as u64 * 3600));

        let invite_id = self.db.create_node_invite(node_id, created_by, &invite_code, max_uses, expires_at)
            .await.map_err(|e| e.to_string())?;

        Ok((invite_id, invite_code))
    }

    pub async fn use_invite(&self, invite_code: &str, user_id: Uuid) -> Result<(Uuid, String), String> {
        // Get invite by code
        let invite = match self.db.get_node_invite_by_code(invite_code).await.map_err(|e| e.to_string())? {
            Some(invite) => invite,
            None => return Err("Invalid invite code".to_string()),
        };

        // Check if invite is expired
        if let Some(expires_at) = invite.expires_at {
            if now() > expires_at {
                return Err("Invite has expired".to_string());
            }
        }

        // Check if invite has reached max uses
        if let Some(max_uses) = invite.max_uses {
            if invite.current_uses >= max_uses {
                return Err("Invite has reached maximum uses".to_string());
            }
        }

        // Check if user is already a member
        if self.db.is_node_member(invite.node_id, user_id).await.unwrap_or(false) {
            return Err("Already a member of this node".to_string());
        }

        // Get node info for response
        let node = self.db.get_node(invite.node_id).await.map_err(|e| e.to_string())?
            .ok_or("Node not found")?;

        // Join user to node
        self.db.add_node_member(invite.node_id, user_id, NodeRole::Member).await.map_err(|e| e.to_string())?;

        // Increment invite usage
        self.db.increment_invite_usage(invite_code).await.map_err(|e| e.to_string())?;

        Ok((invite.node_id, node.name))
    }

    pub async fn list_invites(&self, node_id: Uuid, user_id: Uuid) -> Result<Vec<crate::models::NodeInvite>, String> {
        // Check if user has permission to manage invites
        let member = self.db.get_node_member(node_id, user_id).await.map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::ManageInvites) {
                    return Err("Insufficient permissions to list invites".to_string());
                }
            }
            None => return Err("Must be a member of the node".to_string()),
        }

        self.db.get_node_invites(node_id).await.map_err(|e| e.to_string())
    }

    pub async fn revoke_invite(&self, invite_id: Uuid, user_id: Uuid) -> Result<(), String> {
        // Get invite to verify permissions
        let invite = match self.db.get_node_invite(invite_id).await.map_err(|e| e.to_string())? {
            Some(invite) => invite,
            None => return Err("Invite not found".to_string()),
        };

        // Check if user has permission to manage invites or is the creator
        let member = self.db.get_node_member(invite.node_id, user_id).await.map_err(|e| e.to_string())?;
        let has_permission = match member {
            Some(m) => {
                has_permission(m.role, Permission::ManageInvites) || invite.created_by == user_id
            }
            None => false,
        };

        if !has_permission {
            return Err("Insufficient permissions to revoke this invite".to_string());
        }

        self.db.delete_node_invite(invite_id).await.map_err(|e| e.to_string())
    }

    // ── Channel operations (now Node-scoped) ──

    pub async fn join_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        // Verify channel exists and user is member of the Node
        let channel = match self.db.get_channel(channel_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err("Channel not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        };
        if !self.db.is_node_member(channel.node_id, user_id).await.unwrap_or(false) {
            return Err("Must be a member of the node to join its channels".to_string());
        }
        self.db.add_user_to_channel(channel_id, user_id).await.map_err(|e| e.to_string())
    }

    pub async fn leave_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        self.db.remove_user_from_channel(channel_id, user_id).await.map_err(|e| e.to_string())
    }

    pub async fn create_channel(&self, name: String, node_id: Uuid, created_by: Uuid) -> Result<Channel, String> {
        // Check if user has permission to create channels
        let member = self.db.get_node_member(node_id, created_by).await.map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::CreateChannel) {
                    return Err("Insufficient permissions to create channels".to_string());
                }
            }
            None => return Err("Must be a member of the node to create channels".to_string()),
        }
        self.db.create_channel(&name, node_id, created_by).await.map_err(|e| e.to_string())
    }

    pub async fn delete_channel(&self, channel_id: Uuid, user_id: Uuid) -> Result<(), String> {
        // Get channel to verify it exists and get its node_id
        let channel = match self.db.get_channel(channel_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err("Channel not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        };

        // Check if user has permission to delete channels
        let member = self.db.get_node_member(channel.node_id, user_id).await.map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::DeleteChannel) {
                    return Err("Insufficient permissions to delete channels".to_string());
                }
            }
            None => return Err("Must be a member of the node".to_string()),
        }

        // TODO: Add actual delete_channel method to database layer
        // self.db.delete_channel(channel_id).await.map_err(|e| e.to_string())
        Err("Channel deletion not yet implemented in database layer".to_string())
    }

    pub async fn update_node(&self, node_id: Uuid, user_id: Uuid, _name: Option<String>, _description: Option<String>) -> Result<(), String> {
        // Check if user has permission to manage node
        let member = self.db.get_node_member(node_id, user_id).await.map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::ManageNode) {
                    return Err("Insufficient permissions to manage node settings".to_string());
                }
            }
            None => return Err("Must be a member of the node".to_string()),
        }

        // TODO: Add actual update_node method to database layer
        // self.db.update_node(node_id, name, description).await.map_err(|e| e.to_string())
        Err("Node update not yet implemented in database layer".to_string())
    }

    pub async fn get_channel(&self, channel_id: Uuid) -> Result<Option<Channel>, String> {
        self.db.get_channel(channel_id).await.map_err(|e| e.to_string())
    }

    pub async fn get_user_channels(&self, user_id: Uuid) -> Result<Vec<Channel>, String> {
        self.db.get_user_channels(user_id).await.map_err(|e| e.to_string())
    }

    pub async fn get_channel_members(&self, channel_id: Uuid) -> Vec<Uuid> {
        self.db.get_channel_members(channel_id).await.unwrap_or_default()
    }

    pub async fn store_message(&self, channel_id: Uuid, sender_id: Uuid, encrypted_payload: &[u8]) -> Result<Uuid, String> {
        self.db.store_message(channel_id, sender_id, encrypted_payload).await.map_err(|e| e.to_string())
    }

    // ── Connection management ──

    pub async fn add_connection(&self, user_id: Uuid, sender: broadcast::Sender<String>) {
        self.connections.write().await.insert(user_id, sender);
    }

    pub async fn remove_connection(&self, user_id: Uuid) {
        self.connections.write().await.remove(&user_id);
    }

    pub async fn send_to_user(&self, user_id: Uuid, message: String) -> Result<(), String> {
        let connections = self.connections.read().await;
        if let Some(sender) = connections.get(&user_id) {
            sender.send(message).map_err(|e| format!("Failed to send: {}", e))?;
        }
        Ok(())
    }

    pub async fn send_to_channel(&self, channel_id: Uuid, message: String) -> Result<(), String> {
        let members = self.get_channel_members(channel_id).await;
        let connections = self.connections.read().await;
        for user_id in members {
            if let Some(sender) = connections.get(&user_id) {
                let _ = sender.send(message.clone());
            }
        }
        Ok(())
    }

    // ── Voice channel operations ──

    pub async fn join_voice_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        // Verify user has access to the channel (is a member)
        let channel = self.get_channel(channel_id).await?
            .ok_or_else(|| "Channel not found".to_string())?;
        
        if !self.db.is_node_member(channel.node_id, user_id).await.unwrap_or(false) {
            return Err("Must be a member of the node to join voice channels".to_string());
        }

        let mut voice_channels = self.voice_channels.write().await;
        voice_channels
            .entry(channel_id)
            .or_insert_with(HashSet::new)
            .insert(user_id);
        
        Ok(())
    }

    pub async fn leave_voice_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        let mut voice_channels = self.voice_channels.write().await;
        
        if let Some(participants) = voice_channels.get_mut(&channel_id) {
            participants.remove(&user_id);
            
            // Clean up empty voice channels
            if participants.is_empty() {
                voice_channels.remove(&channel_id);
            }
        }
        
        Ok(())
    }

    pub async fn get_voice_channel_participants(&self, channel_id: Uuid) -> Vec<Uuid> {
        let voice_channels = self.voice_channels.read().await;
        voice_channels
            .get(&channel_id)
            .map(|participants| participants.iter().copied().collect())
            .unwrap_or_default()
    }

    pub async fn send_to_voice_channel(&self, channel_id: Uuid, sender_id: Uuid, message: String) -> Result<(), String> {
        let voice_channels = self.voice_channels.read().await;
        
        if let Some(participants) = voice_channels.get(&channel_id) {
            let connections = self.connections.read().await;
            
            // Send to all participants except the sender
            for &user_id in participants.iter() {
                if user_id != sender_id {
                    if let Some(sender) = connections.get(&user_id) {
                        let _ = sender.send(message.clone());
                    }
                }
            }
        }
        
        Ok(())
    }

    pub fn uptime(&self) -> u64 {
        now() - self.start_time
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Generate a random 8-character alphanumeric invite code
fn generate_invite_code() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}

/// Shared application state type
pub type SharedState = Arc<AppState>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_lifecycle() {
        let state = AppState::new_in_memory().await.unwrap();
        let owner_id = state.register_user("owner".into(), "key".into()).await.unwrap();
        let user_id = state.register_user("user".into(), "key2".into()).await.unwrap();

        // Create node
        let node = state.create_node("Test Node".into(), owner_id, Some("desc".into())).await.unwrap();
        assert_eq!(node.name, "Test Node");

        // Get info
        let info = state.get_node_info(node.id).await.unwrap();
        assert_eq!(info.members.len(), 1);
        assert_eq!(info.channel_count, 1); // default general channel

        // Join
        state.join_node(user_id, node.id).await.unwrap();
        let info = state.get_node_info(node.id).await.unwrap();
        assert_eq!(info.members.len(), 2);

        // Leave
        state.leave_node(user_id, node.id).await.unwrap();
        let info = state.get_node_info(node.id).await.unwrap();
        assert_eq!(info.members.len(), 1);

        // Owner can't leave
        assert!(state.leave_node(owner_id, node.id).await.is_err());
    }

    #[tokio::test]
    async fn test_channel_requires_node_membership() {
        let state = AppState::new_in_memory().await.unwrap();
        let owner_id = state.register_user("owner".into(), "key".into()).await.unwrap();
        let outsider_id = state.register_user("outsider".into(), "key2".into()).await.unwrap();

        let node = state.create_node("Node".into(), owner_id, None).await.unwrap();

        // Owner can create channels
        let channel = state.create_channel("dev".into(), node.id, owner_id).await.unwrap();
        assert_eq!(channel.name, "dev");

        // Outsider cannot create channels
        assert!(state.create_channel("hax".into(), node.id, outsider_id).await.is_err());
    }

    #[tokio::test]
    async fn test_join_channel_auto_create() {
        let state = AppState::new_in_memory().await.unwrap();

        let user1_id = state.register_user("user1".into(), "key1".into()).await.unwrap();
        let user2_id = state.register_user("user2".into(), "key2".into()).await.unwrap();

        // Create a node first
        let node = state.create_node("Node".into(), user1_id, None).await.unwrap();

        // Create a channel in the node
        let channel = state.create_channel("test".into(), node.id, user1_id).await.unwrap();

        // User2 joins node, then channel
        state.join_node(user2_id, node.id).await.unwrap();
        state.join_channel(user2_id, channel.id).await.unwrap();

        let members = state.get_channel_members(channel.id).await;
        assert_eq!(members.len(), 2);
    }

    #[tokio::test]
    async fn test_voice_channel_operations() {
        let state = AppState::new_in_memory().await.unwrap();

        let user1_id = state.register_user("user1".into(), "key1".into()).await.unwrap();
        let user2_id = state.register_user("user2".into(), "key2".into()).await.unwrap();

        // Create a node first
        let node = state.create_node("Node".into(), user1_id, None).await.unwrap();

        // Create a channel in the node  
        let channel = state.create_channel("voice-test".into(), node.id, user1_id).await.unwrap();

        // Both users join the node
        state.join_node(user2_id, node.id).await.unwrap();

        // Join voice channel
        state.join_voice_channel(user1_id, channel.id).await.unwrap();
        state.join_voice_channel(user2_id, channel.id).await.unwrap();

        // Check participants
        let participants = state.get_voice_channel_participants(channel.id).await;
        assert_eq!(participants.len(), 2);
        assert!(participants.contains(&user1_id));
        assert!(participants.contains(&user2_id));

        // Leave voice channel
        state.leave_voice_channel(user1_id, channel.id).await.unwrap();
        let participants = state.get_voice_channel_participants(channel.id).await;
        assert_eq!(participants.len(), 1);
        assert!(participants.contains(&user2_id));

        // Last user leaves - channel should be cleaned up
        state.leave_voice_channel(user2_id, channel.id).await.unwrap();
        let participants = state.get_voice_channel_participants(channel.id).await;
        assert_eq!(participants.len(), 0);
    }
}
