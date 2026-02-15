//! In-memory state management for the Accord relay server

use crate::models::{AuthToken, Channel, User};
use axum::extract::ws::WebSocket;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

/// Active WebSocket connection
#[derive(Debug)]
pub struct ActiveConnection {
    pub user_id: Uuid,
    pub sender: broadcast::Sender<String>, // For sending messages to this specific connection
}

/// Application state shared across handlers
#[derive(Debug)]
pub struct AppState {
    /// Registered users indexed by user ID
    pub users: RwLock<HashMap<Uuid, User>>,
    /// Users indexed by username for login
    pub users_by_username: RwLock<HashMap<String, Uuid>>,
    /// Active authentication tokens
    pub auth_tokens: RwLock<HashMap<String, AuthToken>>,
    /// Channels indexed by channel ID
    pub channels: RwLock<HashMap<Uuid, Channel>>,
    /// Active WebSocket connections indexed by user ID
    pub connections: RwLock<HashMap<Uuid, broadcast::Sender<String>>>,
    /// Channel memberships: channel_id -> set of user_ids
    pub channel_members: RwLock<HashMap<Uuid, Vec<Uuid>>>,
    /// Server start time for uptime calculation
    pub start_time: u64,
}

impl AppState {
    /// Create new application state
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            users_by_username: RwLock::new(HashMap::new()),
            auth_tokens: RwLock::new(HashMap::new()),
            channels: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
            channel_members: RwLock::new(HashMap::new()),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Register a new user
    pub async fn register_user(&self, username: String, public_key: String) -> Result<Uuid, String> {
        let mut users_by_username = self.users_by_username.write().await;
        
        // Check if username already exists
        if users_by_username.contains_key(&username) {
            return Err("Username already exists".to_string());
        }

        let user_id = Uuid::new_v4();
        let user = User {
            id: user_id,
            username: username.clone(),
            public_key,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Insert into both indexes
        self.users.write().await.insert(user_id, user);
        users_by_username.insert(username, user_id);

        Ok(user_id)
    }

    /// Authenticate user and create token
    pub async fn authenticate_user(&self, username: String, _password: String) -> Result<AuthToken, String> {
        let users_by_username = self.users_by_username.read().await;
        
        let user_id = users_by_username.get(&username)
            .ok_or_else(|| "User not found".to_string())?;

        // For now, simple authentication - just check if user exists
        // In a real implementation, you'd verify the password/signature
        
        let token = format!("tok_{}", Uuid::new_v4().simple());
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 86400; // 24 hours

        let auth_token = AuthToken {
            token: token.clone(),
            user_id: *user_id,
            expires_at,
        };

        self.auth_tokens.write().await.insert(token.clone(), auth_token.clone());
        
        Ok(auth_token)
    }

    /// Validate authentication token
    pub async fn validate_token(&self, token: &str) -> Option<Uuid> {
        let auth_tokens = self.auth_tokens.read().await;
        let auth_token = auth_tokens.get(token)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if auth_token.expires_at > now {
            Some(auth_token.user_id)
        } else {
            None
        }
    }

    /// Add user to channel
    pub async fn join_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        let mut channel_members = self.channel_members.write().await;
        
        let members = channel_members.entry(channel_id).or_insert_with(Vec::new);
        if !members.contains(&user_id) {
            members.push(user_id);
        }
        
        Ok(())
    }

    /// Remove user from channel
    pub async fn leave_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        let mut channel_members = self.channel_members.write().await;
        
        if let Some(members) = channel_members.get_mut(&channel_id) {
            members.retain(|&id| id != user_id);
        }
        
        Ok(())
    }

    /// Get all members of a channel
    pub async fn get_channel_members(&self, channel_id: Uuid) -> Vec<Uuid> {
        let channel_members = self.channel_members.read().await;
        channel_members.get(&channel_id).cloned().unwrap_or_default()
    }

    /// Add WebSocket connection
    pub async fn add_connection(&self, user_id: Uuid, sender: broadcast::Sender<String>) {
        self.connections.write().await.insert(user_id, sender);
    }

    /// Remove WebSocket connection
    pub async fn remove_connection(&self, user_id: Uuid) {
        self.connections.write().await.remove(&user_id);
    }

    /// Send message to specific user
    pub async fn send_to_user(&self, user_id: Uuid, message: String) -> Result<(), String> {
        let connections = self.connections.read().await;
        if let Some(sender) = connections.get(&user_id) {
            sender.send(message).map_err(|e| format!("Failed to send message: {}", e))?;
        }
        Ok(())
    }

    /// Send message to all members of a channel
    pub async fn send_to_channel(&self, channel_id: Uuid, message: String) -> Result<(), String> {
        let members = self.get_channel_members(channel_id).await;
        let connections = self.connections.read().await;

        for user_id in members {
            if let Some(sender) = connections.get(&user_id) {
                let _ = sender.send(message.clone()); // Don't fail if one user is offline
            }
        }
        
        Ok(())
    }

    /// Get server uptime in seconds
    pub fn uptime(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now - self.start_time
    }
}

/// Shared application state type
pub type SharedState = Arc<AppState>;