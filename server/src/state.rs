//! State management for the Accord relay server with SQLite persistence

use crate::db::Database;
use crate::models::{AuthToken, Channel, User};
//use axum::extract::ws::WebSocket;
use anyhow::Result;
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
pub struct AppState {
    /// Database connection for persistent storage
    pub db: Database,
    /// Active authentication tokens (kept in-memory for performance)
    pub auth_tokens: RwLock<HashMap<String, AuthToken>>,
    /// Active WebSocket connections indexed by user ID (ephemeral)
    pub connections: RwLock<HashMap<Uuid, broadcast::Sender<String>>>,
    /// Server start time for uptime calculation
    pub start_time: u64,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db", &"<Database>")
            .field("auth_tokens", &format!("<{} tokens>", self.auth_tokens.try_read().map_or(0, |t| t.len())))
            .field("connections", &format!("<{} connections>", self.connections.try_read().map_or(0, |c| c.len())))
            .field("start_time", &self.start_time)
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
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Create new application state with in-memory database (for testing)
    pub async fn new_in_memory() -> Result<Self> {
        Self::new(":memory:").await
    }

    /// Register a new user
    pub async fn register_user(&self, username: String, public_key: String) -> Result<Uuid, String> {
        // Check if username already exists
        match self.db.username_exists(&username).await {
            Ok(exists) if exists => return Err("Username already exists".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
            _ => {}
        }

        // Create user in database
        match self.db.create_user(&username, &public_key).await {
            Ok(user) => Ok(user.id),
            Err(e) => Err(format!("Failed to create user: {}", e)),
        }
    }

    /// Authenticate user and create token
    pub async fn authenticate_user(&self, username: String, _password: String) -> Result<AuthToken, String> {
        // Get user from database
        let user = match self.db.get_user_by_username(&username).await {
            Ok(Some(user)) => user,
            Ok(None) => return Err("User not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        };

        // For now, simple authentication - just check if user exists
        // In a real implementation, you'd verify the password/signature
        
        let token = format!("tok_{}", Uuid::new_v4().simple());
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 86400; // 24 hours

        let auth_token = AuthToken {
            token: token.clone(),
            user_id: user.id,
            expires_at,
        };

        // Keep auth tokens in memory for fast access
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
        match self.db.add_user_to_channel(channel_id, user_id).await {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("Failed to join channel: {}", e)),
        }
    }

    /// Remove user from channel
    pub async fn leave_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        match self.db.remove_user_from_channel(channel_id, user_id).await {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("Failed to leave channel: {}", e)),
        }
    }

    /// Get all members of a channel
    pub async fn get_channel_members(&self, channel_id: Uuid) -> Vec<Uuid> {
        match self.db.get_channel_members(channel_id).await {
            Ok(members) => members,
            Err(_) => Vec::new(), // Return empty vec on error to maintain compatibility
        }
    }

    /// Create a new channel
    pub async fn create_channel(&self, name: String, created_by: Uuid) -> Result<Channel, String> {
        match self.db.create_channel(&name, created_by).await {
            Ok(channel) => Ok(channel),
            Err(e) => Err(format!("Failed to create channel: {}", e)),
        }
    }

    /// Get a channel by ID
    pub async fn get_channel(&self, channel_id: Uuid) -> Result<Option<Channel>, String> {
        match self.db.get_channel(channel_id).await {
            Ok(channel) => Ok(channel),
            Err(e) => Err(format!("Failed to get channel: {}", e)),
        }
    }

    /// Get all channels for a user
    pub async fn get_user_channels(&self, user_id: Uuid) -> Result<Vec<Channel>, String> {
        match self.db.get_user_channels(user_id).await {
            Ok(channels) => Ok(channels),
            Err(e) => Err(format!("Failed to get user channels: {}", e)),
        }
    }

    /// Store a message in the database
    pub async fn store_message(&self, channel_id: Uuid, sender_id: Uuid, encrypted_payload: &[u8]) -> Result<Uuid, String> {
        match self.db.store_message(channel_id, sender_id, encrypted_payload).await {
            Ok(message_id) => Ok(message_id),
            Err(e) => Err(format!("Failed to store message: {}", e)),
        }
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