//! State management for the Accord relay server with SQLite persistence

use crate::db::Database;
use crate::files::FileHandler;
use crate::models::{AuthToken, Channel};
use crate::node::{Node, NodeCreationPolicy, NodeInfo, NodeRole};
use crate::permissions::{has_permission, Permission};
use crate::rate_limit::RateLimiter;
use accord_core::build_hash::{BuildInfo, BuildTrust, KnownBuild};
use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

use crate::metadata;

/// Metadata storage mode for the relay server.
///
/// Controls how much metadata the relay persists. In `Minimal` mode, the relay
/// strips optional plaintext metadata before writing to the database, storing
/// only what is needed for routing and message ordering.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetadataMode {
    /// Store all metadata as-is (current behavior, full backward compatibility).
    #[default]
    Standard,
    /// Strip optional plaintext metadata before storage. Only routing-essential
    /// data and encrypted blobs are persisted.
    Minimal,
}

impl std::fmt::Display for MetadataMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataMode::Standard => write!(f, "standard"),
            MetadataMode::Minimal => write!(f, "minimal"),
        }
    }
}

impl std::str::FromStr for MetadataMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "standard" => Ok(MetadataMode::Standard),
            "minimal" => Ok(MetadataMode::Minimal),
            other => Err(format!(
                "unknown metadata mode '{}': expected 'standard' or 'minimal'",
                other
            )),
        }
    }
}

/// Build verification mode for client connections.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildVerificationMode {
    /// Accept any client regardless of build hash.
    #[default]
    Disabled,
    /// Log unverified/revoked clients but allow connection.
    Warn,
    /// Reject unverified or revoked builds.
    Enforce,
}

/// Holds server build verification state.
#[derive(Debug, Clone)]
pub struct BuildVerification {
    /// The server's own build info.
    pub server_build_info: BuildInfo,
    /// Optional list of known client build hashes.
    pub known_hashes: Vec<KnownBuild>,
    /// Verification mode.
    pub mode: BuildVerificationMode,
}

impl BuildVerification {
    /// Create a new `BuildVerification`, loading known hashes from `hashes.json` if present.
    pub fn new(mode: BuildVerificationMode) -> Self {
        let server_build_info = BuildInfo::current();
        let known_hashes = Self::load_known_hashes();
        info!(
            "Build verification: mode={:?}, server_hash={}, known_hashes={}",
            mode,
            server_build_info.build_hash,
            known_hashes.len()
        );
        Self {
            server_build_info,
            known_hashes,
            mode,
        }
    }

    fn load_known_hashes() -> Vec<KnownBuild> {
        match std::fs::read_to_string("hashes.json") {
            Ok(contents) => match accord_core::build_hash::parse_hashes_json(&contents) {
                Ok(hashes) => {
                    info!(
                        "Loaded {} known build hashes from hashes.json",
                        hashes.len()
                    );
                    hashes
                }
                Err(e) => {
                    warn!("Failed to parse hashes.json: {}", e);
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        }
    }

    /// Verify a client build hash. Returns the trust level.
    pub fn verify_client_hash(&self, hash: &str) -> BuildTrust {
        if self.known_hashes.is_empty() {
            return BuildTrust::Unknown;
        }
        accord_core::build_hash::verify_build_hash(hash, &self.known_hashes)
    }
}

/// Application state shared across handlers
pub struct AppState {
    /// Database connection for persistent storage
    pub db: Database,
    /// File handler for encrypted file storage
    pub file_handler: FileHandler,
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
    /// Rate limiter
    pub rate_limiter: RateLimiter,
    /// Build hash verification
    pub build_verification: BuildVerification,
    /// Metadata storage mode (standard or minimal)
    pub metadata_mode: MetadataMode,
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

#[allow(dead_code)]
impl AppState {
    /// Create new application state with database connection
    pub async fn new(db_path: &str) -> Result<Self> {
        let db = Database::new(db_path).await?;
        let file_handler = FileHandler::with_default_config();
        file_handler.init().await?;
        Ok(Self {
            db,
            file_handler,
            auth_tokens: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
            voice_channels: RwLock::new(HashMap::new()),
            start_time: now(),
            node_creation_policy: NodeCreationPolicy::default(),
            rate_limiter: RateLimiter::new(),
            build_verification: BuildVerification::new(BuildVerificationMode::default()),
            metadata_mode: MetadataMode::default(),
        })
    }

    /// Create new application state with in-memory database (for testing)
    pub async fn new_in_memory() -> Result<Self> {
        Self::new(":memory:").await
    }

    // ── User operations ──

    /// Register a user by public key. No username at the relay level.
    pub async fn register_user(
        &self,
        public_key: String,
        password: String,
    ) -> Result<Uuid, String> {
        let public_key_hash = crate::db::compute_public_key_hash(&public_key);
        match self.db.public_key_hash_exists(&public_key_hash).await {
            Ok(true) => return Err("Public key already registered".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
            _ => {}
        }

        // Hash password with Argon2
        let password_hash = if password.is_empty() {
            String::new()
        } else {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| format!("Failed to hash password: {}", e))?
                .to_string()
        };

        match self.db.create_user(&public_key, &password_hash).await {
            Ok(user) => {
                // In minimal mode, strip the default display name that db.create_user set
                if self.metadata_mode == MetadataMode::Minimal {
                    let _ = self
                        .db
                        .update_user_profile(user.id, Some("[redacted]"), None, None, None)
                        .await;
                }
                Ok(user.id)
            }
            Err(e) => Err(format!("Failed to create user: {}", e)),
        }
    }

    /// Authenticate by public_key_hash (or public_key) + password.
    /// For backward compat, also accepts username-based lookups (will be removed).
    pub async fn authenticate_user(
        &self,
        public_key_hash: String,
        password: String,
    ) -> Result<AuthToken, String> {
        let user = match self.db.get_user_by_public_key_hash(&public_key_hash).await {
            Ok(Some(user)) => user,
            Ok(None) => return Err("User not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        };

        // Verify password
        let stored_hash = self
            .db
            .get_user_password_hash_by_pkh(&public_key_hash)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .unwrap_or_default();

        if !stored_hash.is_empty() {
            let parsed_hash = PasswordHash::new(&stored_hash)
                .map_err(|e| format!("Invalid stored password hash: {}", e))?;
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .map_err(|_| "Invalid password".to_string())?;
        }
        // If no password hash is stored, skip verification (legacy/keyless users)

        let token = format!("tok_{}", Uuid::new_v4().simple());
        let expires_at = now() + 86400;

        let auth_token = AuthToken {
            token: token.clone(),
            user_id: user.id,
            expires_at,
        };

        self.auth_tokens
            .write()
            .await
            .insert(token, auth_token.clone());
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

    pub async fn create_node(
        &self,
        name: String,
        owner_id: Uuid,
        description: Option<String>,
    ) -> Result<Node, String> {
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

        let stripped_name = metadata::strip_node_name(self.metadata_mode, &name);
        let stripped_desc = metadata::strip_description(self.metadata_mode, description.as_deref());

        match self
            .db
            .create_node(&stripped_name, owner_id, stripped_desc.as_deref())
            .await
        {
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
        let members = self
            .db
            .get_node_members(node_id)
            .await
            .map_err(|e| e.to_string())?;
        let channel_count = self
            .db
            .count_node_channels(node_id)
            .await
            .map_err(|e| e.to_string())?;

        Ok(NodeInfo {
            node,
            members,
            channel_count,
        })
    }

    pub async fn get_node_member(
        &self,
        node_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<crate::node::NodeMember>, String> {
        self.db
            .get_node_member(node_id, user_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_user_role_in_node(
        &self,
        user_id: Uuid,
        node_id: Uuid,
    ) -> Result<crate::node::NodeRole, String> {
        match self.get_node_member(node_id, user_id).await? {
            Some(member) => Ok(member.role),
            None => Err("User is not a member of this node".to_string()),
        }
    }

    pub async fn join_node(&self, user_id: Uuid, node_id: Uuid) -> Result<(), String> {
        // Check node exists
        match self.db.get_node(node_id).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err("Node not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        }

        // Check ban status
        let public_key_hash = self
            .db
            .get_user_public_key_hash(user_id)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "User not found".to_string())?;

        if self
            .db
            .is_banned_from_node(node_id, &public_key_hash)
            .await
            .unwrap_or(false)
        {
            return Err("You are banned from this node".to_string());
        }

        // Check not already member
        if self
            .db
            .is_node_member(node_id, user_id)
            .await
            .unwrap_or(false)
        {
            return Err("Already a member of this node".to_string());
        }
        self.db
            .add_node_member(node_id, user_id, NodeRole::Member)
            .await
            .map_err(|e| e.to_string())
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
        self.db
            .remove_node_member(node_id, user_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn kick_from_node(
        &self,
        admin_id: Uuid,
        target_id: Uuid,
        node_id: Uuid,
    ) -> Result<(), String> {
        // Check if user has permission to kick members
        let member = self
            .db
            .get_node_member(node_id, admin_id)
            .await
            .map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::KickMembers) {
                    return Err("Insufficient permissions to kick members".to_string());
                }
            }
            None => return Err("Must be a member of the node".to_string()),
        }
        // Can't kick the owner
        let node = self
            .db
            .get_node(node_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Node not found")?;
        if node.owner_id == target_id {
            return Err("Cannot kick the node owner".to_string());
        }
        self.db
            .remove_node_member(node_id, target_id)
            .await
            .map_err(|e| e.to_string())
    }

    // ── Node invite operations ──

    pub async fn create_invite(
        &self,
        node_id: Uuid,
        created_by: Uuid,
        max_uses: Option<u32>,
        expires_in_hours: Option<u32>,
    ) -> Result<(Uuid, String), String> {
        // Check if user has permission to manage invites
        let member = self
            .db
            .get_node_member(node_id, created_by)
            .await
            .map_err(|e| e.to_string())?;
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

        let invite_id = self
            .db
            .create_node_invite(node_id, created_by, &invite_code, max_uses, expires_at)
            .await
            .map_err(|e| e.to_string())?;

        Ok((invite_id, invite_code))
    }

    pub async fn use_invite(
        &self,
        invite_code: &str,
        user_id: Uuid,
    ) -> Result<(Uuid, String), String> {
        // Get invite by code
        let invite = match self
            .db
            .get_node_invite_by_code(invite_code)
            .await
            .map_err(|e| e.to_string())?
        {
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

        // Check ban status
        let public_key_hash = self
            .db
            .get_user_public_key_hash(user_id)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "User not found".to_string())?;

        if self
            .db
            .is_banned_from_node(invite.node_id, &public_key_hash)
            .await
            .unwrap_or(false)
        {
            return Err("You are banned from this node".to_string());
        }

        // Check if user is already a member
        if self
            .db
            .is_node_member(invite.node_id, user_id)
            .await
            .unwrap_or(false)
        {
            return Err("Already a member of this node".to_string());
        }

        // Get node info for response
        let node = self
            .db
            .get_node(invite.node_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Node not found")?;

        // Join user to node
        self.db
            .add_node_member(invite.node_id, user_id, NodeRole::Member)
            .await
            .map_err(|e| e.to_string())?;

        // Increment invite usage
        self.db
            .increment_invite_usage(invite_code)
            .await
            .map_err(|e| e.to_string())?;

        Ok((invite.node_id, node.name))
    }

    pub async fn list_invites(
        &self,
        node_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<crate::models::NodeInvite>, String> {
        // Check if user has permission to manage invites
        let member = self
            .db
            .get_node_member(node_id, user_id)
            .await
            .map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::ManageInvites) {
                    return Err("Insufficient permissions to list invites".to_string());
                }
            }
            None => return Err("Must be a member of the node".to_string()),
        }

        self.db
            .get_node_invites(node_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn revoke_invite(&self, invite_id: Uuid, user_id: Uuid) -> Result<(), String> {
        // Get invite to verify permissions
        let invite = match self
            .db
            .get_node_invite(invite_id)
            .await
            .map_err(|e| e.to_string())?
        {
            Some(invite) => invite,
            None => return Err("Invite not found".to_string()),
        };

        // Check if user has permission to manage invites or is the creator
        let member = self
            .db
            .get_node_member(invite.node_id, user_id)
            .await
            .map_err(|e| e.to_string())?;
        let has_permission = match member {
            Some(m) => {
                has_permission(m.role, Permission::ManageInvites) || invite.created_by == user_id
            }
            None => false,
        };

        if !has_permission {
            return Err("Insufficient permissions to revoke this invite".to_string());
        }

        self.db
            .delete_node_invite(invite_id)
            .await
            .map_err(|e| e.to_string())
    }

    // ── Channel operations (now Node-scoped) ──

    pub async fn join_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        // Verify channel exists and user is member of the Node
        let channel = match self.db.get_channel(channel_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err("Channel not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        };
        if !self
            .db
            .is_node_member(channel.node_id, user_id)
            .await
            .unwrap_or(false)
        {
            return Err("Must be a member of the node to join its channels".to_string());
        }
        self.db
            .add_user_to_channel(channel_id, user_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn leave_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        self.db
            .remove_user_from_channel(channel_id, user_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn create_channel(
        &self,
        name: String,
        node_id: Uuid,
        created_by: Uuid,
    ) -> Result<Channel, String> {
        // Check if user has permission to create channels
        let member = self
            .db
            .get_node_member(node_id, created_by)
            .await
            .map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::CreateChannel) {
                    return Err("Insufficient permissions to create channels".to_string());
                }
            }
            None => return Err("Must be a member of the node to create channels".to_string()),
        }
        let stripped_name = metadata::strip_channel_name(self.metadata_mode, &name);
        self.db
            .create_channel(&stripped_name, node_id, created_by)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn delete_channel(&self, channel_id: Uuid, user_id: Uuid) -> Result<(), String> {
        // Get channel to verify it exists and get its node_id
        let channel = match self.db.get_channel(channel_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err("Channel not found".to_string()),
            Err(e) => return Err(format!("Database error: {}", e)),
        };

        // Check if user has permission to delete channels
        let member = self
            .db
            .get_node_member(channel.node_id, user_id)
            .await
            .map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::DeleteChannel) {
                    return Err("Insufficient permissions to delete channels".to_string());
                }
            }
            None => return Err("Must be a member of the node".to_string()),
        }

        self.db
            .delete_channel(channel_id)
            .await
            .map_err(|e| e.to_string())
    }

    // ── Channel Category operations ──

    pub async fn create_channel_category(
        &self,
        node_id: Uuid,
        name: &str,
    ) -> Result<crate::models::ChannelCategory, String> {
        let stripped_name = metadata::strip_category_name(self.metadata_mode, name);
        self.db
            .create_channel_category(node_id, &stripped_name)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_channel_category(
        &self,
        category_id: Uuid,
    ) -> Result<Option<crate::models::ChannelCategory>, String> {
        self.db
            .get_category_by_id(category_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_channel_category(
        &self,
        category_id: Uuid,
        name: Option<&str>,
        position: Option<u32>,
    ) -> Result<(), String> {
        let stripped_name = name.map(|n| metadata::strip_category_name(self.metadata_mode, n));
        self.db
            .update_channel_category(category_id, stripped_name.as_deref(), position)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn delete_channel_category(&self, category_id: Uuid) -> Result<(), String> {
        self.db
            .delete_channel_category(category_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_channel_category_and_position(
        &self,
        channel_id: Uuid,
        category_id: Option<Uuid>,
        position: Option<u32>,
    ) -> Result<(), String> {
        self.db
            .update_channel_category_and_position(channel_id, category_id, position)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_channels_with_categories(
        &self,
        node_id: Uuid,
    ) -> Result<Vec<crate::models::ChannelWithCategory>, String> {
        self.db
            .get_channels_with_categories(node_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_node(
        &self,
        node_id: Uuid,
        user_id: Uuid,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<(), String> {
        // Check if user has permission to manage node
        let member = self
            .db
            .get_node_member(node_id, user_id)
            .await
            .map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !has_permission(m.role, Permission::ManageNode) {
                    return Err("Insufficient permissions to manage node settings".to_string());
                }
            }
            None => return Err("Must be a member of the node".to_string()),
        }

        let stripped_name = name
            .as_deref()
            .map(|n| metadata::strip_node_name(self.metadata_mode, n));
        let stripped_desc = description
            .as_deref()
            .and_then(|d| metadata::strip_description(self.metadata_mode, Some(d)));

        self.db
            .update_node(node_id, stripped_name.as_deref(), stripped_desc.as_deref())
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_channel(&self, channel_id: Uuid) -> Result<Option<Channel>, String> {
        self.db
            .get_channel(channel_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_user_channels(&self, user_id: Uuid) -> Result<Vec<Channel>, String> {
        self.db
            .get_user_channels(user_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_channel_members(&self, channel_id: Uuid) -> Vec<Uuid> {
        self.db
            .get_channel_members(channel_id)
            .await
            .unwrap_or_default()
    }

    pub async fn store_message(
        &self,
        channel_id: Uuid,
        sender_id: Uuid,
        encrypted_payload: &[u8],
    ) -> Result<Uuid, String> {
        self.db
            .store_message(channel_id, sender_id, encrypted_payload, None)
            .await
            .map_err(|e| e.to_string())
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
            sender
                .send(message)
                .map_err(|e| format!("Failed to send: {}", e))?;
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

    // ── User profile operations ──

    pub async fn get_user_profile(
        &self,
        user_id: Uuid,
    ) -> Result<Option<crate::models::UserProfile>, String> {
        self.db
            .get_user_profile(user_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_user_profile(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        bio: Option<&str>,
        status: Option<&str>,
        custom_status: Option<&str>,
    ) -> Result<(), String> {
        // Strip metadata in minimal mode
        let stripped_display =
            display_name.map(|n| metadata::strip_display_name(self.metadata_mode, n));
        let stripped_bio = metadata::strip_optional_text(self.metadata_mode, bio);
        let stripped_custom = metadata::strip_optional_text(self.metadata_mode, custom_status);

        // Update profile in database
        self.db
            .update_user_profile(
                user_id,
                stripped_display.as_deref(),
                stripped_bio.as_deref(),
                // Status (online/offline/dnd/idle) is routing-relevant, always store
                status,
                stripped_custom.as_deref(),
            )
            .await
            .map_err(|e| e.to_string())?;

        // If status changed, broadcast presence update to all nodes the user is in
        if status.is_some() || custom_status.is_some() {
            self.broadcast_presence_update(user_id).await?;
        }

        Ok(())
    }

    pub async fn get_node_members_with_profiles(
        &self,
        node_id: Uuid,
    ) -> Result<Vec<crate::models::MemberWithProfile>, String> {
        self.db
            .get_node_members_with_profiles(node_id)
            .await
            .map_err(|e| e.to_string())
    }

    // ── Presence tracking ──

    pub async fn set_user_online(&self, user_id: Uuid) -> Result<(), String> {
        self.db
            .update_user_status(user_id, "online")
            .await
            .map_err(|e| e.to_string())?;
        self.broadcast_presence_update(user_id).await
    }

    pub async fn set_user_offline(&self, user_id: Uuid) -> Result<(), String> {
        self.db
            .update_user_status(user_id, "offline")
            .await
            .map_err(|e| e.to_string())?;
        self.broadcast_presence_update(user_id).await
    }

    async fn broadcast_presence_update(&self, user_id: Uuid) -> Result<(), String> {
        // Get updated profile for broadcast
        let profile = match self.get_user_profile(user_id).await? {
            Some(profile) => profile,
            None => return Ok(()), // No profile to broadcast
        };

        let presence = crate::models::UserPresence {
            user_id,
            status: profile.status,
            custom_status: profile.custom_status,
            updated_at: profile.updated_at,
        };

        // Get all nodes this user is a member of
        let user_nodes = self
            .db
            .get_user_nodes(user_id)
            .await
            .map_err(|e| e.to_string())?;

        // Broadcast presence update to all members of those nodes
        for node in user_nodes {
            let members = self
                .db
                .get_node_members(node.id)
                .await
                .map_err(|e| e.to_string())?;

            let presence_message = serde_json::json!({
                "type": "presence_update",
                "user_id": user_id,
                "status": presence.status,
                "custom_status": presence.custom_status,
                "updated_at": presence.updated_at
            })
            .to_string();

            let connections = self.connections.read().await;
            for member in members {
                if member.user_id != user_id {
                    // Don't send to self
                    if let Some(sender) = connections.get(&member.user_id) {
                        let _ = sender.send(presence_message.clone());
                    }
                }
            }
        }

        Ok(())
    }

    // ── Voice channel operations ──

    pub async fn join_voice_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        // Verify user has access to the channel (is a member)
        let channel = self
            .get_channel(channel_id)
            .await?
            .ok_or_else(|| "Channel not found".to_string())?;

        if !self
            .db
            .is_node_member(channel.node_id, user_id)
            .await
            .unwrap_or(false)
        {
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

    pub async fn send_to_voice_channel(
        &self,
        channel_id: Uuid,
        sender_id: Uuid,
        message: String,
    ) -> Result<(), String> {
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

    // ── Message operations ──

    /// Get channel messages with cursor-based pagination
    pub async fn get_channel_messages_paginated(
        &self,
        channel_id: Uuid,
        limit: u32,
        before_id: Option<Uuid>,
    ) -> Result<Vec<crate::models::MessageMetadata>, String> {
        self.db
            .get_channel_messages_paginated(channel_id, limit, before_id)
            .await
            .map_err(|e| format!("Database error: {}", e))
    }

    /// Search messages within a Node by metadata
    pub async fn search_messages(
        &self,
        node_id: Uuid,
        query: &str,
        channel_id_filter: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<crate::models::SearchResult>, String> {
        self.db
            .search_messages(node_id, query, channel_id_filter, limit)
            .await
            .map_err(|e| format!("Database error: {}", e))
    }

    /// Check if user can access a specific channel (must be node member and channel member)
    pub async fn user_can_access_channel(
        &self,
        user_id: Uuid,
        channel_id: Uuid,
    ) -> Result<bool, String> {
        // Get channel info to find the node
        let channel = self
            .db
            .get_channel(channel_id)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        let channel = channel.ok_or_else(|| "Channel not found".to_string())?;

        // Check if user is a member of the node
        let is_node_member = self
            .db
            .is_node_member(channel.node_id, user_id)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        // For now, all node members can access all channels in the node
        // TODO(permissions): Per-channel permission overrides — currently all members share node-level permissions
        Ok(is_node_member)
    }

    /// Check if user is a member of a node
    pub async fn is_node_member(&self, user_id: Uuid, node_id: Uuid) -> Result<bool, String> {
        self.db
            .is_node_member(node_id, user_id)
            .await
            .map_err(|e| format!("Database error: {}", e))
    }

    /// Remove expired auth tokens from memory (H3: token cleanup)
    pub async fn cleanup_expired_tokens(&self) -> usize {
        let current_time = now();
        let mut tokens = self.auth_tokens.write().await;
        let before = tokens.len();
        tokens.retain(|_, token| token.expires_at > current_time);
        before - tokens.len()
    }

    pub fn uptime(&self) -> u64 {
        now() - self.start_time
    }

    // ── Bot operations ──
    // NOTE: These are in-memory stubs. Production would use the database.
    // For now, bot state lives only in memory for the initial API framework.

    pub async fn register_bot(&self, _bot: crate::bot_api::Bot) -> Result<(), String> {
        // TODO: Persist to database
        Ok(())
    }

    pub async fn get_bot(&self, _bot_id: Uuid) -> Result<crate::bot_api::Bot, String> {
        Err("Bot not found (bot persistence not yet implemented)".into())
    }

    pub async fn update_bot(
        &self,
        _bot_id: Uuid,
        _request: crate::bot_api::UpdateBotRequest,
    ) -> Result<(), String> {
        Err("Bot not found".into())
    }

    pub async fn delete_bot(&self, _bot_id: Uuid) -> Result<(), String> {
        Err("Bot not found".into())
    }

    pub async fn update_bot_token_hash(
        &self,
        _bot_id: Uuid,
        _new_hash: String,
    ) -> Result<(), String> {
        Err("Bot not found".into())
    }

    pub async fn validate_bot_token(&self, _token_hash: &str) -> Option<crate::bot_api::Bot> {
        None
    }

    pub async fn add_bot_to_channel(
        &self,
        _bot_id: Uuid,
        _channel_id: Uuid,
        _node_id: Uuid,
        _added_by: Uuid,
    ) -> Result<(), String> {
        Ok(())
    }

    pub async fn remove_bot_from_channel(
        &self,
        _bot_id: Uuid,
        _channel_id: Uuid,
    ) -> Result<(), String> {
        Ok(())
    }

    pub async fn is_bot_in_channel(
        &self,
        _bot_id: Uuid,
        _channel_id: Uuid,
    ) -> Result<bool, String> {
        Ok(false)
    }

    pub async fn check_bot_rate_limit(&self, _bot_id: Uuid, _action: &str) -> Result<(), String> {
        Ok(())
    }

    pub async fn broadcast_to_channel(
        &self,
        channel_id: Uuid,
        message: String,
    ) -> Result<(), String> {
        self.send_to_channel(channel_id, message).await
    }

    pub async fn get_channel_bots(
        &self,
        _channel_id: Uuid,
    ) -> Result<Vec<crate::bot_api::BotInfo>, String> {
        Ok(vec![])
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
        let owner_id = state.register_user("key".into(), "".into()).await.unwrap();
        let user_id = state.register_user("key2".into(), "".into()).await.unwrap();

        // Create node
        let node = state
            .create_node("Test Node".into(), owner_id, Some("desc".into()))
            .await
            .unwrap();
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
        let owner_id = state.register_user("key".into(), "".into()).await.unwrap();
        let outsider_id = state.register_user("key2".into(), "".into()).await.unwrap();

        let node = state
            .create_node("Node".into(), owner_id, None)
            .await
            .unwrap();

        // Owner can create channels
        let channel = state
            .create_channel("dev".into(), node.id, owner_id)
            .await
            .unwrap();
        assert_eq!(channel.name, "dev");

        // Outsider cannot create channels
        assert!(state
            .create_channel("hax".into(), node.id, outsider_id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_join_channel_auto_create() {
        let state = AppState::new_in_memory().await.unwrap();

        let user1_id = state.register_user("key1".into(), "".into()).await.unwrap();
        let user2_id = state.register_user("key2".into(), "".into()).await.unwrap();

        // Create a node first
        let node = state
            .create_node("Node".into(), user1_id, None)
            .await
            .unwrap();

        // Create a channel in the node
        let channel = state
            .create_channel("test".into(), node.id, user1_id)
            .await
            .unwrap();

        // User2 joins node, then channel
        state.join_node(user2_id, node.id).await.unwrap();
        state.join_channel(user2_id, channel.id).await.unwrap();

        let members = state.get_channel_members(channel.id).await;
        assert_eq!(members.len(), 2);
    }

    #[tokio::test]
    async fn test_voice_channel_operations() {
        let state = AppState::new_in_memory().await.unwrap();

        let user1_id = state.register_user("key1".into(), "".into()).await.unwrap();
        let user2_id = state.register_user("key2".into(), "".into()).await.unwrap();

        // Create a node first
        let node = state
            .create_node("Node".into(), user1_id, None)
            .await
            .unwrap();

        // Create a channel in the node
        let channel = state
            .create_channel("voice-test".into(), node.id, user1_id)
            .await
            .unwrap();

        // Both users join the node
        state.join_node(user2_id, node.id).await.unwrap();

        // Join voice channel
        state
            .join_voice_channel(user1_id, channel.id)
            .await
            .unwrap();
        state
            .join_voice_channel(user2_id, channel.id)
            .await
            .unwrap();

        // Check participants
        let participants = state.get_voice_channel_participants(channel.id).await;
        assert_eq!(participants.len(), 2);
        assert!(participants.contains(&user1_id));
        assert!(participants.contains(&user2_id));

        // Leave voice channel
        state
            .leave_voice_channel(user1_id, channel.id)
            .await
            .unwrap();
        let participants = state.get_voice_channel_participants(channel.id).await;
        assert_eq!(participants.len(), 1);
        assert!(participants.contains(&user2_id));

        // Last user leaves - channel should be cleaned up
        state
            .leave_voice_channel(user2_id, channel.id)
            .await
            .unwrap();
        let participants = state.get_voice_channel_participants(channel.id).await;
        assert_eq!(participants.len(), 0);
    }

    #[tokio::test]
    async fn test_friend_request_flow() {
        let state = AppState::new_in_memory().await.unwrap();

        let user_a = state.register_user("keyA".into(), "".into()).await.unwrap();
        let user_b = state.register_user("keyB".into(), "".into()).await.unwrap();

        // Create a shared node
        let node = state
            .create_node("Shared".into(), user_a, None)
            .await
            .unwrap();
        state.join_node(user_b, node.id).await.unwrap();

        // Verify they share a node
        assert!(state.db.share_a_node(user_a, user_b).await.unwrap());

        // Send friend request
        let req_id = state
            .db
            .create_friend_request(user_a, user_b, node.id, None)
            .await
            .unwrap();

        // Check pending requests
        let pending = state.db.get_pending_requests(user_b).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].from_user_id, user_a);

        // Accept
        assert!(state.db.accept_friend_request(req_id, None).await.unwrap());

        // Verify friendship
        let hash_a = state
            .db
            .get_user_public_key_hash(user_a)
            .await
            .unwrap()
            .unwrap();
        let hash_b = state
            .db
            .get_user_public_key_hash(user_b)
            .await
            .unwrap()
            .unwrap();
        assert!(state.db.are_friends(&hash_a, &hash_b).await.unwrap());

        // List friends
        let friends = state.db.get_friends(&hash_a).await.unwrap();
        assert_eq!(friends.len(), 1);
    }

    #[tokio::test]
    async fn test_friend_request_rejection() {
        let state = AppState::new_in_memory().await.unwrap();

        let user_a = state.register_user("keyA".into(), "".into()).await.unwrap();
        let user_b = state.register_user("keyB".into(), "".into()).await.unwrap();

        let node = state
            .create_node("Node".into(), user_a, None)
            .await
            .unwrap();
        state.join_node(user_b, node.id).await.unwrap();

        let req_id = state
            .db
            .create_friend_request(user_a, user_b, node.id, None)
            .await
            .unwrap();

        // Reject
        assert!(state.db.reject_friend_request(req_id).await.unwrap());

        // Not friends
        let hash_a = state
            .db
            .get_user_public_key_hash(user_a)
            .await
            .unwrap()
            .unwrap();
        let hash_b = state
            .db
            .get_user_public_key_hash(user_b)
            .await
            .unwrap()
            .unwrap();
        assert!(!state.db.are_friends(&hash_a, &hash_b).await.unwrap());

        // Can't accept after rejection
        assert!(!state.db.accept_friend_request(req_id, None).await.unwrap());
    }

    #[tokio::test]
    async fn test_no_shared_node_no_friend_request() {
        let state = AppState::new_in_memory().await.unwrap();

        let user_a = state.register_user("keyA".into(), "".into()).await.unwrap();
        let user_b = state.register_user("keyB".into(), "".into()).await.unwrap();

        // No shared node
        assert!(!state.db.share_a_node(user_a, user_b).await.unwrap());
    }

    #[tokio::test]
    async fn test_dm_requires_friendship() {
        let state = AppState::new_in_memory().await.unwrap();

        let user_a = state.register_user("keyA".into(), "".into()).await.unwrap();
        let user_b = state.register_user("keyB".into(), "".into()).await.unwrap();

        // Not friends — check are_friends returns false
        let hash_a = state
            .db
            .get_user_public_key_hash(user_a)
            .await
            .unwrap()
            .unwrap();
        let hash_b = state
            .db
            .get_user_public_key_hash(user_b)
            .await
            .unwrap()
            .unwrap();
        assert!(!state.db.are_friends(&hash_a, &hash_b).await.unwrap());

        // After becoming friends, DM should work
        let node = state
            .create_node("Node".into(), user_a, None)
            .await
            .unwrap();
        state.join_node(user_b, node.id).await.unwrap();
        let req_id = state
            .db
            .create_friend_request(user_a, user_b, node.id, None)
            .await
            .unwrap();
        state.db.accept_friend_request(req_id, None).await.unwrap();

        assert!(state.db.are_friends(&hash_a, &hash_b).await.unwrap());

        // Friendship gate verified — are_friends now returns true,
        // so the DM creation handler would allow it.
    }

    #[tokio::test]
    async fn test_remove_friend() {
        let state = AppState::new_in_memory().await.unwrap();

        let user_a = state.register_user("keyA".into(), "".into()).await.unwrap();
        let user_b = state.register_user("keyB".into(), "".into()).await.unwrap();

        let node = state
            .create_node("Node".into(), user_a, None)
            .await
            .unwrap();
        state.join_node(user_b, node.id).await.unwrap();

        let req_id = state
            .db
            .create_friend_request(user_a, user_b, node.id, None)
            .await
            .unwrap();
        state.db.accept_friend_request(req_id, None).await.unwrap();

        let hash_a = state
            .db
            .get_user_public_key_hash(user_a)
            .await
            .unwrap()
            .unwrap();
        let hash_b = state
            .db
            .get_user_public_key_hash(user_b)
            .await
            .unwrap()
            .unwrap();

        assert!(state.db.are_friends(&hash_a, &hash_b).await.unwrap());
        assert!(state.db.remove_friend(&hash_a, &hash_b).await.unwrap());
        assert!(!state.db.are_friends(&hash_a, &hash_b).await.unwrap());
    }
}
