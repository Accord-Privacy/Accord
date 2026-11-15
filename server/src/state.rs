//! State management for the Accord relay server with SQLite persistence

use crate::db::Database;
use crate::files::FileHandler;
use crate::models::{AuthToken, Channel};
use crate::node::{Node, NodeCreationPolicy, NodeInfo};
use crate::permissions::Permission;
use crate::rate_limit::RateLimiter;
use accord_core::build_hash::{BuildInfo, BuildTrust, KnownBuild};
use anyhow::Result;
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

/// Relay-level build hash enforcement mode.
///
/// This is separate from `BuildVerificationMode` (which checks against hashes.json).
/// This mode enforces a relay admin-managed allowlist stored in the database.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildHashEnforcementMode {
    /// Allow all clients regardless of build hash.
    #[default]
    Off,
    /// Log unverified builds but allow connection.
    Warn,
    /// Reject clients whose build hash is not in the relay allowlist.
    Strict,
}

impl std::fmt::Display for BuildHashEnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildHashEnforcementMode::Off => write!(f, "off"),
            BuildHashEnforcementMode::Warn => write!(f, "warn"),
            BuildHashEnforcementMode::Strict => write!(f, "strict"),
        }
    }
}

impl std::str::FromStr for BuildHashEnforcementMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "off" => Ok(BuildHashEnforcementMode::Off),
            "warn" => Ok(BuildHashEnforcementMode::Warn),
            "strict" => Ok(BuildHashEnforcementMode::Strict),
            other => Err(format!(
                "unknown build-hash-enforcement mode '{}': expected 'off', 'warn', or 'strict'",
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
    /// Active WebSocket connections: user_id -> { device_id -> sender }
    /// Supports multiple devices per user for multi-device connectivity.
    pub connections: RwLock<HashMap<Uuid, HashMap<Uuid, broadcast::Sender<String>>>>,
    /// Voice channels state (channel_id -> set of user_ids)
    pub voice_channels: RwLock<HashMap<Uuid, HashSet<Uuid>>>,
    /// Voice mode per channel: true = relay (default), false = p2p
    pub voice_relay_mode: RwLock<HashMap<Uuid, bool>>,
    /// Server start time
    pub start_time: u64,
    /// Node creation policy
    pub node_creation_policy: NodeCreationPolicy,
    /// Rate limiter
    pub rate_limiter: RateLimiter,
    /// True only when the relay mesh is enabled — gates /federation/* routes.
    pub federation_enabled: bool,
    /// Build hash verification
    pub build_verification: BuildVerification,
    /// Metadata storage mode (standard or minimal)
    pub metadata_mode: MetadataMode,
    /// Connected clients' build hashes (user_id -> build_hash)
    pub client_build_hashes: RwLock<HashMap<Uuid, String>>,
    /// Relay-level build hash enforcement mode
    pub build_hash_enforcement: BuildHashEnforcementMode,
    /// Optional mesh handle for cross-relay DM routing
    pub mesh_handle: RwLock<Option<crate::relay_mesh::service::MeshHandle>>,
    /// Link preview cache (url -> (result_json, fetched_at))
    pub link_preview_cache: RwLock<HashMap<String, (serde_json::Value, u64)>>,
    /// Last activity timestamp per user (for idle detection)
    pub last_activity: RwLock<HashMap<Uuid, u64>>,
    /// Slow mode cooldowns: (channel_id, user_id) -> last_message_timestamp
    pub slow_mode_cooldowns: RwLock<HashMap<(Uuid, Uuid), u64>>,
    /// IP ban cache for DoS/DDoS defense: ip -> expires_at (None = permanent).
    /// Relay-owner only; never correlated to a node. Backed by the ip_bans table.
    pub ip_bans: RwLock<HashMap<String, Option<i64>>>,
    /// Fixed dummy PHC hash that credential refusals verify against, computed
    /// once at startup (SPEC-01 REQ-2(b)).
    dummy_password_hash: &'static str,
    /// Test instrumentation: the PHC hash given to each password verification.
    #[cfg(test)]
    password_verifications: std::sync::Mutex<Vec<String>>,
}

/// Boot options of the relay state.
#[derive(Debug, Clone, Default)]
pub struct AppStateOptions {
    /// Enable SQLCipher encryption at rest (with the `sqlcipher` feature).
    pub database_encryption: bool,
    /// Options of the admission boot repair and ledger migrations.
    pub db: crate::db::DbOptions,
    /// Blob storage; `None` uses the default `./data/files`.
    pub file_config: Option<crate::files::FileConfig>,
}

/// Delete the blobs whose `files` rows the boot repair removed. Only the
/// number of failures is logged (SPEC-01 §6.6, after the commit, step 4).
async fn remove_repaired_blobs(db: &Database, file_handler: &FileHandler) {
    let mut failures = 0usize;
    for path in db.take_repair_blob_paths() {
        if !std::path::Path::new(&path).exists() {
            continue;
        }
        if file_handler.delete_file(&path).await.is_err() {
            failures += 1;
        }
    }
    if failures > 0 {
        tracing::warn!(
            target: crate::db::repair::LOG_TARGET,
            "admission repair: {} blobs of deleted files could not be removed",
            failures
        );
    }
}

/// The single response text of every credential refusal on `POST /auth`
/// (wrong password, unusable stored hash, reserved user).
pub const INVALID_PASSWORD: &str = "Invalid password";

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
        Self::new_with_encryption(db_path, false).await
    }

    /// Create new application state with explicit encryption control
    pub async fn new_with_encryption(db_path: &str, database_encryption: bool) -> Result<Self> {
        Self::new_with_options(
            db_path,
            AppStateOptions {
                database_encryption,
                ..AppStateOptions::default()
            },
        )
        .await
    }

    /// Create application state with every boot option. Opening the database
    /// runs the admission boot repair; the blobs of `files` rows it deleted
    /// are removed here, once the file handler exists (SPEC-01 §6.6).
    pub async fn new_with_options(db_path: &str, options: AppStateOptions) -> Result<Self> {
        let db =
            Database::new_with_options(db_path, options.database_encryption, options.db).await?;
        let file_handler = match options.file_config {
            Some(config) => FileHandler::new(config),
            None => FileHandler::with_default_config(),
        };
        file_handler.init().await?;
        remove_repaired_blobs(&db, &file_handler).await;
        let dummy_password_hash =
            crate::admission::dummy_password_hash().map_err(|e| anyhow::anyhow!(e))?;
        Ok(Self {
            db,
            file_handler,
            auth_tokens: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
            voice_channels: RwLock::new(HashMap::new()),
            voice_relay_mode: RwLock::new(HashMap::new()),
            start_time: now(),
            node_creation_policy: NodeCreationPolicy::default(),
            rate_limiter: RateLimiter::new(),
            build_verification: BuildVerification::new(BuildVerificationMode::default()),
            metadata_mode: MetadataMode::default(),
            client_build_hashes: RwLock::new(HashMap::new()),
            build_hash_enforcement: BuildHashEnforcementMode::default(),
            mesh_handle: RwLock::new(None),
            federation_enabled: false,
            link_preview_cache: RwLock::new(HashMap::new()),
            last_activity: RwLock::new(HashMap::new()),
            slow_mode_cooldowns: RwLock::new(HashMap::new()),
            ip_bans: RwLock::new(HashMap::new()),
            dummy_password_hash,
            #[cfg(test)]
            password_verifications: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Create new application state with in-memory database (for testing)
    pub async fn new_in_memory() -> Result<Self> {
        Self::new(":memory:").await
    }

    /// The fault points of this relay instance. Tests arm request-path
    /// points here at run time (inert without the `fault-injection` feature).
    pub fn faults(&self) -> &crate::faults::FaultPlan {
        self.db.faults()
    }

    // ── IP bans (relay-owner DoS/DDoS defense, node-correlation-free) ──

    /// Load the IP ban cache from the database (call once at boot). Expired bans
    /// are pruned by the DB layer during load.
    pub async fn load_ip_bans(&self) {
        match self.db.load_ip_ban_cache().await {
            Ok(entries) => {
                let mut cache = self.ip_bans.write().await;
                cache.clear();
                for (ip, expires_at) in entries {
                    cache.insert(ip, expires_at);
                }
            }
            Err(e) => tracing::error!("Failed to load IP ban cache: {}", e),
        }
    }

    /// Is this IP currently banned? Honors expiry live against the cache.
    pub async fn is_ip_banned(&self, ip: &str) -> bool {
        let cache = self.ip_bans.read().await;
        match cache.get(ip) {
            None => false,
            Some(None) => true, // permanent
            Some(Some(expires_at)) => *expires_at > now() as i64,
        }
    }

    /// Ban an IP (DB + cache). `expires_at = None` is permanent.
    pub async fn ban_ip(
        &self,
        ip: &str,
        reason: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<(), String> {
        self.db
            .add_ip_ban(ip, reason, expires_at)
            .await
            .map_err(|e| e.to_string())?;
        self.ip_bans
            .write()
            .await
            .insert(ip.to_string(), expires_at);
        Ok(())
    }

    /// Remove an IP ban (DB + cache). Returns true if a ban existed.
    pub async fn unban_ip(&self, ip: &str) -> Result<bool, String> {
        let removed = self.db.remove_ip_ban(ip).await.map_err(|e| e.to_string())?;
        self.ip_bans.write().await.remove(ip);
        Ok(removed)
    }

    // ── User operations ──

    /// Register a user by public key. No username at the relay level.
    /// A password is required: an account without one could never log in
    /// (SPEC-01 REQ-4(a)).
    pub async fn register_user(
        &self,
        public_key: String,
        password: String,
    ) -> Result<Uuid, String> {
        if password.is_empty() {
            return Err("Password is required".to_string());
        }
        let public_key_hash = crate::db::compute_public_key_hash(&public_key);
        match self.db.public_key_hash_exists(&public_key_hash).await {
            Ok(true) => return Err("Public key already registered".to_string()),
            Err(e) => {
                return Err({
                    tracing::error!("Database error: {}", e);
                    "Database error".to_string()
                })
            }
            _ => {}
        }

        // Hash password with Argon2
        let password_hash = crate::admission::hash_new_password(&password)?;

        match self.db.create_user(&public_key, &password_hash).await {
            Ok(user) => {
                // In minimal mode, strip the default display name that db.create_user set
                if self.metadata_mode == MetadataMode::Minimal {
                    let _ = self
                        .db
                        .update_user_profile(
                            user.id,
                            Some("[redacted]"),
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                        .await;
                }
                Ok(user.id)
            }
            Err(e) => Err({
                tracing::error!("Failed to create user: {}", e);
                "Failed to create user".to_string()
            }),
        }
    }

    /// Register a user with username + password (v2 flow).
    /// Optionally registers a device key and enforces per-device alt limits.
    pub async fn register_user_v2(
        &self,
        username: String,
        password: String,
        device_fingerprint_hash: Option<String>,
        device_public_key: Option<String>,
        device_label: Option<String>,
    ) -> Result<(Uuid, Option<Uuid>), String> {
        // Validate username
        let username = username.trim().to_string();
        if username.is_empty() || username.len() < 3 || username.len() > 32 {
            return Err("Username must be 3-32 characters".to_string());
        }
        if !username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(
                "Username may only contain letters, numbers, underscores, and hyphens".to_string(),
            );
        }
        if password.is_empty() {
            return Err("Password is required for username-based registration".to_string());
        }

        // Check username uniqueness
        match self.db.username_exists(&username).await {
            Ok(true) => return Err("Username already taken".to_string()),
            Err(e) => {
                return Err({
                    tracing::error!("Database error: {}", e);
                    "Database error".to_string()
                })
            }
            _ => {}
        }

        // Check device alt limit (max 5 accounts per device). Skipped under
        // --disable-rate-limits: automated tests register many accounts from
        // one device, and this guard is the same abuse class as rate limits.
        if let (false, Some(ref fingerprint)) =
            (self.rate_limiter.is_disabled(), &device_fingerprint_hash)
        {
            match self
                .db
                .count_registrations_for_fingerprint(fingerprint)
                .await
            {
                Ok(count) if count >= 5 => {
                    return Err("Maximum accounts per device reached (5)".to_string());
                }
                Err(e) => {
                    return Err({
                        tracing::error!("Database error: {}", e);
                        "Database error".to_string()
                    })
                }
                _ => {}
            }
        }

        // Hash password with Argon2
        let password_hash = crate::admission::hash_new_password(&password)?;

        // Create user
        let user = self
            .db
            .create_user_with_username(&username, &password_hash)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create user: {}", e);
                "Failed to create user".to_string()
            })?;

        // Register device key if provided
        let device_id = if let Some(ref fingerprint) = device_fingerprint_hash {
            let pk = device_public_key.as_deref().unwrap_or("");
            let label = device_label.as_deref().unwrap_or("Unknown");
            let device_id = self
                .db
                .create_device_key(user.id, fingerprint, pk, label, false)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create device key: {}", e);
                    "Failed to create device key".to_string()
                })?;

            // Record device registration for anti-alt tracking
            let _ = self
                .db
                .record_device_registration(fingerprint, user.id)
                .await;

            Some(device_id)
        } else {
            None
        };

        if self.metadata_mode == MetadataMode::Minimal {
            let _ = self
                .db
                .update_user_profile(user.id, Some("[redacted]"), None, None, None, None, None)
                .await;
        }

        Ok((user.id, device_id))
    }

    /// Authenticate by username + password (v2 flow).
    pub async fn authenticate_user_by_username(
        &self,
        username: String,
        password: String,
        device_fingerprint_hash: Option<String>,
    ) -> Result<(AuthToken, Option<Uuid>), String> {
        let user = match self.db.get_user_by_username(&username).await {
            Ok(Some(user)) => user,
            Ok(None) => return Err("User not found".to_string()),
            Err(e) => {
                return Err({
                    tracing::error!("Database error: {}", e);
                    "Database error".to_string()
                })
            }
        };

        // The reserved user is refused before its stored hash is consulted.
        if crate::admission::is_reserved_user(user.id) {
            return Err(self.refuse_credentials(&password));
        }

        // Verify password
        let stored_hash = self
            .db
            .get_user_password_hash_by_username(&username)
            .await
            .map_err(|e| {
                tracing::error!("Database error: {}", e);
                "Database error".to_string()
            })?
            .unwrap_or_default();
        self.check_password(&password, &stored_hash)?;

        // Handle device key tracking
        let device_id = if let Some(ref fingerprint) = device_fingerprint_hash {
            match self
                .db
                .get_device_key_by_fingerprint(user.id, fingerprint)
                .await
            {
                Ok(Some(did)) => {
                    let _ = self.db.touch_device_key(did).await;
                    Some(did)
                }
                _ => None, // Device not registered yet — client can register it later
            }
        } else {
            None
        };

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

        if let Err(e) = self
            .db
            .save_auth_token(&auth_token.token, auth_token.user_id, auth_token.expires_at)
            .await
        {
            tracing::warn!("Failed to persist auth token: {}", e);
        }

        Ok((auth_token, device_id))
    }

    /// Authenticate by public_key_hash (or public_key) + password (legacy v1 flow).
    pub async fn authenticate_user(
        &self,
        public_key_hash: String,
        password: String,
    ) -> Result<AuthToken, String> {
        let user = match self.db.get_user_by_public_key_hash(&public_key_hash).await {
            Ok(Some(user)) => user,
            Ok(None) => return Err("User not found".to_string()),
            Err(e) => {
                return Err({
                    tracing::error!("Database error: {}", e);
                    "Database error".to_string()
                })
            }
        };

        // The reserved user is refused before its stored hash is consulted.
        if crate::admission::is_reserved_user(user.id) {
            return Err(self.refuse_credentials(&password));
        }

        // Verify password
        let stored_hash = self
            .db
            .get_user_password_hash_by_pkh(&public_key_hash)
            .await
            .map_err(|e| {
                tracing::error!("Database error: {}", e);
                "Database error".to_string()
            })?
            .unwrap_or_default();
        self.check_password(&password, &stored_hash)?;

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

        // Persist to database so tokens survive restarts
        if let Err(e) = self
            .db
            .save_auth_token(&auth_token.token, auth_token.user_id, auth_token.expires_at)
            .await
        {
            tracing::warn!("Failed to persist auth token: {}", e);
        }

        Ok(auth_token)
    }

    /// Check `password` against a stored hash. An unusable stored hash is
    /// refused exactly like a wrong password, at the same cost (SPEC-01 REQ-1,
    /// REQ-2(b)). Every error is `INVALID_PASSWORD`.
    fn check_password(&self, password: &str, stored_hash: &str) -> Result<(), String> {
        if crate::admission::is_unusable_password_hash(stored_hash) {
            return Err(self.refuse_credentials(password));
        }
        if self.verify_password_against(password, stored_hash) {
            Ok(())
        } else {
            Err(INVALID_PASSWORD.to_string())
        }
    }

    /// Refuse a login without consulting the stored hash. Runs exactly one
    /// Argon2 verification against the dummy hash and discards the result, so
    /// the refusal costs about as much as a wrong password (SPEC-01 REQ-2(b)).
    fn refuse_credentials(&self, password: &str) -> String {
        let _ = self.verify_password_against(password, self.dummy_password_hash);
        INVALID_PASSWORD.to_string()
    }

    /// The single place where a password is verified against a PHC hash.
    fn verify_password_against(&self, password: &str, phc_hash: &str) -> bool {
        #[cfg(test)]
        self.password_verifications
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(phc_hash.to_string());
        crate::admission::verify_password(password, phc_hash)
    }

    /// Resolve a session token to its user. A token of the reserved user is
    /// never valid, whatever its expiry, and is dropped from the in-memory map
    /// (SPEC-01 REQ-3).
    pub async fn validate_token(&self, token: &str) -> Option<Uuid> {
        let user_id = {
            let auth_tokens = self.auth_tokens.read().await;
            let auth_token = auth_tokens.get(token)?;
            if auth_token.expires_at <= now() {
                return None;
            }
            auth_token.user_id
        };
        if crate::admission::is_reserved_user(user_id) {
            self.auth_tokens.write().await.remove(token);
            return None;
        }
        Some(user_id)
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
            Err(e) => Err({
                tracing::error!("Failed to create node: {}", e);
                "Failed to create node".to_string()
            }),
        }
    }

    pub async fn get_node_info(&self, node_id: Uuid) -> Result<NodeInfo, String> {
        // The reserved DM system node is refused exactly like a missing node
        // (SPEC-01 REQ-7): its roster and channel count are never shown.
        if crate::admission::is_reserved_node(node_id) {
            return Err("Node not found".to_string());
        }
        let node = match self.db.get_node(node_id).await {
            Ok(Some(n)) => n,
            Ok(None) => return Err("Node not found".to_string()),
            Err(e) => {
                return Err({
                    tracing::error!("Database error: {}", e);
                    "Database error".to_string()
                })
            }
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

    /// Leave `node_id` as `user_id` through the leave routine of SPEC-01
    /// REQ-34 (charged, `not_member` when there was no membership, removal
    /// hooks after the commit). A convenience wrapper for programmatic
    /// callers and tests; the handlers call `admission::leave` directly.
    pub async fn leave_node(&self, user_id: Uuid, node_id: Uuid) -> Result<(), String> {
        crate::admission::leave(self, user_id, node_id)
            .await
            .map_err(|e| e.message())
    }

    /// Kick `target_id` from `node_id` as `admin_id` through the kick
    /// routine of SPEC-01 REQ-35. A convenience wrapper for programmatic
    /// callers and tests; the handler calls `admission::kick` directly.
    pub async fn kick_from_node(
        &self,
        admin_id: Uuid,
        target_id: Uuid,
        node_id: Uuid,
    ) -> Result<(), String> {
        crate::admission::kick(self, admin_id, node_id, target_id)
            .await
            .map_err(|e| e.message())
    }

    // ── Node invite operations ──
    //
    // Convenience wrappers over the admission service (`crate::admission`)
    // for programmatic callers and tests. The HTTP and WebSocket handlers
    // call the admission service directly.

    /// Create an invite as `created_by`, with an optional use limit and an
    /// optional lifetime in whole hours. Requires admission authority
    /// (SPEC-01 REQ-38). Returns the invite id and code.
    pub async fn create_invite(
        &self,
        node_id: Uuid,
        created_by: Uuid,
        max_uses: Option<u32>,
        expires_in_hours: Option<u32>,
    ) -> Result<(Uuid, String), String> {
        let params = crate::admission::CreateInviteParams {
            max_uses,
            lifetime_secs: expires_in_hours.map(|hours| u64::from(hours) * 3600),
        };
        crate::admission::create_invite(self, node_id, created_by, params)
            .await
            .map(|invite| (invite.id, invite.invite_code))
            .map_err(|e| e.message())
    }

    /// Redeem `invite_code` as `user_id` through the admission entry point of
    /// `POST /invites/:code/join`, with no fingerprint and no build hash.
    /// Returns the node id and name.
    pub async fn use_invite(
        &self,
        invite_code: &str,
        user_id: Uuid,
    ) -> Result<(Uuid, String), String> {
        crate::admission::validate_join_fields(Some(invite_code), None).map_err(|e| e.message())?;
        match crate::admission::join(
            self,
            crate::admission::AdmissionContext::bare(user_id),
            crate::admission::AdmissionEntry::InviteCode {
                code: invite_code.to_string(),
            },
        )
        .await
        {
            Ok(crate::admission::AdmissionOutcome::Joined {
                node_id, node_name, ..
            }) => Ok((node_id, node_name)),
            Ok(crate::admission::AdmissionOutcome::Pending { .. }) => {
                Err("Join request pending".to_string())
            }
            Err(e) => Err(e.message()),
        }
    }

    /// List a node's invites. Requires admission authority (SPEC-01 REQ-38).
    pub async fn list_invites(
        &self,
        node_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<crate::models::NodeInvite>, String> {
        crate::admission::list_invites(self, node_id, user_id)
            .await
            .map_err(|e| e.message())
    }

    /// Revoke an invite by id (SPEC-01 REQ-38).
    pub async fn revoke_invite(&self, invite_id: Uuid, user_id: Uuid) -> Result<(), String> {
        crate::admission::revoke_invite_by_id(self, invite_id, user_id)
            .await
            .map(|_| ())
            .map_err(|e| e.message())
    }

    // ── Channel operations (now Node-scoped) ──

    pub async fn join_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<(), String> {
        // DM channels: membership is being one of the two participants (the
        // DM system node has no members, so the node check below would fail).
        // A failed DM lookup denies (SPEC-01 REQ-17(c)).
        match self.db.dm_participants(channel_id).await {
            Ok(Some((user1, user2))) => {
                if user1 == user_id || user2 == user_id {
                    return self
                        .db
                        .add_user_to_channel(channel_id, user_id)
                        .await
                        .map_err(|e| e.to_string());
                }
                return Err("Not a participant of this DM channel".to_string());
            }
            Ok(None) => {}
            Err(_) => return Err("Channel lookup failed".to_string()),
        }

        // Verify channel exists and user is member of the Node
        let channel = match self.db.get_channel(channel_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err("Channel not found".to_string()),
            Err(e) => {
                return Err({
                    tracing::error!("Database error: {}", e);
                    "Database error".to_string()
                })
            }
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
                if !self
                    .db
                    .node_member_can(m.node_id, m.user_id, Permission::CreateChannel)
                    .await
                {
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
            Err(e) => {
                return Err({
                    tracing::error!("Database error: {}", e);
                    "Database error".to_string()
                })
            }
        };

        // Check if user has permission to delete channels
        let member = self
            .db
            .get_node_member(channel.node_id, user_id)
            .await
            .map_err(|e| e.to_string())?;
        match member {
            Some(m) => {
                if !self
                    .db
                    .node_member_can(m.node_id, m.user_id, Permission::DeleteChannel)
                    .await
                {
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
    ) -> Result<(Uuid, i64), String> {
        self.db
            .store_message(channel_id, sender_id, encrypted_payload, None, None)
            .await
            .map_err(|e| e.to_string())
    }

    // ── Connection management ──

    /// Register a device connection. Returns the device_id used (caller
    /// needs it later for `remove_connection`).
    pub async fn add_connection(
        &self,
        user_id: Uuid,
        device_id: Option<Uuid>,
        sender: broadcast::Sender<String>,
    ) -> Uuid {
        let did = device_id.unwrap_or_else(Uuid::new_v4);
        self.connections
            .write()
            .await
            .entry(user_id)
            .or_default()
            .insert(did, sender);
        did
    }

    /// Remove a single device connection. If the user has no remaining
    /// devices, their entry is cleaned up entirely.
    pub async fn remove_connection(&self, user_id: Uuid, device_id: Uuid) {
        let mut conns = self.connections.write().await;
        if let Some(devices) = conns.get_mut(&user_id) {
            devices.remove(&device_id);
            if devices.is_empty() {
                conns.remove(&user_id);
            }
        }
        drop(conns);
        // Only remove build hash when ALL devices of this user are gone
        if !self.connections.read().await.contains_key(&user_id) {
            self.client_build_hashes.write().await.remove(&user_id);
        }
    }

    /// Store the client's build hash for later allowlist checks.
    pub async fn set_client_build_hash(&self, user_id: Uuid, build_hash: String) {
        self.client_build_hashes
            .write()
            .await
            .insert(user_id, build_hash);
    }

    /// Get the client's build hash.
    pub async fn get_client_build_hash(&self, user_id: Uuid) -> Option<String> {
        self.client_build_hashes.read().await.get(&user_id).cloned()
    }

    /// Check relay-level build hash enforcement.
    /// Returns Ok(()) if allowed, Err with message if rejected.
    pub async fn check_relay_build_hash(&self, client_hash: Option<&str>) -> Result<(), String> {
        let mode = self.build_hash_enforcement;
        if mode == BuildHashEnforcementMode::Off {
            return Ok(());
        }

        // If allowlist is empty, allow everything regardless of mode
        let allowlist = self
            .db
            .get_relay_build_hash_allowlist()
            .await
            .map_err(|e| {
                tracing::error!("Failed to check relay build allowlist: {}", e);
                "Failed to check relay build allowlist".to_string()
            })?;
        if allowlist.is_empty() {
            return Ok(());
        }

        let hash = client_hash.unwrap_or("");
        let is_allowed = allowlist.iter().any(|entry| entry.build_hash == hash);

        match mode {
            BuildHashEnforcementMode::Off => Ok(()),
            BuildHashEnforcementMode::Warn => {
                if !is_allowed {
                    warn!(
                        "Relay build hash enforcement (warn): unverified build hash '{}'",
                        hash
                    );
                }
                Ok(())
            }
            BuildHashEnforcementMode::Strict => {
                if is_allowed {
                    Ok(())
                } else {
                    Err("Build not accepted by relay administrator".to_string())
                }
            }
        }
    }

    /// Check if a user's build hash is allowed for a given node.
    /// Returns Ok(()) if allowed, Err with message if not.
    pub async fn check_build_hash_for_node(
        &self,
        user_id: Uuid,
        node_id: Uuid,
    ) -> Result<(), String> {
        let client_hash = self.get_client_build_hash(user_id).await;
        let hash_str = client_hash.as_deref().unwrap_or("");

        match self.db.is_build_hash_allowed(node_id, hash_str).await {
            Ok(true) => Ok(()),
            Ok(false) => Err("Build not allowed by Node admin".to_string()),
            Err(e) => Err({
                tracing::error!("Failed to check build allowlist: {}", e);
                "Failed to check build allowlist".to_string()
            }),
        }
    }

    pub async fn send_to_user(&self, user_id: Uuid, message: String) -> Result<(), String> {
        let connections = self.connections.read().await;
        if let Some(devices) = connections.get(&user_id) {
            for sender in devices.values() {
                let _ = sender.send(message.clone());
            }
        }
        Ok(())
    }

    pub async fn send_to_channel(&self, channel_id: Uuid, message: String) -> Result<(), String> {
        // A DM channel's frames go only to its two participants, taken from
        // `dm_channels` (SPEC-01 REQ-17(e)). If that lookup fails, the
        // `channel_members` cache is used: triggers and the boot repair keep
        // it a subset of the participants.
        let members = match self.db.dm_participants(channel_id).await {
            Ok(Some((user1, user2))) => vec![user1, user2],
            _ => self.get_channel_members(channel_id).await,
        };
        let connections = self.connections.read().await;
        for user_id in members {
            if let Some(devices) = connections.get(&user_id) {
                for sender in devices.values() {
                    let _ = sender.send(message.clone());
                }
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

    #[allow(clippy::too_many_arguments)]
    pub async fn update_user_profile(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        bio: Option<&str>,
        status: Option<&str>,
        custom_status: Option<&str>,
        banner_color: Option<&str>,
        banner_url: Option<&str>,
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
                banner_color,
                banner_url,
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

    /// Idle timeout in seconds (5 minutes)
    const IDLE_TIMEOUT_SECS: u64 = 300;

    pub async fn set_user_online(&self, user_id: Uuid) -> Result<(), String> {
        self.last_activity.write().await.insert(user_id, now());
        self.db
            .update_user_status(user_id, "online")
            .await
            .map_err(|e| e.to_string())?;
        self.broadcast_presence_update(user_id).await
    }

    pub async fn set_user_offline(&self, user_id: Uuid) -> Result<(), String> {
        self.last_activity.write().await.remove(&user_id);
        self.db
            .update_user_status(user_id, "offline")
            .await
            .map_err(|e| e.to_string())?;
        self.broadcast_presence_update(user_id).await
    }

    /// Record user activity (resets idle timer, promotes idle→online)
    pub async fn record_user_activity(&self, user_id: Uuid) -> Result<(), String> {
        self.last_activity.write().await.insert(user_id, now());
        // If user was idle, promote back to online
        if let Ok(Some(profile)) = self.get_user_profile(user_id).await {
            if profile.status == "idle" {
                self.db
                    .update_user_status(user_id, "online")
                    .await
                    .map_err(|e| e.to_string())?;
                self.broadcast_presence_update(user_id).await?;
            }
        }
        Ok(())
    }

    /// Check all connected users for idle timeout and transition them
    pub async fn check_idle_users(&self) -> Result<(), String> {
        let current_time = now();
        let activity = self.last_activity.read().await;
        let connections = self.connections.read().await;
        let mut idle_users = Vec::new();

        for (user_id, last) in activity.iter() {
            if connections.contains_key(user_id)
                && current_time.saturating_sub(*last) >= Self::IDLE_TIMEOUT_SECS
            {
                idle_users.push(*user_id);
            }
        }
        drop(activity);
        drop(connections);

        for user_id in idle_users {
            // Only transition online→idle (don't override dnd or already idle)
            if let Ok(Some(profile)) = self.get_user_profile(user_id).await {
                if profile.status == "online" {
                    self.db
                        .update_user_status(user_id, "idle")
                        .await
                        .map_err(|e| e.to_string())?;
                    self.broadcast_presence_update(user_id).await?;
                }
            }
        }
        Ok(())
    }

    /// Get presence status for all members of a node
    pub async fn get_node_presence(&self, node_id: Uuid) -> Result<Vec<serde_json::Value>, String> {
        let members = self
            .db
            .get_node_members(node_id)
            .await
            .map_err(|e| e.to_string())?;

        let connections = self.connections.read().await;
        let mut result = Vec::new();

        for member in members {
            let status = if let Ok(Some(profile)) = self.get_user_profile(member.user_id).await {
                if connections.contains_key(&member.user_id) {
                    profile.status
                } else {
                    "offline".to_string()
                }
            } else {
                "offline".to_string()
            };

            result.push(serde_json::json!({
                "user_id": member.user_id,
                "status": status,
            }));
        }

        Ok(result)
    }

    /// Send current presence state for all of a user's nodes
    pub async fn send_initial_presence(&self, user_id: Uuid) -> Result<(), String> {
        let user_nodes = self
            .db
            .get_user_nodes(user_id)
            .await
            .map_err(|e| e.to_string())?;

        let connections = self.connections.read().await;
        let devices = match connections.get(&user_id) {
            Some(d) => d.values().cloned().collect::<Vec<_>>(),
            None => return Ok(()),
        };
        drop(connections);

        for node in user_nodes {
            let presence = self.get_node_presence(node.id).await?;
            let msg = serde_json::json!({
                "type": "presence_bulk",
                "node_id": node.id,
                "members": presence,
            })
            .to_string();
            for sender in &devices {
                let _ = sender.send(msg.clone());
            }
        }

        Ok(())
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
                    if let Some(devices) = connections.get(&member.user_id) {
                        for sender in devices.values() {
                            let _ = sender.send(presence_message.clone());
                        }
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

    /// Remove user from all voice channels they're in, returning the channel IDs they left
    pub async fn leave_all_voice_channels(&self, user_id: Uuid) -> Vec<Uuid> {
        let mut voice_channels = self.voice_channels.write().await;
        let mut left_channels = Vec::new();

        voice_channels.retain(|channel_id, participants| {
            if participants.remove(&user_id) {
                left_channels.push(*channel_id);
            }
            !participants.is_empty()
        });

        left_channels
    }

    /// Get voice mode for a channel (true = relay, false = p2p). Default is relay.
    pub async fn get_voice_relay_mode(&self, channel_id: Uuid) -> bool {
        let modes = self.voice_relay_mode.read().await;
        modes.get(&channel_id).copied().unwrap_or(true) // default: relay
    }

    /// Set voice mode for a channel
    pub async fn set_voice_relay_mode(&self, channel_id: Uuid, relay: bool) {
        let mut modes = self.voice_relay_mode.write().await;
        modes.insert(channel_id, relay);
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

            // Send to all participants except the sender (all their devices)
            for &user_id in participants.iter() {
                if user_id != sender_id {
                    if let Some(devices) = connections.get(&user_id) {
                        for sender in devices.values() {
                            let _ = sender.send(message.clone());
                        }
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
            .map_err(|e| {
                tracing::error!("Database error: {}", e);
                "Database error".to_string()
            })
    }

    /// Search messages within a Node by metadata
    #[allow(clippy::too_many_arguments)]
    pub async fn search_messages(
        &self,
        node_id: Uuid,
        query: &str,
        channel_id_filter: Option<Uuid>,
        author_filter: Option<Uuid>,
        before_filter: Option<i64>,
        after_filter: Option<i64>,
        limit: u32,
    ) -> Result<Vec<crate::models::SearchResult>, String> {
        self.db
            .search_messages(
                node_id,
                query,
                channel_id_filter,
                author_filter,
                before_filter,
                after_filter,
                limit,
            )
            .await
            .map_err(|e| {
                tracing::error!("Database error: {}", e);
                "Database error".to_string()
            })
    }

    /// Check if user can access a specific channel (must be node member and channel member)
    pub async fn user_can_access_channel(
        &self,
        user_id: Uuid,
        channel_id: Uuid,
    ) -> Result<bool, String> {
        // DM channels live under the DM system node, which has no members —
        // access is simply "am I one of the two participants". A failed DM
        // lookup denies instead of falling through to the node checks
        // (SPEC-01 REQ-17(c)).
        match self.db.dm_participants(channel_id).await {
            Ok(Some((user1, user2))) => return Ok(user1 == user_id || user2 == user_id),
            Ok(None) => {}
            Err(_) => return Err("Channel lookup failed".to_string()),
        }

        // Get channel info to find the node
        let channel = self.db.get_channel(channel_id).await.map_err(|e| {
            tracing::error!("Database error: {}", e);
            "Database error".to_string()
        })?;

        let channel = channel.ok_or_else(|| "Channel not found".to_string())?;

        // Check if user is a member of the node
        let is_node_member = self
            .db
            .is_node_member(channel.node_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Database error: {}", e);
                "Database error".to_string()
            })?;

        if !is_node_member {
            return Ok(false);
        }

        // Check VIEW_CHANNEL permission via channel permission cascade
        let perms = self
            .db
            .compute_channel_permissions(channel.node_id, user_id, channel_id)
            .await
            .map_err(|e| {
                tracing::error!("Permission compute error: {}", e);
                "Permission compute error".to_string()
            })?;

        Ok(perms & crate::models::permission_bits::VIEW_CHANNEL != 0)
    }

    /// Check if user is a member of a node
    pub async fn is_node_member(&self, user_id: Uuid, node_id: Uuid) -> Result<bool, String> {
        self.db.is_node_member(node_id, user_id).await.map_err(|e| {
            tracing::error!("Database error: {}", e);
            "Database error".to_string()
        })
    }

    /// Load persisted auth tokens from database (call on startup)
    pub async fn load_persisted_tokens(&self) -> usize {
        match self.db.load_auth_tokens(now()).await {
            Ok(tokens) => {
                let count = tokens.len();
                let mut auth_tokens = self.auth_tokens.write().await;
                for (token, user_id, expires_at) in tokens {
                    auth_tokens.insert(
                        token.clone(),
                        AuthToken {
                            token,
                            user_id,
                            expires_at,
                        },
                    );
                }
                count
            }
            Err(e) => {
                tracing::warn!("Failed to load persisted tokens: {}", e);
                0
            }
        }
    }

    /// Clean up stale in-memory state to prevent unbounded growth.
    ///
    /// 1. Removes `slow_mode_cooldowns` entries older than 1 hour.
    /// 2. Removes `last_activity` entries for users no longer connected.
    /// 3. Evicts `link_preview_cache` entries older than 1 hour (TTL-based;
    ///    the 1000-entry hard cap in the handler remains as a safety valve).
    pub async fn cleanup_stale_state(&self) {
        let current_time = now();
        let one_hour_ago = current_time.saturating_sub(3600);

        // 1. Evict slow-mode cooldown entries older than 1 hour.
        {
            let mut cooldowns = self.slow_mode_cooldowns.write().await;
            let before = cooldowns.len();
            cooldowns.retain(|_, ts| *ts >= one_hour_ago);
            let removed = before - cooldowns.len();
            if removed > 0 {
                tracing::debug!("Cleaned {} stale slow_mode_cooldown entries", removed);
            }
        }

        // 2. Remove last_activity entries for disconnected users.
        {
            let connections = self.connections.read().await;
            let mut activity = self.last_activity.write().await;
            let before = activity.len();
            activity.retain(|user_id, _| connections.contains_key(user_id));
            let removed = before - activity.len();
            if removed > 0 {
                tracing::debug!("Cleaned {} stale last_activity entries", removed);
            }
        }

        // 3. TTL-evict link_preview_cache entries older than 1 hour.
        {
            let mut cache = self.link_preview_cache.write().await;
            let before = cache.len();
            cache.retain(|_, (_, fetched_at)| *fetched_at >= one_hour_ago);
            let removed = before - cache.len();
            if removed > 0 {
                tracing::debug!("Evicted {} stale link_preview_cache entries", removed);
            }
        }
    }

    /// Remove expired auth tokens from memory and database (H3: token cleanup)
    pub async fn cleanup_expired_tokens(&self) -> usize {
        let current_time = now();
        let mut tokens = self.auth_tokens.write().await;
        let before = tokens.len();
        tokens.retain(|_, token| token.expires_at > current_time);
        let removed = before - tokens.len();

        // Also clean DB
        if let Err(e) = self.db.delete_expired_auth_tokens(current_time).await {
            tracing::warn!("Failed to clean expired tokens from DB: {}", e);
        }

        removed
    }

    pub fn uptime(&self) -> u64 {
        now() - self.start_time
    }

    // ── Bot API v2 operations ──

    #[allow(clippy::too_many_arguments)]
    pub async fn install_bot(
        &self,
        bot_id: &str,
        node_id: Uuid,
        name: &str,
        icon: Option<&str>,
        description: Option<&str>,
        webhook_url: &str,
        bot_token_hash: &str,
        ed25519_pubkey: Option<&str>,
        x25519_pubkey: Option<&str>,
        allowed_channels_json: &str,
        installed_at: u64,
        _commands_json: &str,
        commands: &[crate::bot_api::BotCommand],
    ) -> Result<(), String> {
        self.db
            .install_bot(
                bot_id,
                node_id,
                name,
                icon,
                description,
                webhook_url,
                bot_token_hash,
                ed25519_pubkey,
                x25519_pubkey,
                allowed_channels_json,
                installed_at,
            )
            .await
            .map_err(|e| e.to_string())?;

        // Store each command
        for cmd in commands {
            let params_json = serde_json::to_string(&cmd.params).unwrap_or_default();
            self.db
                .store_bot_command(bot_id, node_id, &cmd.name, &cmd.description, &params_json)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub async fn uninstall_bot(&self, bot_id: &str, node_id: Uuid) -> Result<(), String> {
        let deleted = self
            .db
            .uninstall_bot(bot_id, node_id)
            .await
            .map_err(|e| e.to_string())?;
        if !deleted {
            return Err("Bot not found".into());
        }
        Ok(())
    }

    pub async fn list_installed_bots(
        &self,
        node_id: Uuid,
    ) -> Result<Vec<crate::bot_api::InstalledBotInfo>, String> {
        self.db
            .list_installed_bots(node_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_bot_commands(
        &self,
        bot_id: &str,
        node_id: Uuid,
    ) -> Result<Vec<crate::bot_api::BotCommand>, String> {
        let commands = self
            .db
            .get_bot_commands(bot_id, node_id)
            .await
            .map_err(|e| e.to_string())?;
        if commands.is_empty() {
            // Check if bot exists at all
            self.db
                .get_bot_webhook_info(bot_id, node_id)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(commands)
    }

    pub async fn get_bot_webhook_info(
        &self,
        bot_id: &str,
        node_id: Uuid,
    ) -> Result<(String, String), String> {
        self.db
            .get_bot_webhook_info(bot_id, node_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn validate_bot_token_v2(&self, token_hash: &str) -> Option<(String, Uuid)> {
        self.db
            .validate_bot_token_v2(token_hash)
            .await
            .ok()
            .flatten()
    }

    pub async fn create_bot_invocation(
        &self,
        invocation_id: &str,
        bot_id: &str,
        node_id: Uuid,
        channel_id: &str,
        invoker_user_id: Uuid,
        command_name: &str,
    ) -> Result<(), String> {
        self.db
            .create_bot_invocation(
                invocation_id,
                bot_id,
                node_id,
                channel_id,
                invoker_user_id,
                command_name,
            )
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_invocation_info(
        &self,
        invocation_id: &str,
        bot_id: &str,
        node_id: Uuid,
    ) -> Result<(String, String), String> {
        self.db
            .get_invocation_info(invocation_id, bot_id, node_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn update_invocation_status(
        &self,
        invocation_id: &str,
        status: &str,
    ) -> Result<(), String> {
        self.db
            .update_invocation_status(invocation_id, status)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn increment_bot_invocation_count(
        &self,
        bot_id: &str,
        node_id: Uuid,
    ) -> Result<(), String> {
        self.db
            .increment_bot_invocation_count(bot_id, node_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn store_bot_crypto(
        &self,
        bot_id: &str,
        node_id: Uuid,
        node_x25519_privkey: &str,
        shared_secret: &str,
    ) -> Result<(), String> {
        self.db
            .store_bot_crypto(bot_id, node_id, node_x25519_privkey, shared_secret)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_bot_crypto_info(
        &self,
        bot_id: &str,
        node_id: Uuid,
    ) -> Result<Option<crate::bot_api::BotCryptoInfo>, String> {
        self.db
            .get_bot_crypto_info(bot_id, node_id)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn rotate_bot_crypto(
        &self,
        bot_id: &str,
        node_id: Uuid,
        node_x25519_privkey: &str,
        x25519_pubkey: &str,
        shared_secret: &str,
    ) -> Result<(), String> {
        self.db
            .rotate_bot_crypto(
                bot_id,
                node_id,
                node_x25519_privkey,
                x25519_pubkey,
                shared_secret,
            )
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_user_display_name(&self, user_id: Uuid) -> Result<String, String> {
        // Try to get from user profile
        let profile = self
            .db
            .get_user_profile(user_id)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(profile) = profile {
            return Ok(profile.display_name);
        }
        // Fallback to public key hash prefix
        let user = self
            .db
            .get_user_by_id(user_id)
            .await
            .map_err(|e| e.to_string())?;
        match user {
            Some(u) => Ok(u.public_key_hash[..8].to_string()),
            None => Ok("Unknown".into()),
        }
    }

    pub async fn broadcast_to_channel(
        &self,
        channel_id: Uuid,
        message: String,
    ) -> Result<(), String> {
        self.send_to_channel(channel_id, message).await
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Shared application state type
pub type SharedState = Arc<AppState>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NodeRole;

    #[tokio::test]
    async fn test_node_lifecycle() {
        let state = AppState::new_in_memory().await.unwrap();
        let owner_id = state
            .register_user("key".into(), "pw".into())
            .await
            .unwrap();
        let user_id = state
            .register_user("key2".into(), "pw".into())
            .await
            .unwrap();

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

        // Join (through an invite the owner created)
        crate::test_support::admit_with_owner_invite(&state, node.id, user_id)
            .await
            .unwrap();
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
        let owner_id = state
            .register_user("key".into(), "pw".into())
            .await
            .unwrap();
        let outsider_id = state
            .register_user("key2".into(), "pw".into())
            .await
            .unwrap();

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

        let user1_id = state
            .register_user("key1".into(), "pw".into())
            .await
            .unwrap();
        let user2_id = state
            .register_user("key2".into(), "pw".into())
            .await
            .unwrap();

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
        crate::test_support::admit_with_owner_invite(&state, node.id, user2_id)
            .await
            .unwrap();
        state.join_channel(user2_id, channel.id).await.unwrap();

        let members = state.get_channel_members(channel.id).await;
        assert_eq!(members.len(), 2);
    }

    #[tokio::test]
    async fn test_voice_channel_operations() {
        let state = AppState::new_in_memory().await.unwrap();

        let user1_id = state
            .register_user("key1".into(), "pw".into())
            .await
            .unwrap();
        let user2_id = state
            .register_user("key2".into(), "pw".into())
            .await
            .unwrap();

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
        crate::test_support::admit_with_owner_invite(&state, node.id, user2_id)
            .await
            .unwrap();

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

        let user_a = state
            .register_user("keyA".into(), "pw".into())
            .await
            .unwrap();
        let user_b = state
            .register_user("keyB".into(), "pw".into())
            .await
            .unwrap();

        // Create a shared node
        let node = state
            .create_node("Shared".into(), user_a, None)
            .await
            .unwrap();
        crate::test_support::admit_with_owner_invite(&state, node.id, user_b)
            .await
            .unwrap();

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

        let user_a = state
            .register_user("keyA".into(), "pw".into())
            .await
            .unwrap();
        let user_b = state
            .register_user("keyB".into(), "pw".into())
            .await
            .unwrap();

        let node = state
            .create_node("Node".into(), user_a, None)
            .await
            .unwrap();
        crate::test_support::admit_with_owner_invite(&state, node.id, user_b)
            .await
            .unwrap();

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

        let user_a = state
            .register_user("keyA".into(), "pw".into())
            .await
            .unwrap();
        let user_b = state
            .register_user("keyB".into(), "pw".into())
            .await
            .unwrap();

        // No shared node
        assert!(!state.db.share_a_node(user_a, user_b).await.unwrap());
    }

    #[tokio::test]
    async fn test_dm_requires_friendship() {
        let state = AppState::new_in_memory().await.unwrap();

        let user_a = state
            .register_user("keyA".into(), "pw".into())
            .await
            .unwrap();
        let user_b = state
            .register_user("keyB".into(), "pw".into())
            .await
            .unwrap();

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
        crate::test_support::admit_with_owner_invite(&state, node.id, user_b)
            .await
            .unwrap();
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

        let user_a = state
            .register_user("keyA".into(), "pw".into())
            .await
            .unwrap();
        let user_b = state
            .register_user("keyB".into(), "pw".into())
            .await
            .unwrap();

        let node = state
            .create_node("Node".into(), user_a, None)
            .await
            .unwrap();
        crate::test_support::admit_with_owner_invite(&state, node.id, user_b)
            .await
            .unwrap();

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

    // ── Enum Display/FromStr tests ──

    #[test]
    fn test_metadata_mode_display() {
        assert_eq!(MetadataMode::Standard.to_string(), "standard");
        assert_eq!(MetadataMode::Minimal.to_string(), "minimal");
    }

    #[test]
    fn test_metadata_mode_from_str() {
        assert_eq!(
            "standard".parse::<MetadataMode>().unwrap(),
            MetadataMode::Standard
        );
        assert_eq!(
            "STANDARD".parse::<MetadataMode>().unwrap(),
            MetadataMode::Standard
        );
        assert_eq!(
            "Minimal".parse::<MetadataMode>().unwrap(),
            MetadataMode::Minimal
        );
        assert!("invalid".parse::<MetadataMode>().is_err());
        assert!("".parse::<MetadataMode>().is_err());
    }

    #[test]
    fn test_metadata_mode_default() {
        assert_eq!(MetadataMode::default(), MetadataMode::Standard);
    }

    #[test]
    fn test_build_hash_enforcement_mode_display() {
        assert_eq!(BuildHashEnforcementMode::Off.to_string(), "off");
        assert_eq!(BuildHashEnforcementMode::Warn.to_string(), "warn");
        assert_eq!(BuildHashEnforcementMode::Strict.to_string(), "strict");
    }

    #[test]
    fn test_build_hash_enforcement_mode_from_str() {
        assert_eq!(
            "off".parse::<BuildHashEnforcementMode>().unwrap(),
            BuildHashEnforcementMode::Off
        );
        assert_eq!(
            "WARN".parse::<BuildHashEnforcementMode>().unwrap(),
            BuildHashEnforcementMode::Warn
        );
        assert_eq!(
            "Strict".parse::<BuildHashEnforcementMode>().unwrap(),
            BuildHashEnforcementMode::Strict
        );
        assert!("bogus".parse::<BuildHashEnforcementMode>().is_err());
    }

    #[test]
    fn test_build_hash_enforcement_mode_default() {
        assert_eq!(
            BuildHashEnforcementMode::default(),
            BuildHashEnforcementMode::Off
        );
    }

    #[test]
    fn test_build_verification_mode_default() {
        assert_eq!(
            BuildVerificationMode::default(),
            BuildVerificationMode::Disabled
        );
    }

    // ── BuildVerification tests ──

    #[test]
    fn test_build_verification_new() {
        let bv = BuildVerification::new(BuildVerificationMode::Disabled);
        assert_eq!(bv.mode, BuildVerificationMode::Disabled);
        assert!(!bv.server_build_info.build_hash.is_empty());
    }

    #[test]
    fn test_build_verification_unknown_hash() {
        let bv = BuildVerification::new(BuildVerificationMode::Warn);
        let trust = bv.verify_client_hash("definitely-not-a-real-hash");
        // With no hashes.json loaded, should be Unknown
        assert_eq!(trust, BuildTrust::Unknown);
    }

    // ── AppState creation tests ──

    #[tokio::test]
    async fn test_new_in_memory_state() {
        let state = AppState::new_in_memory().await.unwrap();
        assert!(state.auth_tokens.read().await.is_empty());
        assert!(state.connections.read().await.is_empty());
        assert!(state.voice_channels.read().await.is_empty());
        assert_eq!(state.metadata_mode, MetadataMode::Standard);
    }

    // ── Registration edge cases ──

    #[tokio::test]
    async fn test_register_user_happy_path() {
        let state = AppState::new_in_memory().await.unwrap();
        let user_id = state
            .register_user("pubkey123".into(), "password".into())
            .await
            .unwrap();
        // Returned user_id should be a valid UUID
        assert!(!user_id.is_nil());
    }

    #[tokio::test]
    async fn test_register_user_duplicate_key() {
        let state = AppState::new_in_memory().await.unwrap();
        state
            .register_user("same_key".into(), "pass1".into())
            .await
            .unwrap();
        // Second registration with same key should fail
        let result = state.register_user("same_key".into(), "pass2".into()).await;
        assert!(result.is_err());
    }

    /// T-4 (REQ-4(a)): an empty password is refused and creates no account.
    #[tokio::test]
    async fn test_register_user_empty_password() {
        let state = AppState::new_in_memory().await.unwrap();
        let result = state.register_user("pk1".into(), "".into()).await;
        assert!(result.is_err());
        let pkh = crate::db::compute_public_key_hash("pk1");
        assert!(!state.db.public_key_hash_exists(&pkh).await.unwrap());
    }

    // ── Authentication tests ──

    #[tokio::test]
    async fn test_authenticate_valid() {
        let state = AppState::new_in_memory().await.unwrap();
        state
            .register_user("authkey".into(), "secret".into())
            .await
            .unwrap();
        let pkh = crate::db::compute_public_key_hash("authkey");
        let auth_token = state.authenticate_user(pkh, "secret".into()).await.unwrap();
        assert!(!auth_token.token.is_empty());
    }

    #[tokio::test]
    async fn test_authenticate_wrong_password() {
        let state = AppState::new_in_memory().await.unwrap();
        state
            .register_user("authkey2".into(), "correct".into())
            .await
            .unwrap();
        let pkh = crate::db::compute_public_key_hash("authkey2");
        let result = state.authenticate_user(pkh, "wrong".into()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_nonexistent_user() {
        let state = AppState::new_in_memory().await.unwrap();
        let pkh = crate::db::compute_public_key_hash("no_such_key");
        let result = state.authenticate_user(pkh, "pass".into()).await;
        assert!(result.is_err());
    }

    // ── Token validation ──

    #[tokio::test]
    async fn test_validate_token_valid() {
        let state = AppState::new_in_memory().await.unwrap();
        let user_id = state
            .register_user("tokkey".into(), "pass".into())
            .await
            .unwrap();
        let pkh = crate::db::compute_public_key_hash("tokkey");
        let auth_token = state.authenticate_user(pkh, "pass".into()).await.unwrap();
        let validated = state.validate_token(&auth_token.token).await;
        assert_eq!(validated, Some(user_id));
    }

    #[tokio::test]
    async fn test_validate_token_invalid() {
        let state = AppState::new_in_memory().await.unwrap();
        assert_eq!(state.validate_token("garbage-token").await, None);
    }

    // ── SPEC-01: credential refusals and the reserved user ──

    /// Insert an account with a raw stored hash, reachable on v1 by
    /// `public_key_hash` and on v2 by `username`.
    async fn insert_raw_account(state: &AppState, pkh: &str, username: &str, hash: &str) {
        sqlx::query(
            "INSERT INTO users (id, public_key_hash, public_key, password_hash, username, created_at) VALUES (?, ?, ?, ?, ?, 0)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(pkh)
        .bind(pkh)
        .bind(hash)
        .bind(username)
        .execute(state.db.pool())
        .await
        .unwrap();
    }

    /// The PHC hashes given to the password verifier since the last call.
    fn take_verifications(state: &AppState) -> Vec<String> {
        std::mem::take(
            &mut *state
                .password_verifications
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
        )
    }

    /// T-2b (REQ-1, REQ-2): each refusal of the reserved user or of an
    /// unusable stored hash runs exactly one verification, against the dummy
    /// hash; a wrong password runs one against the stored hash.
    #[tokio::test]
    async fn test_credential_refusals_verify_once_against_dummy_hash() {
        use argon2::password_hash::PasswordHash;
        let state = AppState::new_in_memory().await.unwrap();
        let dummy = state.dummy_password_hash.to_string();

        // The sentinel holds a real hash of "pw" and a username, so only the
        // reserved-user check can refuse it, on v1 and on v2.
        let sentinel_hash = crate::admission::hash_new_password("pw").unwrap();
        sqlx::query("UPDATE users SET password_hash = ?, username = 'sentinel' WHERE id = ?")
            .bind(&sentinel_hash)
            .bind(crate::db::DM_SYSTEM_USER_ID.to_string())
            .execute(state.db.pool())
            .await
            .unwrap();
        let unusable = [
            ("pkh_locked", "!locked"),
            ("pkh_system", "SYSTEM"),
            ("pkh_empty", ""),
        ];
        for (pkh, hash) in unusable {
            insert_raw_account(&state, pkh, &format!("user_{pkh}"), hash).await;
        }

        let refused = state.authenticate_user("SYSTEM".into(), "pw".into()).await;
        assert_eq!(refused.unwrap_err(), INVALID_PASSWORD);
        assert_eq!(take_verifications(&state), vec![dummy.clone()]);
        let refused = state
            .authenticate_user_by_username("sentinel".into(), "pw".into(), None)
            .await;
        assert_eq!(refused.unwrap_err(), INVALID_PASSWORD);
        assert_eq!(take_verifications(&state), vec![dummy.clone()]);

        for (pkh, _) in unusable {
            for password in ["", "x"] {
                let refused = state.authenticate_user(pkh.into(), password.into()).await;
                assert_eq!(refused.unwrap_err(), INVALID_PASSWORD, "v1 {pkh}");
                assert_eq!(take_verifications(&state), vec![dummy.clone()], "v1 {pkh}");
            }
            let refused = state
                .authenticate_user_by_username(format!("user_{pkh}"), "x".into(), None)
                .await;
            assert_eq!(refused.unwrap_err(), INVALID_PASSWORD, "v2 {pkh}");
            assert_eq!(take_verifications(&state), vec![dummy.clone()], "v2 {pkh}");
        }
        assert!(state.auth_tokens.read().await.is_empty());

        // A wrong password on a real account verifies once, against its hash.
        state
            .register_user("real_pk".into(), "correct".into())
            .await
            .unwrap();
        let real_pkh = crate::db::compute_public_key_hash("real_pk");
        let stored = state
            .db
            .get_user_password_hash_by_pkh(&real_pkh)
            .await
            .unwrap()
            .unwrap();
        let refused = state
            .authenticate_user(real_pkh.clone(), "wrong".into())
            .await;
        assert_eq!(refused.unwrap_err(), INVALID_PASSWORD);
        assert_eq!(take_verifications(&state), vec![stored.clone()]);

        state
            .register_user_v2("real_user".into(), "correct".into(), None, None, None)
            .await
            .unwrap();
        let refused = state
            .authenticate_user_by_username("real_user".into(), "wrong".into(), None)
            .await;
        assert_eq!(refused.unwrap_err(), INVALID_PASSWORD);
        assert_eq!(take_verifications(&state).len(), 1);

        // The dummy hash has the parameters of a freshly made hash.
        let dummy = PasswordHash::new(&dummy).unwrap();
        let fresh = PasswordHash::new(&stored).unwrap();
        assert_eq!(dummy.algorithm, fresh.algorithm);
        assert_eq!(dummy.version, fresh.version);
        assert_eq!(dummy.params, fresh.params);

        // The right password still works.
        assert!(state
            .authenticate_user(real_pkh, "correct".into())
            .await
            .is_ok());
        assert_eq!(take_verifications(&state), vec![stored]);
    }

    /// T-3 (REQ-3): a token of the reserved user never validates and is
    /// dropped from the in-memory map.
    #[tokio::test]
    async fn test_reserved_user_token_is_never_valid() {
        let state = AppState::new_in_memory().await.unwrap();
        state.auth_tokens.write().await.insert(
            "tok_sentinel".into(),
            AuthToken {
                token: "tok_sentinel".into(),
                user_id: crate::db::DM_SYSTEM_USER_ID,
                expires_at: now() + 3600,
            },
        );
        assert_eq!(state.validate_token("tok_sentinel").await, None);
        assert!(!state.auth_tokens.read().await.contains_key("tok_sentinel"));
    }

    /// T-9 (REQ-9), state level: redeeming an invite of a node owned by the
    /// reserved user neither transfers ownership nor grants a role.
    #[tokio::test]
    async fn test_invite_into_sentinel_owned_node_grants_nothing() {
        let state = AppState::new_in_memory().await.unwrap();
        let sentinel = crate::db::DM_SYSTEM_USER_ID;
        let node_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO nodes (id, name, owner_id, description, created_at) VALUES (?, 'Management', ?, NULL, 0)",
        )
        .bind(node_id.to_string())
        .bind(sentinel.to_string())
        .execute(state.db.pool())
        .await
        .unwrap();
        state.db.seed_management_roles(node_id).await.unwrap();
        let moderator = state
            .register_user("t9_m".into(), "pw".into())
            .await
            .unwrap();
        state
            .db
            .seed_node_member(node_id, moderator, NodeRole::Admin)
            .await
            .unwrap();
        let (_, code) = state
            .create_invite(node_id, moderator, None, None)
            .await
            .unwrap();

        let joiner = state
            .register_user("t9_u".into(), "pw".into())
            .await
            .unwrap();
        state.use_invite(&code, joiner).await.unwrap();

        let member = state
            .db
            .get_node_member(node_id, joiner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.role, NodeRole::Member);
        assert!(state
            .db
            .get_member_roles(node_id, joiner)
            .await
            .unwrap()
            .is_empty());
        let node = state.db.get_node(node_id).await.unwrap().unwrap();
        assert_eq!(node.owner_id, sentinel);
    }

    // ── Invite system ──

    #[tokio::test]
    async fn test_invite_create_and_use() {
        let state = AppState::new_in_memory().await.unwrap();
        let owner = state
            .register_user("inv_owner".into(), "pw".into())
            .await
            .unwrap();
        let joiner = state
            .register_user("inv_joiner".into(), "pw".into())
            .await
            .unwrap();

        let node = state
            .create_node("InvNode".into(), owner, None)
            .await
            .unwrap();
        let invite = state
            .create_invite(node.id, owner, Some(5), None)
            .await
            .unwrap();
        assert!(!invite.1.is_empty());

        // Use invite
        state.use_invite(&invite.1, joiner).await.unwrap();
        let info = state.get_node_info(node.id).await.unwrap();
        assert_eq!(info.members.len(), 2);
    }

    #[tokio::test]
    async fn test_invite_invalid_code() {
        let state = AppState::new_in_memory().await.unwrap();
        let user = state
            .register_user("inv_user".into(), "pw".into())
            .await
            .unwrap();
        let result = state.use_invite("BADCODE", user).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invite_max_uses() {
        let state = AppState::new_in_memory().await.unwrap();
        let owner = state
            .register_user("maxinv_owner".into(), "pw".into())
            .await
            .unwrap();
        let node = state
            .create_node("MaxNode".into(), owner, None)
            .await
            .unwrap();

        // Create invite with max_uses = 1
        let invite = state
            .create_invite(node.id, owner, Some(1), None)
            .await
            .unwrap();

        let user1 = state
            .register_user("maxinv_u1".into(), "pw".into())
            .await
            .unwrap();
        state.use_invite(&invite.1, user1).await.unwrap();

        // Second use should fail
        let user2 = state
            .register_user("maxinv_u2".into(), "pw".into())
            .await
            .unwrap();
        let result = state.use_invite(&invite.1, user2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_revoke_invite() {
        let state = AppState::new_in_memory().await.unwrap();
        let owner = state
            .register_user("rev_owner".into(), "pw".into())
            .await
            .unwrap();
        let node = state
            .create_node("RevNode".into(), owner, None)
            .await
            .unwrap();
        let invite = state
            .create_invite(node.id, owner, None, None)
            .await
            .unwrap();

        state.revoke_invite(invite.0, owner).await.unwrap();

        // Can't use revoked invite
        let user = state
            .register_user("rev_user".into(), "pw".into())
            .await
            .unwrap();
        let result = state.use_invite(&invite.1, user).await;
        assert!(result.is_err());
    }

    // ── Voice channel additional tests ──

    #[tokio::test]
    async fn test_voice_relay_mode_default() {
        let state = AppState::new_in_memory().await.unwrap();
        let channel_id = Uuid::new_v4();
        // Default should be relay mode (true)
        assert!(state.get_voice_relay_mode(channel_id).await);
    }

    #[tokio::test]
    async fn test_voice_relay_mode_toggle() {
        let state = AppState::new_in_memory().await.unwrap();
        let channel_id = Uuid::new_v4();
        state.set_voice_relay_mode(channel_id, false).await;
        assert!(!state.get_voice_relay_mode(channel_id).await);
        state.set_voice_relay_mode(channel_id, true).await;
        assert!(state.get_voice_relay_mode(channel_id).await);
    }

    #[tokio::test]
    async fn test_leave_all_voice_channels() {
        let state = AppState::new_in_memory().await.unwrap();
        let user = state
            .register_user("voice_leaver".into(), "pw".into())
            .await
            .unwrap();
        let owner = state
            .register_user("voice_owner".into(), "pw".into())
            .await
            .unwrap();
        let node = state
            .create_node("VNode".into(), owner, None)
            .await
            .unwrap();
        crate::test_support::admit_with_owner_invite(&state, node.id, user)
            .await
            .unwrap();

        let ch1 = state
            .create_channel("vc1".into(), node.id, owner)
            .await
            .unwrap();
        let ch2 = state
            .create_channel("vc2".into(), node.id, owner)
            .await
            .unwrap();

        state.join_voice_channel(user, ch1.id).await.unwrap();
        state.join_voice_channel(user, ch2.id).await.unwrap();

        let left = state.leave_all_voice_channels(user).await;
        assert_eq!(left.len(), 2);
        assert!(state
            .get_voice_channel_participants(ch1.id)
            .await
            .is_empty());
        assert!(state
            .get_voice_channel_participants(ch2.id)
            .await
            .is_empty());
    }

    // ── Uptime test ──

    #[tokio::test]
    async fn test_uptime() {
        let state = AppState::new_in_memory().await.unwrap();
        let uptime = state.uptime();
        // Should be 0 or 1 second immediately after creation
        assert!(uptime <= 2);
    }

    // ── Client build hash tracking ──

    #[tokio::test]
    async fn test_client_build_hash_tracking() {
        let state = AppState::new_in_memory().await.unwrap();
        let user = state
            .register_user("hash_user".into(), "pw".into())
            .await
            .unwrap();

        assert!(state.get_client_build_hash(user).await.is_none());
        state.set_client_build_hash(user, "abc123".into()).await;
        assert_eq!(state.get_client_build_hash(user).await.unwrap(), "abc123");
    }

    // ── Node info edge cases ──

    #[tokio::test]
    async fn test_get_node_info_nonexistent() {
        let state = AppState::new_in_memory().await.unwrap();
        let result = state.get_node_info(Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    // ── Channel deletion permission check ──

    #[tokio::test]
    async fn test_delete_channel_requires_permission() {
        let state = AppState::new_in_memory().await.unwrap();
        let owner = state
            .register_user("delch_owner".into(), "pw".into())
            .await
            .unwrap();
        let member = state
            .register_user("delch_member".into(), "pw".into())
            .await
            .unwrap();

        let node = state
            .create_node("DelNode".into(), owner, None)
            .await
            .unwrap();
        crate::test_support::admit_with_owner_invite(&state, node.id, member)
            .await
            .unwrap();

        let channel = state
            .create_channel("doomed".into(), node.id, owner)
            .await
            .unwrap();

        // Non-owner shouldn't be able to delete
        let result = state.delete_channel(channel.id, member).await;
        assert!(result.is_err());

        // Owner should succeed
        state.delete_channel(channel.id, owner).await.unwrap();
    }

    // ── Token cleanup ──

    #[tokio::test]
    async fn test_cleanup_expired_tokens() {
        let state = AppState::new_in_memory().await.unwrap();
        // Insert an expired token manually
        let expired_token = AuthToken {
            token: "expired_tok".into(),
            user_id: Uuid::new_v4(),
            expires_at: 1000, // long past
        };
        state
            .auth_tokens
            .write()
            .await
            .insert("expired_tok".into(), expired_token);

        let cleaned = state.cleanup_expired_tokens().await;
        assert!(cleaned >= 1);
        assert!(state.validate_token("expired_tok").await.is_none());
    }

    // ── Connection management ──

    #[tokio::test]
    async fn test_add_remove_connection() {
        let state = AppState::new_in_memory().await.unwrap();
        let user = Uuid::new_v4();
        let (sender, _) = broadcast::channel(16);

        let device_id = state.add_connection(user, None, sender).await;
        assert!(state.connections.read().await.contains_key(&user));

        state.remove_connection(user, device_id).await;
        assert!(!state.connections.read().await.contains_key(&user));
    }

    // ── Relay build hash check ──

    #[tokio::test]
    async fn test_relay_build_hash_check_off() {
        let state = AppState::new_in_memory().await.unwrap();
        // Default enforcement is Off, should accept anything
        let result = state.check_relay_build_hash(Some("any-hash")).await;
        assert!(result.is_ok());
        let result = state.check_relay_build_hash(None).await;
        assert!(result.is_ok());
    }

    // ── Join node already member ──

    #[tokio::test]
    async fn test_join_node_already_member() {
        let state = AppState::new_in_memory().await.unwrap();
        let user = state
            .register_user("already_m".into(), "pw".into())
            .await
            .unwrap();
        let node = state.create_node("ANode".into(), user, None).await.unwrap();
        // Owner is already a member, joining again is refused (REQ-24(b)).
        let result = crate::admission::join(
            &state,
            crate::admission::AdmissionContext::bare(user),
            crate::admission::AdmissionEntry::Node {
                node_id: node.id,
                invite_code: None,
            },
        )
        .await;
        assert_eq!(result, Err(crate::admission::AdmissionError::AlreadyMember));
    }
}
