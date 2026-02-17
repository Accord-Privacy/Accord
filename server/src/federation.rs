//! Federation protocol for Accord server-to-server communication.
//!
//! Enables Accord servers to exchange messages, presence, and membership events
//! while preserving E2E encryption. Federated servers are relays — they cannot
//! read user content.
//!
//! # Security Model
//! - Each server has an Ed25519 identity keypair
//! - Every federation message is signed by the sending server
//! - Receiving servers verify signatures before processing
//! - Server discovery via `/.well-known/accord-federation` or DNS SRV
//! - Federation is opt-in per Node
//! - Replay protection via nonce + timestamp window

use crate::federation_models::*;
use crate::state::SharedState;
use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

/// Current federation protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum age (in seconds) for a federation message to be accepted.
/// Messages older than this are rejected to prevent replay attacks.
const MAX_MESSAGE_AGE_SECS: u64 = 300; // 5 minutes

/// Maximum number of nonces to track for replay protection.
const MAX_NONCE_CACHE_SIZE: usize = 10_000;

// ── Configuration ──

/// Federation configuration for this server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FederationConfig {
    /// Whether federation is enabled at the server level
    pub enabled: bool,
    /// This server's domain (e.g., "accord.example.com")
    pub server_domain: String,
    /// Allowlist of server domains. If non-empty, only these servers can federate.
    pub allowed_servers: Vec<String>,
    /// Blocklist of server domains. These servers are always rejected.
    pub blocked_servers: Vec<String>,
    /// Node IDs that have opted into federation
    pub federated_node_ids: Vec<Uuid>,
}

impl FederationConfig {
    /// Check if a remote server domain is allowed to federate.
    pub fn is_server_allowed(&self, domain: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if self.blocked_servers.contains(&domain.to_string()) {
            return false;
        }
        if !self.allowed_servers.is_empty() {
            return self.allowed_servers.contains(&domain.to_string());
        }
        true // Open federation (no allowlist, not blocked)
    }

    /// Check if a Node has opted into federation.
    pub fn is_node_federated(&self, node_id: Uuid) -> bool {
        self.federated_node_ids.contains(&node_id)
    }
}

// ── Server Identity ──

/// The server's cryptographic identity for federation.
pub struct ServerIdentity {
    /// Ed25519 signing key (private)
    signing_key: SigningKey,
    /// Ed25519 verifying key (public) — derived from signing_key
    verifying_key: VerifyingKey,
}

impl ServerIdentity {
    /// Generate a new random server identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Restore from an existing secret key (32 bytes).
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the secret key bytes (for persistence).
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Get the public key as base64.
    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.verifying_key.as_bytes())
    }

    /// Sign arbitrary data and return the signature as base64.
    pub fn sign(&self, data: &[u8]) -> String {
        let signature = self.signing_key.sign(data);
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    }

    /// Build the canonical bytes to sign for a FederatedMessage.
    fn canonical_message_bytes(
        sender_domain: &str,
        recipient_domain: &str,
        timestamp: u64,
        nonce: &str,
        event_json: &str,
    ) -> Vec<u8> {
        // Deterministic concatenation: domain|domain|timestamp|nonce|event
        let mut data = Vec::new();
        data.extend_from_slice(sender_domain.as_bytes());
        data.push(b'|');
        data.extend_from_slice(recipient_domain.as_bytes());
        data.push(b'|');
        data.extend_from_slice(timestamp.to_le_bytes().as_ref());
        data.push(b'|');
        data.extend_from_slice(nonce.as_bytes());
        data.push(b'|');
        data.extend_from_slice(event_json.as_bytes());
        data
    }

    /// Create and sign a FederatedMessage.
    pub fn create_signed_message(
        &self,
        sender_domain: &str,
        recipient_domain: &str,
        event: FederationEvent,
    ) -> Result<FederatedMessage, String> {
        let timestamp = now();
        let nonce = generate_nonce();
        let event_json = serde_json::to_string(&event)
            .map_err(|e| format!("Failed to serialize event: {}", e))?;

        let canonical = Self::canonical_message_bytes(
            sender_domain,
            recipient_domain,
            timestamp,
            &nonce,
            &event_json,
        );

        let signature = self.sign(&canonical);

        Ok(FederatedMessage {
            sender_domain: sender_domain.to_string(),
            recipient_domain: recipient_domain.to_string(),
            timestamp,
            nonce,
            event,
            signature,
        })
    }

    /// Verify a FederatedMessage signature against a known public key.
    pub fn verify_message(
        message: &FederatedMessage,
        public_key_base64: &str,
    ) -> Result<(), String> {
        let pub_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(public_key_base64)
            .map_err(|e| format!("Invalid public key base64: {}", e))?;

        if pub_key_bytes.len() != 32 {
            return Err(format!(
                "Invalid public key length: expected 32, got {}",
                pub_key_bytes.len()
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&pub_key_bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| format!("Invalid public key: {}", e))?;

        let event_json = serde_json::to_string(&message.event)
            .map_err(|e| format!("Failed to serialize event: {}", e))?;

        let canonical = Self::canonical_message_bytes(
            &message.sender_domain,
            &message.recipient_domain,
            message.timestamp,
            &message.nonce,
            &event_json,
        );

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&message.signature)
            .map_err(|e| format!("Invalid signature base64: {}", e))?;

        if sig_bytes.len() != 64 {
            return Err(format!(
                "Invalid signature length: expected 64, got {}",
                sig_bytes.len()
            ));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        verifying_key
            .verify(&canonical, &signature)
            .map_err(|e| format!("Signature verification failed: {}", e))
    }
}

// ── Federation State ──

/// Runtime state for federation, held alongside AppState.
pub struct FederationState {
    pub config: RwLock<FederationConfig>,
    pub identity: ServerIdentity,
    /// Cache of known remote server public keys: domain -> base64 public key
    pub known_servers: RwLock<HashMap<String, String>>,
    /// Recently seen nonces for replay protection
    pub seen_nonces: RwLock<HashSet<String>>,
}

impl FederationState {
    pub fn new(config: FederationConfig, identity: ServerIdentity) -> Self {
        Self {
            config: RwLock::new(config),
            identity,
            known_servers: RwLock::new(HashMap::new()),
            seen_nonces: RwLock::new(HashSet::new()),
        }
    }

    /// Register a remote server's public key.
    pub async fn register_server(&self, domain: &str, public_key_base64: &str) {
        self.known_servers
            .write()
            .await
            .insert(domain.to_string(), public_key_base64.to_string());
    }

    /// Get a remote server's public key, if known.
    pub async fn get_server_key(&self, domain: &str) -> Option<String> {
        self.known_servers.read().await.get(domain).cloned()
    }

    /// Validate an incoming federated message.
    pub async fn validate_incoming(&self, message: &FederatedMessage) -> Result<(), String> {
        let config = self.config.read().await;

        // 1. Check federation is enabled
        if !config.enabled {
            return Err("Federation is disabled on this server".to_string());
        }

        // 2. Check the sender is allowed
        if !config.is_server_allowed(&message.sender_domain) {
            return Err(format!(
                "Server '{}' is not allowed to federate",
                message.sender_domain
            ));
        }

        // 3. Check the message is addressed to us
        if message.recipient_domain != config.server_domain {
            return Err(format!(
                "Message addressed to '{}', but we are '{}'",
                message.recipient_domain, config.server_domain
            ));
        }

        // 4. Check timestamp is within acceptable window
        let current_time = now();
        let age = current_time.saturating_sub(message.timestamp);
        if age > MAX_MESSAGE_AGE_SECS {
            return Err(format!(
                "Message too old: {} seconds (max {})",
                age, MAX_MESSAGE_AGE_SECS
            ));
        }
        // Also reject messages from the future (clock skew tolerance: 30s)
        if message.timestamp > current_time + 30 {
            return Err("Message timestamp is in the future".to_string());
        }

        // 5. Check for replay (nonce uniqueness)
        {
            let mut nonces = self.seen_nonces.write().await;
            if nonces.contains(&message.nonce) {
                return Err("Duplicate nonce — possible replay attack".to_string());
            }
            // Evict old nonces if cache is too large
            if nonces.len() >= MAX_NONCE_CACHE_SIZE {
                nonces.clear(); // Simple eviction; could be smarter with timestamps
            }
            nonces.insert(message.nonce.clone());
        }

        // 6. Verify signature
        let sender_key = self
            .get_server_key(&message.sender_domain)
            .await
            .ok_or_else(|| {
                format!(
                    "Unknown server '{}' — no public key on file",
                    message.sender_domain
                )
            })?;

        ServerIdentity::verify_message(message, &sender_key)?;

        Ok(())
    }

    /// Create a signed outbound message.
    pub async fn create_outbound_message(
        &self,
        recipient_domain: &str,
        event: FederationEvent,
    ) -> Result<FederatedMessage, String> {
        let config = self.config.read().await;
        if !config.enabled {
            return Err("Federation is disabled".to_string());
        }
        if !config.is_server_allowed(recipient_domain) {
            return Err(format!("Server '{}' is not allowed", recipient_domain));
        }

        self.identity
            .create_signed_message(&config.server_domain, recipient_domain, event)
    }
}

// ── HTTP Client for outbound federation ──

/// Client for sending federation messages to remote servers.
pub struct FederationClient {
    http_client: reqwest::Client,
}

impl Default for FederationClient {
    fn default() -> Self {
        Self::new()
    }
}

impl FederationClient {
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    /// Discover a remote server's federation endpoint via well-known URL.
    pub async fn discover_server(&self, domain: &str) -> Result<WellKnownFederation, String> {
        let url = format!("https://{}/.well-known/accord-federation", domain);
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to reach {}: {}", url, e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Server discovery failed: HTTP {}",
                response.status()
            ));
        }

        response
            .json::<WellKnownFederation>()
            .await
            .map_err(|e| format!("Invalid discovery response: {}", e))
    }

    /// Send a signed federation message to a remote server.
    pub async fn send_message(
        &self,
        federation_endpoint: &str,
        message: &FederatedMessage,
    ) -> Result<(), String> {
        let url = format!("{}/v1/federation/inbox", federation_endpoint);
        let response = self
            .http_client
            .post(&url)
            .json(message)
            .send()
            .await
            .map_err(|e| format!("Failed to send federation message: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Remote server rejected message: HTTP {} — {}",
                status, body
            ));
        }

        Ok(())
    }

    /// Perform challenge-response verification with a remote server.
    pub async fn verify_server(
        &self,
        federation_endpoint: &str,
        challenge: &ServerChallenge,
    ) -> Result<ServerChallengeResponse, String> {
        let url = format!("{}/v1/federation/challenge", federation_endpoint);
        let response = self
            .http_client
            .post(&url)
            .json(challenge)
            .send()
            .await
            .map_err(|e| format!("Challenge request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Challenge failed: HTTP {}", response.status()));
        }

        response
            .json::<ServerChallengeResponse>()
            .await
            .map_err(|e| format!("Invalid challenge response: {}", e))
    }
}

// ── Axum Handlers (inbound federation routes) ──

/// Well-known federation discovery endpoint.
/// GET /.well-known/accord-federation
pub async fn well_known_handler(
    State(state): State<SharedState>,
) -> Result<Json<WellKnownFederation>, StatusCode> {
    let fed_state = match state.federation.as_ref() {
        Some(f) => f,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let config = fed_state.config.read().await;
    if !config.enabled {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(WellKnownFederation {
        federation_endpoint: format!("https://{}", config.server_domain),
        public_key: fed_state.identity.public_key_base64(),
        protocol_version: PROTOCOL_VERSION,
    }))
}

/// Receive a federation message.
/// POST /v1/federation/inbox
pub async fn federation_inbox_handler(
    State(state): State<SharedState>,
    Json(message): Json<FederatedMessage>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let fed_state = match state.federation.as_ref() {
        Some(f) => f,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Federation not enabled"})),
            ))
        }
    };

    // Validate the incoming message (checks signature, replay, timestamp, etc.)
    if let Err(e) = fed_state.validate_incoming(&message).await {
        warn!(
            "Federation message rejected from {}: {}",
            message.sender_domain, e
        );
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": e}))));
    }

    info!(
        "Accepted federation message from {} (event: {:?})",
        message.sender_domain,
        std::mem::discriminant(&message.event)
    );

    // Process the event
    match &message.event {
        FederationEvent::Message {
            from,
            to,
            encrypted_payload: _,
            message_id,
            reply_to: _,
        } => {
            // Route the E2E encrypted message to the local recipient
            info!(
                "Federation message {} -> {} (msg_id: {})",
                from, to, message_id
            );
            // TODO: Look up local user, deliver via WebSocket
        }
        FederationEvent::TypingStart {
            from,
            to,
            channel_id: _,
        } => {
            info!("Federation typing {} -> {}", from, to);
            // TODO: Relay typing indicator
        }
        FederationEvent::PresenceUpdate { user, status, .. } => {
            info!("Federation presence update: {} -> {}", user, status);
            // TODO: Update federated user presence
        }
        FederationEvent::JoinRequest { user, node_id, .. } => {
            info!("Federation join request: {} -> node {}", user, node_id);
            // TODO: Process join request
        }
        FederationEvent::JoinResponse { .. } => {
            // TODO: Handle join response
        }
        FederationEvent::Leave { user, node_id } => {
            info!("Federation leave: {} from node {}", user, node_id);
            // TODO: Process leave
        }
        FederationEvent::ServerHello { info } => {
            info!("Federation hello from {}", info.domain);
            fed_state
                .register_server(&info.domain, &info.public_key)
                .await;
        }
    }

    Ok(Json(serde_json::json!({"status": "accepted"})))
}

/// Challenge-response endpoint for server verification.
/// POST /v1/federation/challenge
pub async fn federation_challenge_handler(
    State(state): State<SharedState>,
    Json(challenge): Json<ServerChallenge>,
) -> Result<Json<ServerChallengeResponse>, (StatusCode, Json<serde_json::Value>)> {
    let fed_state = match state.federation.as_ref() {
        Some(f) => f,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Federation not enabled"})),
            ))
        }
    };

    let config = fed_state.config.read().await;
    if !config.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Federation not enabled"})),
        ));
    }

    // Decode and sign the challenge
    let challenge_bytes = base64::engine::general_purpose::STANDARD
        .decode(&challenge.challenge)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid challenge base64"})),
            )
        })?;

    let signature = fed_state.identity.sign(&challenge_bytes);

    Ok(Json(ServerChallengeResponse {
        challenge: challenge.challenge,
        signature,
        server_info: ServerInfo {
            domain: config.server_domain.clone(),
            public_key: fed_state.identity.public_key_base64(),
            protocol_version: PROTOCOL_VERSION,
            software_version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: vec![
                capabilities::MESSAGING.to_string(),
                capabilities::TYPING.to_string(),
                capabilities::PRESENCE.to_string(),
            ],
        },
    }))
}

/// Server info endpoint.
/// GET /v1/federation/info
pub async fn federation_info_handler(
    State(state): State<SharedState>,
) -> Result<Json<ServerInfo>, StatusCode> {
    let fed_state = match state.federation.as_ref() {
        Some(f) => f,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let config = fed_state.config.read().await;
    if !config.enabled {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(ServerInfo {
        domain: config.server_domain.clone(),
        public_key: fed_state.identity.public_key_base64(),
        protocol_version: PROTOCOL_VERSION,
        software_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            capabilities::MESSAGING.to_string(),
            capabilities::TYPING.to_string(),
            capabilities::PRESENCE.to_string(),
        ],
    }))
}

/// Build the federation router (to be nested under the main app).
pub fn federation_routes() -> axum::Router<SharedState> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/.well-known/accord-federation", get(well_known_handler))
        .route("/v1/federation/inbox", post(federation_inbox_handler))
        .route(
            "/v1/federation/challenge",
            post(federation_challenge_handler),
        )
        .route("/v1/federation/info", get(federation_info_handler))
}

// ── Helpers ──

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_nonce() -> String {
    use rand::Rng;
    let nonce: [u8; 16] = rand::thread_rng().gen();
    base64::engine::general_purpose::STANDARD.encode(nonce)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_identity_generate_and_sign() {
        let identity = ServerIdentity::generate();
        let pub_key = identity.public_key_base64();

        // Public key should be valid base64 and 32 bytes decoded
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&pub_key)
            .unwrap();
        assert_eq!(decoded.len(), 32);

        // Sign and verify
        let data = b"hello federation";
        let sig = identity.sign(data);

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig)
            .unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn test_server_identity_roundtrip() {
        let identity = ServerIdentity::generate();
        let secret = *identity.secret_bytes();
        let restored = ServerIdentity::from_secret_bytes(&secret);

        assert_eq!(identity.public_key_base64(), restored.public_key_base64());
    }

    #[test]
    fn test_create_and_verify_signed_message() {
        let identity = ServerIdentity::generate();
        let pub_key = identity.public_key_base64();

        let event = FederationEvent::PresenceUpdate {
            user: FederatedUserId::new("alice", "server-a.com"),
            status: "online".to_string(),
            custom_status: None,
        };

        let message = identity
            .create_signed_message("server-a.com", "server-b.com", event)
            .unwrap();

        // Verify succeeds with correct key
        assert!(ServerIdentity::verify_message(&message, &pub_key).is_ok());

        // Verify fails with wrong key
        let other = ServerIdentity::generate();
        assert!(ServerIdentity::verify_message(&message, &other.public_key_base64()).is_err());
    }

    #[test]
    fn test_tampered_message_fails_verification() {
        let identity = ServerIdentity::generate();
        let pub_key = identity.public_key_base64();

        let event = FederationEvent::Message {
            message_id: Uuid::new_v4(),
            from: FederatedUserId::new("alice", "a.com"),
            to: FederatedUserId::new("bob", "b.com"),
            encrypted_payload: "secret".to_string(),
            reply_to: None,
        };

        let mut message = identity
            .create_signed_message("a.com", "b.com", event)
            .unwrap();

        // Tamper with the sender domain
        message.sender_domain = "evil.com".to_string();

        // Verification should fail
        assert!(ServerIdentity::verify_message(&message, &pub_key).is_err());
    }

    #[test]
    fn test_federation_config_server_allowed() {
        let mut config = FederationConfig {
            enabled: true,
            server_domain: "local.com".to_string(),
            allowed_servers: vec![],
            blocked_servers: vec!["evil.com".to_string()],
            federated_node_ids: vec![],
        };

        // Open federation: everything except blocked
        assert!(config.is_server_allowed("friend.com"));
        assert!(!config.is_server_allowed("evil.com"));

        // With allowlist: only allowed
        config.allowed_servers = vec!["friend.com".to_string()];
        assert!(config.is_server_allowed("friend.com"));
        assert!(!config.is_server_allowed("other.com"));
        assert!(!config.is_server_allowed("evil.com")); // blocked overrides

        // Disabled: nothing allowed
        config.enabled = false;
        assert!(!config.is_server_allowed("friend.com"));
    }

    #[test]
    fn test_federation_config_node_federated() {
        let node_id = Uuid::new_v4();
        let config = FederationConfig {
            enabled: true,
            server_domain: "local.com".to_string(),
            allowed_servers: vec![],
            blocked_servers: vec![],
            federated_node_ids: vec![node_id],
        };

        assert!(config.is_node_federated(node_id));
        assert!(!config.is_node_federated(Uuid::new_v4()));
    }

    #[tokio::test]
    async fn test_federation_state_validate_incoming() {
        let server_a = ServerIdentity::generate();
        let server_b = ServerIdentity::generate();

        let config_b = FederationConfig {
            enabled: true,
            server_domain: "b.com".to_string(),
            allowed_servers: vec![],
            blocked_servers: vec![],
            federated_node_ids: vec![],
        };

        let state_b = FederationState::new(config_b, server_b);

        // Register server A's key
        state_b
            .register_server("a.com", &server_a.public_key_base64())
            .await;

        // Create a valid message from A to B
        let event = FederationEvent::PresenceUpdate {
            user: FederatedUserId::new("alice", "a.com"),
            status: "online".to_string(),
            custom_status: None,
        };

        let message = server_a
            .create_signed_message("a.com", "b.com", event)
            .unwrap();

        // Should validate successfully
        assert!(state_b.validate_incoming(&message).await.is_ok());

        // Same nonce should be rejected (replay)
        assert!(state_b.validate_incoming(&message).await.is_err());
    }

    #[tokio::test]
    async fn test_federation_state_rejects_unknown_server() {
        let server_a = ServerIdentity::generate();
        let server_b = ServerIdentity::generate();

        let config_b = FederationConfig {
            enabled: true,
            server_domain: "b.com".to_string(),
            allowed_servers: vec![],
            blocked_servers: vec![],
            federated_node_ids: vec![],
        };

        let state_b = FederationState::new(config_b, server_b);
        // Don't register server A's key

        let event = FederationEvent::PresenceUpdate {
            user: FederatedUserId::new("alice", "a.com"),
            status: "online".to_string(),
            custom_status: None,
        };

        let message = server_a
            .create_signed_message("a.com", "b.com", event)
            .unwrap();

        let result = state_b.validate_incoming(&message).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown server"));
    }

    #[tokio::test]
    async fn test_federation_state_rejects_blocked_server() {
        let server_a = ServerIdentity::generate();
        let server_b = ServerIdentity::generate();

        let config_b = FederationConfig {
            enabled: true,
            server_domain: "b.com".to_string(),
            allowed_servers: vec![],
            blocked_servers: vec!["a.com".to_string()],
            federated_node_ids: vec![],
        };

        let state_b = FederationState::new(config_b, server_b);
        state_b
            .register_server("a.com", &server_a.public_key_base64())
            .await;

        let event = FederationEvent::PresenceUpdate {
            user: FederatedUserId::new("alice", "a.com"),
            status: "online".to_string(),
            custom_status: None,
        };

        let message = server_a
            .create_signed_message("a.com", "b.com", event)
            .unwrap();

        let result = state_b.validate_incoming(&message).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not allowed"));
    }
}
