//! Bot API v2 — Airgapped Command Architecture
//!
//! Bots are stateless command processors that never see messages, member lists,
//! or encrypted data. They register command manifests and respond to invocations.
//! All bot ↔ Node communication is (will be) E2EE.

use crate::models::ErrorResponse;
use crate::state::SharedState;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

// ── Bot API v2 Models ──

/// Bot command manifest — declares what a bot can do
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotManifest {
    pub bot_id: String,
    pub name: String,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub commands: Vec<BotCommand>,
}

/// A single command a bot supports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotCommand {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub params: Vec<BotCommandParam>,
}

/// A parameter for a bot command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotCommandParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Command invocation sent to the bot's webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInvocation {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub command: String,
    pub invoker_display_name: String,
    pub params: HashMap<String, serde_json::Value>,
    pub invocation_id: String,
    pub channel_id: String,
}

/// Response from a bot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub invocation_id: String,
    pub content: ResponseContent,
}

/// Content of a bot response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseContent {
    Text {
        text: String,
    },
    Embed {
        title: Option<String>,
        sections: Vec<EmbedSection>,
    },
}

/// Section types for embed responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmbedSection {
    Text {
        text: String,
    },
    Grid {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Image {
        url: String,
        #[serde(default)]
        alt: Option<String>,
    },
    Actions {
        buttons: Vec<ActionButton>,
    },
    Divider {},
    Fields {
        fields: Vec<FieldEntry>,
    },
    Progress {
        label: String,
        value: f64,
        #[serde(default)]
        max: Option<f64>,
    },
    Code {
        code: String,
        #[serde(default)]
        language: Option<String>,
    },
    Input {
        name: String,
        #[serde(default)]
        placeholder: Option<String>,
        #[serde(default)]
        command: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionButton {
    pub label: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub params: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub params_prompt: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEntry {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub inline: bool,
}

/// Installed bot record (public view)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledBotInfo {
    pub bot_id: String,
    pub name: String,
    pub icon: Option<String>,
    pub description: Option<String>,
    pub commands: Vec<BotCommand>,
    pub installed_at: u64,
    pub invocation_count: u64,
}

// ── Request / Response types ──

/// Request to install a bot on a node
#[derive(Debug, Deserialize)]
pub struct InstallBotRequest {
    pub manifest: BotManifest,
    pub webhook_url: String,
    /// Bot's Ed25519 public key (base64) for signature verification
    #[serde(default)]
    pub ed25519_pubkey: Option<String>,
    /// Bot's X25519 public key (base64) for key exchange
    #[serde(default)]
    pub x25519_pubkey: Option<String>,
    /// Channels the bot is allowed to respond in (empty = all)
    #[serde(default)]
    pub allowed_channels: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct InstallBotResponse {
    pub bot_id: String,
    pub bot_token: String,
    /// Node's X25519 public key for key exchange (base64)
    pub node_x25519_pubkey: Option<String>,
    pub message: String,
}

/// Request to invoke a bot command
#[derive(Debug, Deserialize)]
pub struct InvokeCommandRequest {
    pub command: String,
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
    pub channel_id: String,
}

#[derive(Debug, Serialize)]
pub struct InvokeCommandResponse {
    pub invocation_id: String,
    pub status: String,
}

/// Bot posts a response (authenticated via bot_token)
#[derive(Debug, Deserialize)]
pub struct BotRespondRequest {
    pub invocation_id: String,
    pub content: ResponseContent,
    /// Ed25519 signature of the response payload (base64)
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BotRespondResponse {
    pub status: String,
}

/// Crypto info for an installed bot (returned from DB)
#[derive(Debug, Clone)]
pub struct BotCryptoInfo {
    pub shared_secret: Option<String>,
    pub ed25519_pubkey: Option<String>,
    pub x25519_pubkey: Option<String>,
    pub node_x25519_privkey: Option<String>,
    pub invocation_count: u64,
    pub key_rotated_at: Option<u64>,
}

/// Encrypted payload sent to/from bots
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// base64(nonce + ciphertext + tag)
    pub encrypted: String,
    /// base64(Ed25519 signature of the encrypted blob)
    pub signature: String,
    /// base64(Ed25519 public key of the signer)
    pub node_pubkey: String,
    /// Optional key rotation request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_rotation: Option<KeyRotationRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    pub new_x25519_pubkey: String,
}

/// Encrypted response from a bot
#[derive(Debug, Deserialize)]
pub struct EncryptedBotResponse {
    pub encrypted: String,
    pub signature: String,
    /// Bot's Ed25519 public key
    #[serde(default)]
    pub bot_pubkey: Option<String>,
    /// Bot's new X25519 public key (key rotation response)
    #[serde(default)]
    pub new_x25519_pubkey: Option<String>,
}

// ── Constants ──

const BOT_TOKEN_PREFIX: &str = "accord_botv2_";
const HKDF_CONTEXT: &[u8] = b"accord-bot-v2-encryption";
const KEY_ROTATION_INTERVAL_SECS: u64 = 24 * 60 * 60; // 24 hours
const KEY_ROTATION_INVOCATION_THRESHOLD: u64 = 1000;

// ── Helpers ──

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_bot_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let token_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    format!(
        "{}{}",
        BOT_TOKEN_PREFIX,
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &token_bytes
        )
    )
}

fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Derive an AES-256-GCM key from an X25519 shared secret via HKDF-SHA256
fn derive_encryption_key(shared_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(HKDF_CONTEXT, &mut key)
        .expect("HKDF expand failed");
    key
}

/// Perform X25519 key exchange and return (node_privkey_bytes, node_pubkey_bytes, derived_key)
fn perform_key_exchange(bot_x25519_pubkey_bytes: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let node_secret = X25519StaticSecret::random_from_rng(rand::thread_rng());
    let node_pubkey = X25519PublicKey::from(&node_secret);
    let bot_pubkey = X25519PublicKey::from(*bot_x25519_pubkey_bytes);
    let shared_secret = node_secret.diffie_hellman(&bot_pubkey);
    let encryption_key = derive_encryption_key(shared_secret.as_bytes());
    let privkey_bytes: [u8; 32] = node_secret.to_bytes();
    (privkey_bytes, *node_pubkey.as_bytes(), encryption_key)
}

/// Encrypt a payload with AES-256-GCM. Returns nonce + ciphertext (includes tag).
fn encrypt_payload(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("AES key error: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a payload (nonce + ciphertext) with AES-256-GCM
fn decrypt_payload(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("Encrypted data too short".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("AES key error: {}", e))?;
    let nonce = Nonce::from_slice(&data[..12]);
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| format!("Decryption failed: {}", e))
}

/// Sign data with Ed25519
fn sign_data(signing_key: &ed25519_dalek::SigningKey, data: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}

/// Verify Ed25519 signature
fn verify_signature(
    pubkey_bytes: &[u8],
    data: &[u8],
    signature_bytes: &[u8],
) -> Result<(), String> {
    use ed25519_dalek::Verifier;
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(
        pubkey_bytes
            .try_into()
            .map_err(|_| "Invalid Ed25519 pubkey length")?,
    )
    .map_err(|e| format!("Invalid Ed25519 pubkey: {}", e))?;
    let signature = ed25519_dalek::Signature::from_bytes(
        signature_bytes
            .try_into()
            .map_err(|_| "Invalid signature length")?,
    );
    pubkey
        .verify(data, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

/// Check if key rotation is needed
fn needs_key_rotation(crypto_info: &BotCryptoInfo) -> bool {
    let now = now_secs();
    if crypto_info.invocation_count >= KEY_ROTATION_INVOCATION_THRESHOLD {
        return true;
    }
    if let Some(rotated_at) = crypto_info.key_rotated_at {
        if now - rotated_at >= KEY_ROTATION_INTERVAL_SECS {
            return true;
        }
    }
    false
}

/// Extract token from Authorization: Bearer header, falling back to query param
fn extract_token_from_headers_or_params<'a>(
    headers: &'a HeaderMap,
    params: &'a HashMap<String, String>,
) -> Option<&'a str> {
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token);
            }
        }
    }
    params.get("token").map(|s| s.as_str())
}

async fn extract_user_from_token(
    state: &SharedState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let token = extract_token_from_headers_or_params(headers, params).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing token".into(),
                code: 401,
            }),
        )
    })?;
    state.validate_token(token).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".into(),
                code: 401,
            }),
        )
    })
}

async fn require_node_admin(
    state: &SharedState,
    user_id: Uuid,
    node_id: Uuid,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let role = state
        .get_user_role_in_node(user_id, node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!("Not a member of this node: {}", e),
                    code: 403,
                }),
            )
        })?;
    if role != crate::node::NodeRole::Admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only node admins can perform this action".into(),
                code: 403,
            }),
        ));
    }
    Ok(())
}

async fn require_node_member(
    state: &SharedState,
    user_id: Uuid,
    node_id: Uuid,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if !state
        .is_node_member(user_id, node_id)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Must be a member of this node".into(),
                code: 403,
            }),
        ));
    }
    Ok(())
}

// ── Route Handlers ──

/// Install a bot on a node (POST /api/nodes/{node_id}/bots)
/// Admin only.
pub async fn install_bot_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<InstallBotRequest>,
) -> Result<Json<InstallBotResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_node_admin(&state, user_id, node_id).await?;

    // Validate manifest
    if request.manifest.bot_id.is_empty() || request.manifest.name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "bot_id and name are required in manifest".into(),
                code: 400,
            }),
        ));
    }

    if request.webhook_url.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "webhook_url is required".into(),
                code: 400,
            }),
        ));
    }

    // Generate bot token
    let bot_token = generate_bot_token();
    let bot_token_hash = hash_token(&bot_token);

    // Perform X25519 key exchange if bot provides its public key
    let node_x25519_pubkey: Option<String>;
    let mut node_privkey_b64: Option<String> = None;
    let mut shared_secret_b64: Option<String> = None;

    if let Some(ref bot_x25519_b64) = request.x25519_pubkey {
        let bot_x25519_bytes: [u8; 32] =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, bot_x25519_b64)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: format!("Invalid x25519_pubkey base64: {}", e),
                            code: 400,
                        }),
                    )
                })?
                .try_into()
                .map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "x25519_pubkey must be 32 bytes".into(),
                            code: 400,
                        }),
                    )
                })?;

        let (privkey_bytes, pubkey_bytes, encryption_key) = perform_key_exchange(&bot_x25519_bytes);

        node_x25519_pubkey = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pubkey_bytes,
        ));
        node_privkey_b64 = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            privkey_bytes,
        ));
        shared_secret_b64 = Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            encryption_key,
        ));

        tracing::info!(
            "X25519 key exchange completed for bot '{}'",
            request.manifest.bot_id
        );
    } else {
        node_x25519_pubkey = None;
        tracing::info!(
            "Bot '{}' installed without E2EE (no x25519_pubkey provided)",
            request.manifest.bot_id
        );
    }

    let now = now_secs();
    let allowed_channels_json =
        serde_json::to_string(&request.allowed_channels).unwrap_or_else(|_| "[]".into());

    // Store commands as JSON
    let commands_json = serde_json::to_string(&request.manifest.commands).unwrap_or_default();

    // Store in DB
    state
        .install_bot(
            &request.manifest.bot_id,
            node_id,
            &request.manifest.name,
            request.manifest.icon.as_deref(),
            request.manifest.description.as_deref(),
            &request.webhook_url,
            &bot_token_hash,
            request.ed25519_pubkey.as_deref(),
            request.x25519_pubkey.as_deref(),
            &allowed_channels_json,
            now,
            &commands_json,
            &request.manifest.commands,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to install bot: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Store crypto keys if key exchange was performed
    if let (Some(ref privkey), Some(ref secret)) = (&node_privkey_b64, &shared_secret_b64) {
        state
            .store_bot_crypto(&request.manifest.bot_id, node_id, privkey, secret)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to store bot crypto: {}", e),
                        code: 500,
                    }),
                )
            })?;
    }

    tracing::info!(
        "Bot '{}' installed on node {} by user {}",
        request.manifest.bot_id,
        node_id,
        user_id
    );

    Ok(Json(InstallBotResponse {
        bot_id: request.manifest.bot_id,
        bot_token,
        node_x25519_pubkey,
        message: "Bot installed successfully. Store the bot_token securely.".into(),
    }))
}

/// Uninstall a bot from a node (DELETE /api/nodes/{node_id}/bots/{bot_id})
/// Admin only. Zeroizes keys.
pub async fn uninstall_bot_handler(
    State(state): State<SharedState>,
    Path((node_id, bot_id)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_node_admin(&state, user_id, node_id).await?;

    // Zeroize crypto material before deletion
    if let Ok(Some(mut crypto_info)) = state.get_bot_crypto_info(&bot_id, node_id).await {
        if let Some(ref mut secret) = crypto_info.shared_secret {
            secret.zeroize();
        }
        if let Some(ref mut privkey) = crypto_info.node_x25519_privkey {
            privkey.zeroize();
        }
        tracing::debug!("Zeroized crypto material for bot '{}'", bot_id);
    }

    state.uninstall_bot(&bot_id, node_id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Bot not found or failed to uninstall: {}", e),
                code: 404,
            }),
        )
    })?;

    tracing::info!(
        "Bot '{}' uninstalled from node {} by user {}",
        bot_id,
        node_id,
        user_id
    );

    Ok(Json(serde_json::json!({
        "status": "uninstalled",
        "bot_id": bot_id,
    })))
}

/// List installed bots on a node (GET /api/nodes/{node_id}/bots)
/// Members can view.
pub async fn list_bots_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<InstalledBotInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_node_member(&state, user_id, node_id).await?;

    let bots = state.list_installed_bots(node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to list bots: {}", e),
                code: 500,
            }),
        )
    })?;

    Ok(Json(bots))
}

/// Get a bot's command manifest (GET /api/nodes/{node_id}/bots/{bot_id}/commands)
/// Members can view.
pub async fn get_bot_commands_handler(
    State(state): State<SharedState>,
    Path((node_id, bot_id)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<BotCommand>>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_node_member(&state, user_id, node_id).await?;

    let commands = state
        .get_bot_commands(&bot_id, node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Bot not found: {}", e),
                    code: 404,
                }),
            )
        })?;

    Ok(Json(commands))
}

/// Invoke a bot command (POST /api/nodes/{node_id}/bots/{bot_id}/invoke)
/// Members can invoke.
pub async fn invoke_command_handler(
    State(state): State<SharedState>,
    Path((node_id, bot_id)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<InvokeCommandRequest>,
) -> Result<Json<InvokeCommandResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_node_member(&state, user_id, node_id).await?;

    // Get the bot's webhook URL and verify command exists
    let (webhook_url, _bot_token_hash) = state
        .get_bot_webhook_info(&bot_id, node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Bot not found: {}", e),
                    code: 404,
                }),
            )
        })?;

    // Get invoker display name
    let display_name = state
        .get_user_display_name(user_id)
        .await
        .unwrap_or_else(|_| "Unknown".into());

    let invocation_id = Uuid::new_v4().to_string();

    // Store invocation
    state
        .create_bot_invocation(
            &invocation_id,
            &bot_id,
            node_id,
            &request.channel_id,
            user_id,
            &request.command,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to create invocation: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Build invocation payload
    let invocation = CommandInvocation {
        msg_type: "command_invocation".into(),
        command: request.command.clone(),
        invoker_display_name: display_name,
        params: request.params,
        invocation_id: invocation_id.clone(),
        channel_id: request.channel_id,
    };

    // Check if E2EE is available for this bot
    let crypto_info = state
        .get_bot_crypto_info(&bot_id, node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get bot crypto info: {}", e),
                    code: 500,
                }),
            )
        })?;

    let use_encryption = crypto_info
        .as_ref()
        .map(|c| c.shared_secret.is_some())
        .unwrap_or(false);

    // Check if key rotation is needed
    let mut rotation_request: Option<KeyRotationRequest> = None;
    let mut new_node_privkey: Option<[u8; 32]> = None;
    let mut new_node_pubkey: Option<[u8; 32]> = None;

    if use_encryption {
        let ci = crypto_info.as_ref().unwrap();
        if needs_key_rotation(ci) {
            let new_secret = X25519StaticSecret::random_from_rng(rand::thread_rng());
            let new_pub = X25519PublicKey::from(&new_secret);
            new_node_privkey = Some(new_secret.to_bytes());
            new_node_pubkey = Some(*new_pub.as_bytes());
            rotation_request = Some(KeyRotationRequest {
                new_x25519_pubkey: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    new_pub.as_bytes(),
                ),
            });
            tracing::info!("Key rotation initiated for bot '{}'", bot_id);
        }
    }

    // Fire-and-forget webhook to bot
    let webhook_url_clone = webhook_url.clone();
    let invocation_clone = invocation.clone();
    let bot_id_clone = bot_id.clone();

    if use_encryption {
        let ci = crypto_info.as_ref().unwrap();
        let shared_secret_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            ci.shared_secret.as_ref().unwrap(),
        )
        .unwrap_or_default();
        let mut key = [0u8; 32];
        key.copy_from_slice(&shared_secret_bytes[..32.min(shared_secret_bytes.len())]);

        // Encrypt the invocation
        let plaintext = serde_json::to_vec(&invocation_clone).unwrap_or_default();
        match encrypt_payload(&key, &plaintext) {
            Ok(encrypted_blob) => {
                // Sign with Node's Ed25519 key (generate ephemeral for now)
                let node_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
                let node_ed25519_pub = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    node_signing_key.verifying_key().as_bytes(),
                );
                let signature_bytes = sign_data(&node_signing_key, &encrypted_blob);
                let signature_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &signature_bytes,
                );
                let encrypted_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &encrypted_blob,
                );

                let payload = EncryptedPayload {
                    encrypted: encrypted_b64,
                    signature: signature_b64,
                    node_pubkey: node_ed25519_pub,
                    key_rotation: rotation_request,
                };

                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    match client
                        .post(&webhook_url_clone)
                        .json(&payload)
                        .timeout(std::time::Duration::from_secs(30))
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            tracing::debug!(
                                "Encrypted webhook delivered to bot '{}', status: {}",
                                bot_id_clone,
                                resp.status()
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to deliver encrypted webhook to bot '{}': {}",
                                bot_id_clone,
                                e
                            );
                        }
                    }
                });
            }
            Err(e) => {
                tracing::error!("Failed to encrypt invocation for bot '{}': {}", bot_id, e);
                // Fall back to plaintext
                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    let _ = client
                        .post(&webhook_url_clone)
                        .json(&invocation_clone)
                        .timeout(std::time::Duration::from_secs(30))
                        .send()
                        .await;
                });
            }
        }
        key.zeroize();
    } else {
        // Plaintext fallback for dev bots
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            match client
                .post(&webhook_url_clone)
                .json(&invocation_clone)
                .timeout(std::time::Duration::from_secs(30))
                .send()
                .await
            {
                Ok(resp) => {
                    tracing::debug!("Webhook delivered to bot, status: {}", resp.status());
                }
                Err(e) => {
                    tracing::warn!("Failed to deliver webhook to bot: {}", e);
                }
            }
        });
    }

    // Store rotation keys if initiated
    if let (Some(new_priv), Some(_new_pub)) = (new_node_privkey, new_node_pubkey) {
        // We store the new private key; the bot's new X25519 pubkey will come in the response
        let _ = state
            .store_bot_crypto(
                &bot_id,
                node_id,
                &base64::Engine::encode(&base64::engine::general_purpose::STANDARD, new_priv),
                // Keep old shared secret until bot confirms rotation
                crypto_info
                    .as_ref()
                    .unwrap()
                    .shared_secret
                    .as_deref()
                    .unwrap_or(""),
            )
            .await;
    }

    // Increment invocation count
    let _ = state.increment_bot_invocation_count(&bot_id, node_id).await;

    Ok(Json(InvokeCommandResponse {
        invocation_id,
        status: "sent".into(),
    }))
}

/// Bot posts a response (POST /api/bots/respond)
/// Authenticated via bot_token in Authorization: Bearer header.
pub async fn bot_respond_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<BotRespondRequest>,
) -> Result<Json<BotRespondResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Extract bot token from Authorization header
    let bot_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing bot_token in Authorization: Bearer header".into(),
                    code: 401,
                }),
            )
        })?;

    let token_hash = hash_token(bot_token);

    // Validate token and get bot info
    let (bot_id, node_id) = state
        .validate_bot_token_v2(&token_hash)
        .await
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid bot token".into(),
                    code: 401,
                }),
            )
        })?;

    // Check if bot sent an encrypted response (signature field present)
    // If so, verify Ed25519 signature and decrypt with AES-256-GCM
    // Note: The BotRespondRequest already has the deserialized content for plaintext.
    // For encrypted responses, bots should send encrypted+signature fields via a different path.
    // For now, if signature is present, we verify it against the serialized content.
    if let Some(ref signature_b64) = request.signature {
        // Get bot's crypto info
        if let Ok(Some(crypto_info)) = state.get_bot_crypto_info(&bot_id, node_id).await {
            if let Some(ref ed25519_pub_b64) = crypto_info.ed25519_pubkey {
                let pubkey_bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    ed25519_pub_b64,
                )
                .unwrap_or_default();
                let sig_bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    signature_b64,
                )
                .unwrap_or_default();
                let content_bytes = serde_json::to_vec(&request.content).unwrap_or_default();
                if let Err(e) = verify_signature(&pubkey_bytes, &content_bytes, &sig_bytes) {
                    tracing::warn!(
                        "Bot '{}' response signature verification failed: {}",
                        bot_id,
                        e
                    );
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(ErrorResponse {
                            error: format!("Signature verification failed: {}", e),
                            code: 401,
                        }),
                    ));
                }
                tracing::debug!("Bot '{}' response signature verified", bot_id);
            }
        }
    }

    // Look up the invocation to get channel_id
    let (channel_id, _command) = state
        .get_invocation_info(&request.invocation_id, &bot_id, node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Invocation not found: {}", e),
                    code: 404,
                }),
            )
        })?;

    // Update invocation status
    let _ = state
        .update_invocation_status(&request.invocation_id, "completed")
        .await;

    // Build WS broadcast message
    let ws_message = serde_json::json!({
        "type": "bot_response",
        "bot_id": bot_id,
        "invocation_id": request.invocation_id,
        "content": request.content,
    });

    let channel_uuid = Uuid::parse_str(&channel_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid channel_id in invocation".into(),
                code: 400,
            }),
        )
    })?;

    // Broadcast to channel members via WebSocket
    let _ = state
        .broadcast_to_channel(channel_uuid, ws_message.to_string())
        .await;

    tracing::info!(
        "Bot '{}' responded to invocation '{}'",
        bot_id,
        request.invocation_id
    );

    Ok(Json(BotRespondResponse {
        status: "delivered".into(),
    }))
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bot_token() {
        let token = generate_bot_token();
        assert!(token.starts_with(BOT_TOKEN_PREFIX));
        assert!(token.len() > BOT_TOKEN_PREFIX.len() + 10);
    }

    #[test]
    fn test_hash_token_deterministic() {
        let hash1 = hash_token("test_token");
        let hash2 = hash_token("test_token");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_response_content_text_serialization() {
        let content = ResponseContent::Text {
            text: "Hello".into(),
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"text\""));
        assert!(json.contains("\"text\":\"Hello\""));
    }

    #[test]
    fn test_response_content_embed_serialization() {
        let content = ResponseContent::Embed {
            title: Some("Test".into()),
            sections: vec![
                EmbedSection::Text {
                    text: "Hello".into(),
                },
                EmbedSection::Divider {},
                EmbedSection::Grid {
                    columns: vec!["A".into(), "B".into()],
                    rows: vec![vec!["1".into(), "2".into()]],
                },
            ],
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"embed\""));
        assert!(json.contains("\"type\":\"text\""));
        assert!(json.contains("\"type\":\"divider\""));
        assert!(json.contains("\"type\":\"grid\""));
    }

    #[test]
    fn test_command_invocation_serialization() {
        let invocation = CommandInvocation {
            msg_type: "command_invocation".into(),
            command: "forecast".into(),
            invoker_display_name: "Gage".into(),
            params: {
                let mut m = HashMap::new();
                m.insert(
                    "location".into(),
                    serde_json::Value::String("Grand Rapids".into()),
                );
                m
            },
            invocation_id: "abc123".into(),
            channel_id: "general".into(),
        };
        let json = serde_json::to_string(&invocation).unwrap();
        assert!(json.contains("\"command\":\"forecast\""));
        assert!(json.contains("\"invoker_display_name\":\"Gage\""));
    }

    #[test]
    fn test_x25519_key_exchange_and_encryption() {
        // Simulate bot side
        let bot_secret = X25519StaticSecret::random_from_rng(rand::thread_rng());
        let bot_pubkey = X25519PublicKey::from(&bot_secret);

        // Perform node-side key exchange
        let (node_privkey, node_pubkey, node_key) = perform_key_exchange(bot_pubkey.as_bytes());

        // Bot derives same shared secret
        let node_pub = X25519PublicKey::from(node_pubkey);
        let bot_shared = bot_secret.diffie_hellman(&node_pub);
        let bot_key = derive_encryption_key(bot_shared.as_bytes());

        // Keys should match
        assert_eq!(node_key, bot_key);

        // Test encrypt/decrypt round-trip
        let plaintext = b"hello world";
        let encrypted = encrypt_payload(&node_key, plaintext).unwrap();
        let decrypted = decrypt_payload(&bot_key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // Ensure privkey is non-zero (sanity)
        assert_ne!(node_privkey, [0u8; 32]);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let data = b"test data for signing";
        let sig = sign_data(&signing_key, data);
        assert!(verify_signature(signing_key.verifying_key().as_bytes(), data, &sig).is_ok());

        // Tampered data should fail
        assert!(
            verify_signature(signing_key.verifying_key().as_bytes(), b"tampered", &sig).is_err()
        );
    }

    #[test]
    fn test_needs_key_rotation() {
        let crypto = BotCryptoInfo {
            shared_secret: Some("test".into()),
            ed25519_pubkey: None,
            x25519_pubkey: None,
            node_x25519_privkey: None,
            invocation_count: 999,
            key_rotated_at: Some(now_secs()),
        };
        assert!(!needs_key_rotation(&crypto));

        let crypto_over_threshold = BotCryptoInfo {
            invocation_count: 1000,
            ..crypto.clone()
        };
        assert!(needs_key_rotation(&crypto_over_threshold));

        let crypto_old_rotation = BotCryptoInfo {
            invocation_count: 0,
            key_rotated_at: Some(now_secs() - 86401),
            ..crypto
        };
        assert!(needs_key_rotation(&crypto_old_rotation));
    }

    #[test]
    fn test_bot_manifest_deserialization() {
        let json = r#"{
            "bot_id": "weather-bot",
            "name": "Weather",
            "icon": "🌤️",
            "description": "Get weather",
            "commands": [
                {
                    "name": "forecast",
                    "description": "Get forecast",
                    "params": [
                        {"name": "location", "type": "string", "required": true}
                    ]
                }
            ]
        }"#;
        let manifest: BotManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.bot_id, "weather-bot");
        assert_eq!(manifest.commands.len(), 1);
        assert_eq!(manifest.commands[0].params.len(), 1);
        assert!(manifest.commands[0].params[0].required);
    }
}
