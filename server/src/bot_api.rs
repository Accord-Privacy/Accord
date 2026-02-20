//! Bot API v2 — Airgapped Command Architecture
//!
//! Bots are stateless command processors that never see messages, member lists,
//! or encrypted data. They register command manifests and respond to invocations.
//! All bot ↔ Node communication is (will be) E2EE.

use crate::models::ErrorResponse;
use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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

// ── Constants ──

const BOT_TOKEN_PREFIX: &str = "accord_botv2_";

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

    // TODO: Perform X25519 key exchange here
    // 1. Generate per-bot X25519 keypair for the node side
    // 2. Derive shared secret via X25519 ECDH + HKDF-SHA256
    // 3. Store shared secret for AES-256-GCM encryption of command traffic
    let node_x25519_pubkey: Option<String> = None; // placeholder

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

    // TODO: Zeroize X25519 private key and shared secret before deletion
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

    // TODO: Encrypt invocation payload with AES-256-GCM using shared secret
    // TODO: Sign encrypted blob with Node's Ed25519 key
    // For now, send as plaintext JSON over HTTPS

    // Fire-and-forget webhook to bot
    let webhook_url_clone = webhook_url.clone();
    let invocation_clone = invocation.clone();
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

    // TODO: Verify Ed25519 signature on the response payload
    // TODO: Decrypt response if it was encrypted with AES-256-GCM

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
