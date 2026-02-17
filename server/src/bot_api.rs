//! Bot API for Accord
//!
//! Provides registration, authentication, permission scoping, event subscription,
//! and webhook delivery for third-party bots.
//!
//! # Privacy Warning
//! Bots break E2E encryption in channels they participate in. Channels with bots
//! present show a warning to all users. Bots only see messages in channels they
//! are explicitly invited to.

use crate::models::ErrorResponse;
use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

// ── Bot Permission Scopes ──

/// Permission scopes that can be granted to a bot
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotScope {
    /// Read messages in channels the bot is invited to
    ReadMessages,
    /// Send messages in channels the bot is invited to
    SendMessages,
    /// Read channel metadata (name, topic, members)
    ReadChannels,
    /// Create/delete/rename channels (requires node admin approval)
    ManageChannels,
    /// Read member list and profiles
    ReadMembers,
    /// Add/remove reactions
    ManageReactions,
    /// Read message reactions
    ReadReactions,
    /// Upload and manage files
    ManageFiles,
}

impl BotScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            BotScope::ReadMessages => "read_messages",
            BotScope::SendMessages => "send_messages",
            BotScope::ReadChannels => "read_channels",
            BotScope::ManageChannels => "manage_channels",
            BotScope::ReadMembers => "read_members",
            BotScope::ManageReactions => "manage_reactions",
            BotScope::ReadReactions => "read_reactions",
            BotScope::ManageFiles => "manage_files",
        }
    }

    pub fn all() -> HashSet<BotScope> {
        use BotScope::*;
        [
            ReadMessages,
            SendMessages,
            ReadChannels,
            ManageChannels,
            ReadMembers,
            ManageReactions,
            ReadReactions,
            ManageFiles,
        ]
        .into_iter()
        .collect()
    }
}

// ── Event Types ──

/// Events that bots can subscribe to
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotEventType {
    /// A message was sent in a channel the bot is in
    MessageCreate,
    /// A message was edited
    MessageEdit,
    /// A message was deleted
    MessageDelete,
    /// A user joined a channel the bot is in
    MemberJoin,
    /// A user left a channel the bot is in
    MemberLeave,
    /// A reaction was added to a message
    ReactionAdd,
    /// A reaction was removed from a message
    ReactionRemove,
    /// A channel was created in a node the bot is in
    ChannelCreate,
    /// A channel was deleted
    ChannelDelete,
    /// A user started typing
    TypingStart,
}

// ── Bot Data Models ──

/// Registered bot metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bot {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub owner_id: Uuid,
    pub api_token_hash: String,
    pub scopes: Vec<BotScope>,
    pub event_subscriptions: Vec<BotEventType>,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub is_active: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Public bot info (no secrets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotInfo {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub owner_id: Uuid,
    pub scopes: Vec<BotScope>,
    pub is_active: bool,
    pub created_at: u64,
}

/// Bot's presence in a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotChannelMembership {
    pub bot_id: Uuid,
    pub channel_id: Uuid,
    pub node_id: Uuid,
    pub added_by: Uuid,
    pub added_at: u64,
}

// ── Request / Response Models ──

/// Request to register a new bot
#[derive(Debug, Deserialize)]
pub struct RegisterBotRequest {
    pub name: String,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub scopes: Vec<BotScope>,
    pub event_subscriptions: Option<Vec<BotEventType>>,
    pub webhook_url: Option<String>,
}

/// Response after registering a bot
#[derive(Debug, Serialize)]
pub struct RegisterBotResponse {
    pub bot_id: Uuid,
    pub api_token: String,
    pub webhook_secret: Option<String>,
    pub message: String,
    pub privacy_warning: String,
}

/// Request to update bot settings
#[derive(Debug, Deserialize)]
pub struct UpdateBotRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub scopes: Option<Vec<BotScope>>,
    pub event_subscriptions: Option<Vec<BotEventType>>,
    pub webhook_url: Option<String>,
}

/// Request to invite a bot to a channel
#[derive(Debug, Deserialize)]
pub struct InviteBotRequest {
    pub bot_id: Uuid,
    pub channel_id: Uuid,
}

/// Response for inviting a bot
#[derive(Debug, Serialize)]
pub struct InviteBotResponse {
    pub status: String,
    pub bot_id: Uuid,
    pub channel_id: Uuid,
    pub privacy_warning: String,
}

/// Regenerate API token response
#[derive(Debug, Serialize)]
pub struct RegenerateTokenResponse {
    pub api_token: String,
    pub message: String,
}

/// Event payload delivered to bots (via WebSocket or webhook)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotEvent {
    pub event_id: Uuid,
    pub event_type: BotEventType,
    pub bot_id: Uuid,
    pub channel_id: Uuid,
    pub node_id: Uuid,
    pub data: serde_json::Value,
    pub timestamp: u64,
}

/// Webhook delivery payload (wraps BotEvent with signature)
#[derive(Debug, Serialize)]
pub struct WebhookPayload {
    pub event: BotEvent,
    /// HMAC-SHA256 signature of the event JSON using webhook_secret
    pub signature: String,
}

// ── Constants ──

const PRIVACY_WARNING: &str = "⚠️ PRIVACY NOTICE: Bots receive plaintext messages in channels \
they are invited to. This breaks end-to-end encryption for those channels. All channel members \
will be notified that a bot is present, and a permanent warning indicator will be shown.";

const BOT_TOKEN_PREFIX: &str = "accord_bot_";

// ── Rate Limits for Bots ──

/// Bot-specific rate limits (more restrictive than user limits)
#[derive(Debug, Clone, Copy)]
pub struct BotRateLimits {
    /// Messages per minute
    pub messages_per_minute: u32,
    /// API calls per minute
    pub api_calls_per_minute: u32,
    /// Webhook retries per event
    pub max_webhook_retries: u32,
}

impl Default for BotRateLimits {
    fn default() -> Self {
        Self {
            messages_per_minute: 20,
            api_calls_per_minute: 60,
            max_webhook_retries: 3,
        }
    }
}

// ── Helper Functions ──

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

fn generate_webhook_secret() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let secret_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &secret_bytes,
    )
}

fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

// ── Route Handlers ──

/// Register a new bot (POST /bots)
/// Requires authentication as a user (the bot owner)
pub async fn register_bot_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<RegisterBotRequest>,
) -> Result<Json<RegisterBotResponse>, (StatusCode, Json<ErrorResponse>)> {
    let owner_id = extract_user_from_token(&state, &params).await?;

    // Validate bot name
    if request.name.is_empty() || request.name.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Bot name must be 1-64 characters".into(),
                code: 400,
            }),
        ));
    }

    if request.scopes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "At least one scope is required".into(),
                code: 400,
            }),
        ));
    }

    // Generate API token and webhook secret
    let api_token = generate_bot_token();
    let token_hash = hash_token(&api_token);

    let webhook_secret = request
        .webhook_url
        .as_ref()
        .map(|_| generate_webhook_secret());

    let bot_id = Uuid::new_v4();
    let now = now_secs();

    let bot = Bot {
        id: bot_id,
        name: request.name,
        description: request.description,
        avatar_url: request.avatar_url,
        owner_id,
        api_token_hash: token_hash,
        scopes: request.scopes,
        event_subscriptions: request.event_subscriptions.unwrap_or_default(),
        webhook_url: request.webhook_url,
        webhook_secret: webhook_secret.clone(),
        is_active: true,
        created_at: now,
        updated_at: now,
    };

    // Store the bot (in production, this would go to the database)
    state.register_bot(bot).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to register bot: {}", e),
                code: 500,
            }),
        )
    })?;

    tracing::info!(
        "Bot registered: {} (id: {}) by user {}",
        bot_id,
        bot_id,
        owner_id
    );

    Ok(Json(RegisterBotResponse {
        bot_id,
        api_token,
        webhook_secret,
        message: "Bot registered successfully. Store the API token securely — it cannot be retrieved later.".into(),
        privacy_warning: PRIVACY_WARNING.into(),
    }))
}

/// Get bot info (GET /bots/:id)
pub async fn get_bot_handler(
    State(state): State<SharedState>,
    Path(bot_id): Path<Uuid>,
) -> Result<Json<BotInfo>, (StatusCode, Json<ErrorResponse>)> {
    let bot = state.get_bot(bot_id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Bot not found: {}", e),
                code: 404,
            }),
        )
    })?;

    Ok(Json(BotInfo {
        id: bot.id,
        name: bot.name,
        description: bot.description,
        avatar_url: bot.avatar_url,
        owner_id: bot.owner_id,
        scopes: bot.scopes,
        is_active: bot.is_active,
        created_at: bot.created_at,
    }))
}

/// Update bot settings (PATCH /bots/:id)
/// Only the bot owner can update
pub async fn update_bot_handler(
    State(state): State<SharedState>,
    Path(bot_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<UpdateBotRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let bot = state.get_bot(bot_id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Bot not found: {}", e),
                code: 404,
            }),
        )
    })?;

    if bot.owner_id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only the bot owner can update bot settings".into(),
                code: 403,
            }),
        ));
    }

    state.update_bot(bot_id, request).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to update bot: {}", e),
                code: 500,
            }),
        )
    })?;

    Ok(Json(
        serde_json::json!({ "status": "updated", "bot_id": bot_id }),
    ))
}

/// Delete a bot (DELETE /bots/:id)
pub async fn delete_bot_handler(
    State(state): State<SharedState>,
    Path(bot_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let bot = state.get_bot(bot_id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Bot not found: {}", e),
                code: 404,
            }),
        )
    })?;

    if bot.owner_id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only the bot owner can delete a bot".into(),
                code: 403,
            }),
        ));
    }

    state.delete_bot(bot_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to delete bot: {}", e),
                code: 500,
            }),
        )
    })?;

    Ok(Json(
        serde_json::json!({ "status": "deleted", "bot_id": bot_id }),
    ))
}

/// Regenerate bot API token (POST /bots/:id/regenerate-token)
pub async fn regenerate_bot_token_handler(
    State(state): State<SharedState>,
    Path(bot_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<RegenerateTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let bot = state.get_bot(bot_id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Bot not found: {}", e),
                code: 404,
            }),
        )
    })?;

    if bot.owner_id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only the bot owner can regenerate the token".into(),
                code: 403,
            }),
        ));
    }

    let new_token = generate_bot_token();
    let new_hash = hash_token(&new_token);

    state
        .update_bot_token_hash(bot_id, new_hash)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to regenerate token: {}", e),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(RegenerateTokenResponse {
        api_token: new_token,
        message: "Token regenerated. The old token is now invalid.".into(),
    }))
}

/// Invite a bot to a channel (POST /bots/invite)
/// Requires admin/mod permission in the node
pub async fn invite_bot_to_channel_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<InviteBotRequest>,
) -> Result<Json<InviteBotResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Verify bot exists
    let _bot = state.get_bot(request.bot_id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Bot not found: {}", e),
                code: 404,
            }),
        )
    })?;

    // Verify channel exists and get node_id
    let channel = state.get_channel(request.channel_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get channel: {}", e),
                code: 500,
            }),
        )
    })?;

    let channel = channel.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Channel not found".into(),
                code: 404,
            }),
        )
    })?;

    // Check if user has permission to manage bots in this node
    let user_role = state
        .get_user_role_in_node(user_id, channel.node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Permission check failed: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !crate::permissions::has_permission(
        user_role,
        crate::permissions::Permission::ManageChannels,
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "You need ManageChannels permission to invite bots".into(),
                code: 403,
            }),
        ));
    }

    // Add bot to channel
    state
        .add_bot_to_channel(request.bot_id, request.channel_id, channel.node_id, user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to invite bot: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Notify channel members that a bot has been added
    let notification = serde_json::json!({
        "type": "bot_joined_channel",
        "bot_id": request.bot_id,
        "channel_id": request.channel_id,
        "added_by": user_id,
        "privacy_warning": PRIVACY_WARNING,
    });
    let _ = state
        .broadcast_to_channel(request.channel_id, notification.to_string())
        .await;

    Ok(Json(InviteBotResponse {
        status: "invited".into(),
        bot_id: request.bot_id,
        channel_id: request.channel_id,
        privacy_warning: PRIVACY_WARNING.into(),
    }))
}

/// Remove a bot from a channel (DELETE /bots/:bot_id/channels/:channel_id)
pub async fn remove_bot_from_channel_handler(
    State(state): State<SharedState>,
    Path((bot_id, channel_id)): Path<(Uuid, Uuid)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Verify channel and check permissions
    let channel = state
        .get_channel(channel_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get channel: {}", e),
                    code: 500,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Channel not found".into(),
                    code: 404,
                }),
            )
        })?;

    let user_role = state
        .get_user_role_in_node(user_id, channel.node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Permission check failed: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !crate::permissions::has_permission(
        user_role,
        crate::permissions::Permission::ManageChannels,
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "You need ManageChannels permission to remove bots".into(),
                code: 403,
            }),
        ));
    }

    state
        .remove_bot_from_channel(bot_id, channel_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to remove bot: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Notify channel
    let notification = serde_json::json!({
        "type": "bot_left_channel",
        "bot_id": bot_id,
        "channel_id": channel_id,
        "removed_by": user_id,
    });
    let _ = state
        .broadcast_to_channel(channel_id, notification.to_string())
        .await;

    Ok(Json(serde_json::json!({
        "status": "removed",
        "bot_id": bot_id,
        "channel_id": channel_id,
    })))
}

/// Bot sends a message to a channel (POST /bot/channels/:channel_id/messages)
/// Authenticated via bot API token in Authorization header
pub async fn bot_send_message_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let bot = extract_bot_from_token(&state, &params).await?;

    // Check scope
    if !bot.scopes.contains(&BotScope::SendMessages) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Bot does not have send_messages scope".into(),
                code: 403,
            }),
        ));
    }

    // Check bot is in this channel
    if !state
        .is_bot_in_channel(bot.id, channel_id)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Bot is not a member of this channel".into(),
                code: 403,
            }),
        ));
    }

    // Rate limit check
    state
        .check_bot_rate_limit(bot.id, "message")
        .await
        .map_err(|e| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: format!("Rate limit exceeded: {}", e),
                    code: 429,
                }),
            )
        })?;

    let content = body
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Missing 'content' field".into(),
                    code: 400,
                }),
            )
        })?;

    let message_id = Uuid::new_v4();
    let now = now_secs();

    // Bot messages are NOT E2E encrypted — they're plaintext, which is the whole
    // point of the privacy warning. The server stores them as-is.
    let message = serde_json::json!({
        "type": "bot_message",
        "message_id": message_id,
        "channel_id": channel_id,
        "bot_id": bot.id,
        "bot_name": bot.name,
        "content": content,
        "timestamp": now,
        "is_bot": true,
    });

    let _ = state
        .broadcast_to_channel(channel_id, message.to_string())
        .await;

    Ok(Json(serde_json::json!({
        "message_id": message_id,
        "channel_id": channel_id,
        "timestamp": now,
    })))
}

/// List bots in a channel (GET /channels/:id/bots)
pub async fn list_channel_bots_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id = extract_user_from_token(&state, &params).await?;

    let bots = state.get_channel_bots(channel_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to list bots: {}", e),
                code: 500,
            }),
        )
    })?;

    let has_bots = !bots.is_empty();
    Ok(Json(serde_json::json!({
        "bots": bots,
        "has_bots": has_bots,
        "privacy_warning": if has_bots { Some(PRIVACY_WARNING) } else { None },
    })))
}

// ── Auth Helpers ──

async fn extract_user_from_token(
    state: &SharedState,
    params: &HashMap<String, String>,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let token = params.get("token").ok_or_else(|| {
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

async fn extract_bot_from_token(
    state: &SharedState,
    params: &HashMap<String, String>,
) -> Result<Bot, (StatusCode, Json<ErrorResponse>)> {
    let token = params.get("bot_token").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing bot_token".into(),
                code: 401,
            }),
        )
    })?;

    let token_hash = hash_token(token);
    state.validate_bot_token(&token_hash).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid bot token".into(),
                code: 401,
            }),
        )
    })
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bot_scope_as_str() {
        assert_eq!(BotScope::ReadMessages.as_str(), "read_messages");
        assert_eq!(BotScope::SendMessages.as_str(), "send_messages");
        assert_eq!(BotScope::ManageChannels.as_str(), "manage_channels");
    }

    #[test]
    fn test_bot_scope_all() {
        let all = BotScope::all();
        assert_eq!(all.len(), 8);
        assert!(all.contains(&BotScope::ReadMessages));
        assert!(all.contains(&BotScope::ManageFiles));
    }

    #[test]
    fn test_generate_bot_token() {
        let token = generate_bot_token();
        assert!(token.starts_with(BOT_TOKEN_PREFIX));
        assert!(token.len() > BOT_TOKEN_PREFIX.len() + 10);
    }

    #[test]
    fn test_generate_webhook_secret() {
        let secret = generate_webhook_secret();
        assert!(!secret.is_empty());
        assert!(secret.len() > 20);
    }

    #[test]
    fn test_hash_token_deterministic() {
        let token = "test_token_123";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_different_inputs() {
        let hash1 = hash_token("token_a");
        let hash2 = hash_token("token_b");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_default_bot_rate_limits() {
        let limits = BotRateLimits::default();
        assert_eq!(limits.messages_per_minute, 20);
        assert_eq!(limits.api_calls_per_minute, 60);
        assert_eq!(limits.max_webhook_retries, 3);
    }

    #[test]
    fn test_privacy_warning_exists() {
        assert!(PRIVACY_WARNING.contains("PRIVACY NOTICE"));
        assert!(PRIVACY_WARNING.contains("end-to-end encryption"));
    }

    #[test]
    fn test_bot_event_serialization() {
        let event = BotEvent {
            event_id: Uuid::new_v4(),
            event_type: BotEventType::MessageCreate,
            bot_id: Uuid::new_v4(),
            channel_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
            data: serde_json::json!({"content": "hello"}),
            timestamp: 1234567890,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("message_create"));

        let deserialized: BotEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.event_type, BotEventType::MessageCreate);
    }
}
