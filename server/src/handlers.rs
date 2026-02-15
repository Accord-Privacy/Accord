//! HTTP and WebSocket handlers for the Accord relay server

use crate::models::{
    AuthRequest, AuthResponse, CreateInviteRequest, CreateInviteResponse, CreateNodeRequest, 
    ErrorResponse, HealthResponse, RegisterRequest, RegisterResponse, UseInviteResponse, 
    WsMessage, WsMessageType,
};
use crate::node::NodeInfo;
use crate::state::SharedState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use std::collections::HashMap;
use tokio::sync::broadcast;
use tracing::{error, info};
use uuid::Uuid;

/// Health check endpoint
pub async fn health_handler(State(state): State<SharedState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.uptime(),
    })
}

/// User registration endpoint
pub async fn register_handler(
    State(state): State<SharedState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    if request.username.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Username cannot be empty".into(), code: 400 })));
    }
    if request.public_key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Public key cannot be empty".into(), code: 400 })));
    }

    match state.register_user(request.username, request.public_key).await {
        Ok(user_id) => {
            info!("Registered new user: {}", user_id);
            Ok(Json(RegisterResponse { user_id, message: "User registered successfully".into() }))
        }
        Err(err) => Err((StatusCode::CONFLICT, Json(ErrorResponse { error: err, code: 409 }))),
    }
}

/// User authentication endpoint
pub async fn auth_handler(
    State(state): State<SharedState>,
    Json(request): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.authenticate_user(request.username, request.password).await {
        Ok(auth_token) => {
            info!("User authenticated: {}", auth_token.user_id);
            Ok(Json(AuthResponse { token: auth_token.token, user_id: auth_token.user_id, expires_at: auth_token.expires_at }))
        }
        Err(err) => Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: err, code: 401 }))),
    }
}

// ── Node REST endpoints ──

/// Create a new Node
pub async fn create_node_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<CreateNodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.create_node(request.name, user_id, request.description).await {
        Ok(node) => {
            info!("Node created: {} by {}", node.id, user_id);
            Ok(Json(serde_json::json!({
                "id": node.id,
                "name": node.name,
                "owner_id": node.owner_id,
                "description": node.description,
                "created_at": node.created_at,
            })))
        }
        Err(err) => Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: err, code: 400 }))),
    }
}

/// Get Node info
pub async fn get_node_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<NodeInfo>, (StatusCode, Json<ErrorResponse>)> {
    match state.get_node_info(node_id).await {
        Ok(info) => Ok(Json(info)),
        Err(err) => Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: err, code: 404 }))),
    }
}

/// Join a Node
pub async fn join_node_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.join_node(user_id, node_id).await {
        Ok(()) => Ok(Json(serde_json::json!({ "status": "joined", "node_id": node_id }))),
        Err(err) => Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: err, code: 400 }))),
    }
}

/// Leave a Node
pub async fn leave_node_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.leave_node(user_id, node_id).await {
        Ok(()) => Ok(Json(serde_json::json!({ "status": "left", "node_id": node_id }))),
        Err(err) => Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: err, code: 400 }))),
    }
}

// ── Node invite endpoints ──

/// Create a new invite for a Node (POST /nodes/:id/invites)
pub async fn create_invite_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<CreateInviteRequest>,
) -> Result<Json<CreateInviteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.create_invite(node_id, user_id, request.max_uses, request.expires_in_hours).await {
        Ok((invite_id, invite_code)) => {
            info!("Invite created: {} for node {} by {}", invite_code, node_id, user_id);
            
            // Calculate expires_at for response
            let expires_at = request.expires_in_hours.map(|hours| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + (hours as u64 * 3600)
            });

            Ok(Json(CreateInviteResponse {
                id: invite_id,
                invite_code,
                max_uses: request.max_uses,
                expires_at,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }))
        }
        Err(err) => Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: err, code: 403 }))),
    }
}

/// List invites for a Node (GET /nodes/:id/invites)
pub async fn list_invites_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.list_invites(node_id, user_id).await {
        Ok(invites) => Ok(Json(serde_json::json!({ "invites": invites }))),
        Err(err) => Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: err, code: 403 }))),
    }
}

/// Revoke an invite (DELETE /invites/:invite_id)
pub async fn revoke_invite_handler(
    State(state): State<SharedState>,
    Path(invite_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.revoke_invite(invite_id, user_id).await {
        Ok(()) => {
            info!("Invite revoked: {} by {}", invite_id, user_id);
            Ok(Json(serde_json::json!({ "status": "revoked", "invite_id": invite_id })))
        }
        Err(err) => Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: err, code: 403 }))),
    }
}

/// Use an invite code to join a Node (POST /invites/:code/join)
pub async fn use_invite_handler(
    State(state): State<SharedState>,
    Path(invite_code): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<UseInviteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.use_invite(&invite_code, user_id).await {
        Ok((node_id, node_name)) => {
            info!("Invite used: {} by {} to join node {}", invite_code, user_id, node_id);
            Ok(Json(UseInviteResponse {
                status: "joined".to_string(),
                node_id,
                node_name,
            }))
        }
        Err(err) => Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: err, code: 400 }))),
    }
}

/// Helper to extract user_id from token query param
async fn extract_user_from_token(
    state: &SharedState,
    params: &HashMap<String, String>,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let token = params.get("token").ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Missing token".into(), code: 401 }))
    })?;
    state.validate_token(token).await.ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid or expired token".into(), code: 401 }))
    })
}

// ── WebSocket ──

/// WebSocket upgrade handler
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Response {
    let token = match params.get("token") {
        Some(token) => token.clone(),
        None => return (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Missing authentication token".into(), code: 401 })).into_response(),
    };

    let user_id = match state.validate_token(&token).await {
        Some(uid) => uid,
        None => return (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid or expired token".into(), code: 401 })).into_response(),
    };

    info!("WebSocket connection established for user: {}", user_id);
    ws.on_upgrade(move |socket| websocket_handler(socket, user_id, state))
}

async fn websocket_handler(socket: WebSocket, user_id: Uuid, state: SharedState) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = broadcast::channel::<String>(100);

    state.add_connection(user_id, tx.clone()).await;

    let outgoing_task = tokio::spawn(async move {
        while let Ok(message) = rx.recv().await {
            if sender.send(Message::Text(message)).await.is_err() {
                break;
            }
        }
    });

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Err(err) = handle_ws_message(&text, user_id, &state).await {
                    error!("Error handling WebSocket message: {}", err);
                    let error_msg = serde_json::json!({ "error": err, "type": "error" });
                    let _ = tx.send(error_msg.to_string());
                }
            }
            Ok(Message::Close(_)) => {
                info!("WebSocket closed for user: {}", user_id);
                break;
            }
            Ok(Message::Ping(_)) => {
                let pong = serde_json::json!({ "type": "pong", "timestamp": now_secs() });
                if tx.send(pong.to_string()).is_err() { break; }
            }
            Ok(_) => {}
            Err(err) => {
                error!("WebSocket error for user {}: {}", user_id, err);
                break;
            }
        }
    }

    state.remove_connection(user_id).await;
    outgoing_task.abort();
    info!("WebSocket handler terminated for user: {}", user_id);
}

async fn handle_ws_message(message: &str, sender_user_id: Uuid, state: &SharedState) -> Result<(), String> {
    let ws_message: WsMessage = serde_json::from_str(message).map_err(|e| format!("Invalid message format: {}", e))?;

    match ws_message.message_type {
        WsMessageType::CreateNode { name, description } => {
            let node = state.create_node(name, sender_user_id, description).await?;
            let resp = serde_json::json!({ "type": "node_created", "node": node });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
        }

        WsMessageType::JoinNode { node_id } => {
            state.join_node(sender_user_id, node_id).await?;
            let resp = serde_json::json!({ "type": "node_joined", "node_id": node_id });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
        }

        WsMessageType::LeaveNode { node_id } => {
            state.leave_node(sender_user_id, node_id).await?;
            let resp = serde_json::json!({ "type": "node_left", "node_id": node_id });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
        }

        WsMessageType::GetNodeInfo { node_id } => {
            let info = state.get_node_info(node_id).await?;
            let resp = serde_json::json!({ "type": "node_info", "data": info });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
        }

        WsMessageType::CreateChannel { node_id, name } => {
            let channel = state.create_channel(name, node_id, sender_user_id).await?;
            let resp = serde_json::json!({ "type": "channel_created", "channel": channel });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
        }

        WsMessageType::JoinChannel { channel_id } => {
            state.join_channel(sender_user_id, channel_id).await?;
            info!("User {} joined channel {}", sender_user_id, channel_id);
        }

        WsMessageType::LeaveChannel { channel_id } => {
            state.leave_channel(sender_user_id, channel_id).await?;
            info!("User {} left channel {}", sender_user_id, channel_id);
        }

        WsMessageType::DirectMessage { to_user, encrypted_data } => {
            let relay = serde_json::json!({
                "type": "direct_message", "from": sender_user_id,
                "encrypted_data": encrypted_data, "message_id": ws_message.message_id,
                "timestamp": ws_message.timestamp
            });
            state.send_to_user(to_user, relay.to_string()).await?;
        }

        WsMessageType::ChannelMessage { channel_id, encrypted_data } => {
            let relay = serde_json::json!({
                "type": "channel_message", "from": sender_user_id, "channel_id": channel_id,
                "encrypted_data": encrypted_data, "message_id": ws_message.message_id,
                "timestamp": ws_message.timestamp
            });
            state.send_to_channel(channel_id, relay.to_string()).await?;
        }

        WsMessageType::Ping => {
            let pong = serde_json::json!({ "type": "pong", "timestamp": now_secs() });
            state.send_to_user(sender_user_id, pong.to_string()).await?;
        }

        WsMessageType::Pong => {
            info!("Received pong from user: {}", sender_user_id);
        }

        // ── Voice operations ──
        WsMessageType::JoinVoiceChannel { channel_id } => {
            state.join_voice_channel(sender_user_id, channel_id).await?;
            let resp = serde_json::json!({ 
                "type": "voice_channel_joined", 
                "channel_id": channel_id,
                "user_id": sender_user_id
            });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
            info!("User {} joined voice channel {}", sender_user_id, channel_id);
        }

        WsMessageType::LeaveVoiceChannel { channel_id } => {
            state.leave_voice_channel(sender_user_id, channel_id).await?;
            let resp = serde_json::json!({ 
                "type": "voice_channel_left", 
                "channel_id": channel_id,
                "user_id": sender_user_id
            });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
            info!("User {} left voice channel {}", sender_user_id, channel_id);
        }

        WsMessageType::VoicePacket { channel_id, encrypted_audio, sequence } => {
            // Relay encrypted voice packet to all other participants in the channel
            let relay = serde_json::json!({
                "type": "voice_packet",
                "from": sender_user_id,
                "channel_id": channel_id,
                "encrypted_audio": encrypted_audio,
                "sequence": sequence,
                "timestamp": ws_message.timestamp
            });
            state.send_to_voice_channel(channel_id, sender_user_id, relay.to_string()).await?;
        }

        WsMessageType::VoiceSpeakingState { channel_id, user_id, speaking } => {
            // Broadcast speaking state change to all participants
            let broadcast = serde_json::json!({
                "type": "voice_speaking_state",
                "channel_id": channel_id,
                "user_id": user_id,
                "speaking": speaking,
                "timestamp": ws_message.timestamp
            });
            state.send_to_voice_channel(channel_id, sender_user_id, broadcast.to_string()).await?;
        }
    }

    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}
