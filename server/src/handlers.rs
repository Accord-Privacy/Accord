//! HTTP and WebSocket handlers for the Accord relay server

use crate::models::{
    AuthRequest, AuthResponse, ErrorResponse, HealthResponse, RegisterRequest, RegisterResponse,
    WsMessage, WsMessageType,
};
use crate::state::SharedState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::broadcast;
use tracing::{error, info, warn};
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
    // Validate input
    if request.username.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username cannot be empty".to_string(),
                code: 400,
            }),
        ));
    }

    if request.public_key.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Public key cannot be empty".to_string(),
                code: 400,
            }),
        ));
    }

    match state.register_user(request.username, request.public_key).await {
        Ok(user_id) => {
            info!("Registered new user: {}", user_id);
            Ok(Json(RegisterResponse {
                user_id,
                message: "User registered successfully".to_string(),
            }))
        }
        Err(err) => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: err,
                code: 409,
            }),
        )),
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
            Ok(Json(AuthResponse {
                token: auth_token.token,
                user_id: auth_token.user_id,
                expires_at: auth_token.expires_at,
            }))
        }
        Err(err) => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: err,
                code: 401,
            }),
        )),
    }
}

/// WebSocket upgrade handler
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Response {
    // Extract token from query parameters
    let token = match params.get("token") {
        Some(token) => token.clone(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing authentication token".to_string(),
                    code: 401,
                }),
            )
                .into_response();
        }
    };

    // Validate token and get user ID
    let user_id = match state.validate_token(&token).await {
        Some(user_id) => user_id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired token".to_string(),
                    code: 401,
                }),
            )
                .into_response();
        }
    };

    info!("WebSocket connection established for user: {}", user_id);

    // Upgrade to WebSocket
    ws.on_upgrade(move |socket| websocket_handler(socket, user_id, state))
}

/// WebSocket connection handler
async fn websocket_handler(socket: WebSocket, user_id: Uuid, state: SharedState) {
    let (mut sender, mut receiver) = socket.split();
    
    // Create broadcast channel for this connection
    let (tx, mut rx) = broadcast::channel::<String>(100);
    
    // Register the connection
    state.add_connection(user_id, tx.clone()).await;

    // Spawn task to handle outgoing messages (server -> client)
    let tx_clone = tx.clone();
    let outgoing_task = tokio::spawn(async move {
        while let Ok(message) = rx.recv().await {
            if sender.send(Message::Text(message)).await.is_err() {
                break;
            }
        }
    });

    // Handle incoming messages (client -> server)
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Err(err) = handle_ws_message(&text, user_id, &state).await {
                    error!("Error handling WebSocket message: {}", err);
                    let error_msg = serde_json::json!({
                        "error": err,
                        "type": "error"
                    });
                    let _ = tx.send(error_msg.to_string());
                }
            }
            Ok(Message::Close(_)) => {
                info!("WebSocket connection closed for user: {}", user_id);
                break;
            }
            Ok(Message::Ping(data)) => {
                // Respond to ping with pong
                let pong_msg = Message::Pong(data);
                if tx.send(serde_json::to_string(&pong_msg).unwrap_or_default()).is_err() {
                    break;
                }
            }
            Ok(_) => {
                // Ignore other message types (binary, pong)
            }
            Err(err) => {
                error!("WebSocket error for user {}: {}", user_id, err);
                break;
            }
        }
    }

    // Cleanup: remove connection and cancel outgoing task
    state.remove_connection(user_id).await;
    outgoing_task.abort();
    info!("WebSocket handler terminated for user: {}", user_id);
}

/// Handle individual WebSocket messages
async fn handle_ws_message(
    message: &str,
    sender_user_id: Uuid,
    state: &SharedState,
) -> Result<(), String> {
    let ws_message: WsMessage = serde_json::from_str(message)
        .map_err(|e| format!("Invalid message format: {}", e))?;

    match ws_message.message_type {
        WsMessageType::JoinChannel { channel_id } => {
            state.join_channel(sender_user_id, channel_id).await?;
            info!("User {} joined channel {}", sender_user_id, channel_id);
        }

        WsMessageType::LeaveChannel { channel_id } => {
            state.leave_channel(sender_user_id, channel_id).await?;
            info!("User {} left channel {}", sender_user_id, channel_id);
        }

        WsMessageType::DirectMessage { to_user, encrypted_data } => {
            // Route encrypted message directly to recipient
            // Server never decrypts - just forwards the blob
            let relay_message = serde_json::json!({
                "type": "direct_message",
                "from": sender_user_id,
                "encrypted_data": encrypted_data,
                "message_id": ws_message.message_id,
                "timestamp": ws_message.timestamp
            });

            state.send_to_user(to_user, relay_message.to_string()).await?;
            info!("Relayed direct message from {} to {}", sender_user_id, to_user);
        }

        WsMessageType::ChannelMessage { channel_id, encrypted_data } => {
            // Route encrypted message to all channel members
            // Server never decrypts - just forwards the blob
            let relay_message = serde_json::json!({
                "type": "channel_message",
                "from": sender_user_id,
                "channel_id": channel_id,
                "encrypted_data": encrypted_data,
                "message_id": ws_message.message_id,
                "timestamp": ws_message.timestamp
            });

            state.send_to_channel(channel_id, relay_message.to_string()).await?;
            info!("Relayed channel message from {} to channel {}", sender_user_id, channel_id);
        }

        WsMessageType::Ping => {
            // Respond with pong
            let pong_message = serde_json::json!({
                "type": "pong",
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });

            state.send_to_user(sender_user_id, pong_message.to_string()).await?;
        }

        WsMessageType::Pong => {
            // Just log pong receipt
            info!("Received pong from user: {}", sender_user_id);
        }
    }

    Ok(())
}

use futures_util::{sink::SinkExt, stream::StreamExt};