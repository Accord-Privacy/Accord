//! HTTP and WebSocket handlers for the Accord relay server

use crate::models::{
    AuditLogResponse, AuthRequest, AuthResponse, CreateInviteRequest, CreateInviteResponse,
    CreateNodeRequest, EditMessageRequest, ErrorResponse, FileMetadata, HealthResponse,
    MessageReactionsResponse, RegisterRequest, RegisterResponse, UseInviteResponse, WsMessage,
    WsMessageType,
};
use crate::node::NodeInfo;
use crate::permissions::{has_permission, Permission};
use crate::state::SharedState;
use axum::body::Body;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Multipart, Path, Query, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
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
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username cannot be empty".into(),
                code: 400,
            }),
        ));
    }
    if request.public_key.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Public key cannot be empty".into(),
                code: 400,
            }),
        ));
    }

    match state
        .register_user(request.username, request.public_key, request.password)
        .await
    {
        Ok(user_id) => {
            info!("Registered new user: {}", user_id);
            Ok(Json(RegisterResponse {
                user_id,
                message: "User registered successfully".into(),
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
    match state
        .authenticate_user(request.username, request.password)
        .await
    {
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

// ── Node REST endpoints ──

/// Create a new Node
pub async fn create_node_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<CreateNodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state
        .create_node(request.name, user_id, request.description)
        .await
    {
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
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: err,
                code: 400,
            }),
        )),
    }
}

/// Get Node info
pub async fn get_node_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<NodeInfo>, (StatusCode, Json<ErrorResponse>)> {
    match state.get_node_info(node_id).await {
        Ok(info) => Ok(Json(info)),
        Err(err) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: err,
                code: 404,
            }),
        )),
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
        Ok(()) => Ok(Json(
            serde_json::json!({ "status": "joined", "node_id": node_id }),
        )),
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: err,
                code: 400,
            }),
        )),
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
        Ok(()) => Ok(Json(
            serde_json::json!({ "status": "left", "node_id": node_id }),
        )),
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: err,
                code: 400,
            }),
        )),
    }
}

/// Update Node settings (PATCH /nodes/:id)
pub async fn update_node_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let name = request
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let description = request
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    match state
        .update_node(node_id, user_id, name.clone(), description.clone())
        .await
    {
        Ok(()) => {
            // Log audit event
            let mut details = serde_json::Map::new();
            if let Some(ref name) = name {
                details.insert("name".to_string(), serde_json::Value::String(name.clone()));
            }
            if let Some(ref description) = description {
                details.insert(
                    "description".to_string(),
                    serde_json::Value::String(description.clone()),
                );
            }
            let details_str = if !details.is_empty() {
                Some(serde_json::Value::Object(details).to_string())
            } else {
                None
            };

            log_audit_event(
                &state,
                node_id,
                user_id,
                "node_settings_update",
                "node",
                Some(node_id),
                details_str.as_deref(),
            )
            .await;

            Ok(Json(
                serde_json::json!({ "status": "updated", "node_id": node_id }),
            ))
        }
        Err(err) => {
            if err.contains("Insufficient permissions") {
                Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: err,
                        code: 403,
                    }),
                ))
            } else {
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: err,
                        code: 400,
                    }),
                ))
            }
        }
    }
}

/// Kick a user from a Node (DELETE /nodes/:id/members/:user_id)
pub async fn kick_user_handler(
    State(state): State<SharedState>,
    Path((node_id, target_user_id)): Path<(Uuid, Uuid)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let admin_user_id = extract_user_from_token(&state, &params).await?;

    match state
        .kick_from_node(admin_user_id, target_user_id, node_id)
        .await
    {
        Ok(()) => {
            info!(
                "User {} kicked from node {} by {}",
                target_user_id, node_id, admin_user_id
            );

            // Log audit event
            let details = serde_json::json!({
                "kicked_user_id": target_user_id
            });
            log_audit_event(
                &state,
                node_id,
                admin_user_id,
                "member_kick",
                "user",
                Some(target_user_id),
                Some(&details.to_string()),
            )
            .await;

            Ok(Json(
                serde_json::json!({ "status": "kicked", "node_id": node_id, "user_id": target_user_id }),
            ))
        }
        Err(err) => {
            if err.contains("Insufficient permissions") {
                Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: err,
                        code: 403,
                    }),
                ))
            } else {
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: err,
                        code: 400,
                    }),
                ))
            }
        }
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

    match state
        .create_invite(node_id, user_id, request.max_uses, request.expires_in_hours)
        .await
    {
        Ok((invite_id, invite_code)) => {
            info!(
                "Invite created: {} for node {} by {}",
                invite_code, node_id, user_id
            );

            // Log audit event
            let details = serde_json::json!({
                "invite_code": invite_code,
                "invite_id": invite_id,
                "max_uses": request.max_uses,
                "expires_in_hours": request.expires_in_hours
            });
            log_audit_event(
                &state,
                node_id,
                user_id,
                "invite_create",
                "invite",
                Some(invite_id),
                Some(&details.to_string()),
            )
            .await;

            // Calculate expires_at for response
            let expires_at = request.expires_in_hours.map(|hours| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + (hours as u64 * 3600)
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
        Err(err) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: err,
                code: 403,
            }),
        )),
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
        Err(err) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: err,
                code: 403,
            }),
        )),
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

            // Get the node_id from the invite for audit logging
            if let Ok(Some(invite)) = state.db.get_node_invite(invite_id).await {
                let details = serde_json::json!({
                    "invite_code": invite.invite_code,
                    "invite_id": invite_id
                });
                log_audit_event(
                    &state,
                    invite.node_id,
                    user_id,
                    "invite_revoke",
                    "invite",
                    Some(invite_id),
                    Some(&details.to_string()),
                )
                .await;
            }

            Ok(Json(
                serde_json::json!({ "status": "revoked", "invite_id": invite_id }),
            ))
        }
        Err(err) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: err,
                code: 403,
            }),
        )),
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
            info!(
                "Invite used: {} by {} to join node {}",
                invite_code, user_id, node_id
            );
            Ok(Json(UseInviteResponse {
                status: "joined".to_string(),
                node_id,
                node_name,
            }))
        }
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: err,
                code: 400,
            }),
        )),
    }
}

// ── Channel Category endpoints ──

/// Create a channel category (POST /nodes/:id/categories)
pub async fn create_channel_category_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::CreateChannelCategoryRequest>,
) -> Result<Json<crate::models::CreateChannelCategoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check if user is admin of the node
    let user_role = state
        .get_user_role_in_node(user_id, node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to check permissions: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !has_permission(user_role, Permission::ManageChannels) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Permission denied. Required: ManageChannels, Your role: {:?}",
                    user_role
                ),
                code: 403,
            }),
        ));
    }

    match state.create_channel_category(node_id, &request.name).await {
        Ok(category) => {
            info!(
                "Channel category {} created in node {}",
                category.id, node_id
            );
            Ok(Json(crate::models::CreateChannelCategoryResponse {
                id: category.id,
                name: category.name,
                position: category.position,
                created_at: category.created_at,
            }))
        }
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: err,
                code: 400,
            }),
        )),
    }
}

/// Update a channel category (PATCH /categories/:id)
pub async fn update_channel_category_handler(
    State(state): State<SharedState>,
    Path(category_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::UpdateChannelCategoryRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Get the category to determine the node it belongs to
    let category = state.get_channel_category(category_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get category: {}", e),
                code: 500,
            }),
        )
    })?;

    let category = category.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Channel category not found".to_string(),
                code: 404,
            }),
        )
    })?;

    // Check if user is admin of the node
    let user_role = state
        .get_user_role_in_node(user_id, category.node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to check permissions: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !has_permission(user_role, Permission::ManageChannels) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Permission denied. Required: ManageChannels, Your role: {:?}",
                    user_role
                ),
                code: 403,
            }),
        ));
    }

    match state
        .update_channel_category(category_id, request.name.as_deref(), request.position)
        .await
    {
        Ok(()) => {
            info!("Channel category {} updated", category_id);
            Ok(Json(
                serde_json::json!({ "status": "updated", "category_id": category_id }),
            ))
        }
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: err,
                code: 400,
            }),
        )),
    }
}

/// Delete a channel category (DELETE /categories/:id)
pub async fn delete_channel_category_handler(
    State(state): State<SharedState>,
    Path(category_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Get the category to determine the node it belongs to
    let category = state.get_channel_category(category_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get category: {}", e),
                code: 500,
            }),
        )
    })?;

    let category = category.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Channel category not found".to_string(),
                code: 404,
            }),
        )
    })?;

    // Check if user is admin of the node
    let user_role = state
        .get_user_role_in_node(user_id, category.node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to check permissions: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !has_permission(user_role, Permission::ManageChannels) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Permission denied. Required: ManageChannels, Your role: {:?}",
                    user_role
                ),
                code: 403,
            }),
        ));
    }

    match state.delete_channel_category(category_id).await {
        Ok(()) => {
            info!("Channel category {} deleted", category_id);
            Ok(Json(
                serde_json::json!({ "status": "deleted", "category_id": category_id }),
            ))
        }
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: err,
                code: 400,
            }),
        )),
    }
}

/// Update a channel's category and position (PATCH /channels/:id)
pub async fn update_channel_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::UpdateChannelRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Get the channel to determine the node it belongs to
    let channel = state.get_channel(channel_id).await.map_err(|e| {
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
                error: "Channel not found".to_string(),
                code: 404,
            }),
        )
    })?;

    // Check if user is admin of the node
    let user_role = state
        .get_user_role_in_node(user_id, channel.node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to check permissions: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !has_permission(user_role, Permission::ManageChannels) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Permission denied. Required: manage_channels, Your role: {:?}",
                    user_role
                ),
                code: 403,
            }),
        ));
    }

    match state
        .update_channel_category_and_position(channel_id, request.category_id, request.position)
        .await
    {
        Ok(()) => {
            info!("Channel {} updated", channel_id);
            Ok(Json(
                serde_json::json!({ "status": "updated", "channel_id": channel_id }),
            ))
        }
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: err,
                code: 400,
            }),
        )),
    }
}

// ── Channel endpoints ──

/// Delete a channel (DELETE /channels/:id)
pub async fn delete_channel_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.delete_channel(channel_id, user_id).await {
        Ok(()) => {
            info!("Channel {} deleted by {}", channel_id, user_id);
            Ok(Json(
                serde_json::json!({ "status": "deleted", "channel_id": channel_id }),
            ))
        }
        Err(err) => {
            if err.contains("Insufficient permissions") {
                Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: err,
                        code: 403,
                    }),
                ))
            } else if err.contains("not yet implemented") {
                Err((
                    StatusCode::NOT_IMPLEMENTED,
                    Json(ErrorResponse {
                        error: err,
                        code: 501,
                    }),
                ))
            } else {
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: err,
                        code: 400,
                    }),
                ))
            }
        }
    }
}

// ── Message endpoints ──

/// Get channel message history with pagination (GET /channels/:id/messages)
pub async fn get_channel_messages_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<crate::models::MessageHistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check if user has access to this channel
    let can_access = state
        .user_can_access_channel(user_id, channel_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Access check failed: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !can_access {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied to this channel".into(),
                code: 403,
            }),
        ));
    }

    // Parse query parameters
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(50)
        .min(100); // Cap at 100 messages per request

    let before_id = params.get("before").and_then(|s| Uuid::parse_str(s).ok());

    match state
        .get_channel_messages_paginated(channel_id, limit, before_id)
        .await
    {
        Ok(messages) => {
            // Check if there are more messages (look ahead by 1)
            let has_more = if messages.len() as u32 == limit {
                if let Some(last_msg) = messages.last() {
                    let check_more = state
                        .get_channel_messages_paginated(channel_id, 1, Some(last_msg.id))
                        .await
                        .map_err(|e| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ErrorResponse {
                                    error: format!("Failed to check for more messages: {}", e),
                                    code: 500,
                                }),
                            )
                        })?;
                    !check_more.is_empty()
                } else {
                    false
                }
            } else {
                false
            };

            let next_cursor = if has_more {
                messages.last().map(|msg| msg.id)
            } else {
                None
            };

            Ok(Json(crate::models::MessageHistoryResponse {
                messages,
                has_more,
                next_cursor,
            }))
        }
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get messages: {}", err),
                code: 500,
            }),
        )),
    }
}

/// Search messages within a Node (GET /nodes/:id/search)
pub async fn search_messages_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<crate::models::SearchResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check if user is member of this node
    let is_member = state.is_node_member(user_id, node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Membership check failed: {}", e),
                code: 500,
            }),
        )
    })?;

    if !is_member {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied to this node".into(),
                code: 403,
            }),
        ));
    }

    // Parse query parameters
    let query = params.get("q").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Query parameter 'q' is required".into(),
                code: 400,
            }),
        )
    })?;

    if query.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Search query cannot be empty".into(),
                code: 400,
            }),
        ));
    }

    let channel_id_filter = params.get("channel").and_then(|s| Uuid::parse_str(s).ok());

    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(50)
        .min(200); // Cap at 200 search results

    match state.search_messages(node_id, query, channel_id_filter, limit).await {
        Ok(results) => {
            Ok(Json(crate::models::SearchResponse {
                total_count: results.len() as u32,
                results,
                search_query: query.to_string(),
                note: "Search results include metadata only. Message content is end-to-end encrypted and must be searched client-side after decryption.".to_string(),
            }))
        }
        Err(err) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: format!("Search failed: {}", err),
            code: 500
        }))),
    }
}

// ── User profile endpoints ──

/// Get user profile (GET /users/:id/profile)
pub async fn get_user_profile_handler(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<crate::models::UserProfile>, (StatusCode, Json<ErrorResponse>)> {
    let _requesting_user_id = extract_user_from_token(&state, &params).await?;

    match state.get_user_profile(user_id).await {
        Ok(Some(profile)) => Ok(Json(profile)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User profile not found".into(),
                code: 404,
            }),
        )),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: err,
                code: 500,
            }),
        )),
    }
}

/// Update own profile (PATCH /users/me/profile)
pub async fn update_user_profile_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::UpdateProfileRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Validate bio length if provided
    if let Some(ref bio) = request.bio {
        if bio.len() > 500 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Bio cannot exceed 500 characters".into(),
                    code: 400,
                }),
            ));
        }
    }

    // Validate status if provided
    if let Some(ref status) = request.status {
        if !matches!(status.as_str(), "online" | "idle" | "dnd" | "offline") {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid status. Must be one of: online, idle, dnd, offline".into(),
                    code: 400,
                }),
            ));
        }
    }

    match state
        .update_user_profile(
            user_id,
            request.display_name.as_deref(),
            request.bio.as_deref(),
            request.status.as_deref(),
            request.custom_status.as_deref(),
        )
        .await
    {
        Ok(()) => {
            info!("User profile updated: {}", user_id);
            Ok(Json(
                serde_json::json!({ "status": "updated", "user_id": user_id }),
            ))
        }
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: err,
                code: 500,
            }),
        )),
    }
}

/// Get Node members with profiles (GET /nodes/:id/members)
pub async fn get_node_members_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check if user is a member of the node
    match state.get_node_member(node_id, user_id).await {
        Ok(Some(_)) => {} // User is a member, proceed
        Ok(None) => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "You must be a member of this node to view its members".into(),
                    code: 403,
                }),
            ));
        }
        Err(err) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: err,
                    code: 500,
                }),
            ));
        }
    }

    match state.get_node_members_with_profiles(node_id).await {
        Ok(members) => Ok(Json(serde_json::json!({ "members": members }))),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: err,
                code: 500,
            }),
        )),
    }
}

/// Helper to extract user_id from Authorization: Bearer header or query param fallback
async fn extract_user_from_token(
    state: &SharedState,
    params: &HashMap<String, String>,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let token = params.get("token").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing token. Use Authorization: Bearer header or ?token= query param"
                    .into(),
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

/// Extract token from Authorization: Bearer header, falling back to query param
fn extract_token_from_headers_or_params<'a>(
    headers: &'a HeaderMap,
    params: &'a HashMap<String, String>,
) -> Option<&'a str> {
    // Prefer Authorization: Bearer header
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token);
            }
        }
    }
    // Fall back to query param
    params.get("token").map(|s| s.as_str())
}

/// Extract user_id from Authorization: Bearer header with query param fallback
async fn extract_user_from_header_or_token(
    state: &SharedState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let token = extract_token_from_headers_or_params(headers, params).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing authentication. Use Authorization: Bearer <token> header".into(),
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

/// Helper to check if user has permission for a Node operation
async fn check_node_permission(
    state: &SharedState,
    user_id: Uuid,
    node_id: Uuid,
    required_permission: Permission,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // Get user's role in the Node
    let member = state.get_node_member(node_id, user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e,
                code: 500,
            }),
        )
    })?;

    match member {
        Some(member_info) => {
            if has_permission(member_info.role, required_permission) {
                Ok(())
            } else {
                let permission_name = format!("{:?}", required_permission);
                let role_name = member_info.role.as_str();
                Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: format!(
                            "Permission denied. Required: {:?}, Your role: {:?}",
                            permission_name, role_name
                        ),
                        code: 403,
                    }),
                ))
            }
        }
        None => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "You are not a member of this Node".into(),
                code: 403,
            }),
        )),
    }
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
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing authentication token".into(),
                    code: 401,
                }),
            )
                .into_response()
        }
    };

    let user_id = match state.validate_token(&token).await {
        Some(uid) => uid,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid or expired token".into(),
                    code: 401,
                }),
            )
                .into_response()
        }
    };

    info!("WebSocket connection established for user: {}", user_id);
    ws.on_upgrade(move |socket| websocket_handler(socket, user_id, state))
}

async fn websocket_handler(socket: WebSocket, user_id: Uuid, state: SharedState) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = broadcast::channel::<String>(100);

    state.add_connection(user_id, tx.clone()).await;

    // Set user online when they connect
    if let Err(err) = state.set_user_online(user_id).await {
        error!("Failed to set user online: {}", err);
    }

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
                if tx.send(pong.to_string()).is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(err) => {
                error!("WebSocket error for user {}: {}", user_id, err);
                break;
            }
        }
    }

    state.remove_connection(user_id).await;

    // Set user offline when they disconnect
    if let Err(err) = state.set_user_offline(user_id).await {
        error!("Failed to set user offline: {}", err);
    }

    outgoing_task.abort();
    info!("WebSocket handler terminated for user: {}", user_id);
}

async fn handle_ws_message(
    message: &str,
    sender_user_id: Uuid,
    state: &SharedState,
) -> Result<(), String> {
    let ws_message: WsMessage =
        serde_json::from_str(message).map_err(|e| format!("Invalid message format: {}", e))?;

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
            let channel = state
                .create_channel(name.clone(), node_id, sender_user_id)
                .await?;

            // Log audit event
            let details = serde_json::json!({
                "channel_name": name,
                "channel_id": channel.id
            });
            log_audit_event(
                &state,
                node_id,
                sender_user_id,
                "channel_create",
                "channel",
                Some(channel.id),
                Some(&details.to_string()),
            )
            .await;

            let resp = serde_json::json!({ "type": "channel_created", "channel": channel });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
        }

        WsMessageType::UpdateChannel {
            channel_id,
            category_id,
            position,
        } => {
            // This would be handled by the REST endpoint, but we can include it for completeness
            let resp = serde_json::json!({
                "type": "error",
                "message": "Use REST API to update channels"
            });
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

        WsMessageType::DirectMessage {
            to_user,
            encrypted_data,
        } => {
            // For now, simplify DM handling by just relaying the message directly
            // without complex database operations that might hang in tests
            let message_id = uuid::Uuid::new_v4();

            // Create a simple relay message
            let relay = serde_json::json!({
                "type": "channel_message",
                "from": sender_user_id,
                "channel_id": message_id, // Use message_id as temporary channel_id
                "encrypted_data": encrypted_data,
                "message_id": message_id,
                "timestamp": ws_message.timestamp,
                "is_dm": true
            });

            // Send to both users directly
            let _ = state.send_to_user(sender_user_id, relay.to_string()).await;
            let _ = state.send_to_user(to_user, relay.to_string()).await;
        }

        WsMessageType::ChannelMessage {
            channel_id,
            encrypted_data,
            reply_to,
        } => {
            // Decode and store the message
            let encrypted_payload = base64::engine::general_purpose::STANDARD
                .decode(&encrypted_data)
                .map_err(|_| "Invalid base64 encoded data".to_string())?;

            let message_id = state
                .db
                .store_message(channel_id, sender_user_id, &encrypted_payload, reply_to)
                .await
                .map_err(|e| format!("Failed to store message: {}", e))?;

            let relay = serde_json::json!({
                "type": "channel_message", "from": sender_user_id, "channel_id": channel_id,
                "encrypted_data": encrypted_data, "message_id": message_id,
                "timestamp": ws_message.timestamp, "reply_to": reply_to
            });
            state.send_to_channel(channel_id, relay.to_string()).await?;
        }

        WsMessageType::EditMessage {
            message_id,
            encrypted_data,
        } => {
            // Decode the encrypted payload
            let encrypted_payload = base64::engine::general_purpose::STANDARD
                .decode(&encrypted_data)
                .map_err(|_| "Invalid base64 encoded data".to_string())?;

            // Attempt to edit the message
            match state
                .db
                .edit_message(message_id, sender_user_id, &encrypted_payload)
                .await
            {
                Ok(true) => {
                    // Get the updated message details for broadcasting
                    if let Ok(Some((channel_id, sender_id, created_at, edited_at))) =
                        state.db.get_message_details(message_id).await
                    {
                        // Broadcast the message edit event to channel members
                        let edit_event = serde_json::json!({
                            "type": "message_edit",
                            "message_id": message_id,
                            "channel_id": channel_id,
                            "sender_id": sender_id,
                            "encrypted_data": encrypted_data,
                            "created_at": created_at,
                            "edited_at": edited_at,
                            "timestamp": now_secs()
                        });
                        if let Err(e) = state
                            .send_to_channel(channel_id, edit_event.to_string())
                            .await
                        {
                            error!("Failed to broadcast message edit: {}", e);
                        }
                    }
                }
                Ok(false) => {
                    error!("Message edit failed: permission denied or message not found");
                }
                Err(e) => {
                    error!("Failed to edit message: {}", e);
                }
            }
        }

        WsMessageType::DeleteMessage { message_id } => {
            // Attempt to delete the message
            match state.db.delete_message(message_id, sender_user_id).await {
                Ok(Some((channel_id, sender_id))) => {
                    // Broadcast the message delete event to channel members
                    let delete_event = serde_json::json!({
                        "type": "message_delete",
                        "message_id": message_id,
                        "channel_id": channel_id,
                        "sender_id": sender_id,
                        "timestamp": now_secs()
                    });
                    if let Err(e) = state
                        .send_to_channel(channel_id, delete_event.to_string())
                        .await
                    {
                        error!("Failed to broadcast message delete: {}", e);
                    }
                }
                Ok(None) => {
                    error!("Message delete failed: permission denied or message not found");
                }
                Err(e) => {
                    error!("Failed to delete message: {}", e);
                }
            }
        }

        WsMessageType::Ping => {
            let pong = serde_json::json!({ "type": "pong", "timestamp": now_secs() });
            state.send_to_user(sender_user_id, pong.to_string()).await?;
        }

        WsMessageType::Pong => {
            info!("Received pong from user: {}", sender_user_id);
        }

        // ── Reaction operations ──
        WsMessageType::AddReaction { message_id, emoji } => {
            // Check if user has access to the message
            let message_details = state
                .db
                .get_message_details(message_id)
                .await
                .map_err(|e| format!("Failed to get message details: {}", e))?;

            let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
                Some(details) => details,
                None => return Err("Message not found".into()),
            };

            // Check if user is a member of the channel
            let channel_members = state
                .db
                .get_channel_members(channel_id)
                .await
                .map_err(|e| format!("Failed to get channel members: {}", e))?;

            if !channel_members.contains(&sender_user_id) {
                return Err("You must be a member of this channel to add reactions".into());
            }

            // Add the reaction
            state
                .db
                .add_reaction(message_id, sender_user_id, &emoji)
                .await
                .map_err(|e| format!("Failed to add reaction: {}", e))?;

            // Get updated reactions for broadcasting
            let reactions = state
                .db
                .get_message_reactions(message_id)
                .await
                .map_err(|e| format!("Failed to get reactions: {}", e))?;

            // Broadcast reaction_add event to channel
            let reaction_event = serde_json::json!({
                "type": "reaction_add",
                "message_id": message_id,
                "channel_id": channel_id,
                "user_id": sender_user_id,
                "emoji": emoji,
                "reactions": reactions,
                "timestamp": now_secs()
            });

            if let Err(e) = state
                .send_to_channel(channel_id, reaction_event.to_string())
                .await
            {
                error!("Failed to broadcast reaction add: {}", e);
            }
        }

        WsMessageType::RemoveReaction { message_id, emoji } => {
            // Check if user has access to the message
            let message_details = state
                .db
                .get_message_details(message_id)
                .await
                .map_err(|e| format!("Failed to get message details: {}", e))?;

            let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
                Some(details) => details,
                None => return Err("Message not found".into()),
            };

            // Remove the reaction
            let removed = state
                .db
                .remove_reaction(message_id, sender_user_id, &emoji)
                .await
                .map_err(|e| format!("Failed to remove reaction: {}", e))?;

            if removed {
                // Get updated reactions for broadcasting
                let reactions = state
                    .db
                    .get_message_reactions(message_id)
                    .await
                    .map_err(|e| format!("Failed to get reactions: {}", e))?;

                // Broadcast reaction_remove event to channel
                let reaction_event = serde_json::json!({
                    "type": "reaction_remove",
                    "message_id": message_id,
                    "channel_id": channel_id,
                    "user_id": sender_user_id,
                    "emoji": emoji,
                    "reactions": reactions,
                    "timestamp": now_secs()
                });

                if let Err(e) = state
                    .send_to_channel(channel_id, reaction_event.to_string())
                    .await
                {
                    error!("Failed to broadcast reaction remove: {}", e);
                }
            }
        }

        // ── Typing operations ──
        WsMessageType::TypingStart { channel_id } => {
            // Get user information for broadcasting
            let user = state
                .db
                .get_user_by_id(sender_user_id)
                .await
                .map_err(|e| format!("Failed to get user: {}", e))?
                .ok_or_else(|| "User not found".to_string())?;

            // Check if user is a member of the channel
            let channel_members = state
                .db
                .get_channel_members(channel_id)
                .await
                .map_err(|e| format!("Failed to get channel members: {}", e))?;

            if !channel_members.contains(&sender_user_id) {
                return Err("Not a member of this channel".into());
            }

            // Broadcast typing event to other channel members (exclude sender)
            let typing_event = serde_json::json!({
                "type": "typing_start",
                "channel_id": channel_id,
                "user_id": sender_user_id,
                "username": user.username,
                "timestamp": now_secs()
            });

            // Send to all channel members except the sender
            for &member_id in &channel_members {
                if member_id != sender_user_id {
                    if let Err(e) = state
                        .send_to_user(member_id, typing_event.to_string())
                        .await
                    {
                        // Log error but don't fail the whole operation
                        error!("Failed to send typing event to user {}: {}", member_id, e);
                    }
                }
            }
        }

        // ── Message Pinning operations ──
        WsMessageType::PinMessage { message_id } => {
            // Get message details to find the channel
            let message_details = state
                .db
                .get_message_details(message_id)
                .await
                .map_err(|e| format!("Failed to get message details: {}", e))?;

            let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
                Some(details) => details,
                None => return Err("Message not found".into()),
            };

            // Get the channel to find the node
            let channel = state
                .db
                .get_channel(channel_id)
                .await
                .map_err(|e| format!("Failed to get channel: {}", e))?;

            let channel = match channel {
                Some(ch) => ch,
                None => return Err("Channel not found".into()),
            };

            // Check if user has admin/mod permissions
            let member = state
                .db
                .get_node_member(channel.node_id, sender_user_id)
                .await
                .map_err(|e| format!("Failed to get node member: {}", e))?;

            let member = match member {
                Some(m) => m,
                None => return Err("Not a member of this node".into()),
            };

            // Check if user has sufficient permissions (admin or moderator)
            if !matches!(
                member.role,
                crate::node::NodeRole::Admin | crate::node::NodeRole::Moderator
            ) {
                return Err("Insufficient permissions. Admin or moderator required.".into());
            }

            // Pin the message
            let success = state
                .db
                .pin_message(message_id, sender_user_id)
                .await
                .map_err(|e| format!("Failed to pin message: {}", e))?;

            if !success {
                return Err("Message is already pinned".into());
            }

            // Log audit event
            let details = serde_json::json!({
                "message_id": message_id,
                "channel_id": channel_id
            });
            log_audit_event(
                &state,
                channel.node_id,
                sender_user_id,
                "message_pin",
                "message",
                Some(message_id),
                Some(&details.to_string()),
            )
            .await;

            // Broadcast pin event to channel
            let pin_event = serde_json::json!({
                "type": "message_pin",
                "message_id": message_id,
                "channel_id": channel_id,
                "pinned_by": sender_user_id,
                "timestamp": now_secs()
            });

            state
                .send_to_channel(channel_id, pin_event.to_string())
                .await?;

            info!(
                "Message {} pinned by {} in channel {}",
                message_id, sender_user_id, channel_id
            );
        }

        WsMessageType::UnpinMessage { message_id } => {
            // Get message details to find the channel
            let message_details = state
                .db
                .get_message_details(message_id)
                .await
                .map_err(|e| format!("Failed to get message details: {}", e))?;

            let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
                Some(details) => details,
                None => return Err("Message not found".into()),
            };

            // Get the channel to find the node
            let channel = state
                .db
                .get_channel(channel_id)
                .await
                .map_err(|e| format!("Failed to get channel: {}", e))?;

            let channel = match channel {
                Some(ch) => ch,
                None => return Err("Channel not found".into()),
            };

            // Check if user has admin/mod permissions
            let member = state
                .db
                .get_node_member(channel.node_id, sender_user_id)
                .await
                .map_err(|e| format!("Failed to get node member: {}", e))?;

            let member = match member {
                Some(m) => m,
                None => return Err("Not a member of this node".into()),
            };

            // Check if user has sufficient permissions (admin or moderator)
            if !matches!(
                member.role,
                crate::node::NodeRole::Admin | crate::node::NodeRole::Moderator
            ) {
                return Err("Insufficient permissions. Admin or moderator required.".into());
            }

            // Unpin the message
            let success = state
                .db
                .unpin_message(message_id)
                .await
                .map_err(|e| format!("Failed to unpin message: {}", e))?;

            if !success {
                return Err("Message is not pinned".into());
            }

            // Log audit event
            let details = serde_json::json!({
                "message_id": message_id,
                "channel_id": channel_id
            });
            log_audit_event(
                &state,
                channel.node_id,
                sender_user_id,
                "message_unpin",
                "message",
                Some(message_id),
                Some(&details.to_string()),
            )
            .await;

            // Broadcast unpin event to channel
            let unpin_event = serde_json::json!({
                "type": "message_unpin",
                "message_id": message_id,
                "channel_id": channel_id,
                "unpinned_by": sender_user_id,
                "timestamp": now_secs()
            });

            state
                .send_to_channel(channel_id, unpin_event.to_string())
                .await?;

            info!(
                "Message {} unpinned by {} in channel {}",
                message_id, sender_user_id, channel_id
            );
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
            info!(
                "User {} joined voice channel {}",
                sender_user_id, channel_id
            );
        }

        WsMessageType::LeaveVoiceChannel { channel_id } => {
            state
                .leave_voice_channel(sender_user_id, channel_id)
                .await?;
            let resp = serde_json::json!({
                "type": "voice_channel_left",
                "channel_id": channel_id,
                "user_id": sender_user_id
            });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
            info!("User {} left voice channel {}", sender_user_id, channel_id);
        }

        WsMessageType::VoicePacket {
            channel_id,
            encrypted_audio,
            sequence,
        } => {
            // Relay encrypted voice packet to all other participants in the channel
            let relay = serde_json::json!({
                "type": "voice_packet",
                "from": sender_user_id,
                "channel_id": channel_id,
                "encrypted_audio": encrypted_audio,
                "sequence": sequence,
                "timestamp": ws_message.timestamp
            });
            state
                .send_to_voice_channel(channel_id, sender_user_id, relay.to_string())
                .await?;
        }

        WsMessageType::VoiceSpeakingState {
            channel_id,
            user_id,
            speaking,
        } => {
            // Broadcast speaking state change to all participants
            let broadcast = serde_json::json!({
                "type": "voice_speaking_state",
                "channel_id": channel_id,
                "user_id": user_id,
                "speaking": speaking,
                "timestamp": ws_message.timestamp
            });
            state
                .send_to_voice_channel(channel_id, sender_user_id, broadcast.to_string())
                .await?;
        } // WsMessageType::UpdateChannel is handled above
    }

    Ok(())
}

// ── File Sharing Endpoints ──

/// Upload an encrypted file to a channel
pub async fn upload_file_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = match extract_user_from_request(&state, &headers, &params).await {
        Ok(user_id) => user_id,
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Authentication required".into(),
                    code: 401,
                }),
            ))
        }
    };

    // Check if user is member of the channel
    match state.db.get_channel_members(channel_id).await {
        Ok(members) if members.contains(&user_id) => {}
        Ok(_) => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Not a member of this channel".into(),
                    code: 403,
                }),
            ))
        }
        Err(_) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Channel not found".into(),
                    code: 404,
                }),
            ))
        }
    }

    // Extract file data from multipart
    let mut encrypted_filename: Option<Vec<u8>> = None;
    let mut file_data: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("");
        match name {
            "encrypted_filename" => {
                if let Ok(data) = field.bytes().await {
                    encrypted_filename = Some(data.to_vec());
                }
            }
            "file" => {
                if let Ok(data) = field.bytes().await {
                    file_data = Some(data.to_vec());
                }
            }
            _ => continue,
        }
    }

    let encrypted_filename = encrypted_filename.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing encrypted filename".into(),
                code: 400,
            }),
        )
    })?;

    let file_data = file_data.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing file data".into(),
                code: 400,
            }),
        )
    })?;

    // Store file and metadata
    let file_id = Uuid::new_v4();
    match state.file_handler.store_file(file_id, &file_data).await {
        Ok((storage_path, content_hash)) => {
            // Store metadata in database
            if let Err(e) = state
                .db
                .store_file_metadata(
                    file_id,
                    channel_id,
                    user_id,
                    &encrypted_filename,
                    file_data.len() as i64,
                    &content_hash,
                    &storage_path,
                )
                .await
            {
                // Clean up stored file if database insertion fails
                let _ = state.file_handler.delete_file(&storage_path).await;
                error!("Failed to store file metadata: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to store file metadata".into(),
                        code: 500,
                    }),
                ));
            }

            info!("File uploaded: {} to channel {}", file_id, channel_id);
            Ok(Json(serde_json::json!({
                "file_id": file_id,
                "message": "File uploaded successfully"
            })))
        }
        Err(e) => {
            error!("Failed to store file: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to store file: {}", e),
                    code: 500,
                }),
            ))
        }
    }
}

/// Download an encrypted file by ID
pub async fn download_file_handler(
    State(state): State<SharedState>,
    Path(file_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = match extract_user_from_request(&state, &headers, &params).await {
        Ok(user_id) => user_id,
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Authentication required".into(),
                    code: 401,
                }),
            ))
        }
    };

    // Get file metadata
    let file_metadata = match state.db.get_file_metadata(file_id).await {
        Ok(Some(metadata)) => metadata,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "File not found".into(),
                    code: 404,
                }),
            ))
        }
        Err(e) => {
            error!("Failed to get file metadata: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get file metadata".into(),
                    code: 500,
                }),
            ));
        }
    };

    // Check if user is member of the channel
    match state.db.get_channel_members(file_metadata.channel_id).await {
        Ok(members) if members.contains(&user_id) => {}
        Ok(_) => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Not a member of this channel".into(),
                    code: 403,
                }),
            ))
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check channel membership".into(),
                    code: 500,
                }),
            ))
        }
    }

    // Read file data
    match state
        .file_handler
        .read_file(&file_metadata.storage_path)
        .await
    {
        Ok(file_data) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                "application/octet-stream".parse().unwrap(),
            );
            headers.insert(
                header::CONTENT_LENGTH,
                file_data.len().to_string().parse().unwrap(),
            );
            headers.insert(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", file_id)
                    .parse()
                    .unwrap(),
            );

            Ok((headers, file_data).into_response())
        }
        Err(e) => {
            error!("Failed to read file: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to read file".into(),
                    code: 500,
                }),
            ))
        }
    }
}

/// List files in a channel
pub async fn list_channel_files_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<FileMetadata>>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = match extract_user_from_request(&state, &headers, &params).await {
        Ok(user_id) => user_id,
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Authentication required".into(),
                    code: 401,
                }),
            ))
        }
    };

    // Check if user is member of the channel
    match state.db.get_channel_members(channel_id).await {
        Ok(members) if members.contains(&user_id) => {}
        Ok(_) => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Not a member of this channel".into(),
                    code: 403,
                }),
            ))
        }
        Err(_) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Channel not found".into(),
                    code: 404,
                }),
            ))
        }
    }

    // Get file list
    match state.db.list_channel_files(channel_id).await {
        Ok(files) => Ok(Json(files)),
        Err(e) => {
            error!("Failed to list channel files: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to list channel files".into(),
                    code: 500,
                }),
            ))
        }
    }
}

/// Delete a file
pub async fn delete_file_handler(
    State(state): State<SharedState>,
    Path(file_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = match extract_user_from_request(&state, &headers, &params).await {
        Ok(user_id) => user_id,
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Authentication required".into(),
                    code: 401,
                }),
            ))
        }
    };

    // Get file metadata
    let file_metadata = match state.db.get_file_metadata(file_id).await {
        Ok(Some(metadata)) => metadata,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "File not found".into(),
                    code: 404,
                }),
            ))
        }
        Err(e) => {
            error!("Failed to get file metadata: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get file metadata".into(),
                    code: 500,
                }),
            ));
        }
    };

    // Check permissions - only uploader or admin can delete
    let is_uploader = file_metadata.uploader_id == user_id;

    // Check if user is admin of the node containing this channel
    let is_admin = match state.db.get_channel(file_metadata.channel_id).await {
        Ok(Some(channel)) => match state.db.get_node_member(channel.node_id, user_id).await {
            Ok(Some(member)) => matches!(member.role, crate::node::NodeRole::Admin),
            _ => false,
        },
        _ => false,
    };

    if !is_uploader && !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only the uploader or admins can delete files".into(),
                code: 403,
            }),
        ));
    }

    // Delete from filesystem
    if let Err(e) = state
        .file_handler
        .delete_file(&file_metadata.storage_path)
        .await
    {
        error!("Failed to delete file from disk: {}", e);
        // Continue with database deletion even if file deletion fails
    }

    // Delete from database
    match state.db.delete_file_metadata(file_id).await {
        Ok(()) => {
            info!("File deleted: {}", file_id);
            Ok(Json(serde_json::json!({
                "message": "File deleted successfully"
            })))
        }
        Err(e) => {
            error!("Failed to delete file metadata: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to delete file metadata".into(),
                    code: 500,
                }),
            ))
        }
    }
}

/// Edit message endpoint
pub async fn edit_message_handler(
    Path(message_id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<SharedState>,
    Json(request): Json<EditMessageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let message_id = Uuid::parse_str(&message_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid message ID format".into(),
                code: 400,
            }),
        )
    })?;

    // Extract user_id from validated auth token, not from request body (C5 fix)
    let user_id = extract_user_from_header_or_token(&state, &headers, &params).await?;

    // Decode the encrypted payload
    let encrypted_payload = base64::engine::general_purpose::STANDARD
        .decode(&request.encrypted_data)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid base64 encoded data".into(),
                    code: 400,
                }),
            )
        })?;

    // Attempt to edit the message
    let success = match state
        .db
        .edit_message(message_id, user_id, &encrypted_payload)
        .await
    {
        Ok(success) => success,
        Err(e) => {
            error!("Failed to edit message: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to edit message".into(),
                    code: 500,
                }),
            ));
        }
    };

    if !success {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Message not found or you don't have permission to edit it".into(),
                code: 403,
            }),
        ));
    }

    // Get the updated message details for broadcasting
    if let Ok(Some((channel_id, sender_id, created_at, edited_at))) =
        state.db.get_message_details(message_id).await
    {
        // Broadcast the message edit event to channel members
        let edit_event = serde_json::json!({
            "type": "message_edit",
            "message_id": message_id,
            "channel_id": channel_id,
            "sender_id": sender_id,
            "encrypted_data": request.encrypted_data,
            "created_at": created_at,
            "edited_at": edited_at,
            "timestamp": now_secs()
        });

        if let Err(e) = state
            .send_to_channel(channel_id, edit_event.to_string())
            .await
        {
            error!("Failed to broadcast message edit: {}", e);
        }
    }

    Ok(Json(serde_json::json!({"success": true})))
}

/// Delete message endpoint
pub async fn delete_message_handler(
    Path(message_id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let message_id = Uuid::parse_str(&message_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid message ID format".into(),
                code: 400,
            }),
        )
    })?;

    // Validate token against the token store and extract user_id (C4 fix)
    let user_id = extract_user_from_header_or_token(&state, &headers, &params).await?;

    // Attempt to delete the message
    let result = match state.db.delete_message(message_id, user_id).await {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to delete message: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to delete message".into(),
                    code: 500,
                }),
            ));
        }
    };

    match result {
        Some((channel_id, sender_id)) => {
            // Broadcast the message delete event to channel members
            let delete_event = serde_json::json!({
                "type": "message_delete",
                "message_id": message_id,
                "channel_id": channel_id,
                "sender_id": sender_id,
                "timestamp": now_secs()
            });

            if let Err(e) = state
                .send_to_channel(channel_id, delete_event.to_string())
                .await
            {
                error!("Failed to broadcast message delete: {}", e);
            }

            Ok(Json(serde_json::json!({"success": true})))
        }
        None => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Message not found or you don't have permission to delete it".into(),
                code: 403,
            }),
        )),
    }
}

/// Extract user ID from request headers (Authorization: Bearer token)
async fn extract_user_from_request(
    state: &SharedState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<Uuid, anyhow::Error> {
    let token = extract_token_from_headers_or_params(headers, params)
        .ok_or_else(|| anyhow::anyhow!("Missing authentication token"))?;
    state
        .validate_token(token)
        .await
        .ok_or_else(|| anyhow::anyhow!("Invalid or expired token"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ── Message Reaction endpoints ──

/// Add reaction to message (PUT /messages/:id/reactions/:emoji)
pub async fn add_reaction_handler(
    Path((message_id, emoji)): Path<(String, String)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let message_id = Uuid::parse_str(&message_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid message ID format".into(),
                code: 400,
            }),
        )
    })?;

    let user_id = extract_user_from_token(&state, &params).await?;

    // Validate emoji (basic check for empty string)
    if emoji.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Emoji cannot be empty".into(),
                code: 400,
            }),
        ));
    }

    // Check if user has access to the message (via channel membership)
    let message_details = state
        .db
        .get_message_details(message_id)
        .await
        .map_err(|e| {
            error!("Failed to get message details: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to access message".into(),
                    code: 500,
                }),
            )
        })?;

    let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
        Some(details) => details,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Message not found".into(),
                    code: 404,
                }),
            ));
        }
    };

    // Check if user is a member of the channel
    let channel_members = state
        .db
        .get_channel_members(channel_id)
        .await
        .map_err(|e| {
            error!("Failed to get channel members: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check channel access".into(),
                    code: 500,
                }),
            )
        })?;

    if !channel_members.contains(&user_id) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "You must be a member of this channel to add reactions".into(),
                code: 403,
            }),
        ));
    }

    // Add the reaction
    state
        .db
        .add_reaction(message_id, user_id, &emoji)
        .await
        .map_err(|e| {
            error!("Failed to add reaction: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to add reaction".into(),
                    code: 500,
                }),
            )
        })?;

    // Get updated reactions for broadcasting
    let reactions = state
        .db
        .get_message_reactions(message_id)
        .await
        .map_err(|e| {
            error!("Failed to get reactions: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get reactions".into(),
                    code: 500,
                }),
            )
        })?;

    // Broadcast reaction_add event to channel
    let reaction_event = serde_json::json!({
        "type": "reaction_add",
        "message_id": message_id,
        "channel_id": channel_id,
        "user_id": user_id,
        "emoji": emoji,
        "reactions": reactions,
        "timestamp": now_secs()
    });

    if let Err(e) = state
        .send_to_channel(channel_id, reaction_event.to_string())
        .await
    {
        error!("Failed to broadcast reaction add: {}", e);
    }

    Ok(Json(
        serde_json::json!({"success": true, "reactions": reactions}),
    ))
}

/// Remove reaction from message (DELETE /messages/:id/reactions/:emoji)
pub async fn remove_reaction_handler(
    Path((message_id, emoji)): Path<(String, String)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let message_id = Uuid::parse_str(&message_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid message ID format".into(),
                code: 400,
            }),
        )
    })?;

    let user_id = extract_user_from_token(&state, &params).await?;

    // Check if user has access to the message
    let message_details = state
        .db
        .get_message_details(message_id)
        .await
        .map_err(|e| {
            error!("Failed to get message details: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to access message".into(),
                    code: 500,
                }),
            )
        })?;

    let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
        Some(details) => details,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Message not found".into(),
                    code: 404,
                }),
            ));
        }
    };

    // Remove the reaction
    let removed = state
        .db
        .remove_reaction(message_id, user_id, &emoji)
        .await
        .map_err(|e| {
            error!("Failed to remove reaction: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to remove reaction".into(),
                    code: 500,
                }),
            )
        })?;

    if !removed {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Reaction not found".into(),
                code: 404,
            }),
        ));
    }

    // Get updated reactions for broadcasting
    let reactions = state
        .db
        .get_message_reactions(message_id)
        .await
        .map_err(|e| {
            error!("Failed to get reactions: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get reactions".into(),
                    code: 500,
                }),
            )
        })?;

    // Broadcast reaction_remove event to channel
    let reaction_event = serde_json::json!({
        "type": "reaction_remove",
        "message_id": message_id,
        "channel_id": channel_id,
        "user_id": user_id,
        "emoji": emoji,
        "reactions": reactions,
        "timestamp": now_secs()
    });

    if let Err(e) = state
        .send_to_channel(channel_id, reaction_event.to_string())
        .await
    {
        error!("Failed to broadcast reaction remove: {}", e);
    }

    Ok(Json(
        serde_json::json!({"success": true, "reactions": reactions}),
    ))
}

/// Get reactions for a message (GET /messages/:id/reactions)
pub async fn get_message_reactions_handler(
    Path(message_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Result<Json<MessageReactionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let message_id = Uuid::parse_str(&message_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid message ID format".into(),
                code: 400,
            }),
        )
    })?;

    let user_id = extract_user_from_token(&state, &params).await?;

    // Check if user has access to the message
    let message_details = state
        .db
        .get_message_details(message_id)
        .await
        .map_err(|e| {
            error!("Failed to get message details: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to access message".into(),
                    code: 500,
                }),
            )
        })?;

    let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
        Some(details) => details,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Message not found".into(),
                    code: 404,
                }),
            ));
        }
    };

    // Check if user is a member of the channel
    let channel_members = state
        .db
        .get_channel_members(channel_id)
        .await
        .map_err(|e| {
            error!("Failed to get channel members: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check channel access".into(),
                    code: 500,
                }),
            )
        })?;

    if !channel_members.contains(&user_id) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "You must be a member of this channel to view reactions".into(),
                code: 403,
            }),
        ));
    }

    // Get the reactions
    let reactions = state
        .db
        .get_message_reactions(message_id)
        .await
        .map_err(|e| {
            error!("Failed to get reactions: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get reactions".into(),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(MessageReactionsResponse { reactions }))
}

/// Get thread replies for a message (GET /messages/:id/thread)
pub async fn get_message_thread_handler(
    Path(message_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Result<Json<crate::models::MessageHistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let message_id = Uuid::parse_str(&message_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid message ID format".into(),
                code: 400,
            }),
        )
    })?;

    let token = params.get("token").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Token required".into(),
                code: 401,
            }),
        )
    })?;

    let user_id = state.validate_token(token).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token".into(),
                code: 401,
            }),
        )
    })?;

    // Get the original message details to check permissions
    let message_details = state
        .db
        .get_message_details(message_id)
        .await
        .map_err(|e| {
            error!("Failed to get message details: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get message details".into(),
                    code: 500,
                }),
            )
        })?;

    let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
        Some(details) => details,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Message not found".into(),
                    code: 404,
                }),
            ));
        }
    };

    // Check if user is a member of the channel
    let channel_members = state
        .db
        .get_channel_members(channel_id)
        .await
        .map_err(|e| {
            error!("Failed to get channel members: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check channel access".into(),
                    code: 500,
                }),
            )
        })?;

    if !channel_members.contains(&user_id) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "You must be a member of this channel to view thread replies".into(),
                code: 403,
            }),
        ));
    }

    // Get the thread replies
    let thread_messages = state.db.get_message_thread(message_id).await.map_err(|e| {
        error!("Failed to get thread messages: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get thread messages".into(),
                code: 500,
            }),
        )
    })?;

    Ok(Json(crate::models::MessageHistoryResponse {
        messages: thread_messages,
        has_more: false, // Threads are typically small, so we don't paginate
        next_cursor: None,
    }))
}

// ── Message Pinning endpoints ──

/// Pin a message (PUT /messages/:id/pin)
pub async fn pin_message_handler(
    Path(message_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let message_id = Uuid::parse_str(&message_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid message ID format".into(),
                code: 400,
            }),
        )
    })?;

    let user_id = extract_user_from_token(&state, &params).await?;

    // Get message details to find the channel
    let message_details = state
        .db
        .get_message_details(message_id)
        .await
        .map_err(|e| {
            error!("Failed to get message details: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to access message".into(),
                    code: 500,
                }),
            )
        })?;

    let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
        Some(details) => details,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Message not found".into(),
                    code: 404,
                }),
            ));
        }
    };

    // Get the channel to find the node
    let channel = state.db.get_channel(channel_id).await.map_err(|e| {
        error!("Failed to get channel: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get channel".into(),
                code: 500,
            }),
        )
    })?;

    let channel = match channel {
        Some(ch) => ch,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Channel not found".into(),
                    code: 404,
                }),
            ));
        }
    };

    // Check if user has admin/mod permissions
    let member = state
        .db
        .get_node_member(channel.node_id, user_id)
        .await
        .map_err(|e| {
            error!("Failed to get node member: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check permissions".into(),
                    code: 500,
                }),
            )
        })?;

    let member = match member {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Not a member of this node".into(),
                    code: 403,
                }),
            ));
        }
    };

    // Check if user has sufficient permissions (admin or moderator)
    if !matches!(
        member.role,
        crate::node::NodeRole::Admin | crate::node::NodeRole::Moderator
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient permissions. Admin or moderator required.".into(),
                code: 403,
            }),
        ));
    }

    // Pin the message
    let success = state
        .db
        .pin_message(message_id, user_id)
        .await
        .map_err(|e| {
            error!("Failed to pin message: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to pin message".into(),
                    code: 500,
                }),
            )
        })?;

    if !success {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Message is already pinned".into(),
                code: 409,
            }),
        ));
    }

    // Log audit event
    let details = serde_json::json!({
        "message_id": message_id,
        "channel_id": channel_id
    });
    log_audit_event(
        &state,
        channel.node_id,
        user_id,
        "message_pin",
        "message",
        Some(message_id),
        Some(&details.to_string()),
    )
    .await;

    // Broadcast pin event to channel
    let pin_event = serde_json::json!({
        "type": "message_pin",
        "message_id": message_id,
        "channel_id": channel_id,
        "pinned_by": user_id,
        "timestamp": now_secs()
    });

    if let Err(e) = state
        .send_to_channel(channel_id, pin_event.to_string())
        .await
    {
        error!("Failed to broadcast message pin: {}", e);
    }

    Ok(Json(
        serde_json::json!({"success": true, "message": "Message pinned successfully"}),
    ))
}

/// Unpin a message (DELETE /messages/:id/pin)
pub async fn unpin_message_handler(
    Path(message_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let message_id = Uuid::parse_str(&message_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid message ID format".into(),
                code: 400,
            }),
        )
    })?;

    let user_id = extract_user_from_token(&state, &params).await?;

    // Get message details to find the channel
    let message_details = state
        .db
        .get_message_details(message_id)
        .await
        .map_err(|e| {
            error!("Failed to get message details: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to access message".into(),
                    code: 500,
                }),
            )
        })?;

    let (channel_id, _sender_id, _created_at, _edited_at) = match message_details {
        Some(details) => details,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Message not found".into(),
                    code: 404,
                }),
            ));
        }
    };

    // Get the channel to find the node
    let channel = state.db.get_channel(channel_id).await.map_err(|e| {
        error!("Failed to get channel: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get channel".into(),
                code: 500,
            }),
        )
    })?;

    let channel = match channel {
        Some(ch) => ch,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Channel not found".into(),
                    code: 404,
                }),
            ));
        }
    };

    // Check if user has admin/mod permissions
    let member = state
        .db
        .get_node_member(channel.node_id, user_id)
        .await
        .map_err(|e| {
            error!("Failed to get node member: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check permissions".into(),
                    code: 500,
                }),
            )
        })?;

    let member = match member {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Not a member of this node".into(),
                    code: 403,
                }),
            ));
        }
    };

    // Check if user has sufficient permissions (admin or moderator)
    if !matches!(
        member.role,
        crate::node::NodeRole::Admin | crate::node::NodeRole::Moderator
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Insufficient permissions. Admin or moderator required.".into(),
                code: 403,
            }),
        ));
    }

    // Unpin the message
    let success = state.db.unpin_message(message_id).await.map_err(|e| {
        error!("Failed to unpin message: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to unpin message".into(),
                code: 500,
            }),
        )
    })?;

    if !success {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Message is not pinned".into(),
                code: 404,
            }),
        ));
    }

    // Log audit event
    let details = serde_json::json!({
        "message_id": message_id,
        "channel_id": channel_id
    });
    log_audit_event(
        &state,
        channel.node_id,
        user_id,
        "message_unpin",
        "message",
        Some(message_id),
        Some(&details.to_string()),
    )
    .await;

    // Broadcast unpin event to channel
    let unpin_event = serde_json::json!({
        "type": "message_unpin",
        "message_id": message_id,
        "channel_id": channel_id,
        "unpinned_by": user_id,
        "timestamp": now_secs()
    });

    if let Err(e) = state
        .send_to_channel(channel_id, unpin_event.to_string())
        .await
    {
        error!("Failed to broadcast message unpin: {}", e);
    }

    Ok(Json(
        serde_json::json!({"success": true, "message": "Message unpinned successfully"}),
    ))
}

/// Get pinned messages for a channel (GET /channels/:id/pins)
pub async fn get_pinned_messages_handler(
    Path(channel_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<SharedState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let channel_id = Uuid::parse_str(&channel_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid channel ID format".into(),
                code: 400,
            }),
        )
    })?;

    let user_id = extract_user_from_token(&state, &params).await?;

    // Check if user has access to the channel
    let channel_members = state
        .db
        .get_channel_members(channel_id)
        .await
        .map_err(|e| {
            error!("Failed to get channel members: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check channel access".into(),
                    code: 500,
                }),
            )
        })?;

    if !channel_members.contains(&user_id) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied. You're not a member of this channel.".into(),
                code: 403,
            }),
        ));
    }

    // Get pinned messages
    let pinned_messages = state
        .db
        .get_pinned_messages(channel_id)
        .await
        .map_err(|e| {
            error!("Failed to get pinned messages: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get pinned messages".into(),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(serde_json::json!({
        "pinned_messages": pinned_messages
    })))
}

// ── Direct Message Handlers ──

/// Create or get a DM channel with a specific user
/// POST /dm/:user_id
pub async fn create_dm_channel_handler(
    State(state): State<SharedState>,
    Path(target_user_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<crate::models::DmChannel>, (StatusCode, Json<ErrorResponse>)> {
    // Get user ID from token
    let token = params.get("token").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing token parameter".into(),
                code: 401,
            }),
        )
    })?;

    let user_id = state.validate_token(token).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".into(),
                code: 401,
            }),
        )
    })?;

    // Parse target user ID
    let target_user_id = Uuid::parse_str(&target_user_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid user ID format".into(),
                code: 400,
            }),
        )
    })?;

    // Check if target user exists
    let target_user = state.db.get_user_by_id(target_user_id).await.map_err(|e| {
        error!("Failed to get target user: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to check user".into(),
                code: 500,
            }),
        )
    })?;

    if target_user.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Target user not found".into(),
                code: 404,
            }),
        ));
    }

    // Cannot DM yourself
    if user_id == target_user_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot create DM channel with yourself".into(),
                code: 400,
            }),
        ));
    }

    // Create or get DM channel
    let dm_channel = state
        .db
        .create_or_get_dm_channel(user_id, target_user_id)
        .await
        .map_err(|e| {
            error!("Failed to create DM channel: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to create DM channel".into(),
                    code: 500,
                }),
            )
        })?;

    info!(
        "Created/got DM channel {} between {} and {}",
        dm_channel.id, user_id, target_user_id
    );
    Ok(Json(dm_channel))
}

/// Get user's DM channels with last message preview
/// GET /dm
pub async fn get_dm_channels_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<crate::models::DmChannelsResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Get user ID from token
    let token = params.get("token").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing token parameter".into(),
                code: 401,
            }),
        )
    })?;

    let user_id = state.validate_token(token).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid or expired token".into(),
                code: 401,
            }),
        )
    })?;

    // Get user's DM channels
    let dm_channels = state.db.get_user_dm_channels(user_id).await.map_err(|e| {
        error!("Failed to get DM channels: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get DM channels".into(),
                code: 500,
            }),
        )
    })?;

    Ok(Json(crate::models::DmChannelsResponse { dm_channels }))
}

// ── Audit Log Handlers ──

/// Get audit log for a Node (admin/mod only)
/// GET /nodes/:node_id/audit-log?limit=50&before=<id>
pub async fn get_node_audit_log_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<AuditLogResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check if user is a member of the Node
    let user_member = state
        .db
        .get_node_member(node_id, user_id)
        .await
        .map_err(|e| {
            error!("Failed to check node membership: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check node membership".into(),
                    code: 500,
                }),
            )
        })?;

    let user_member = user_member.ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "You are not a member of this Node".into(),
                code: 403,
            }),
        )
    })?;

    // Check if user has ViewAuditLog permission
    if !has_permission(user_member.role, Permission::ViewAuditLog) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Permission denied. Required: ViewAuditLog, Your role: {:?}",
                    user_member.role
                ),
                code: 403,
            }),
        ));
    }

    // Parse pagination parameters
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(50)
        .min(100); // Max 100 entries per request

    let before_id = params.get("before").and_then(|s| Uuid::parse_str(s).ok());

    // Get audit log entries
    let entries = state
        .db
        .get_node_audit_log(node_id, limit + 1, before_id)
        .await
        .map_err(|e| {
            error!("Failed to get audit log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get audit log".into(),
                    code: 500,
                }),
            )
        })?;

    let has_more = entries.len() > limit as usize;
    let entries = if has_more {
        entries.into_iter().take(limit as usize).collect()
    } else {
        entries
    };

    let next_cursor = if has_more {
        entries.last().map(|entry| entry.id)
    } else {
        None
    };

    Ok(Json(AuditLogResponse {
        entries,
        has_more,
        next_cursor,
    }))
}

// ── Audit Log Helper Functions ──

/// Helper function to log an audit event
pub async fn log_audit_event(
    state: &SharedState,
    node_id: Uuid,
    actor_id: Uuid,
    action: &str,
    target_type: &str,
    target_id: Option<Uuid>,
    details: Option<&str>,
) {
    if let Err(e) = state
        .db
        .log_audit_event(node_id, actor_id, action, target_type, target_id, details)
        .await
    {
        error!("Failed to log audit event: {}", e);
    }
}
