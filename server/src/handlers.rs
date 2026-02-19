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

/// Get presence status for all members of a node
pub async fn get_node_presence_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Must be a member of the node
    if !state
        .is_node_member(user_id, node_id)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Must be a member of the node".into(),
                code: 403,
            }),
        ));
    }

    match state.get_node_presence(node_id).await {
        Ok(presence) => Ok(Json(serde_json::json!({ "members": presence }))),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get presence: {}", err),
                code: 500,
            }),
        )),
    }
}

/// Health check endpoint
pub async fn health_handler(State(state): State<SharedState>) -> Json<HealthResponse> {
    // Database connectivity check
    let database_ok = state.db.count_users().await.is_ok();

    // WebSocket connection count
    let websocket_connections = state.connections.read().await.len();

    // Memory usage (RSS from /proc/self/statm on Linux, fallback 0)
    let memory_usage_bytes = {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/self/statm")
                .ok()
                .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
                .map(|pages| pages * 4096)
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0u64
        }
    };

    let build_hash = state
        .build_verification
        .server_build_info
        .build_hash
        .clone();

    Json(HealthResponse {
        status: if database_ok { "healthy" } else { "degraded" }.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.uptime(),
        build_hash,
        database_ok,
        websocket_connections,
        memory_usage_bytes,
    })
}

/// Extract client IP from X-Forwarded-For header or fall back to "unknown"
fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// User registration endpoint — keypair-only, no username at relay level
pub async fn register_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    // IP-based rate limiting: max 3 registrations per hour per IP
    let client_ip = extract_client_ip(&headers);
    if let Err(err) = state
        .rate_limiter
        .check_ip(&client_ip, crate::rate_limit::ActionType::Registration)
        .await
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!(
                    "Rate limit exceeded: {}. Retry after {}s",
                    err.message, err.retry_after_secs
                ),
                code: 429,
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

    let display_name = request.display_name.clone();
    match state
        .register_user(request.public_key, request.password)
        .await
    {
        Ok(user_id) => {
            // Set display name in user profile if provided
            if let Some(ref name) = display_name {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    let _ = state
                        .update_user_profile(user_id, Some(trimmed), None, None, None)
                        .await;
                }
            }
            info!("Registered new user: {}", user_id);

            // Log audit event for registration (relay-level, use nil node_id)
            let _ = state
                .db
                .log_audit_event_with_ip(
                    Uuid::nil(),
                    user_id,
                    "user_register",
                    "user",
                    Some(user_id),
                    Some(&serde_json::json!({"display_name": display_name}).to_string()),
                    Some(&client_ip),
                )
                .await;

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

/// User authentication endpoint — authenticate by public_key or public_key_hash + password
pub async fn auth_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    // IP-based rate limiting: max 5 auth attempts per minute per IP
    let client_ip = extract_client_ip(&headers);
    if let Err(err) = state
        .rate_limiter
        .check_ip(&client_ip, crate::rate_limit::ActionType::AuthAttempt)
        .await
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!(
                    "Rate limit exceeded: {}. Retry after {}s",
                    err.message, err.retry_after_secs
                ),
                code: 429,
            }),
        ));
    }

    // Relay-level build hash enforcement
    let client_build_hash = headers.get("X-Build-Hash").and_then(|v| v.to_str().ok());
    if let Err(msg) = state.check_relay_build_hash(client_build_hash).await {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: msg,
                code: 403,
            }),
        ));
    }

    // Determine the public_key_hash to authenticate with
    let public_key_hash = if let Some(ref pkh) = request.public_key_hash {
        pkh.clone()
    } else if let Some(ref pk) = request.public_key {
        crate::db::compute_public_key_hash(pk)
    } else if !request.username.is_empty() {
        // Backward compat: treat username as public_key for old clients
        // (they used to send the public key as "username" in some flows)
        crate::db::compute_public_key_hash(&request.username)
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Must provide public_key or public_key_hash".into(),
                code: 400,
            }),
        ));
    };

    match state
        .authenticate_user(public_key_hash, request.password)
        .await
    {
        Ok(auth_token) => {
            info!("User authenticated: {}", auth_token.user_id);

            // Log audit event for login
            let _ = state
                .db
                .log_audit_event_with_ip(
                    Uuid::nil(),
                    auth_token.user_id,
                    "user_login",
                    "user",
                    Some(auth_token.user_id),
                    None,
                    Some(&client_ip),
                )
                .await;

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

/// List nodes the authenticated user belongs to
pub async fn list_user_nodes_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.db.get_user_nodes(user_id).await {
        Ok(nodes) => Ok(Json(
            nodes
                .into_iter()
                .map(|n| {
                    serde_json::json!({
                        "id": n.id,
                        "name": n.name,
                        "owner_id": n.owner_id,
                        "description": n.description,
                        "created_at": n.created_at,
                        "icon_hash": n.icon_hash,
                    })
                })
                .collect(),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to list nodes: {}", e),
                code: 500,
            }),
        )),
    }
}

/// Create a channel in a Node
pub async fn create_channel_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let name = request
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("general");

    match state.db.create_channel(name, node_id, user_id).await {
        Ok(channel) => Ok(Json(serde_json::json!({
            "id": channel.id,
            "name": channel.name,
            "node_id": channel.node_id,
            "created_at": channel.created_at,
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to create channel: {}", e),
                code: 500,
            }),
        )),
    }
}

/// List channels in a Node
pub async fn list_node_channels_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id = extract_user_from_token(&state, &params).await?;

    match state.db.get_node_channels(node_id).await {
        Ok(channels) => {
            let mut result = Vec::new();
            for ch in channels {
                let unread_count = state
                    .db
                    .get_unread_count(_user_id, ch.id)
                    .await
                    .unwrap_or(0);
                result.push(serde_json::json!({
                    "id": ch.id,
                    "name": ch.name,
                    "node_id": ch.node_id,
                    "created_at": ch.created_at,
                    "unread_count": unread_count,
                }));
            }
            Ok(Json(result))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to list channels: {}", e),
                code: 500,
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

/// Request body for marking a channel as read
#[derive(Debug, serde::Deserialize)]
pub struct MarkChannelReadRequest {
    pub message_id: Uuid,
}

/// Optional body for join_node (device fingerprint hash)
#[derive(Debug, serde::Deserialize, Default)]
pub struct JoinNodeRequest {
    /// Optional device fingerprint hash for ban enforcement
    #[serde(default)]
    pub device_fingerprint_hash: Option<String>,
}

/// Join a Node
pub async fn join_node_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: Option<Json<JoinNodeRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;
    let fingerprint_hash = body.and_then(|b| b.0.device_fingerprint_hash);

    // Check build hash allowlist
    let client_build_hash = headers
        .get("X-Build-Hash")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !state
        .db
        .is_build_hash_allowed(node_id, client_build_hash)
        .await
        .unwrap_or(true)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Build not allowed by Node admin".into(),
                code: 403,
            }),
        ));
    }

    // Check device fingerprint ban before joining
    if let Some(ref fph) = fingerprint_hash {
        let device_banned = state
            .db
            .is_device_banned_from_node(node_id, fph)
            .await
            .unwrap_or(false);
        if device_banned {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Your device is banned from this node".into(),
                    code: 403,
                }),
            ));
        }
    }

    match state.join_node(user_id, node_id).await {
        Ok(()) => {
            // Store device fingerprint hash if provided
            if let Some(ref fph) = fingerprint_hash {
                let _ = state
                    .db
                    .set_member_device_fingerprint(node_id, user_id, fph)
                    .await;
            }
            Ok(Json(
                serde_json::json!({ "status": "joined", "node_id": node_id }),
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
    body: Option<Json<CreateInviteRequest>>,
) -> Result<Json<CreateInviteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;
    let request = body.map(|b| b.0).unwrap_or(CreateInviteRequest {
        max_uses: None,
        expires_in_hours: None,
    });

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

// ── Node ban endpoints ──

/// Ban a user from a Node (POST /nodes/:id/bans)
pub async fn ban_user_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::BanUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check permissions (admin/mod only)
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
        Some(m) => {
            if !has_permission(m.role, Permission::KickMembers) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Insufficient permissions to ban users".into(),
                        code: 403,
                    }),
                ));
            }
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be a member of the node".into(),
                    code: 403,
                }),
            ));
        }
    }

    let reason_bytes = request
        .reason_encrypted
        .as_ref()
        .and_then(|r| base64::engine::general_purpose::STANDARD.decode(r).ok());

    state
        .db
        .ban_from_node_with_fingerprint(
            node_id,
            &request.public_key_hash,
            user_id,
            reason_bytes.as_deref(),
            request.expires_at,
            request.device_fingerprint_hash.as_deref(),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to ban user: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Also remove the banned user from the node if they're a member
    if let Ok(Some(banned_user)) = state
        .db
        .get_user_by_public_key_hash(&request.public_key_hash)
        .await
    {
        let _ = state.db.remove_node_member(node_id, banned_user.id).await;
    }

    info!(
        "User with public_key_hash {} banned from node {} by {}",
        &request.public_key_hash[..16.min(request.public_key_hash.len())],
        node_id,
        user_id
    );

    // Log audit event for ban
    let details = serde_json::json!({
        "public_key_hash": request.public_key_hash,
        "expires_at": request.expires_at,
    });
    log_audit_event(
        &state,
        node_id,
        user_id,
        "user_ban",
        "user",
        None,
        Some(&details.to_string()),
    )
    .await;

    Ok(Json(serde_json::json!({
        "status": "banned",
        "node_id": node_id,
        "public_key_hash": request.public_key_hash,
    })))
}

/// Unban a user from a Node (DELETE /nodes/:id/bans)
pub async fn unban_user_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::UnbanUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check permissions
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
        Some(m) => {
            if !has_permission(m.role, Permission::KickMembers) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Insufficient permissions to unban users".into(),
                        code: 403,
                    }),
                ));
            }
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be a member of the node".into(),
                    code: 403,
                }),
            ));
        }
    }

    let removed = state
        .db
        .unban_from_node(node_id, &request.public_key_hash)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to unban user: {}", e),
                    code: 500,
                }),
            )
        })?;

    if removed {
        // Log audit event for unban
        let details = serde_json::json!({"public_key_hash": request.public_key_hash});
        log_audit_event(
            &state,
            node_id,
            user_id,
            "user_unban",
            "user",
            None,
            Some(&details.to_string()),
        )
        .await;

        Ok(Json(serde_json::json!({
            "status": "unbanned",
            "node_id": node_id,
            "public_key_hash": request.public_key_hash,
        })))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Ban not found".into(),
                code: 404,
            }),
        ))
    }
}

/// Check if a user/device is banned from a Node (GET /nodes/:id/ban-check)
pub async fn ban_check_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id = extract_user_from_token(&state, &params).await?;

    let public_key_hash = params.get("public_key_hash");
    let device_fingerprint_hash = params.get("device_fingerprint_hash");

    if public_key_hash.is_none() && device_fingerprint_hash.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Must provide public_key_hash and/or device_fingerprint_hash query param"
                    .into(),
                code: 400,
            }),
        ));
    }

    let key_banned = if let Some(pkh) = public_key_hash {
        state
            .db
            .is_banned_from_node(node_id, pkh)
            .await
            .unwrap_or(false)
    } else {
        false
    };

    let device_banned = if let Some(fph) = device_fingerprint_hash {
        state
            .db
            .is_device_banned_from_node(node_id, fph)
            .await
            .unwrap_or(false)
    } else {
        false
    };

    Ok(Json(serde_json::json!({
        "banned": key_banned || device_banned,
        "key_banned": key_banned,
        "device_banned": device_banned,
    })))
}

/// List bans for a Node (GET /nodes/:id/bans)
pub async fn list_bans_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<crate::models::NodeBansResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check membership
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
        Some(m) => {
            if !has_permission(m.role, Permission::KickMembers) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Insufficient permissions to view bans".into(),
                        code: 403,
                    }),
                ));
            }
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be a member of the node".into(),
                    code: 403,
                }),
            ));
        }
    }

    let bans = state.db.get_node_bans(node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get bans: {}", e),
                code: 500,
            }),
        )
    })?;

    Ok(Json(crate::models::NodeBansResponse { bans }))
}

// ── Build hash allowlist endpoints ──

/// List allowed build hashes for a Node (GET /nodes/:id/build-allowlist)
pub async fn get_build_allowlist_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check admin permission
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
        Some(m) => {
            if !has_permission(m.role, Permission::ManageNode) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Insufficient permissions. Admin required.".into(),
                        code: 403,
                    }),
                ));
            }
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be a member of the node".into(),
                    code: 403,
                }),
            ));
        }
    }

    let entries = state
        .db
        .get_build_hash_allowlist(node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get build allowlist: {}", e),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(serde_json::json!({ "allowlist": entries })))
}

/// Set the full build hash allowlist for a Node (PUT /nodes/:id/build-allowlist)
pub async fn set_build_allowlist_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<Vec<crate::models::BuildHashAllowlistInput>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

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
        Some(m) => {
            if !has_permission(m.role, Permission::ManageNode) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Insufficient permissions. Admin required.".into(),
                        code: 403,
                    }),
                ));
            }
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be a member of the node".into(),
                    code: 403,
                }),
            ));
        }
    }

    state
        .db
        .set_build_hash_allowlist(node_id, user_id, &request)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to set build allowlist: {}", e),
                    code: 500,
                }),
            )
        })?;

    info!(
        "Build allowlist updated for node {} by {} ({} entries)",
        node_id,
        user_id,
        request.len()
    );

    Ok(Json(serde_json::json!({
        "status": "updated",
        "count": request.len()
    })))
}

/// Add a build hash to the allowlist (POST /nodes/:id/build-allowlist)
pub async fn add_build_allowlist_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::BuildHashAllowlistInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

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
        Some(m) => {
            if !has_permission(m.role, Permission::ManageNode) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Insufficient permissions. Admin required.".into(),
                        code: 403,
                    }),
                ));
            }
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be a member of the node".into(),
                    code: 403,
                }),
            ));
        }
    }

    let added = state
        .db
        .add_build_hash_to_allowlist(
            node_id,
            &request.build_hash,
            user_id,
            request.label.as_deref(),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to add build hash: {}", e),
                    code: 500,
                }),
            )
        })?;

    if added {
        info!(
            "Build hash {} added to allowlist for node {} by {}",
            request.build_hash, node_id, user_id
        );
        Ok(Json(serde_json::json!({
            "status": "added",
            "build_hash": request.build_hash
        })))
    } else {
        Ok(Json(serde_json::json!({
            "status": "already_exists",
            "build_hash": request.build_hash
        })))
    }
}

/// Remove a build hash from the allowlist (DELETE /nodes/:id/build-allowlist/:hash)
pub async fn remove_build_allowlist_handler(
    State(state): State<SharedState>,
    Path((node_id, build_hash)): Path<(Uuid, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

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
        Some(m) => {
            if !has_permission(m.role, Permission::ManageNode) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Insufficient permissions. Admin required.".into(),
                        code: 403,
                    }),
                ));
            }
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be a member of the node".into(),
                    code: 403,
                }),
            ));
        }
    }

    let removed = state
        .db
        .remove_build_hash_from_allowlist(node_id, &build_hash)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to remove build hash: {}", e),
                    code: 500,
                }),
            )
        })?;

    if removed {
        info!(
            "Build hash {} removed from allowlist for node {} by {}",
            build_hash, node_id, user_id
        );
        Ok(Json(serde_json::json!({
            "status": "removed",
            "build_hash": build_hash
        })))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Build hash not found in allowlist".into(),
                code: 404,
            }),
        ))
    }
}

// ── Node user profile endpoints ──

/// Set per-Node user profile (PUT /nodes/:id/profile)
pub async fn set_node_user_profile_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::SetNodeUserProfileRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Must be a member
    if !state
        .is_node_member(user_id, node_id)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Must be a member of the node".into(),
                code: 403,
            }),
        ));
    }

    let enc_name = request
        .encrypted_display_name
        .as_ref()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok());
    let enc_avatar = request
        .encrypted_avatar_url
        .as_ref()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok());

    state
        .db
        .set_node_user_profile(node_id, user_id, enc_name.as_deref(), enc_avatar.as_deref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to set node profile: {}", e),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(serde_json::json!({
        "status": "updated",
        "node_id": node_id,
        "user_id": user_id,
    })))
}

/// Get per-Node user profiles (GET /nodes/:id/profiles)
pub async fn get_node_user_profiles_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Must be a member
    if !state
        .is_node_member(user_id, node_id)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Must be a member of the node".into(),
                code: 403,
            }),
        ));
    }

    let profiles = state
        .db
        .get_node_user_profiles(node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get node profiles: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Encode encrypted fields as base64 for JSON transport
    let profiles_json: Vec<serde_json::Value> = profiles
        .iter()
        .map(|p| {
            serde_json::json!({
                "node_id": p.node_id,
                "user_id": p.user_id,
                "encrypted_display_name": p.encrypted_display_name.as_ref().map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
                "encrypted_avatar_url": p.encrypted_avatar_url.as_ref().map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
                "joined_at": p.joined_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "profiles": profiles_json })))
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

/// Mark channel as read up to a message (POST /channels/:id/read)
pub async fn mark_channel_read_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<MarkChannelReadRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Check channel access
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

    let message_id = body.message_id;

    state
        .db
        .mark_channel_read(user_id, channel_id, message_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to mark channel as read: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Broadcast read receipt to channel members via WebSocket
    let read_receipt_event = serde_json::json!({
        "type": "read_receipt",
        "user_id": user_id,
        "channel_id": channel_id,
        "message_id": message_id,
        "timestamp": now_secs()
    });

    let channel_members = state.get_channel_members(channel_id).await;
    for member_id in &channel_members {
        if *member_id != user_id {
            let _ = state
                .send_to_user(*member_id, read_receipt_event.to_string())
                .await;
        }
    }

    Ok(Json(serde_json::json!({ "status": "ok" })))
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
    let author_filter = params.get("author").and_then(|s| Uuid::parse_str(s).ok());
    let before_filter = params.get("before").and_then(|s| s.parse::<i64>().ok());
    let after_filter = params.get("after").and_then(|s| s.parse::<i64>().ok());

    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(25)
        .min(200); // Cap at 200 search results

    match state.search_messages(node_id, query, channel_id_filter, author_filter, before_filter, after_filter, limit).await {
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
#[allow(dead_code)]
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

// ── Node icon / User avatar upload endpoints ──

const MAX_ICON_SIZE: usize = 256 * 1024; // 256 KB

fn validate_image_content_type(ct: &str) -> Option<&'static str> {
    match ct {
        "image/png" => Some("image/png"),
        "image/jpeg" | "image/jpg" => Some("image/jpeg"),
        "image/gif" => Some("image/gif"),
        "image/webp" => Some("image/webp"),
        _ => None,
    }
}

fn content_type_to_ext(ct: &str) -> &'static str {
    match ct {
        "image/png" => "png",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        _ => "bin",
    }
}

fn detect_content_type(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        Some("image/png")
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if data.starts_with(b"GIF8") {
        Some("image/gif")
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// Upload node icon (PUT /nodes/:id/icon)
pub async fn upload_node_icon_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_header_or_token(&state, &headers, &params).await?;

    // Check ownership or admin
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
        Some(m) if has_permission(m.role, Permission::ManageChannels) => {}
        _ => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Insufficient permissions to update node icon".into(),
                    code: 403,
                }),
            ));
        }
    }

    // Extract file from multipart
    let mut file_data: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "icon" || name == "file" {
            if let Ok(data) = field.bytes().await {
                file_data = Some(data.to_vec());
            }
        }
    }

    let data = file_data.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing icon file".into(),
                code: 400,
            }),
        )
    })?;

    if data.len() > MAX_ICON_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Icon must be under 256KB".into(),
                code: 400,
            }),
        ));
    }

    let content_type = detect_content_type(&data).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Unsupported image format. Use PNG, JPEG, GIF, or WebP".into(),
                code: 400,
            }),
        )
    })?;

    // Hash the content
    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(&data));
    let ext = content_type_to_ext(content_type);
    let filename = format!("{}.{}", hash, ext);

    // Save to disk
    let dir = std::path::PathBuf::from("./data/uploads/icons");
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to create upload dir: {}", e),
                code: 500,
            }),
        )
    })?;
    tokio::fs::write(dir.join(&filename), &data)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to write icon: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Update DB
    state
        .db
        .set_node_icon_hash(node_id, &hash)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to update icon hash: {}", e),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(
        serde_json::json!({ "status": "updated", "icon_hash": hash }),
    ))
}

/// Get node icon (GET /nodes/:id/icon)
pub async fn get_node_icon_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let hash = state.db.get_node_icon_hash(node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{}", e),
                code: 500,
            }),
        )
    })?;

    let hash = hash.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "No icon set".into(),
                code: 404,
            }),
        )
    })?;

    // Find the file on disk
    let dir = std::path::PathBuf::from("./data/uploads/icons");
    let mut found_path = None;
    for ext in &["png", "jpg", "gif", "webp"] {
        let p = dir.join(format!("{}.{}", hash, ext));
        if p.exists() {
            found_path = Some((p, *ext));
            break;
        }
    }

    let (path, ext) = found_path.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Icon file not found".into(),
                code: 404,
            }),
        )
    })?;

    let data = tokio::fs::read(&path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to read icon: {}", e),
                code: 500,
            }),
        )
    })?;

    let ct = match ext {
        "png" => "image/png",
        "jpg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    };

    Ok(Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, ct)
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::ETAG, format!("\"{}\"", hash))
        .body(Body::from(data))
        .unwrap())
}

/// Upload user avatar (PUT /users/me/avatar)
pub async fn upload_user_avatar_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_header_or_token(&state, &headers, &params).await?;

    let mut file_data: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "avatar" || name == "file" {
            if let Ok(data) = field.bytes().await {
                file_data = Some(data.to_vec());
            }
        }
    }

    let data = file_data.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing avatar file".into(),
                code: 400,
            }),
        )
    })?;

    if data.len() > MAX_ICON_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Avatar must be under 256KB".into(),
                code: 400,
            }),
        ));
    }

    let content_type = detect_content_type(&data).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Unsupported image format. Use PNG, JPEG, GIF, or WebP".into(),
                code: 400,
            }),
        )
    })?;

    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(&data));
    let ext = content_type_to_ext(content_type);
    let filename = format!("{}.{}", hash, ext);

    let dir = std::path::PathBuf::from("./data/uploads/avatars");
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to create upload dir: {}", e),
                code: 500,
            }),
        )
    })?;
    tokio::fs::write(dir.join(&filename), &data)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to write avatar: {}", e),
                    code: 500,
                }),
            )
        })?;

    state
        .db
        .set_user_avatar_hash(user_id, &hash)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to update avatar hash: {}", e),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(
        serde_json::json!({ "status": "updated", "avatar_hash": hash }),
    ))
}

/// Get user avatar (GET /users/:id/avatar)
pub async fn get_user_avatar_handler(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let hash = state.db.get_user_avatar_hash(user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("{}", e),
                code: 500,
            }),
        )
    })?;

    let hash = hash.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "No avatar set".into(),
                code: 404,
            }),
        )
    })?;

    let dir = std::path::PathBuf::from("./data/uploads/avatars");
    let mut found_path = None;
    for ext in &["png", "jpg", "gif", "webp"] {
        let p = dir.join(format!("{}.{}", hash, ext));
        if p.exists() {
            found_path = Some((p, *ext));
            break;
        }
    }

    let (path, ext) = found_path.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Avatar file not found".into(),
                code: 404,
            }),
        )
    })?;

    let data = tokio::fs::read(&path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to read avatar: {}", e),
                code: 500,
            }),
        )
    })?;

    let ct = match ext {
        "png" => "image/png",
        "jpg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    };

    Ok(Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, ct)
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::ETAG, format!("\"{}\"", hash))
        .body(Body::from(data))
        .unwrap())
}

// ── Key Bundle endpoints (Double Ratchet / X3DH) ──

/// Publish a prekey bundle (POST /keys/bundle)
pub async fn publish_key_bundle_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::PublishKeyBundleRequest>,
) -> Result<Json<crate::models::PublishKeyBundleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let identity_key = base64::engine::general_purpose::STANDARD
        .decode(&request.identity_key)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid base64 for identity_key".into(),
                    code: 400,
                }),
            )
        })?;

    let signed_prekey = base64::engine::general_purpose::STANDARD
        .decode(&request.signed_prekey)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid base64 for signed_prekey".into(),
                    code: 400,
                }),
            )
        })?;

    let mut one_time_prekeys = Vec::new();
    for opk_b64 in &request.one_time_prekeys {
        let opk = base64::engine::general_purpose::STANDARD
            .decode(opk_b64)
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Invalid base64 for one_time_prekey".into(),
                        code: 400,
                    }),
                )
            })?;
        one_time_prekeys.push(opk);
    }

    let count = one_time_prekeys.len();

    state
        .db
        .publish_key_bundle(user_id, &identity_key, &signed_prekey, &one_time_prekeys)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to publish key bundle: {}", e),
                    code: 500,
                }),
            )
        })?;

    info!("Key bundle published for user: {}", user_id);
    Ok(Json(crate::models::PublishKeyBundleResponse {
        status: "published".to_string(),
        one_time_prekeys_stored: count,
    }))
}

/// Fetch a user's prekey bundle (GET /keys/bundle/:user_id)
pub async fn fetch_key_bundle_handler(
    State(state): State<SharedState>,
    Path(target_user_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<crate::models::FetchKeyBundleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id = extract_user_from_token(&state, &params).await?;

    match state.db.fetch_key_bundle(target_user_id).await {
        Ok(Some((identity_key, signed_prekey, one_time_prekey))) => {
            Ok(Json(crate::models::FetchKeyBundleResponse {
                user_id: target_user_id,
                identity_key: base64::engine::general_purpose::STANDARD.encode(&identity_key),
                signed_prekey: base64::engine::general_purpose::STANDARD.encode(&signed_prekey),
                one_time_prekey: one_time_prekey
                    .map(|opk| base64::engine::general_purpose::STANDARD.encode(&opk)),
            }))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "No key bundle found for user".into(),
                code: 404,
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to fetch key bundle: {}", e),
                code: 500,
            }),
        )),
    }
}

/// Store a prekey message (POST /keys/prekey-message)
pub async fn store_prekey_message_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::StorePrekeyMessageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let sender_id = extract_user_from_token(&state, &params).await?;

    let message_data = base64::engine::general_purpose::STANDARD
        .decode(&request.message_data)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid base64 for message_data".into(),
                    code: 400,
                }),
            )
        })?;

    let msg_id = state
        .db
        .store_prekey_message(request.recipient_id, sender_id, &message_data)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to store prekey message: {}", e),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(
        serde_json::json!({ "status": "stored", "message_id": msg_id }),
    ))
}

/// Get pending prekey messages (GET /keys/prekey-messages)
pub async fn get_prekey_messages_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let messages = state.db.get_prekey_messages(user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get prekey messages: {}", e),
                code: 500,
            }),
        )
    })?;

    let response: Vec<crate::models::PrekeyMessageResponse> = messages
        .into_iter()
        .map(
            |(id, sender_id, data, created_at)| crate::models::PrekeyMessageResponse {
                id,
                sender_id,
                message_data: base64::engine::general_purpose::STANDARD.encode(&data),
                created_at,
            },
        )
        .collect();

    Ok(Json(serde_json::json!({ "messages": response })))
}

/// WebSocket upgrade handler
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> Response {
    // Extract optional build hash from headers (checked post-auth inside websocket_handler)
    let client_hash = headers
        .get("X-Build-Hash")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Support legacy query-param token for backward compatibility, but prefer post-upgrade auth.
    let legacy_token = params.get("token").cloned();

    info!("WebSocket upgrade requested (post-upgrade auth)");
    ws.on_upgrade(move |socket| {
        websocket_handler_with_auth(socket, legacy_token, state, client_hash)
    })
}

/// Post-upgrade WebSocket authentication wrapper.
/// The client must send an `Authenticate` message within 5 seconds or the connection is closed.
/// Also supports legacy query-param token for backward compatibility.
async fn websocket_handler_with_auth(
    socket: WebSocket,
    legacy_token: Option<String>,
    state: SharedState,
    client_hash: Option<String>,
) {
    use crate::state::BuildVerificationMode;
    use accord_core::build_hash::BuildTrust;

    let (mut sender, mut receiver) = socket.split();

    // Determine user_id: either from legacy query param or from post-upgrade Authenticate message
    let user_id = if let Some(ref token) = legacy_token {
        // Legacy path: token was in query params (backward compat)
        tracing::warn!("Client using deprecated query-param token authentication");
        match state.validate_token(token).await {
            Some(uid) => uid,
            None => {
                let err = serde_json::json!({
                    "type": "error",
                    "code": "auth_failed",
                    "message": "Invalid or expired token"
                });
                let _ = sender.send(Message::Text(err.to_string())).await;
                let _ = sender.close().await;
                return;
            }
        }
    } else {
        // Post-upgrade auth: wait for Authenticate message within 5 seconds
        let auth_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            wait_for_auth_message(&mut receiver, &state),
        )
        .await;

        match auth_result {
            Ok(Ok(uid)) => uid,
            Ok(Err(err_msg)) => {
                let err = serde_json::json!({
                    "type": "error",
                    "code": "auth_failed",
                    "message": err_msg
                });
                let _ = sender.send(Message::Text(err.to_string())).await;
                let _ = sender.close().await;
                return;
            }
            Err(_) => {
                let err = serde_json::json!({
                    "type": "error",
                    "code": "auth_failed",
                    "message": "Authentication timeout — must authenticate within 5 seconds"
                });
                let _ = sender.send(Message::Text(err.to_string())).await;
                let _ = sender.close().await;
                return;
            }
        }
    };

    // Build hash verification (moved from pre-upgrade to post-auth)
    let bv = &state.build_verification;
    match bv.mode {
        BuildVerificationMode::Disabled => {}
        BuildVerificationMode::Warn => match &client_hash {
            None => {
                tracing::warn!("Client {} connected without build hash", user_id);
            }
            Some(hash) => {
                let trust = bv.verify_client_hash(hash);
                if trust != BuildTrust::Verified {
                    tracing::warn!("Client {} build hash {:?}: {}", user_id, trust, hash);
                }
            }
        },
        BuildVerificationMode::Enforce => match &client_hash {
            None => {
                let err = serde_json::json!({
                    "type": "error",
                    "code": "build_hash_required",
                    "message": "Missing X-Build-Hash header"
                });
                let _ = sender.send(Message::Text(err.to_string())).await;
                let _ = sender.close().await;
                return;
            }
            Some(hash) => {
                let trust = bv.verify_client_hash(hash);
                if trust == BuildTrust::Revoked {
                    let err = serde_json::json!({
                        "type": "error",
                        "code": "build_revoked",
                        "message": "Build has been revoked"
                    });
                    let _ = sender.send(Message::Text(err.to_string())).await;
                    let _ = sender.close().await;
                    return;
                }
                if trust == BuildTrust::Unknown && !bv.known_hashes.is_empty() {
                    let err = serde_json::json!({
                        "type": "error",
                        "code": "build_unknown",
                        "message": "Unrecognized build hash"
                    });
                    let _ = sender.send(Message::Text(err.to_string())).await;
                    let _ = sender.close().await;
                    return;
                }
            }
        },
    }

    // Relay-level build hash enforcement
    if let Err(msg) = state.check_relay_build_hash(client_hash.as_deref()).await {
        let err = serde_json::json!({
            "type": "error",
            "code": "build_rejected",
            "message": msg
        });
        let _ = sender.send(Message::Text(err.to_string())).await;
        let _ = sender.close().await;
        return;
    }

    info!("WebSocket authenticated for user: {}", user_id);

    // Send authentication confirmation so the client knows auth succeeded
    // before considering the connection fully established.
    let auth_confirm = serde_json::json!({
        "type": "authenticated",
        "user_id": user_id,
    });
    let _ = sender.send(Message::Text(auth_confirm.to_string())).await;

    // Continue with the normal handler, passing the already-split halves
    websocket_handler_inner(sender, receiver, user_id, state, client_hash).await;
}

/// Wait for an Authenticate message from the client.
/// Returns the validated user_id or an error string.
async fn wait_for_auth_message(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    state: &SharedState,
) -> Result<Uuid, String> {
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                // Try to parse as Authenticate message
                #[derive(serde::Deserialize)]
                struct AuthenticateMsg {
                    token: String,
                }
                #[derive(serde::Deserialize)]
                enum AuthEnvelope {
                    Authenticate(AuthenticateMsg),
                }

                match serde_json::from_str::<AuthEnvelope>(&text) {
                    Ok(AuthEnvelope::Authenticate(auth)) => {
                        match state.validate_token(&auth.token).await {
                            Some(uid) => return Ok(uid),
                            None => return Err("Invalid or expired token".to_string()),
                        }
                    }
                    Err(_) => {
                        return Err("First message must be an Authenticate message".to_string());
                    }
                }
            }
            Ok(Message::Close(_)) => {
                return Err("Connection closed before authentication".to_string());
            }
            Ok(_) => {
                // Ignore ping/pong/binary during auth phase
                continue;
            }
            Err(e) => {
                return Err(format!("WebSocket error during authentication: {}", e));
            }
        }
    }
    Err("Connection closed before authentication".to_string())
}

/// Build info REST endpoint — returns the server's build identity.
pub async fn build_info_handler(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let bi = &state.build_verification.server_build_info;
    Json(serde_json::json!({
        "commit_hash": bi.commit_hash,
        "version": bi.version,
        "build_hash": bi.build_hash,
        "build_timestamp": bi.build_timestamp,
        "target_triple": bi.target_triple,
    }))
}

async fn websocket_handler(
    socket: WebSocket,
    user_id: Uuid,
    state: SharedState,
    client_hash: Option<String>,
) {
    let (sender, receiver) = socket.split();
    websocket_handler_inner(sender, receiver, user_id, state, client_hash).await;
}

async fn websocket_handler_inner(
    mut sender: futures_util::stream::SplitSink<WebSocket, Message>,
    mut receiver: futures_util::stream::SplitStream<WebSocket>,
    user_id: Uuid,
    state: SharedState,
    client_hash: Option<String>,
) {
    // Store client build hash for per-Node allowlist checks
    if let Some(ref hash) = client_hash {
        state.set_client_build_hash(user_id, hash.clone()).await;
    }
    let (tx, mut rx) = broadcast::channel::<String>(100);

    state.add_connection(user_id, tx.clone()).await;

    // Send welcome message with server build info for mutual verification
    {
        let bi = &state.build_verification.server_build_info;
        let welcome = serde_json::json!({
            "type": "hello",
            "server_version": bi.version,
            "server_build_hash": bi.build_hash,
            "protocol_version": accord_core::PROTOCOL_VERSION,
        });
        let _ = sender.send(Message::Text(welcome.to_string())).await;
    }

    // Set user online when they connect
    if let Err(err) = state.set_user_online(user_id).await {
        error!("Failed to set user online: {}", err);
    }

    // Send current presence state for all user's nodes
    if let Err(err) = state.send_initial_presence(user_id).await {
        error!("Failed to send initial presence: {}", err);
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
                // Record activity for idle detection
                let _ = state.record_user_activity(user_id).await;
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
            // Check build hash allowlist before joining
            state
                .check_build_hash_for_node(sender_user_id, node_id)
                .await?;
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
                state,
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
            channel_id: _,
            category_id: _,
            position: _,
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
            // Check if the recipient has blocked the sender
            if state
                .db
                .is_user_blocked(to_user, sender_user_id)
                .await
                .unwrap_or(false)
            {
                return Err("Cannot send DM to this user".to_string());
            }

            // For now, simplify DM handling by just relaying the message directly
            // without complex database operations that might hang in tests
            let message_id = uuid::Uuid::new_v4();

            // Look up sender's plaintext display name
            let dm_sender_display_name = state
                .db
                .get_user_profile(sender_user_id)
                .await
                .ok()
                .flatten()
                .and_then(|p| {
                    let name = p.display_name;
                    if name.is_empty() {
                        None
                    } else {
                        Some(name)
                    }
                });

            // Create a simple relay message
            let relay = serde_json::json!({
                "type": "channel_message",
                "from": sender_user_id,
                "channel_id": message_id, // Use message_id as temporary channel_id
                "encrypted_data": encrypted_data,
                "message_id": message_id,
                "timestamp": ws_message.timestamp,
                "is_dm": true,
                "sender_display_name": dm_sender_display_name
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
            // Check if this is a DM channel and enforce blocks
            if let Ok(true) = state.db.is_dm_channel(channel_id).await {
                if let Ok(Some(dm)) = state.db.get_dm_channel(channel_id).await {
                    let other_user = if dm.user1_id == sender_user_id {
                        dm.user2_id
                    } else {
                        dm.user1_id
                    };
                    if state
                        .db
                        .is_user_blocked(other_user, sender_user_id)
                        .await
                        .unwrap_or(false)
                    {
                        return Err(
                            "Cannot send message: you have been blocked by this user".to_string()
                        );
                    }
                }
            }

            // Check SEND_MESSAGES permission and build hash allowlist
            if let Ok(Some(channel)) = state.db.get_channel(channel_id).await {
                // Check build hash allowlist
                state
                    .check_build_hash_for_node(sender_user_id, channel.node_id)
                    .await?;

                if let Ok(perms) = state
                    .db
                    .compute_channel_permissions(channel.node_id, sender_user_id, channel_id)
                    .await
                {
                    if perms & crate::models::permission_bits::SEND_MESSAGES == 0 {
                        return Err(
                            "Permission denied: you do not have SEND_MESSAGES in this channel"
                                .to_string(),
                        );
                    }
                }
            }

            // Decode and store the message
            let encrypted_payload = base64::engine::general_purpose::STANDARD
                .decode(&encrypted_data)
                .map_err(|_| "Invalid base64 encoded data".to_string())?;

            let message_id = state
                .db
                .store_message(channel_id, sender_user_id, &encrypted_payload, reply_to)
                .await
                .map_err(|e| format!("Failed to store message: {}", e))?;

            // Look up sender's encrypted display name for this node
            let sender_display_name_b64 =
                if let Ok(Some(channel)) = state.db.get_channel(channel_id).await {
                    if let Ok(Some(profile)) = state
                        .db
                        .get_node_user_profile(channel.node_id, sender_user_id)
                        .await
                    {
                        profile
                            .encrypted_display_name
                            .map(|b| base64::engine::general_purpose::STANDARD.encode(&b))
                    } else {
                        None
                    }
                } else {
                    None
                };

            // Look up sender's plaintext display name from user profile
            let sender_display_name = state
                .db
                .get_user_profile(sender_user_id)
                .await
                .ok()
                .flatten()
                .and_then(|p| {
                    let name = p.display_name;
                    if name.is_empty() {
                        None
                    } else {
                        Some(name)
                    }
                });

            let relay = serde_json::json!({
                "type": "channel_message", "from": sender_user_id, "channel_id": channel_id,
                "encrypted_data": encrypted_data, "message_id": message_id,
                "timestamp": ws_message.timestamp, "reply_to": reply_to,
                "encrypted_display_name": sender_display_name_b64,
                "sender_display_name": sender_display_name
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

        // ── Key exchange operations ──
        WsMessageType::PublishKeyBundle {
            identity_key,
            signed_prekey,
            one_time_prekeys,
        } => {
            let ik = base64::engine::general_purpose::STANDARD
                .decode(&identity_key)
                .map_err(|_| "Invalid base64 for identity_key".to_string())?;
            let spk = base64::engine::general_purpose::STANDARD
                .decode(&signed_prekey)
                .map_err(|_| "Invalid base64 for signed_prekey".to_string())?;
            let mut opks = Vec::new();
            for opk_b64 in &one_time_prekeys {
                let opk = base64::engine::general_purpose::STANDARD
                    .decode(opk_b64)
                    .map_err(|_| "Invalid base64 for one_time_prekey".to_string())?;
                opks.push(opk);
            }
            state
                .db
                .publish_key_bundle(sender_user_id, &ik, &spk, &opks)
                .await
                .map_err(|e| format!("Failed to publish key bundle: {}", e))?;
            let resp = serde_json::json!({ "type": "key_bundle_published" });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
        }

        WsMessageType::FetchKeyBundle { target_user_id } => {
            match state.db.fetch_key_bundle(target_user_id).await {
                Ok(Some((ik, spk, opk))) => {
                    let resp = serde_json::json!({
                        "type": "key_bundle_response",
                        "user_id": target_user_id,
                        "identity_key": base64::engine::general_purpose::STANDARD.encode(&ik),
                        "signed_prekey": base64::engine::general_purpose::STANDARD.encode(&spk),
                        "one_time_prekey": opk.map(|k| base64::engine::general_purpose::STANDARD.encode(&k)),
                    });
                    state.send_to_user(sender_user_id, resp.to_string()).await?;
                }
                Ok(None) => {
                    let resp = serde_json::json!({
                        "type": "error",
                        "message": "No key bundle found for user"
                    });
                    state.send_to_user(sender_user_id, resp.to_string()).await?;
                }
                Err(e) => {
                    return Err(format!("Failed to fetch key bundle: {}", e));
                }
            }
        }

        WsMessageType::StorePrekeyMessage {
            recipient_id,
            message_data,
        } => {
            let data = base64::engine::general_purpose::STANDARD
                .decode(&message_data)
                .map_err(|_| "Invalid base64 for message_data".to_string())?;
            let msg_id = state
                .db
                .store_prekey_message(recipient_id, sender_user_id, &data)
                .await
                .map_err(|e| format!("Failed to store prekey message: {}", e))?;
            let resp = serde_json::json!({ "type": "prekey_message_stored", "message_id": msg_id });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
        }

        WsMessageType::GetPrekeyMessages => {
            let messages = state
                .db
                .get_prekey_messages(sender_user_id)
                .await
                .map_err(|e| format!("Failed to get prekey messages: {}", e))?;
            let msgs: Vec<serde_json::Value> = messages
                .into_iter()
                .map(|(id, sid, data, ts)| {
                    serde_json::json!({
                        "id": id,
                        "sender_id": sid,
                        "message_data": base64::engine::general_purpose::STANDARD.encode(&data),
                        "created_at": ts,
                    })
                })
                .collect();
            let resp = serde_json::json!({ "type": "prekey_messages", "messages": msgs });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
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
                "public_key_hash": user.public_key_hash,
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
                state,
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
                state,
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
            // Get existing participants before joining (so new user knows who's there)
            let existing = state.get_voice_channel_participants(channel_id).await;

            state.join_voice_channel(sender_user_id, channel_id).await?;

            // Send the joining user the current participant list
            let resp = serde_json::json!({
                "type": "voice_channel_joined",
                "channel_id": channel_id,
                "user_id": sender_user_id,
                "participants": existing
            });
            state.send_to_user(sender_user_id, resp.to_string()).await?;

            // Broadcast to existing participants that a new user joined
            let broadcast = serde_json::json!({
                "type": "voice_peer_joined",
                "channel_id": channel_id,
                "user_id": sender_user_id
            });
            state
                .send_to_voice_channel(channel_id, sender_user_id, broadcast.to_string())
                .await?;

            info!(
                "User {} joined voice channel {}",
                sender_user_id, channel_id
            );
        }

        WsMessageType::LeaveVoiceChannel { channel_id } => {
            // Broadcast to remaining participants before leaving
            let broadcast = serde_json::json!({
                "type": "voice_peer_left",
                "channel_id": channel_id,
                "user_id": sender_user_id
            });
            state
                .send_to_voice_channel(channel_id, sender_user_id, broadcast.to_string())
                .await?;

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

        WsMessageType::GetVoiceParticipants { channel_id } => {
            let participants = state.get_voice_channel_participants(channel_id).await;
            let resp = serde_json::json!({
                "type": "voice_participants",
                "channel_id": channel_id,
                "participants": participants
            });
            state.send_to_user(sender_user_id, resp.to_string()).await?;
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
        }

        WsMessageType::VoiceKeyExchange {
            channel_id,
            wrapped_key,
            target_user_id,
            sender_ssrc,
            key_generation,
        } => {
            // Relay voice key exchange opaquely — server cannot decrypt
            let relay = serde_json::json!({
                "type": "voice_key_exchange",
                "from": sender_user_id,
                "channel_id": channel_id,
                "wrapped_key": wrapped_key,
                "sender_ssrc": sender_ssrc,
                "key_generation": key_generation,
                "timestamp": ws_message.timestamp
            });
            if let Some(target) = target_user_id {
                // 1:1 key exchange
                state.send_to_user(target, relay.to_string()).await?;
            } else {
                // Broadcast to voice channel
                state
                    .send_to_voice_channel(channel_id, sender_user_id, relay.to_string())
                    .await?;
            }
        }

        WsMessageType::SrtpVoicePacket {
            channel_id,
            packet_data,
        } => {
            // Relay SRTP packet opaquely — server cannot decrypt
            let relay = serde_json::json!({
                "type": "srtp_voice_packet",
                "from": sender_user_id,
                "channel_id": channel_id,
                "packet_data": packet_data,
                "timestamp": ws_message.timestamp
            });
            state
                .send_to_voice_channel(channel_id, sender_user_id, relay.to_string())
                .await?;
        }
        WsMessageType::P2PSignal {
            channel_id,
            target_user_id,
            signal_data,
        } => {
            // Relay P2P signaling message to the target peer — server cannot interpret content
            let relay = serde_json::json!({
                "type": "p2p_signal",
                "from": sender_user_id,
                "channel_id": channel_id,
                "signal_data": signal_data,
                "timestamp": ws_message.timestamp
            });
            state
                .send_to_user(target_user_id, relay.to_string())
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

/// Get thread starters in a channel (GET /channels/:id/threads)
pub async fn get_channel_threads_handler(
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

    // Check membership
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
                error: "You must be a member of this channel to view threads".into(),
                code: 403,
            }),
        ));
    }

    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<u32>().ok())
        .unwrap_or(50);

    let threads = state
        .db
        .get_channel_threads(channel_id, limit)
        .await
        .map_err(|e| {
            error!("Failed to get channel threads: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to get channel threads".into(),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(serde_json::json!({ "threads": threads })))
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

// ── Friend system endpoints ──

/// Send a friend request (POST /friends/request)
pub async fn send_friend_request_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::SendFriendRequestRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Cannot friend yourself
    if user_id == request.to_user_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot send friend request to yourself".into(),
                code: 400,
            }),
        ));
    }

    // Check target user exists
    if state
        .db
        .get_user_by_id(request.to_user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Target user not found".into(),
                code: 404,
            }),
        ));
    }

    // Must share a node
    let shared = state
        .db
        .share_a_node(user_id, request.to_user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?;
    if !shared {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Must share a Node to send a friend request".into(),
                code: 403,
            }),
        ));
    }

    // Check not already friends
    let user_hash = state
        .db
        .get_user_public_key_hash(user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "User not found".into(),
                    code: 500,
                }),
            )
        })?;

    let target_hash = state
        .db
        .get_user_public_key_hash(request.to_user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Target user not found".into(),
                    code: 500,
                }),
            )
        })?;

    let already_friends = state
        .db
        .are_friends(&user_hash, &target_hash)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?;
    if already_friends {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Already friends".into(),
                code: 409,
            }),
        ));
    }

    let dm_key_bundle = request
        .dm_key_bundle
        .as_ref()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok());

    let request_id = state
        .db
        .create_friend_request(
            user_id,
            request.to_user_id,
            request.node_id,
            dm_key_bundle.as_deref(),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to create friend request: {}", e),
                    code: 500,
                }),
            )
        })?;

    info!(
        "Friend request {} from {} to {}",
        request_id, user_id, request.to_user_id
    );
    Ok(Json(
        serde_json::json!({ "status": "sent", "request_id": request_id }),
    ))
}

/// Accept a friend request (POST /friends/accept)
pub async fn accept_friend_request_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::AcceptFriendRequestRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Verify the request is addressed to this user
    let fr = state
        .db
        .get_friend_request(request.request_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Friend request not found".into(),
                    code: 404,
                }),
            )
        })?;

    if fr.to_user_id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "This request is not addressed to you".into(),
                code: 403,
            }),
        ));
    }

    let proof_bytes = request
        .friendship_proof
        .as_ref()
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok());

    let accepted = state
        .db
        .accept_friend_request(request.request_id, proof_bytes.as_deref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to accept: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !accepted {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Request already handled or not found".into(),
                code: 400,
            }),
        ));
    }

    info!(
        "Friend request {} accepted by {}",
        request.request_id, user_id
    );
    Ok(Json(serde_json::json!({ "status": "accepted" })))
}

/// Reject a friend request (POST /friends/reject)
pub async fn reject_friend_request_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::RejectFriendRequestRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Verify the request is addressed to this user
    let fr = state
        .db
        .get_friend_request(request.request_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Friend request not found".into(),
                    code: 404,
                }),
            )
        })?;

    if fr.to_user_id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "This request is not addressed to you".into(),
                code: 403,
            }),
        ));
    }

    let rejected = state
        .db
        .reject_friend_request(request.request_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to reject: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !rejected {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Request already handled".into(),
                code: 400,
            }),
        ));
    }

    Ok(Json(serde_json::json!({ "status": "rejected" })))
}

/// List friends (GET /friends)
pub async fn list_friends_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let user_hash = state
        .db
        .get_user_public_key_hash(user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "User not found".into(),
                    code: 500,
                }),
            )
        })?;

    let friends = state.db.get_friends(&user_hash).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("DB error: {}", e),
                code: 500,
            }),
        )
    })?;

    Ok(Json(serde_json::json!({ "friends": friends })))
}

/// List pending friend requests (GET /friends/requests)
pub async fn list_friend_requests_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let requests = state.db.get_pending_requests(user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("DB error: {}", e),
                code: 500,
            }),
        )
    })?;

    Ok(Json(serde_json::json!({ "requests": requests })))
}

/// Remove a friend (DELETE /friends/:user_id)
pub async fn remove_friend_handler(
    State(state): State<SharedState>,
    Path(target_user_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let user_hash = state
        .db
        .get_user_public_key_hash(user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "User not found".into(),
                    code: 500,
                }),
            )
        })?;

    let target_hash = state
        .db
        .get_user_public_key_hash(target_user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Target user not found".into(),
                    code: 404,
                }),
            )
        })?;

    let removed = state
        .db
        .remove_friend(&user_hash, &target_hash)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?;

    if !removed {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Friendship not found".into(),
                code: 404,
            }),
        ));
    }

    Ok(Json(serde_json::json!({ "status": "removed" })))
}

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

    // Check if already have a DM channel (existing channels continue to work)
    let existing = state
        .db
        .get_dm_channel_between_users(user_id, target_user_id)
        .await
        .map_err(|e| {
            error!("Failed to check existing DM channel: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to check existing DM channel".into(),
                    code: 500,
                }),
            )
        })?;

    // If no existing DM channel, require friendship
    if existing.is_none() {
        let user_hash = state
            .db
            .get_user_public_key_hash(user_id)
            .await
            .map_err(|e| {
                error!("DB error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal error".into(),
                        code: 500,
                    }),
                )
            })?
            .unwrap_or_default();

        let target_hash = state
            .db
            .get_user_public_key_hash(target_user_id)
            .await
            .map_err(|e| {
                error!("DB error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal error".into(),
                        code: 500,
                    }),
                )
            })?
            .unwrap_or_default();

        let friends = state
            .db
            .are_friends(&user_hash, &target_hash)
            .await
            .map_err(|e| {
                error!("DB error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Internal error".into(),
                        code: 500,
                    }),
                )
            })?;

        if !friends {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be friends to create a DM channel".into(),
                    code: 403,
                }),
            ));
        }
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

// ── Push notification endpoints ──

/// Register a device token for push notifications (POST /push/register)
pub async fn register_push_token_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::RegisterDeviceTokenRequest>,
) -> Result<Json<crate::models::RegisterDeviceTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    if request.token.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Token cannot be empty".into(),
                code: 400,
            }),
        ));
    }

    let privacy_level = request
        .privacy_level
        .unwrap_or(crate::models::NotificationPrivacy::Partial);

    match state
        .db
        .register_device_token(user_id, request.platform, &request.token, privacy_level)
        .await
    {
        Ok(id) => {
            info!(
                "Device token registered for user {} ({:?})",
                user_id, request.platform
            );
            Ok(Json(crate::models::RegisterDeviceTokenResponse {
                id,
                status: "registered".to_string(),
            }))
        }
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to register device token: {}", err),
                code: 500,
            }),
        )),
    }
}

/// Deregister a device token (DELETE /push/register)
pub async fn deregister_push_token_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::DeregisterDeviceTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state.db.remove_device_token(user_id, &request.token).await {
        Ok(true) => Ok(Json(serde_json::json!({ "status": "deregistered" }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Token not found".into(),
                code: 404,
            }),
        )),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to deregister token: {}", err),
                code: 500,
            }),
        )),
    }
}

/// Update push notification preferences (PUT /push/preferences)
pub async fn update_push_preferences_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<crate::models::UpdatePushPreferencesRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    match state
        .db
        .update_push_privacy(user_id, request.token.as_deref(), request.privacy_level)
        .await
    {
        Ok(updated) => {
            if updated == 0 {
                Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "No device tokens found to update".into(),
                        code: 404,
                    }),
                ))
            } else {
                Ok(Json(serde_json::json!({
                    "status": "updated",
                    "tokens_updated": updated
                })))
            }
        }
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to update preferences: {}", err),
                code: 500,
            }),
        )),
    }
}
// ══════════════════════════════════════════════════════════════
// ── Role & Permission Handlers ──
// ══════════════════════════════════════════════════════════════

use crate::models::{
    permission_bits, CreateRoleRequest, ReorderRolesRequest, SetChannelOverwriteRequest,
    UpdateRoleRequest,
};

/// Helper: check that the requesting user has a given permission bit in a Node.
/// Returns Ok(user_id) on success, or a 403 error response.
async fn require_node_permission(
    state: &SharedState,
    params: &HashMap<String, String>,
    node_id: Uuid,
    required_bit: u64,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(state, params).await?;

    // Check membership first
    if !state
        .db
        .is_node_member(node_id, user_id)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Not a member of this node".into(),
                code: 403,
            }),
        ));
    }

    let perms = state
        .db
        .compute_node_permissions(node_id, user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to compute permissions: {}", e),
                    code: 500,
                }),
            )
        })?;

    if perms & required_bit == 0 && perms & permission_bits::ADMINISTRATOR == 0 {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Missing permission: {}",
                    permission_bits::name(required_bit)
                ),
                code: 403,
            }),
        ));
    }

    Ok(user_id)
}

/// GET /nodes/:id/roles — list all roles for a Node
pub async fn list_roles_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id = extract_user_from_token(&state, &params).await?;

    let roles = state.db.get_node_roles(node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get roles: {}", e),
                code: 500,
            }),
        )
    })?;

    Ok(Json(serde_json::json!({ "roles": roles })))
}

/// POST /nodes/:id/roles — create a new role
pub async fn create_role_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id =
        require_node_permission(&state, &params, node_id, permission_bits::MANAGE_ROLES).await?;

    let position = state.db.next_role_position(node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("DB error: {}", e),
                code: 500,
            }),
        )
    })?;

    let role = state
        .db
        .create_role(
            node_id,
            &request.name,
            request.color.unwrap_or(0),
            request.permissions.unwrap_or(0),
            position,
            request.hoist.unwrap_or(false),
            request.mentionable.unwrap_or(false),
            request.icon_emoji.as_deref(),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to create role: {}", e),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(serde_json::json!(role)))
}

/// PATCH /nodes/:id/roles/:role_id — edit a role
pub async fn update_role_handler(
    State(state): State<SharedState>,
    Path((node_id, role_id)): Path<(Uuid, Uuid)>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id =
        require_node_permission(&state, &params, node_id, permission_bits::MANAGE_ROLES).await?;

    // Can't rename @everyone
    let role = state.db.get_role(role_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;
    let role = role.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Role not found".into(),
                code: 404,
            }),
        )
    })?;
    if role.node_id != node_id {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Role not found in this node".into(),
                code: 404,
            }),
        ));
    }

    state
        .db
        .update_role(
            role_id,
            request.name.as_deref(),
            request.color,
            request.permissions,
            request.hoist,
            request.mentionable,
            request.icon_emoji.as_ref().map(|s| Some(s.as_str())),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to update role: {}", e),
                    code: 500,
                }),
            )
        })?;

    let updated = state.db.get_role(role_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    Ok(Json(serde_json::json!(updated)))
}

/// DELETE /nodes/:id/roles/:role_id — delete a role
pub async fn delete_role_handler(
    State(state): State<SharedState>,
    Path((node_id, role_id)): Path<(Uuid, Uuid)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let _user_id =
        require_node_permission(&state, &params, node_id, permission_bits::MANAGE_ROLES).await?;

    // Prevent deleting @everyone (position 0)
    let role = state.db.get_role(role_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;
    let role = role.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Role not found".into(),
                code: 404,
            }),
        )
    })?;
    if role.position == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot delete the @everyone role".into(),
                code: 400,
            }),
        ));
    }

    state.db.delete_role(role_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// PATCH /nodes/:id/roles/reorder — reorder roles
pub async fn reorder_roles_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<ReorderRolesRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let _user_id =
        require_node_permission(&state, &params, node_id, permission_bits::MANAGE_ROLES).await?;

    let entries: Vec<(Uuid, i32)> = request.roles.iter().map(|e| (e.id, e.position)).collect();
    state.db.reorder_roles(&entries).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /nodes/:id/members/:user_id/roles — get a member's roles
pub async fn get_member_roles_handler(
    State(state): State<SharedState>,
    Path((node_id, target_user_id)): Path<(Uuid, Uuid)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id = extract_user_from_token(&state, &params).await?;

    let roles = state
        .db
        .get_member_roles(node_id, target_user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(serde_json::json!({ "roles": roles })))
}

/// PUT /nodes/:id/members/:user_id/roles/:role_id — assign a role to a member
pub async fn assign_member_role_handler(
    State(state): State<SharedState>,
    Path((node_id, target_user_id, role_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let _user_id =
        require_node_permission(&state, &params, node_id, permission_bits::MANAGE_ROLES).await?;

    // Verify the role belongs to this node
    let role = state.db.get_role(role_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;
    let role = role.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Role not found".into(),
                code: 404,
            }),
        )
    })?;
    if role.node_id != node_id {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Role not in this node".into(),
                code: 404,
            }),
        ));
    }

    // Verify target is a member
    if !state
        .db
        .is_node_member(node_id, target_user_id)
        .await
        .unwrap_or(false)
    {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User is not a member of this node".into(),
                code: 404,
            }),
        ));
    }

    state
        .db
        .assign_member_role(node_id, target_user_id, role_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /nodes/:id/members/:user_id/roles/:role_id — remove a role from a member
pub async fn remove_member_role_handler(
    State(state): State<SharedState>,
    Path((node_id, target_user_id, role_id)): Path<(Uuid, Uuid, Uuid)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let _user_id =
        require_node_permission(&state, &params, node_id, permission_bits::MANAGE_ROLES).await?;

    state
        .db
        .remove_member_role(target_user_id, role_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /channels/:id/permissions — list channel permission overwrites
pub async fn list_channel_overwrites_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id = extract_user_from_token(&state, &params).await?;

    let overwrites = state
        .db
        .get_channel_overwrites(channel_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(serde_json::json!({ "overwrites": overwrites })))
}

/// PUT /channels/:id/permissions/:role_id — set a channel permission overwrite
pub async fn set_channel_overwrite_handler(
    State(state): State<SharedState>,
    Path((channel_id, role_id)): Path<(Uuid, Uuid)>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<SetChannelOverwriteRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Get the channel's node to check permissions
    let channel = state
        .db
        .get_channel(channel_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
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

    // Require MANAGE_CHANNELS or MANAGE_ROLES
    let perms = state
        .db
        .compute_node_permissions(channel.node_id, user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;
    let can_manage = perms & permission_bits::ADMINISTRATOR != 0
        || perms & permission_bits::MANAGE_CHANNELS != 0
        || perms & permission_bits::MANAGE_ROLES != 0;
    if !can_manage {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Missing MANAGE_CHANNELS or MANAGE_ROLES".into(),
                code: 403,
            }),
        ));
    }

    state
        .db
        .set_channel_overwrite(channel_id, role_id, request.allow, request.deny)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /channels/:id/permissions/:role_id — remove a channel permission overwrite
pub async fn delete_channel_overwrite_handler(
    State(state): State<SharedState>,
    Path((channel_id, role_id)): Path<(Uuid, Uuid)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let channel = state
        .db
        .get_channel(channel_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
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

    let perms = state
        .db
        .compute_node_permissions(channel.node_id, user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;
    let can_manage = perms & permission_bits::ADMINISTRATOR != 0
        || perms & permission_bits::MANAGE_CHANNELS != 0
        || perms & permission_bits::MANAGE_ROLES != 0;
    if !can_manage {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Missing MANAGE_CHANNELS or MANAGE_ROLES".into(),
                code: 403,
            }),
        ));
    }

    state
        .db
        .delete_channel_overwrite(channel_id, role_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /channels/:id/effective-permissions — compute effective permissions for the requesting user
pub async fn get_effective_permissions_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let channel = state
        .db
        .get_channel(channel_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
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

    let perms = state
        .db
        .compute_channel_permissions(channel.node_id, user_id, channel_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(serde_json::json!({
        "permissions": perms,
        "channel_id": channel_id,
        "user_id": user_id,
    })))
}

// ── Discord Template Import ──

/// Request body for importing a Discord server template.
#[derive(Debug, serde::Deserialize)]
pub struct ImportDiscordTemplateRequest {
    /// A Discord template code (e.g. "RHzsRPA9xrRW"). If provided, the server
    /// fetches the template JSON from Discord's API.
    pub template_code: Option<String>,
    /// Pre-fetched template JSON. Use this when the caller already has the data.
    pub template_json: Option<serde_json::Value>,
}

/// Summary returned after a successful template import.
#[derive(Debug, serde::Serialize)]
pub struct ImportTemplateSummary {
    pub roles_created: u32,
    pub roles_updated: u32,
    pub roles_skipped: u32,
    pub categories_created: u32,
    pub text_channels_created: u32,
    pub voice_channels_created: u32,
    pub overwrites_created: u32,
    pub unsupported_permissions_stripped: Vec<String>,
}

/// Discord permission bit names for bits we do NOT support (for the import summary).
fn discord_bit_name(bit: u32) -> &'static str {
    match bit {
        7 => "Use Application Commands (bit 7)",
        8 => "View Audit Log (bit 8)",
        9 => "Priority Speaker (bit 9)",
        12 => "Send TTS Messages (bit 12)",
        18 => "Use External Emojis (bit 18)",
        19 => "View Guild Insights (bit 19)",
        25 => "Use VAD (bit 25)",
        26 => "Change Nickname (bit 26)",
        27 => "Manage Nicknames (bit 27)",
        29 => "Manage Webhooks (bit 29)",
        30 => "Manage Emojis (bit 30)",
        31 => "Use Slash Commands (bit 31)",
        32 => "Request To Speak (bit 32)",
        33 => "Manage Events (bit 33)",
        34 => "Manage Threads (bit 34)",
        35 => "Create Public Threads (bit 35)",
        36 => "Create Private Threads (bit 36)",
        37 => "Use External Stickers (bit 37)",
        38 => "Send Messages In Threads (bit 38)",
        39 => "Use Embedded Activities (bit 39)",
        40 => "Moderate Members (bit 40)",
        _ => "Unknown",
    }
}

/// POST /api/nodes/{node_id}/import-discord-template
///
/// Imports channels, roles, and permission overwrites from a Discord server template.
/// Requires ADMINISTRATOR or MANAGE_NODE permission.
pub async fn import_discord_template_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<ImportDiscordTemplateRequest>,
) -> Result<Json<ImportTemplateSummary>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    // Permission check: require Admin (ManageNode implies admin-level)
    let user_role = state
        .get_user_role_in_node(user_id, node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Permission check failed: {e}"),
                    code: 500,
                }),
            )
        })?;
    if !has_permission(user_role, Permission::ManageNode) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!(
                    "Permission denied. Required: ManageNode, Your role: {:?}",
                    user_role
                ),
                code: 403,
            }),
        ));
    }

    // Resolve template JSON
    let template_json = if let Some(json) = request.template_json {
        json
    } else if let Some(code) = request.template_code {
        let url = format!("https://discord.com/api/v10/guilds/templates/{}", code);
        let resp = reqwest::get(&url).await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Failed to fetch template: {e}"),
                    code: 502,
                }),
            )
        })?;
        if !resp.status().is_success() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Discord returned status {} for template code '{}'",
                        resp.status(),
                        code
                    ),
                    code: 400,
                }),
            ));
        }
        resp.json::<serde_json::Value>().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: format!("Invalid JSON from Discord: {e}"),
                    code: 502,
                }),
            )
        })?
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Provide either template_code or template_json".into(),
                code: 400,
            }),
        ));
    };

    // Extract serialized_source_guild
    let guild = template_json
        .get("serialized_source_guild")
        .unwrap_or(&template_json); // allow passing guild directly

    let mut summary = ImportTemplateSummary {
        roles_created: 0,
        roles_updated: 0,
        roles_skipped: 0,
        categories_created: 0,
        text_channels_created: 0,
        voice_channels_created: 0,
        overwrites_created: 0,
        unsupported_permissions_stripped: Vec::new(),
    };

    // Track stripped bits across the whole import (deduplicated)
    let mut stripped_bits_seen = std::collections::HashSet::<u32>::new();

    // Helper to map Discord permissions to Accord and track any stripped bits
    let mut mask_perms = |raw: u64| -> u64 {
        let mapped = crate::models::permission_bits::map_discord_permissions(raw);
        // Track Discord bits that have no Accord equivalent for the summary
        let supported_discord_mask: u64 = 0x10000000
            | 0x1000000
            | 0x800000
            | 0x400000
            | 0x200000
            | 0x100000
            | 0x20000
            | 0x10000
            | 0x8000
            | 0x4000
            | 0x2000
            | 0x800
            | 0x400
            | 0x40
            | 0x20
            | 0x10
            | 0x8
            | 0x4
            | 0x2
            | 0x1;
        let unsupported = raw & !supported_discord_mask;
        if unsupported != 0 {
            for bit in 0..64 {
                if unsupported & (1u64 << bit) != 0 {
                    stripped_bits_seen.insert(bit);
                }
            }
        }
        mapped
    };

    // ── 1. Import roles ──
    // Map Discord template role IDs (integers) → new Accord role UUIDs
    let mut role_id_map: HashMap<u64, Uuid> = HashMap::new();

    let roles = guild
        .get("roles")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Get the existing @everyone role for this node
    let everyone_role = state.db.get_everyone_role(node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: 500,
            }),
        )
    })?;

    for role_val in &roles {
        let discord_id = role_val.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let name = role_val
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed");
        let raw_perms_str = role_val
            .get("permissions")
            .and_then(|v| v.as_str())
            .unwrap_or("0");
        let raw_perms: u64 = raw_perms_str.parse().unwrap_or(0);
        let masked_perms = mask_perms(raw_perms);
        let color = role_val.get("color").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let hoist = role_val
            .get("hoist")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mentionable = role_val
            .get("mentionable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let unicode_emoji = role_val.get("unicode_emoji").and_then(|v| v.as_str());

        if discord_id == 0 {
            // Update the existing @everyone role
            if let Some(ref ev) = everyone_role {
                role_id_map.insert(0, ev.id);
                state
                    .db
                    .update_role(ev.id, None, None, Some(masked_perms), None, None, None)
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: e.to_string(),
                                code: 500,
                            }),
                        )
                    })?;
                summary.roles_updated += 1;
            }
            continue;
        }

        // Determine position (use array index as approximation, offset by 1 since @everyone=0)
        let position = state.db.next_role_position(node_id).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: 500,
                }),
            )
        })?;

        let new_role = state
            .db
            .create_role(
                node_id,
                name,
                color,
                masked_perms,
                position,
                hoist,
                mentionable,
                unicode_emoji,
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: 500,
                    }),
                )
            })?;

        role_id_map.insert(discord_id, new_role.id);
        summary.roles_created += 1;
    }

    // ── 2. Import channels ──
    let channels = guild
        .get("channels")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Map Discord channel IDs → Accord channel UUIDs
    let mut channel_id_map: HashMap<u64, Uuid> = HashMap::new();

    // First pass: create categories (type=4)
    for ch in &channels {
        let ch_type = ch.get("type").and_then(|v| v.as_u64()).unwrap_or(0) as i32;
        if ch_type != 4 {
            continue;
        }

        let discord_ch_id = ch.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let name = ch.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");
        let position = ch.get("position").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let icon_emoji_val = ch.get("icon_emoji");
        let icon_emoji = icon_emoji_val
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str());

        let new_id = state
            .db
            .create_channel_full(
                name, node_id, user_id, ch_type, None, position, None, false, icon_emoji,
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: 500,
                    }),
                )
            })?;

        channel_id_map.insert(discord_ch_id, new_id);
        summary.categories_created += 1;
    }

    // Second pass: create text (0) and voice (2) channels
    for ch in &channels {
        let ch_type = ch.get("type").and_then(|v| v.as_u64()).unwrap_or(0) as i32;
        if ch_type == 4 {
            continue;
        }

        // We support types 0 (text) and 2 (voice)
        if ch_type != 0 && ch_type != 2 {
            info!(
                "Skipping unsupported channel type {} for channel {:?}",
                ch_type,
                ch.get("name")
            );
            continue;
        }

        let discord_ch_id = ch.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let name = ch.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");
        let position = ch.get("position").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let topic = ch.get("topic").and_then(|v| v.as_str());
        let nsfw = ch.get("nsfw").and_then(|v| v.as_bool()).unwrap_or(false);
        let icon_emoji_val = ch.get("icon_emoji");
        let icon_emoji = icon_emoji_val
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str());

        // Resolve parent_id (Discord integer → Accord UUID)
        let parent_id = ch
            .get("parent_id")
            .and_then(|v| v.as_u64())
            .and_then(|pid| channel_id_map.get(&pid).copied());

        let new_id = state
            .db
            .create_channel_full(
                name, node_id, user_id, ch_type, parent_id, position, topic, nsfw, icon_emoji,
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: 500,
                    }),
                )
            })?;

        channel_id_map.insert(discord_ch_id, new_id);
        if ch_type == 0 {
            summary.text_channels_created += 1;
        } else {
            summary.voice_channels_created += 1;
        }
    }

    // ── 3. Import permission overwrites ──
    for ch in &channels {
        let discord_ch_id = ch.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let accord_ch_id = match channel_id_map.get(&discord_ch_id) {
            Some(id) => *id,
            None => continue, // channel was skipped
        };

        let overwrites = ch.get("permission_overwrites").and_then(|v| v.as_array());
        if let Some(overwrites) = overwrites {
            for ow in overwrites {
                // type 0 = role overwrite (we only support role overwrites for now)
                let ow_type = ow.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
                if ow_type != 0 {
                    continue;
                }

                let discord_role_id = ow.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let accord_role_id = match role_id_map.get(&discord_role_id) {
                    Some(id) => *id,
                    None => continue, // role not mapped (skipped)
                };

                let allow_str = ow.get("allow").and_then(|v| v.as_str()).unwrap_or("0");
                let deny_str = ow.get("deny").and_then(|v| v.as_str()).unwrap_or("0");
                let allow: u64 = allow_str.parse().unwrap_or(0);
                let deny: u64 = deny_str.parse().unwrap_or(0);

                let masked_allow = mask_perms(allow);
                let masked_deny = mask_perms(deny);

                state
                    .db
                    .set_channel_overwrite(accord_ch_id, accord_role_id, masked_allow, masked_deny)
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: e.to_string(),
                                code: 500,
                            }),
                        )
                    })?;
                summary.overwrites_created += 1;
            }
        }
    }

    // Build stripped bits summary
    let mut stripped: Vec<String> = stripped_bits_seen
        .iter()
        .map(|&bit| {
            let name = discord_bit_name(bit);
            if name == "Unknown" {
                format!("Unknown (bit {})", bit)
            } else {
                name.to_string()
            }
        })
        .collect();
    stripped.sort();
    summary.unsupported_permissions_stripped = stripped;

    info!(
        "Discord template imported into node {}: {} roles, {} categories, {} text, {} voice, {} overwrites",
        node_id, summary.roles_created, summary.categories_created,
        summary.text_channels_created, summary.voice_channels_created, summary.overwrites_created
    );

    Ok(Json(summary))
}

/// Link preview endpoint — fetches Open Graph metadata for a URL
pub async fn link_preview_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Auth check
    let _user_id = extract_user_from_token(&state, &params).await?;

    let url = params.get("url").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing 'url' query parameter".into(),
                code: 400,
            }),
        )
    })?;

    // Validate URL scheme
    let parsed = url::Url::parse(url).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid URL".into(),
                code: 400,
            }),
        )
    })?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Only http/https URLs are allowed".into(),
                    code: 400,
                }),
            ));
        }
    }

    // SSRF protection: block private/reserved IPs
    if let Some(host) = parsed.host_str() {
        let is_private = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.is_unspecified()
                        || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64
                    // 100.64.0.0/10
                }
                std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
            },
            Err(_) => {
                // It's a hostname — block localhost variants
                host == "localhost"
                    || host.ends_with(".local")
                    || host.ends_with(".internal")
                    || host == "0.0.0.0"
                    || host == "[::]"
            }
        };
        if is_private {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "URL points to a private/reserved address".into(),
                    code: 400,
                }),
            ));
        }
    }

    let url_string = url.to_string();

    // Check cache (TTL: 1 hour)
    {
        let cache = state.link_preview_cache.read().await;
        if let Some((cached, fetched_at)) = cache.get(&url_string) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now - fetched_at < 3600 {
                return Ok(Json(cached.clone()));
            }
        }
    }

    // Fetch the URL
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| {
            error!("Failed to build HTTP client: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal error".into(),
                    code: 500,
                }),
            )
        })?;

    let response = client
        .get(&url_string)
        .header("User-Agent", "Accord LinkPreview/1.0")
        .send()
        .await
        .map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: "Failed to fetch URL".into(),
                    code: 502,
                }),
            )
        })?;

    // Check content length (1MB limit)
    if let Some(len) = response.content_length() {
        if len > 1_048_576 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Response too large".into(),
                    code: 400,
                }),
            ));
        }
    }

    let body = response.text().await.map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: "Failed to read response body".into(),
                code: 502,
            }),
        )
    })?;

    // Truncate to 1MB if needed
    let body = if body.len() > 1_048_576 {
        &body[..1_048_576]
    } else {
        &body
    };

    // Parse OG tags and title with simple string scanning
    let mut og_title: Option<String> = None;
    let mut og_description: Option<String> = None;
    let mut og_image: Option<String> = None;
    let mut og_site_name: Option<String> = None;
    let mut html_title: Option<String> = None;

    // Find meta tags with og: properties
    let body_lower = body.to_lowercase();
    for cap in find_meta_tags(body) {
        let lower = cap.to_lowercase();
        if lower.contains("og:title") {
            og_title = extract_content(&cap);
        } else if lower.contains("og:description") {
            og_description = extract_content(&cap);
        } else if lower.contains("og:image") && !lower.contains("og:image:") {
            og_image = extract_content(&cap);
        } else if lower.contains("og:site_name") {
            og_site_name = extract_content(&cap);
        }
    }

    // Fallback: extract <title>
    if let Some(start) = body_lower.find("<title") {
        if let Some(gt) = body_lower[start..].find('>') {
            let after = start + gt + 1;
            if let Some(end) = body_lower[after..].find("</title") {
                html_title = Some(body[after..after + end].trim().to_string());
            }
        }
    }

    let title = og_title.or(html_title);
    let result = serde_json::json!({
        "title": title,
        "description": og_description,
        "image": og_image,
        "siteName": og_site_name,
        "url": url_string,
    });

    // Cache the result
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut cache = state.link_preview_cache.write().await;
        // Evict if cache is too large
        if cache.len() > 1000 {
            cache.clear();
        }
        cache.insert(url_string, (result.clone(), now));
    }

    Ok(Json(result))
}

/// Find all <meta ...> tags in HTML
fn find_meta_tags(html: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let lower = html.to_lowercase();
    let mut search_from = 0;
    while let Some(start) = lower[search_from..].find("<meta ") {
        let abs_start = search_from + start;
        if let Some(end) = html[abs_start..].find('>') {
            tags.push(html[abs_start..abs_start + end + 1].to_string());
            search_from = abs_start + end + 1;
        } else {
            break;
        }
    }
    tags
}

/// Extract content="..." from a meta tag
fn extract_content(tag: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let idx = lower.find("content=")?;
    let after = &tag[idx + 8..];
    if let Some(stripped) = after.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(html_decode(&stripped[..end]))
    } else if let Some(stripped) = after.strip_prefix('\'') {
        let end = stripped.find('\'')?;
        Some(html_decode(&stripped[..end]))
    } else {
        let end = after
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(after.len());
        Some(html_decode(&after[..end]))
    }
}

// ── User block endpoints ──

/// Block a user (POST /users/:id/block)
pub async fn block_user_handler(
    State(state): State<SharedState>,
    Path(target_user_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    if user_id == target_user_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot block yourself".into(),
                code: 400,
            }),
        ));
    }

    // Verify target user exists
    if state
        .db
        .get_user_by_id(target_user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {}", e),
                    code: 500,
                }),
            )
        })?
        .is_none()
    {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User not found".into(),
                code: 404,
            }),
        ));
    }

    state
        .db
        .block_user(user_id, target_user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to block user: {}", e),
                    code: 500,
                }),
            )
        })?;

    Ok(Json(
        serde_json::json!({ "status": "blocked", "user_id": target_user_id }),
    ))
}

/// Unblock a user (DELETE /users/:id/block)
pub async fn unblock_user_handler(
    State(state): State<SharedState>,
    Path(target_user_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let removed = state
        .db
        .unblock_user(user_id, target_user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to unblock user: {}", e),
                    code: 500,
                }),
            )
        })?;

    if removed {
        Ok(Json(
            serde_json::json!({ "status": "unblocked", "user_id": target_user_id }),
        ))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "User was not blocked".into(),
                code: 404,
            }),
        ))
    }
}

/// List blocked users (GET /api/blocked-users)
pub async fn get_blocked_users_handler(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &params).await?;

    let blocked = state.db.get_blocked_users(user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get blocked users: {}", e),
                code: 500,
            }),
        )
    })?;

    let blocked_json: Vec<serde_json::Value> = blocked
        .into_iter()
        .map(|(id, created_at)| serde_json::json!({ "user_id": id, "created_at": created_at }))
        .collect();

    Ok(Json(serde_json::json!({ "blocked_users": blocked_json })))
}

/// Basic HTML entity decoding
fn html_decode(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&apos;", "'")
}
