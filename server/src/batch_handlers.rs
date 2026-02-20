//! Batch API handlers to eliminate N+1 query patterns.
//!
//! These endpoints return aggregated data in single responses,
//! avoiding the need for multiple round-trips from the frontend.

use crate::handlers::extract_user_from_token;
use crate::models::ErrorResponse;
use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use std::collections::HashMap;
use uuid::Uuid;

/// Verify that `user_id` is a member of `node_id`, returning a 403 error if not.
async fn require_node_membership(
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
                error: "Must be a member of the node".into(),
                code: 403,
            }),
        ));
    }
    Ok(())
}

/// `GET /api/nodes/:node_id/members/batch`
///
/// Returns all members with their roles, display names, and online status
/// in a single response, avoiding N+1 queries for member details.
pub async fn batch_members_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_node_membership(&state, user_id, node_id).await?;

    // Fetch members with profiles (single JOIN query)
    let members = state
        .get_node_members_with_profiles(node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get members: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Fetch all roles for the node
    let all_roles = state.db.get_node_roles(node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get roles: {}", e),
                code: 500,
            }),
        )
    })?;

    // Get online status
    let connections = state.connections.read().await;

    // Build response with roles for each member
    let mut result = Vec::with_capacity(members.len());
    for member in &members {
        // Get this member's assigned roles
        let member_roles = state
            .db
            .get_member_roles(node_id, member.user_id)
            .await
            .unwrap_or_default();

        let roles_json: Vec<serde_json::Value> = member_roles
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "name": r.name,
                    "color": r.color,
                    "position": r.position,
                    "hoist": r.hoist,
                })
            })
            .collect();

        let online = connections.contains_key(&member.user_id);
        let status = if online {
            member.profile.status.as_str()
        } else {
            "offline"
        };

        result.push(serde_json::json!({
            "user_id": member.user_id,
            "display_name": member.profile.display_name,
            "avatar_url": member.profile.avatar_url,
            "roles": roles_json,
            "online": online,
            "status": status,
            "custom_status": member.profile.custom_status,
            "joined_at": member.joined_at,
            "node_role": member.role,
        }));
    }
    drop(connections);

    // Include the full role list so the client has the complete hierarchy
    let roles_json: Vec<serde_json::Value> =
        all_roles.iter().map(|r| serde_json::json!(r)).collect();

    Ok(Json(serde_json::json!({
        "members": result,
        "roles": roles_json,
    })))
}

/// `GET /api/nodes/:node_id/channels/batch`
///
/// Returns all channels with their permission overrides and unread counts
/// in a single response, avoiding N+1 queries for channel details.
pub async fn batch_channels_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_node_membership(&state, user_id, node_id).await?;

    // Fetch channels with categories (single JOIN query)
    let channels = state
        .db
        .get_channels_with_categories(node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get channels: {}", e),
                    code: 500,
                }),
            )
        })?;

    let mut result = Vec::with_capacity(channels.len());
    for ch in &channels {
        // Get permission overwrites for this channel
        let overwrites = state
            .db
            .get_channel_overwrites(ch.id)
            .await
            .unwrap_or_default();

        let overwrites_json: Vec<serde_json::Value> = overwrites
            .iter()
            .map(|o| {
                serde_json::json!({
                    "role_id": o.role_id,
                    "allow": o.allow,
                    "deny": o.deny,
                })
            })
            .collect();

        // Get unread count for this user
        let unread_count = state.db.get_unread_count(user_id, ch.id).await.unwrap_or(0);

        result.push(serde_json::json!({
            "id": ch.id,
            "name": ch.name,
            "node_id": ch.node_id,
            "category_id": ch.category_id,
            "category_name": ch.category_name,
            "position": ch.position,
            "permission_overrides": overwrites_json,
            "unread_count": unread_count,
        }));
    }

    Ok(Json(serde_json::json!({
        "channels": result,
    })))
}

/// `GET /api/nodes/:node_id/overview`
///
/// Returns node info + channels + members + roles in a single call,
/// designed for the initial node load to avoid multiple round-trips.
pub async fn node_overview_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_node_membership(&state, user_id, node_id).await?;

    // 1. Node info
    let node_info = state.get_node_info(node_id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e,
                code: 404,
            }),
        )
    })?;

    // 2. Roles
    let roles = state.db.get_node_roles(node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to get roles: {}", e),
                code: 500,
            }),
        )
    })?;

    // 3. Members with profiles
    let members = state
        .get_node_members_with_profiles(node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get members: {}", e),
                    code: 500,
                }),
            )
        })?;

    // 4. Channels with categories
    let channels = state
        .db
        .get_channels_with_categories(node_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get channels: {}", e),
                    code: 500,
                }),
            )
        })?;

    // Build member details with roles and online status
    let connections = state.connections.read().await;
    let mut members_json = Vec::with_capacity(members.len());
    for m in &members {
        let member_roles = state
            .db
            .get_member_roles(node_id, m.user_id)
            .await
            .unwrap_or_default();

        let roles_json: Vec<serde_json::Value> = member_roles
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "name": r.name,
                    "color": r.color,
                    "position": r.position,
                })
            })
            .collect();

        let online = connections.contains_key(&m.user_id);
        members_json.push(serde_json::json!({
            "user_id": m.user_id,
            "display_name": m.profile.display_name,
            "avatar_url": m.profile.avatar_url,
            "roles": roles_json,
            "online": online,
            "status": if online { &m.profile.status } else { "offline" },
            "joined_at": m.joined_at,
            "node_role": m.role,
        }));
    }
    drop(connections);

    // Build channel details with unread counts
    let channels_json: Vec<serde_json::Value> = {
        let mut ch_result = Vec::with_capacity(channels.len());
        for ch in &channels {
            let unread_count = state.db.get_unread_count(user_id, ch.id).await.unwrap_or(0);
            ch_result.push(serde_json::json!({
                "id": ch.id,
                "name": ch.name,
                "node_id": ch.node_id,
                "category_id": ch.category_id,
                "category_name": ch.category_name,
                "position": ch.position,
                "unread_count": unread_count,
            }));
        }
        ch_result
    };

    Ok(Json(serde_json::json!({
        "node": node_info,
        "channels": channels_json,
        "members": members_json,
        "roles": roles,
    })))
}
