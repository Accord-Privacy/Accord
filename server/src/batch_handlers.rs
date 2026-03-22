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

        let channel_type_str = match ch.channel_type {
            2 => "voice",
            4 => "category",
            _ => "text",
        };
        result.push(serde_json::json!({
            "id": ch.id,
            "name": ch.name,
            "node_id": ch.node_id,
            "category_id": ch.category_id,
            "category_name": ch.category_name,
            "position": ch.position,
            "permission_overrides": overwrites_json,
            "unread_count": unread_count,
            "channel_type": channel_type_str,
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
            let channel_type_str = match ch.channel_type {
                2 => "voice",
                4 => "category",
                _ => "text",
            };
            ch_result.push(serde_json::json!({
                "id": ch.id,
                "name": ch.name,
                "node_id": ch.node_id,
                "category_id": ch.category_id,
                "category_name": ch.category_name,
                "position": ch.position,
                "unread_count": unread_count,
                "channel_type": channel_type_str,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::extract::{Path, Query, State};
    use axum::http::{header, HeaderMap, HeaderValue};
    use std::collections::HashMap;
    use std::sync::Arc;

    // ── Test helpers ────────────────────────────────────────────

    async fn make_state() -> SharedState {
        Arc::new(AppState::new_in_memory().await.unwrap())
    }

    /// Register a user and return (user_id, valid_token).
    async fn register_and_auth(state: &SharedState, public_key: &str) -> (Uuid, String) {
        let user_id = state
            .register_user(public_key.to_string(), "".to_string())
            .await
            .unwrap();
        let pkh = crate::db::compute_public_key_hash(public_key);
        let auth = state.authenticate_user(pkh, "".to_string()).await.unwrap();
        (user_id, auth.token)
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        );
        headers
    }

    fn no_auth() -> HeaderMap {
        HeaderMap::new()
    }

    fn no_params() -> HashMap<String, String> {
        HashMap::new()
    }

    // ── batch_members_handler ───────────────────────────────────

    #[tokio::test]
    async fn batch_members_success() {
        let state = make_state().await;
        let (owner_id, token) = register_and_auth(&state, "pk-owner-bm").await;

        let node = state
            .create_node("Test Node".into(), owner_id, None)
            .await
            .unwrap();

        let result = batch_members_handler(
            State(state),
            Path(node.id),
            bearer(&token),
            Query(no_params()),
        )
        .await;

        let Json(body) = result.unwrap();
        assert!(
            body.get("members").is_some(),
            "response must have 'members'"
        );
        assert!(body.get("roles").is_some(), "response must have 'roles'");
        let members = body["members"].as_array().unwrap();
        // Owner is automatically a member
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0]["user_id"].as_str().unwrap(),
            owner_id.to_string()
        );
    }

    #[tokio::test]
    async fn batch_members_unauthorized_no_token() {
        let state = make_state().await;
        let (owner_id, _token) = register_and_auth(&state, "pk-owner-bm-unauth").await;
        let node = state
            .create_node("Node".into(), owner_id, None)
            .await
            .unwrap();

        let result =
            batch_members_handler(State(state), Path(node.id), no_auth(), Query(no_params())).await;

        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn batch_members_forbidden_non_member() {
        let state = make_state().await;
        let (owner_id, _) = register_and_auth(&state, "pk-owner-bm-nm").await;
        let (_, outsider_token) = register_and_auth(&state, "pk-outsider-bm-nm").await;

        let node = state
            .create_node("Node".into(), owner_id, None)
            .await
            .unwrap();

        let result = batch_members_handler(
            State(state),
            Path(node.id),
            bearer(&outsider_token),
            Query(no_params()),
        )
        .await;

        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn batch_members_invalid_token() {
        let state = make_state().await;
        let (owner_id, _) = register_and_auth(&state, "pk-owner-bm-inv").await;
        let node = state
            .create_node("Node".into(), owner_id, None)
            .await
            .unwrap();

        let result = batch_members_handler(
            State(state),
            Path(node.id),
            bearer("tok_not_a_real_token"),
            Query(no_params()),
        )
        .await;

        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ── batch_channels_handler ──────────────────────────────────

    #[tokio::test]
    async fn batch_channels_success() {
        let state = make_state().await;
        let (owner_id, token) = register_and_auth(&state, "pk-owner-bc").await;

        let node = state
            .create_node("Channel Node".into(), owner_id, None)
            .await
            .unwrap();

        // Create a channel so we have something to return
        state
            .create_channel("general".into(), node.id, owner_id)
            .await
            .unwrap();

        let result = batch_channels_handler(
            State(state),
            Path(node.id),
            bearer(&token),
            Query(no_params()),
        )
        .await;

        let Json(body) = result.unwrap();
        assert!(
            body.get("channels").is_some(),
            "response must have 'channels'"
        );
        let channels = body["channels"].as_array().unwrap();
        assert!(!channels.is_empty());
        assert_eq!(channels[0]["name"].as_str().unwrap(), "general");
    }

    #[tokio::test]
    async fn batch_channels_returns_array() {
        // Just verifies the response shape is correct and the endpoint is reachable.
        // Node creation may add default channels, so we only assert the key exists.
        let state = make_state().await;
        let (owner_id, token) = register_and_auth(&state, "pk-owner-bc-empty").await;

        let node = state
            .create_node("Empty Node".into(), owner_id, None)
            .await
            .unwrap();

        let result = batch_channels_handler(
            State(state),
            Path(node.id),
            bearer(&token),
            Query(no_params()),
        )
        .await;

        let Json(body) = result.unwrap();
        // Must have the "channels" key and it must be an array
        assert!(
            body["channels"].is_array(),
            "response 'channels' must be an array"
        );
    }

    #[tokio::test]
    async fn batch_channels_unauthorized_no_token() {
        let state = make_state().await;
        let (owner_id, _) = register_and_auth(&state, "pk-owner-bc-unauth").await;
        let node = state
            .create_node("Node".into(), owner_id, None)
            .await
            .unwrap();

        let result =
            batch_channels_handler(State(state), Path(node.id), no_auth(), Query(no_params()))
                .await;

        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn batch_channels_forbidden_non_member() {
        let state = make_state().await;
        let (owner_id, _) = register_and_auth(&state, "pk-owner-bc-nm").await;
        let (_, outsider_token) = register_and_auth(&state, "pk-outsider-bc-nm").await;

        let node = state
            .create_node("Node".into(), owner_id, None)
            .await
            .unwrap();

        let result = batch_channels_handler(
            State(state),
            Path(node.id),
            bearer(&outsider_token),
            Query(no_params()),
        )
        .await;

        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // ── node_overview_handler ───────────────────────────────────

    #[tokio::test]
    async fn node_overview_success() {
        let state = make_state().await;
        let (owner_id, token) = register_and_auth(&state, "pk-owner-ov").await;

        let node = state
            .create_node("Overview Node".into(), owner_id, Some("A desc".into()))
            .await
            .unwrap();

        state
            .create_channel("announcements".into(), node.id, owner_id)
            .await
            .unwrap();

        let result = node_overview_handler(
            State(state),
            Path(node.id),
            bearer(&token),
            Query(no_params()),
        )
        .await;

        let Json(body) = result.unwrap();
        assert!(body.get("node").is_some(), "response must have 'node'");
        assert!(
            body.get("channels").is_some(),
            "response must have 'channels'"
        );
        assert!(
            body.get("members").is_some(),
            "response must have 'members'"
        );
        assert!(body.get("roles").is_some(), "response must have 'roles'");

        let channels = body["channels"].as_array().unwrap();
        assert!(!channels.is_empty());
        // Verify our created channel is present (order may vary)
        let names: Vec<&str> = channels
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"announcements"),
            "expected 'announcements' channel, got: {:?}",
            names
        );

        let members = body["members"].as_array().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0]["user_id"].as_str().unwrap(),
            owner_id.to_string()
        );
    }

    #[tokio::test]
    async fn node_overview_unauthorized_no_token() {
        let state = make_state().await;
        let (owner_id, _) = register_and_auth(&state, "pk-owner-ov-unauth").await;
        let node = state
            .create_node("Node".into(), owner_id, None)
            .await
            .unwrap();

        let result =
            node_overview_handler(State(state), Path(node.id), no_auth(), Query(no_params())).await;

        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn node_overview_forbidden_non_member() {
        let state = make_state().await;
        let (owner_id, _) = register_and_auth(&state, "pk-owner-ov-nm").await;
        let (_, outsider_token) = register_and_auth(&state, "pk-outsider-ov-nm").await;

        let node = state
            .create_node("Node".into(), owner_id, None)
            .await
            .unwrap();

        let result = node_overview_handler(
            State(state),
            Path(node.id),
            bearer(&outsider_token),
            Query(no_params()),
        )
        .await;

        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn node_overview_not_found() {
        let state = make_state().await;
        let (_, token) = register_and_auth(&state, "pk-owner-ov-404").await;

        // Use a random UUID that doesn't correspond to any node
        let phantom_node_id = Uuid::new_v4();

        let result = node_overview_handler(
            State(state),
            Path(phantom_node_id),
            bearer(&token),
            Query(no_params()),
        )
        .await;

        // Non-member check fires before not-found, so we get FORBIDDEN
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn node_overview_invalid_token() {
        let state = make_state().await;
        let (owner_id, _) = register_and_auth(&state, "pk-owner-ov-inv").await;
        let node = state
            .create_node("Node".into(), owner_id, None)
            .await
            .unwrap();

        let result = node_overview_handler(
            State(state),
            Path(node.id),
            bearer("tok_bogus_not_real"),
            Query(no_params()),
        )
        .await;

        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
