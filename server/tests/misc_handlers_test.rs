//! Integration tests for misc handlers:
//! user profiles, build allowlist, node members, push tokens, audit log,
//! build info, link preview, node presence, and file listing.
#![allow(clippy::all, unused_imports, dead_code)]

use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

use accord_server::{
    handlers::*,
    state::{AppState, SharedState},
};

// ─────────────────────────────────────────────────
//  TestServer helper
// ─────────────────────────────────────────────────

struct TestServer {
    base_url: String,
    client: Client,
    state: SharedState,
}

impl TestServer {
    async fn new() -> Self {
        let state: SharedState = Arc::new(AppState::new_in_memory().await.unwrap());

        let app = Router::new()
            // Auth
            .route("/register", post(register_handler))
            .route("/auth", post(auth_handler))
            // Build info
            .route("/api/build-info", get(build_info_handler))
            // Nodes
            .route(
                "/nodes",
                get(list_user_nodes_handler).post(create_node_handler),
            )
            .route("/nodes/:id", get(get_node_handler))
            .route("/nodes/:id", axum::routing::patch(update_node_handler))
            .route("/nodes/:id/join", post(join_node_handler))
            .route("/nodes/:id/leave", post(leave_node_handler))
            .route(
                "/nodes/:id/channels",
                get(list_node_channels_handler).post(create_channel_handler),
            )
            .route("/nodes/:id/members", get(get_node_members_handler))
            .route("/nodes/:id/members/:user_id", delete(kick_user_handler))
            // Invites
            .route(
                "/nodes/:id/invites",
                post(create_invite_handler).get(list_invites_handler),
            )
            .route("/invites/:invite_id", delete(revoke_invite_handler))
            .route("/invites/:code/preview", get(invite_preview_handler))
            .route("/invites/:code/join", post(use_invite_handler))
            // Presence
            .route("/api/presence/:id", get(get_node_presence_handler))
            // User profiles
            .route("/users/:id/profile", get(get_user_profile_handler))
            .route(
                "/users/me/profile",
                axum::routing::patch(update_user_profile_handler),
            )
            // Build allowlist
            .route(
                "/nodes/:id/build-allowlist",
                get(get_build_allowlist_handler)
                    .put(set_build_allowlist_handler)
                    .post(add_build_allowlist_handler),
            )
            .route(
                "/nodes/:id/build-allowlist/:hash",
                delete(remove_build_allowlist_handler),
            )
            // Audit log
            .route("/nodes/:id/audit-log", get(get_node_audit_log_handler))
            // Push tokens
            .route(
                "/push/register",
                post(register_push_token_handler).delete(deregister_push_token_handler),
            )
            .route(
                "/push/preferences",
                axum::routing::put(update_push_preferences_handler),
            )
            // Link preview
            .route("/api/link-preview", get(link_preview_handler))
            // Files
            .route("/channels/:id/files", get(list_channel_files_handler))
            .with_state(state.clone())
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(
                        CorsLayer::new()
                            .allow_methods(Any)
                            .allow_headers(Any)
                            .allow_origin(Any),
                    ),
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{}", addr);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            base_url,
            client: Client::new(),
            state,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Register a user and return (user_id, token).
    async fn register_and_auth(&self, name: &str) -> (Uuid, String) {
        let pk = format!("misc_test_pk_{}", name);

        let resp = self
            .client
            .post(&self.url("/register"))
            .json(&json!({ "public_key": pk }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "register failed for {name}");
        let body: Value = resp.json().await.unwrap();
        let user_id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();

        let resp = self
            .client
            .post(&self.url("/auth"))
            .json(&json!({ "public_key": pk, "password": "" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "auth failed for {name}");
        let body: Value = resp.json().await.unwrap();
        let token = body["token"].as_str().unwrap().to_string();

        (user_id, token)
    }

    /// Create a node, return node_id.
    async fn create_node(&self, token: &str, name: &str) -> Uuid {
        let resp = self
            .client
            .post(&format!("{}/nodes?token={}", self.base_url, token))
            .json(&json!({ "name": name }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create_node failed");
        let body: Value = resp.json().await.unwrap();
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
    }

    /// Create a channel in a node, return channel_id.
    async fn create_channel(&self, token: &str, node_id: Uuid, name: &str) -> Uuid {
        let resp = self
            .client
            .post(&format!(
                "{}/nodes/{}/channels?token={}",
                self.base_url, node_id, token
            ))
            .json(&json!({ "name": name }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create_channel failed");
        let body: Value = resp.json().await.unwrap();
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
    }

    /// Have `token` join `node_id`.
    async fn join_node(&self, token: &str, node_id: Uuid) {
        let resp = self
            .client
            .post(&format!(
                "{}/nodes/{}/join?token={}",
                self.base_url, node_id, token
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "join_node failed");
    }
}

// ═══════════════════════════════════════════════════════════════
//  1. User Profiles
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_update_user_profile_success() {
    let server = TestServer::new().await;
    let (_user_id, token) = server.register_and_auth("profile_upd_user").await;

    let resp = server
        .client
        .patch(&format!("{}/users/me/profile?token={}", server.base_url, token))
        .json(&json!({
            "display_name": "Test User",
            "bio": "Hello world",
            "status": "online"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
}

#[tokio::test]
async fn test_update_user_profile_unauthorized() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .patch(&format!("{}/users/me/profile", server.base_url))
        .json(&json!({ "display_name": "Ghost" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_update_user_profile_invalid_status() {
    let server = TestServer::new().await;
    let (_user_id, token) = server.register_and_auth("profile_bad_status").await;

    let resp = server
        .client
        .patch(&format!("{}/users/me/profile?token={}", server.base_url, token))
        .json(&json!({ "status": "invisible" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_get_user_profile_success() {
    let server = TestServer::new().await;
    let (user_id, token) = server.register_and_auth("profile_get_user").await;

    // Update profile so there's something to retrieve
    server
        .client
        .patch(&format!("{}/users/me/profile?token={}", server.base_url, token))
        .json(&json!({ "display_name": "GetMe", "bio": "bio text", "status": "online" }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/users/{}/profile?token={}",
            server.base_url, user_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Profile should have a user_id field
    assert_eq!(body["user_id"], user_id.to_string());
}

#[tokio::test]
async fn test_get_user_profile_not_found() {
    let server = TestServer::new().await;
    let (_user_id, token) = server.register_and_auth("profile_get_nf").await;

    let fake_id = Uuid::new_v4();
    let resp = server
        .client
        .get(&format!(
            "{}/users/{}/profile?token={}",
            server.base_url, fake_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_user_profile_unauthorized() {
    let server = TestServer::new().await;
    let (user_id, _token) = server.register_and_auth("profile_get_unauth").await;

    let resp = server
        .client
        .get(&format!("{}/users/{}/profile", server.base_url, user_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  2. Build Allowlist
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_build_allowlist_owner_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_get_owner").await;
    let node_id = server.create_node(&owner_token, "AllowListNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/build-allowlist?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["allowlist"].is_array());
}

#[tokio::test]
async fn test_get_build_allowlist_member_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_get_own2").await;
    let (_, member_token) = server.register_and_auth("allow_get_mem").await;
    let node_id = server.create_node(&owner_token, "AllowListForbNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/build-allowlist?token={}",
            server.base_url, node_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_get_build_allowlist_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_get_unauth").await;
    let node_id = server.create_node(&owner_token, "AllowListUnauthNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/build-allowlist",
            server.base_url, node_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_add_build_allowlist_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_add_owner").await;
    let node_id = server.create_node(&owner_token, "AllowAddNode").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/build-allowlist?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({
            "build_hash": "abc123def456",
            "label": "v1.0.0"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["status"] == "added" || body["status"] == "already_exists",
        "Expected 'added' or 'already_exists', got: {}",
        body
    );
    assert_eq!(body["build_hash"], "abc123def456");
}

#[tokio::test]
async fn test_add_build_allowlist_idempotent() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_idem_owner").await;
    let node_id = server.create_node(&owner_token, "AllowIdemNode").await;

    let payload = json!({
        "build_hash": "deadbeef1234",
        "label": "test-build"
    });

    // Add first time
    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/build-allowlist?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "added");

    // Add again — should return "already_exists" not an error
    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/build-allowlist?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "already_exists");
}

#[tokio::test]
async fn test_add_build_allowlist_member_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_add_own2").await;
    let (_, member_token) = server.register_and_auth("allow_add_mem").await;
    let node_id = server.create_node(&owner_token, "AllowAddForbNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/build-allowlist?token={}",
            server.base_url, node_id, member_token
        ))
        .json(&json!({ "build_hash": "nope", "label": null }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_set_build_allowlist_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_set_owner").await;
    let node_id = server.create_node(&owner_token, "AllowSetNode").await;

    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/build-allowlist?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!([
            { "build_hash": "hash1111", "label": "build-A" },
            { "build_hash": "hash2222", "label": "build-B" }
        ]))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    assert_eq!(body["count"], 2);
}

#[tokio::test]
async fn test_set_build_allowlist_member_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_set_own2").await;
    let (_, member_token) = server.register_and_auth("allow_set_mem").await;
    let node_id = server.create_node(&owner_token, "AllowSetForbNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/build-allowlist?token={}",
            server.base_url, node_id, member_token
        ))
        .json(&json!([]))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_remove_build_allowlist_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_rm_owner").await;
    let node_id = server.create_node(&owner_token, "AllowRmNode").await;

    // Add a hash first
    server
        .client
        .post(&format!(
            "{}/nodes/{}/build-allowlist?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "build_hash": "removeme123", "label": null }))
        .send()
        .await
        .unwrap();

    // Remove it
    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/build-allowlist/removeme123?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "removed");
    assert_eq!(body["build_hash"], "removeme123");
}

#[tokio::test]
async fn test_remove_build_allowlist_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_rm_nf").await;
    let node_id = server.create_node(&owner_token, "AllowRmNfNode").await;

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/build-allowlist/ghosthash?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_remove_build_allowlist_member_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("allow_rm_own2").await;
    let (_, member_token) = server.register_and_auth("allow_rm_mem").await;
    let node_id = server.create_node(&owner_token, "AllowRmForbNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/build-allowlist/somehash?token={}",
            server.base_url, node_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  3. Node Members & User Nodes
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_node_members_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("members_own").await;
    let (_, member_token) = server.register_and_auth("members_mem").await;
    let node_id = server.create_node(&owner_token, "MembersNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/members?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["members"].is_array());
    let members = body["members"].as_array().unwrap();
    assert!(members.len() >= 2, "Should have owner + member");
}

#[tokio::test]
async fn test_get_node_members_forbidden_for_non_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("members_own2").await;
    let (_, stranger_token) = server.register_and_auth("members_stranger").await;
    let node_id = server.create_node(&owner_token, "MembersForbNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/members?token={}",
            server.base_url, node_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_get_node_members_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("members_unauth").await;
    let node_id = server.create_node(&owner_token, "MembersUnauthNode").await;

    let resp = server
        .client
        .get(&format!("{}/nodes/{}/members", server.base_url, node_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_list_user_nodes_success() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("user_nodes_user").await;

    // Create two nodes
    server.create_node(&token, "UserNodeA").await;
    server.create_node(&token, "UserNodeB").await;

    let resp = server
        .client
        .get(&format!("{}/nodes?token={}", server.base_url, token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let nodes = body.as_array().unwrap();
    assert!(nodes.len() >= 2);
    let names: Vec<&str> = nodes.iter().filter_map(|n| n["name"].as_str()).collect();
    assert!(names.contains(&"UserNodeA"));
    assert!(names.contains(&"UserNodeB"));
}

#[tokio::test]
async fn test_list_user_nodes_empty() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("user_nodes_empty").await;

    let resp = server
        .client
        .get(&format!("{}/nodes?token={}", server.base_url, token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // New user has no nodes
    let nodes = body.as_array().unwrap();
    assert_eq!(nodes.len(), 0);
}

#[tokio::test]
async fn test_list_user_nodes_unauthorized() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(&format!("{}/nodes", server.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  4. Push Tokens
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_register_push_token_success() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("push_reg_user").await;

    let resp = server
        .client
        .post(&format!("{}/push/register?token={}", server.base_url, token))
        .json(&json!({
            "platform": "ios",
            "token": "device-token-abc-123",
            "privacy_level": "partial"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "registered");
    assert!(body["id"].is_string());
}

#[tokio::test]
async fn test_register_push_token_android() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("push_android_user").await;

    let resp = server
        .client
        .post(&format!("{}/push/register?token={}", server.base_url, token))
        .json(&json!({
            "platform": "android",
            "token": "fcm-device-token-xyz",
            "privacy_level": "full"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "registered");
}

#[tokio::test]
async fn test_register_push_token_empty_token() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("push_empty_user").await;

    let resp = server
        .client
        .post(&format!("{}/push/register?token={}", server.base_url, token))
        .json(&json!({
            "platform": "ios",
            "token": ""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_register_push_token_unauthorized() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .post(&format!("{}/push/register", server.base_url))
        .json(&json!({
            "platform": "ios",
            "token": "some-token"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_deregister_push_token_success() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("push_dereg_user").await;

    let device_token = "my-device-token-999";

    // Register first
    let resp = server
        .client
        .post(&format!("{}/push/register?token={}", server.base_url, token))
        .json(&json!({
            "platform": "ios",
            "token": device_token
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Now deregister
    let resp = server
        .client
        .delete(&format!("{}/push/register?token={}", server.base_url, token))
        .json(&json!({ "token": device_token }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "deregistered");
}

#[tokio::test]
async fn test_deregister_push_token_not_found() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("push_dereg_nf").await;

    let resp = server
        .client
        .delete(&format!("{}/push/register?token={}", server.base_url, token))
        .json(&json!({ "token": "nonexistent-token" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_deregister_push_token_unauthorized() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .delete(&format!("{}/push/register", server.base_url))
        .json(&json!({ "token": "some-token" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_update_push_preferences_success() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("push_pref_user").await;

    let device_token = "pref-device-token-001";

    // Register a token first
    server
        .client
        .post(&format!("{}/push/register?token={}", server.base_url, token))
        .json(&json!({
            "platform": "ios",
            "token": device_token,
            "privacy_level": "partial"
        }))
        .send()
        .await
        .unwrap();

    // Update preferences
    let resp = server
        .client
        .put(&format!("{}/push/preferences?token={}", server.base_url, token))
        .json(&json!({
            "privacy_level": "stealth",
            "token": device_token
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    assert!(body["tokens_updated"].as_u64().unwrap_or(0) >= 1);
}

#[tokio::test]
async fn test_update_push_preferences_no_tokens() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("push_pref_empty").await;

    // No tokens registered — should return 404
    let resp = server
        .client
        .put(&format!("{}/push/preferences?token={}", server.base_url, token))
        .json(&json!({ "privacy_level": "full" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_update_push_preferences_unauthorized() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .put(&format!("{}/push/preferences", server.base_url))
        .json(&json!({ "privacy_level": "full" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  5. Audit Log
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_audit_log_owner_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("audit_owner").await;
    let node_id = server.create_node(&owner_token, "AuditNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/audit-log?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["entries"].is_array());
    assert!(body["has_more"].is_boolean());
}

#[tokio::test]
async fn test_get_audit_log_member_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("audit_own2").await;
    let (_, member_token) = server.register_and_auth("audit_mem").await;
    let node_id = server.create_node(&owner_token, "AuditForbNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/audit-log?token={}",
            server.base_url, node_id, member_token
        ))
        .send()
        .await
        .unwrap();

    // Members without ViewAuditLog permission should be forbidden
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_get_audit_log_non_member_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("audit_own3").await;
    let (_, stranger_token) = server.register_and_auth("audit_stranger").await;
    let node_id = server.create_node(&owner_token, "AuditStrangerNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/audit-log?token={}",
            server.base_url, node_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_get_audit_log_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("audit_unauth").await;
    let node_id = server.create_node(&owner_token, "AuditUnauthNode").await;

    let resp = server
        .client
        .get(&format!("{}/nodes/{}/audit-log", server.base_url, node_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_get_audit_log_with_limit() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("audit_limit").await;
    let node_id = server.create_node(&owner_token, "AuditLimitNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/audit-log?token={}&limit=10",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let entries = body["entries"].as_array().unwrap();
    assert!(entries.len() <= 10);
}

// ═══════════════════════════════════════════════════════════════
//  6. Build Info
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_build_info_success() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(&format!("{}/api/build-info", server.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Should have at minimum these fields
    assert!(body["version"].is_string(), "Expected version field");
}

// ═══════════════════════════════════════════════════════════════
//  7. Link Preview
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_link_preview_missing_url() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("lp_no_url").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/link-preview?token={}",
            server.base_url, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_link_preview_invalid_url() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("lp_bad_url").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/link-preview?token={}&url=not-a-url",
            server.base_url, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_link_preview_private_ip_blocked() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("lp_private").await;

    // Localhost URL should be blocked (SSRF protection)
    let resp = server
        .client
        .get(&format!(
            "{}/api/link-preview?token={}&url=http://127.0.0.1/secret",
            server.base_url, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_link_preview_localhost_blocked() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("lp_localhost").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/link-preview?token={}&url=http://localhost/admin",
            server.base_url, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_link_preview_non_http_scheme_blocked() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("lp_scheme").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/link-preview?token={}&url=ftp://example.com/file",
            server.base_url, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_link_preview_unauthorized() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/link-preview?url=https://example.com",
            server.base_url
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  8. Node Presence
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_node_presence_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("presence_own").await;
    let node_id = server.create_node(&owner_token, "PresenceNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/presence/{}?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["members"].is_array() || body["members"].is_object());
}

#[tokio::test]
async fn test_get_node_presence_non_member_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("presence_own2").await;
    let (_, stranger_token) = server.register_and_auth("presence_stranger").await;
    let node_id = server.create_node(&owner_token, "PresenceForbNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/presence/{}?token={}",
            server.base_url, node_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_get_node_presence_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("presence_unauth").await;
    let node_id = server.create_node(&owner_token, "PresenceUnauthNode").await;

    let resp = server
        .client
        .get(&format!("{}/api/presence/{}", server.base_url, node_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  9. File Listing
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_list_channel_files_success() {
    let server = TestServer::new().await;
    let (user_id, token) = server.register_and_auth("files_list_user").await;
    let node_id = server.create_node(&token, "FilesListNode").await;
    let channel_id = server.create_channel(&token, node_id, "files-ch").await;

    // Join the channel so we have access
    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/files?token={}",
            server.base_url, channel_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Should return an array (possibly empty)
    assert!(body.is_array(), "Expected array of files, got: {}", body);
}

#[tokio::test]
async fn test_list_channel_files_not_a_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("files_list_own").await;
    let (_, stranger_token) = server.register_and_auth("files_list_stranger").await;
    let node_id = server.create_node(&owner_token, "FilesListForbNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "private-files-ch")
        .await;

    // Stranger is not a channel member
    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/files?token={}",
            server.base_url, channel_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    // Should get 403 (not a member) or 404 (channel not found from their perspective)
    assert!(
        resp.status() == 403 || resp.status() == 404,
        "Expected 403 or 404, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_list_channel_files_channel_not_found() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("files_list_nf").await;
    let fake_channel_id = Uuid::new_v4();

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/files?token={}",
            server.base_url, fake_channel_id, token
        ))
        .send()
        .await
        .unwrap();

    // Channel doesn't exist → 403 (handler queries channel_members which returns empty,
    // treating it as "not a member") or 404 depending on implementation.
    assert!(
        resp.status() == 403 || resp.status() == 404,
        "Expected 403 or 404 for nonexistent channel, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_list_channel_files_unauthorized() {
    let server = TestServer::new().await;
    let (user_id, token) = server.register_and_auth("files_list_unauth").await;
    let node_id = server.create_node(&token, "FilesUnauthNode").await;
    let channel_id = server
        .create_channel(&token, node_id, "unauth-files-ch")
        .await;

    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!("{}/channels/{}/files", server.base_url, channel_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}
