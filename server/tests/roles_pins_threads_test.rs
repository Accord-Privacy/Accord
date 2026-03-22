//! Integration tests for:
//! - Roles CRUD (create, update, delete, list, reorder, assign/remove/get member roles)
//! - Message pinning (pin, unpin, get pinned messages)
//! - Message threading (get channel threads, get message thread)
//! - Slow mode (set, get)
//! - Channel management (update, reorder, list overwrites, mark read)
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
//  TestServer
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
            // Nodes
            .route(
                "/nodes",
                get(list_user_nodes_handler).post(create_node_handler),
            )
            .route("/nodes/:id", get(get_node_handler))
            .route("/nodes/:id", axum::routing::patch(update_node_handler))
            .route(
                "/nodes/:id/channels",
                get(list_node_channels_handler).post(create_channel_handler),
            )
            .route("/nodes/:id/join", post(join_node_handler))
            .route("/nodes/:id/leave", post(leave_node_handler))
            .route("/nodes/:id/members", get(get_node_members_handler))
            .route("/nodes/:id/members/:user_id", delete(kick_user_handler))
            // Roles
            .route(
                "/nodes/:id/roles",
                get(list_roles_handler).post(create_role_handler),
            )
            .route(
                "/nodes/:id/roles/reorder",
                axum::routing::patch(reorder_roles_handler),
            )
            .route(
                "/nodes/:id/roles/:role_id",
                axum::routing::patch(update_role_handler).delete(delete_role_handler),
            )
            // Member roles
            .route(
                "/nodes/:id/members/:user_id/roles",
                get(get_member_roles_handler),
            )
            .route(
                "/nodes/:id/members/:user_id/roles/:role_id",
                axum::routing::put(assign_member_role_handler).delete(remove_member_role_handler),
            )
            // Channel management
            .route(
                "/nodes/:id/channels/reorder",
                axum::routing::put(reorder_channels_handler),
            )
            .route(
                "/channels/:id",
                axum::routing::patch(update_channel_handler).delete(delete_channel_handler),
            )
            .route("/channels/:id/messages", get(get_channel_messages_handler))
            .route(
                "/channels/:id/slow-mode",
                axum::routing::put(set_slow_mode_handler).get(get_slow_mode_handler),
            )
            .route("/channels/:id/pins", get(get_pinned_messages_handler))
            .route("/channels/:id/read", post(mark_channel_read_handler))
            .route("/channels/:id/threads", get(get_channel_threads_handler))
            .route(
                "/channels/:id/permissions",
                get(list_channel_overwrites_handler),
            )
            .route(
                "/channels/:id/permissions/:role_id",
                axum::routing::put(set_channel_overwrite_handler)
                    .delete(delete_channel_overwrite_handler),
            )
            .route(
                "/channels/:id/effective-permissions",
                get(get_effective_permissions_handler),
            )
            // Message endpoints
            .route(
                "/messages/:id/pin",
                axum::routing::put(pin_message_handler).delete(unpin_message_handler),
            )
            .route("/messages/:id/thread", get(get_message_thread_handler))
            // Invites
            .route(
                "/nodes/:id/invites",
                post(create_invite_handler).get(list_invites_handler),
            )
            .route("/invites/:invite_id", delete(revoke_invite_handler))
            .route("/invites/:code/preview", get(invite_preview_handler))
            .route("/invites/:code/join", post(use_invite_handler))
            // Categories
            .route(
                "/nodes/:id/categories",
                post(create_channel_category_handler),
            )
            .route(
                "/categories/:id",
                patch(update_channel_category_handler).delete(delete_channel_category_handler),
            )
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

    async fn register_and_auth(&self, name: &str) -> (Uuid, String) {
        let pk = format!("rpt_test_pk_{}", name);

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

    /// Create a role in a node, return role_id.
    async fn create_role(&self, token: &str, node_id: Uuid, name: &str) -> Uuid {
        let resp = self
            .client
            .post(&format!(
                "{}/nodes/{}/roles?token={}",
                self.base_url, node_id, token
            ))
            .json(&json!({ "name": name, "permissions": 0, "color": 0 }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create_role failed");
        let body: Value = resp.json().await.unwrap();
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
    }

    /// Store a message via state directly (no HTTP POST for sending messages), return message_id.
    async fn store_message(&self, channel_id: Uuid, sender_id: Uuid) -> Uuid {
        let (message_id, _seq) = self
            .state
            .store_message(channel_id, sender_id, b"test_encrypted_payload")
            .await
            .unwrap();
        message_id
    }
}

// ═══════════════════════════════════════════════════════════════
//  1. Roles CRUD
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_create_role_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_create_own").await;
    let node_id = server.create_node(&owner_token, "RoleCreateNode").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/roles?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "name": "Moderator", "color": 255, "permissions": 8 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["id"].is_string());
    assert_eq!(body["name"], "Moderator");
}

#[tokio::test]
async fn test_create_role_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_create_unauth").await;
    let node_id = server
        .create_node(&owner_token, "RoleCreateUnauthNode")
        .await;

    let resp = server
        .client
        .post(&format!("{}/nodes/{}/roles", server.base_url, node_id))
        .json(&json!({ "name": "Ghost" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_create_role_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_create_own2").await;
    let (_, member_token) = server.register_and_auth("role_create_mem2").await;
    let node_id = server.create_node(&owner_token, "RoleCreateFrbNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/roles?token={}",
            server.base_url, node_id, member_token
        ))
        .json(&json!({ "name": "SelfGranted" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_list_roles_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_list_own").await;
    let node_id = server.create_node(&owner_token, "RoleListNode").await;

    server.create_role(&owner_token, node_id, "Alpha").await;
    server.create_role(&owner_token, node_id, "Beta").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/roles?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let roles = body["roles"].as_array().unwrap();
    // At least the 2 we created, plus the @everyone role auto-created with the node
    assert!(roles.len() >= 2);
    let names: Vec<&str> = roles.iter().filter_map(|r| r["name"].as_str()).collect();
    assert!(names.contains(&"Alpha"));
    assert!(names.contains(&"Beta"));
}

#[tokio::test]
async fn test_list_roles_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_list_unauth").await;
    let node_id = server.create_node(&owner_token, "RoleListUnauthNode").await;

    let resp = server
        .client
        .get(&format!("{}/nodes/{}/roles", server.base_url, node_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_update_role_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_upd_own").await;
    let node_id = server.create_node(&owner_token, "RoleUpdNode").await;
    let role_id = server
        .create_role(&owner_token, node_id, "OldRoleName")
        .await;

    let resp = server
        .client
        .patch(&format!(
            "{}/nodes/{}/roles/{}?token={}",
            server.base_url, node_id, role_id, owner_token
        ))
        .json(&json!({ "name": "NewRoleName", "color": 16711680 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Response is the updated role
    assert_eq!(body["name"].as_str().unwrap_or(""), "NewRoleName");
}

#[tokio::test]
async fn test_update_role_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_upd_nf").await;
    let node_id = server.create_node(&owner_token, "RoleUpdNfNode").await;
    let fake_role_id = Uuid::new_v4();

    let resp = server
        .client
        .patch(&format!(
            "{}/nodes/{}/roles/{}?token={}",
            server.base_url, node_id, fake_role_id, owner_token
        ))
        .json(&json!({ "name": "Ghost" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_update_role_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_upd_own2").await;
    let (_, member_token) = server.register_and_auth("role_upd_mem2").await;
    let node_id = server.create_node(&owner_token, "RoleUpdFrbNode").await;
    let role_id = server.create_role(&owner_token, node_id, "Locked").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .patch(&format!(
            "{}/nodes/{}/roles/{}?token={}",
            server.base_url, node_id, role_id, member_token
        ))
        .json(&json!({ "name": "Hacked" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_delete_role_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_del_own").await;
    let node_id = server.create_node(&owner_token, "RoleDelNode").await;
    let role_id = server.create_role(&owner_token, node_id, "ToDelete").await;

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/roles/{}?token={}",
            server.base_url, node_id, role_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_delete_role_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_del_nf").await;
    let node_id = server.create_node(&owner_token, "RoleDelNfNode").await;
    let fake_id = Uuid::new_v4();

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/roles/{}?token={}",
            server.base_url, node_id, fake_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_role_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_del_own2").await;
    let (_, member_token) = server.register_and_auth("role_del_mem2").await;
    let node_id = server.create_node(&owner_token, "RoleDelFrbNode").await;
    let role_id = server.create_role(&owner_token, node_id, "Protected").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/roles/{}?token={}",
            server.base_url, node_id, role_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_reorder_roles_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_reorder_own").await;
    let node_id = server.create_node(&owner_token, "RoleReorderNode").await;
    let role1_id = server.create_role(&owner_token, node_id, "RoleA").await;
    let role2_id = server.create_role(&owner_token, node_id, "RoleB").await;

    let resp = server
        .client
        .patch(&format!(
            "{}/nodes/{}/roles/reorder?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({
            "roles": [
                { "id": role1_id, "position": 2 },
                { "id": role2_id, "position": 1 }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_reorder_roles_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_reorder_own2").await;
    let (_, member_token) = server.register_and_auth("role_reorder_mem2").await;
    let node_id = server.create_node(&owner_token, "RoleReorderFrbNode").await;
    let role_id = server.create_role(&owner_token, node_id, "Unmovable").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .patch(&format!(
            "{}/nodes/{}/roles/reorder?token={}",
            server.base_url, node_id, member_token
        ))
        .json(&json!({ "roles": [{ "id": role_id, "position": 1 }] }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_assign_and_remove_member_role() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_assign_own").await;
    let (member_id, member_token) = server.register_and_auth("role_assign_mem").await;
    let node_id = server.create_node(&owner_token, "RoleAssignNode").await;
    let role_id = server
        .create_role(&owner_token, node_id, "Assignable")
        .await;
    server.join_node(&member_token, node_id).await;

    // Assign role
    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/members/{}/roles/{}?token={}",
            server.base_url, node_id, member_id, role_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Get member roles — should contain our role
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/members/{}/roles?token={}",
            server.base_url, node_id, member_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let roles = body["roles"].as_array().unwrap();
    let ids: Vec<&str> = roles.iter().filter_map(|r| r["id"].as_str()).collect();
    assert!(ids.contains(&role_id.to_string().as_str()));

    // Remove role
    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/members/{}/roles/{}?token={}",
            server.base_url, node_id, member_id, role_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Get member roles again — role should be gone
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/members/{}/roles?token={}",
            server.base_url, node_id, member_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let roles = body["roles"].as_array().unwrap();
    let ids: Vec<&str> = roles.iter().filter_map(|r| r["id"].as_str()).collect();
    assert!(!ids.contains(&role_id.to_string().as_str()));
}

#[tokio::test]
async fn test_assign_member_role_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_assign_own3").await;
    let (_member_id, member_token) = server.register_and_auth("role_assign_mem3").await;
    let (other_id, other_token) = server.register_and_auth("role_assign_other3").await;
    let node_id = server.create_node(&owner_token, "RoleAssignFrbNode").await;
    let role_id = server.create_role(&owner_token, node_id, "Coveted").await;
    server.join_node(&member_token, node_id).await;
    server.join_node(&other_token, node_id).await;

    // member tries to assign a role to other — should fail
    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/members/{}/roles/{}?token={}",
            server.base_url, node_id, other_id, role_id, member_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_get_member_roles_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("role_get_unauth").await;
    let (member_id, _) = server.register_and_auth("role_get_target").await;
    let node_id = server.create_node(&owner_token, "RoleGetUnauthNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/members/{}/roles",
            server.base_url, node_id, member_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  2. Message Pinning
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_pin_message_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("pin_own").await;
    let node_id = server.create_node(&owner_token, "PinNode").await;
    let channel_id = server.create_channel(&owner_token, node_id, "pin-ch").await;

    // Owner needs to be in the channel for message storage and pin permission check
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let message_id = server.store_message(channel_id, owner_id).await;

    let resp = server
        .client
        .put(&format!(
            "{}/messages/{}/pin?token={}",
            server.base_url, message_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_pin_message_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("pin_nf").await;
    server.create_node(&owner_token, "PinNfNode").await;
    let fake_id = Uuid::new_v4();

    let resp = server
        .client
        .put(&format!(
            "{}/messages/{}/pin?token={}",
            server.base_url, fake_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_pin_message_forbidden_for_member() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("pin_own2").await;
    let (member_id, member_token) = server.register_and_auth("pin_mem2").await;
    let node_id = server.create_node(&owner_token, "PinFrbNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "pin-frb-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    server.join_node(&member_token, node_id).await;
    server
        .state
        .join_channel(member_id, channel_id)
        .await
        .unwrap();

    let message_id = server.store_message(channel_id, owner_id).await;

    // Regular member cannot pin — only Admin/Moderator can
    let resp = server
        .client
        .put(&format!(
            "{}/messages/{}/pin?token={}",
            server.base_url, message_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_unpin_message_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("unpin_own").await;
    let node_id = server.create_node(&owner_token, "UnpinNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "unpin-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let message_id = server.store_message(channel_id, owner_id).await;

    // Pin first
    let pin_resp = server
        .client
        .put(&format!(
            "{}/messages/{}/pin?token={}",
            server.base_url, message_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(pin_resp.status(), 200);

    // Now unpin
    let resp = server
        .client
        .delete(&format!(
            "{}/messages/{}/pin?token={}",
            server.base_url, message_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_pin_message_duplicate_fails() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("pin_dup_own").await;
    let node_id = server.create_node(&owner_token, "PinDupNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "pin-dup-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let message_id = server.store_message(channel_id, owner_id).await;

    // Pin once
    let resp = server
        .client
        .put(&format!(
            "{}/messages/{}/pin?token={}",
            server.base_url, message_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Pin again — should conflict
    let resp = server
        .client
        .put(&format!(
            "{}/messages/{}/pin?token={}",
            server.base_url, message_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn test_get_pinned_messages_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("pinlist_own").await;
    let node_id = server.create_node(&owner_token, "PinListNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "pin-list-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let msg1 = server.store_message(channel_id, owner_id).await;
    let msg2 = server.store_message(channel_id, owner_id).await;

    // Pin both
    server
        .client
        .put(&format!(
            "{}/messages/{}/pin?token={}",
            server.base_url, msg1, owner_token
        ))
        .send()
        .await
        .unwrap();
    server
        .client
        .put(&format!(
            "{}/messages/{}/pin?token={}",
            server.base_url, msg2, owner_token
        ))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/pins?token={}",
            server.base_url, channel_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let pins = body["pinned_messages"].as_array().unwrap();
    assert_eq!(pins.len(), 2);
}

#[tokio::test]
async fn test_get_pinned_messages_access_denied() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("pinlist_own2").await;
    let (_, stranger_token) = server.register_and_auth("pinlist_stranger2").await;
    let node_id = server.create_node(&owner_token, "PinListDenyNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "pin-list-deny-ch")
        .await;

    // Stranger is not a member of the channel
    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/pins?token={}",
            server.base_url, channel_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  3. Threads
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_channel_threads_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("threads_own").await;
    let node_id = server.create_node(&owner_token, "ThreadsNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "threads-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/threads?token={}",
            server.base_url, channel_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["threads"].is_array());
}

#[tokio::test]
async fn test_get_channel_threads_access_denied() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("threads_own2").await;
    let (_, stranger_token) = server.register_and_auth("threads_stranger2").await;
    let node_id = server.create_node(&owner_token, "ThreadsDenyNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "threads-deny-ch")
        .await;

    // Stranger hasn't joined the channel
    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/threads?token={}",
            server.base_url, channel_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_get_channel_threads_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("threads_unauth").await;
    let node_id = server.create_node(&owner_token, "ThreadsUnauthNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "threads-unauth-ch")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/threads",
            server.base_url, channel_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_get_message_thread_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("msgthread_own").await;
    let node_id = server.create_node(&owner_token, "MsgThreadNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "msg-thread-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let message_id = server.store_message(channel_id, owner_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/messages/{}/thread?token={}",
            server.base_url, message_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["messages"].is_array());
}

#[tokio::test]
async fn test_get_message_thread_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("msgthread_nf").await;
    server.create_node(&owner_token, "MsgThreadNfNode").await;
    let fake_id = Uuid::new_v4();

    let resp = server
        .client
        .get(&format!(
            "{}/messages/{}/thread?token={}",
            server.base_url, fake_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_message_thread_access_denied() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("msgthread_own2").await;
    let (_, stranger_token) = server.register_and_auth("msgthread_stranger2").await;
    let node_id = server.create_node(&owner_token, "MsgThreadDenyNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "msg-thread-deny-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let message_id = server.store_message(channel_id, owner_id).await;

    // Stranger is not a channel member
    let resp = server
        .client
        .get(&format!(
            "{}/messages/{}/thread?token={}",
            server.base_url, message_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  4. Slow Mode
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_set_slow_mode_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("slowmode_own").await;
    let node_id = server.create_node(&owner_token, "SlowModeNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "slow-mode-ch")
        .await;

    let resp = server
        .client
        .put(&format!(
            "{}/channels/{}/slow-mode?token={}",
            server.base_url, channel_id, owner_token
        ))
        .json(&json!({ "seconds": 30 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    assert_eq!(body["slow_mode_seconds"], 30);
}

#[tokio::test]
async fn test_set_slow_mode_caps_at_3600() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("slowmode_cap_own").await;
    let node_id = server.create_node(&owner_token, "SlowModeCapNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "slow-mode-cap-ch")
        .await;

    let resp = server
        .client
        .put(&format!(
            "{}/channels/{}/slow-mode?token={}",
            server.base_url, channel_id, owner_token
        ))
        .json(&json!({ "seconds": 99999 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Should be capped at 3600
    assert_eq!(body["slow_mode_seconds"], 3600);
}

#[tokio::test]
async fn test_set_slow_mode_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("slowmode_own2").await;
    let (_, member_token) = server.register_and_auth("slowmode_mem2").await;
    let node_id = server.create_node(&owner_token, "SlowModeFrbNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "slow-mode-frb-ch")
        .await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .put(&format!(
            "{}/channels/{}/slow-mode?token={}",
            server.base_url, channel_id, member_token
        ))
        .json(&json!({ "seconds": 10 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_set_slow_mode_channel_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("slowmode_nf").await;
    server.create_node(&owner_token, "SlowModeNfNode").await;
    let fake_id = Uuid::new_v4();

    let resp = server
        .client
        .put(&format!(
            "{}/channels/{}/slow-mode?token={}",
            server.base_url, fake_id, owner_token
        ))
        .json(&json!({ "seconds": 5 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_slow_mode_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("getslowmode_own").await;
    let node_id = server.create_node(&owner_token, "GetSlowModeNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "get-slow-mode-ch")
        .await;

    // Set slow mode first
    server
        .client
        .put(&format!(
            "{}/channels/{}/slow-mode?token={}",
            server.base_url, channel_id, owner_token
        ))
        .json(&json!({ "seconds": 45 }))
        .send()
        .await
        .unwrap();

    // Now get it
    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/slow-mode?token={}",
            server.base_url, channel_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["slow_mode_seconds"], 45);
    assert_eq!(body["channel_id"], channel_id.to_string());
}

#[tokio::test]
async fn test_get_slow_mode_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("getslowmode_unauth").await;
    let node_id = server
        .create_node(&owner_token, "GetSlowModeUnauthNode")
        .await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "get-slow-unauth-ch")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/slow-mode",
            server.base_url, channel_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  5. Channel Management
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_update_channel_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("chan_upd_own").await;
    let node_id = server.create_node(&owner_token, "ChanUpdNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "to-update-ch")
        .await;

    let resp = server
        .client
        .patch(&format!(
            "{}/channels/{}?token={}",
            server.base_url, channel_id, owner_token
        ))
        .json(&json!({ "position": 2 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    assert_eq!(body["channel_id"], channel_id.to_string());
}

#[tokio::test]
async fn test_update_channel_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("chan_upd_nf").await;
    server.create_node(&owner_token, "ChanUpdNfNode").await;
    let fake_id = Uuid::new_v4();

    let resp = server
        .client
        .patch(&format!(
            "{}/channels/{}?token={}",
            server.base_url, fake_id, owner_token
        ))
        .json(&json!({ "position": 1 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_update_channel_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("chan_upd_own2").await;
    let (_, member_token) = server.register_and_auth("chan_upd_mem2").await;
    let node_id = server.create_node(&owner_token, "ChanUpdFrbNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "upd-frb-ch")
        .await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .patch(&format!(
            "{}/channels/{}?token={}",
            server.base_url, channel_id, member_token
        ))
        .json(&json!({ "position": 1 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_reorder_channels_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("chan_reorder_own").await;
    let node_id = server.create_node(&owner_token, "ChanReorderNode").await;
    let ch1 = server
        .create_channel(&owner_token, node_id, "reorder-ch1")
        .await;
    let ch2 = server
        .create_channel(&owner_token, node_id, "reorder-ch2")
        .await;

    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/channels/reorder?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({
            "channels": [
                { "id": ch1, "position": 2, "category_id": null },
                { "id": ch2, "position": 1, "category_id": null }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_reorder_channels_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("chan_reorder_own2").await;
    let (_, member_token) = server.register_and_auth("chan_reorder_mem2").await;
    let node_id = server.create_node(&owner_token, "ChanReorderFrbNode").await;
    let ch_id = server
        .create_channel(&owner_token, node_id, "reorder-frb-ch")
        .await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/channels/reorder?token={}",
            server.base_url, node_id, member_token
        ))
        .json(&json!({ "channels": [{ "id": ch_id, "position": 1, "category_id": null }] }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_list_channel_overwrites_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("list_ow_own").await;
    let node_id = server.create_node(&owner_token, "ListOwNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "list-ow-ch")
        .await;
    let role_id = server.create_role(&owner_token, node_id, "OwRole").await;

    // Set an overwrite first
    server
        .client
        .put(&format!(
            "{}/channels/{}/permissions/{}?token={}",
            server.base_url, channel_id, role_id, owner_token
        ))
        .json(&json!({ "allow": 1024, "deny": 0 }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/permissions?token={}",
            server.base_url, channel_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let overwrites = body["overwrites"].as_array().unwrap();
    assert!(!overwrites.is_empty());
}

#[tokio::test]
async fn test_list_channel_overwrites_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("list_ow_unauth").await;
    let node_id = server.create_node(&owner_token, "ListOwUnauthNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "list-ow-unauth-ch")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/permissions",
            server.base_url, channel_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_mark_channel_read_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("mark_read_own").await;
    let node_id = server.create_node(&owner_token, "MarkReadNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "mark-read-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let message_id = server.store_message(channel_id, owner_id).await;

    let resp = server
        .client
        .post(&format!(
            "{}/channels/{}/read?token={}",
            server.base_url, channel_id, owner_token
        ))
        .json(&json!({ "message_id": message_id }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_mark_channel_read_access_denied() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("mark_read_own2").await;
    let (_, stranger_token) = server.register_and_auth("mark_read_stranger2").await;
    let node_id = server.create_node(&owner_token, "MarkReadDenyNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "mark-read-deny-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let message_id = server.store_message(channel_id, owner_id).await;

    // Stranger has no access to this channel
    let resp = server
        .client
        .post(&format!(
            "{}/channels/{}/read?token={}",
            server.base_url, channel_id, stranger_token
        ))
        .json(&json!({ "message_id": message_id }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_mark_channel_read_unauthorized() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("mark_read_unauth").await;
    let node_id = server.create_node(&owner_token, "MarkReadUnauthNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "mark-read-unauth-ch")
        .await;

    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let message_id = server.store_message(channel_id, owner_id).await;

    let resp = server
        .client
        .post(&format!("{}/channels/{}/read", server.base_url, channel_id))
        .json(&json!({ "message_id": message_id }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}
