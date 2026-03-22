//! Integration tests for CRUD handlers:
//! channel, channel-category, invite, node management, and channel permissions/overwrites.
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
            // Channel categories
            .route(
                "/nodes/:id/categories",
                post(create_channel_category_handler),
            )
            .route(
                "/categories/:id",
                patch(update_channel_category_handler).delete(delete_channel_category_handler),
            )
            // Channels
            .route(
                "/channels/:id",
                patch(update_channel_handler).delete(delete_channel_handler),
            )
            .route("/channels/:id/messages", get(get_channel_messages_handler))
            // Channel permission overwrites
            .route(
                "/channels/:id/permissions/:role_id",
                put(set_channel_overwrite_handler).delete(delete_channel_overwrite_handler),
            )
            .route(
                "/channels/:id/effective-permissions",
                get(get_effective_permissions_handler),
            )
            // Roles (needed to create roles for overwrite tests)
            .route(
                "/nodes/:id/roles",
                get(list_roles_handler).post(create_role_handler),
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

    /// Register a user and return (user_id, token).
    async fn register_and_auth(&self, name: &str) -> (Uuid, String) {
        let pk = format!("crud_test_pk_{}", name);

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

    /// Create a channel category, return category_id.
    async fn create_category(&self, token: &str, node_id: Uuid, name: &str) -> Uuid {
        let resp = self
            .client
            .post(&format!(
                "{}/nodes/{}/categories?token={}",
                self.base_url, node_id, token
            ))
            .json(&json!({ "name": name }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create_category failed");
        let body: Value = resp.json().await.unwrap();
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
    }

    /// Create an invite, return invite_code.
    async fn create_invite(&self, token: &str, node_id: Uuid) -> String {
        let resp = self
            .client
            .post(&format!(
                "{}/nodes/{}/invites?token={}",
                self.base_url, node_id, token
            ))
            .json(&json!({ "max_uses": 10, "expires_in_hours": 24 }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create_invite failed");
        let body: Value = resp.json().await.unwrap();
        body["invite_code"].as_str().unwrap().to_string()
    }
}

// ═══════════════════════════════════════════════════════════════
//  1. Channel CRUD
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_create_channel_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("chan_owner1").await;
    let node_id = server.create_node(&owner_token, "ChanNode1").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/channels?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "name": "general" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["id"].is_string());
    assert_eq!(body["name"], "general");
    assert_eq!(body["node_id"], node_id.to_string());
    assert_eq!(body["channel_type"], "text");
}

#[tokio::test]
async fn test_create_voice_channel_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("voice_chan_owner").await;
    let node_id = server.create_node(&owner_token, "VoiceChanNode").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/channels?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "name": "voice-room", "channel_type": "voice" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["channel_type"], "voice");
}

#[tokio::test]
async fn test_create_channel_invalid_name() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("chan_owner_inv").await;
    let node_id = server.create_node(&owner_token, "ChanNodeInv").await;

    // Empty name should be rejected
    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/channels?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "name": "" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_channel_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("chan_owner_unauth").await;
    let node_id = server.create_node(&owner_token, "ChanNodeUnauth").await;

    // No token → 401
    let resp = server
        .client
        .post(&format!("{}/nodes/{}/channels", server.base_url, node_id))
        .json(&json!({ "name": "general" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_list_node_channels() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("list_chan_owner").await;
    let node_id = server.create_node(&owner_token, "ListChanNode").await;

    server
        .create_channel(&owner_token, node_id, "ch-alpha")
        .await;
    server
        .create_channel(&owner_token, node_id, "ch-beta")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/channels?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let channels = body.as_array().unwrap();
    assert!(channels.len() >= 2);
    let names: Vec<&str> = channels.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(names.contains(&"ch-alpha"));
    assert!(names.contains(&"ch-beta"));
}

#[tokio::test]
async fn test_list_node_channels_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("list_chan_unauth").await;
    let node_id = server.create_node(&owner_token, "ListChanNodeUnauth").await;

    let resp = server
        .client
        .get(&format!("{}/nodes/{}/channels", server.base_url, node_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_delete_channel_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("del_chan_owner").await;
    let node_id = server.create_node(&owner_token, "DelChanNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "to-delete")
        .await;

    let resp = server
        .client
        .delete(&format!(
            "{}/channels/{}?token={}",
            server.base_url, channel_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "deleted");
}

#[tokio::test]
async fn test_delete_channel_by_non_owner_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("del_chan_owner2").await;
    let (_, member_token) = server.register_and_auth("del_chan_member").await;
    let node_id = server.create_node(&owner_token, "DelChanNode2").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "protected-ch")
        .await;

    // Member joins but is not admin
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .delete(&format!(
            "{}/channels/{}?token={}",
            server.base_url, channel_id, member_token
        ))
        .send()
        .await
        .unwrap();

    // Expect 403 (insufficient permissions) or 400
    assert!(
        resp.status() == 403 || resp.status() == 400,
        "Expected 403 or 400, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_get_channel_messages_empty() {
    let server = TestServer::new().await;
    let (user_id, token) = server.register_and_auth("msg_hist_user").await;
    let node_id = server.create_node(&token, "MsgHistNode").await;
    let channel_id = server.create_channel(&token, node_id, "history-ch").await;

    // Join the channel so we have access
    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/messages?token={}",
            server.base_url, channel_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["messages"].is_array());
    assert_eq!(body["has_more"], false);
}

#[tokio::test]
async fn test_get_channel_messages_access_denied() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("msg_hist_owner").await;
    let (_, stranger_token) = server.register_and_auth("msg_hist_stranger").await;
    let node_id = server.create_node(&owner_token, "MsgHistNode2").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "private-ch")
        .await;

    // Stranger is not a member of the node at all
    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/messages?token={}",
            server.base_url, channel_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  2. Channel Categories
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_create_channel_category_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("cat_owner1").await;
    let node_id = server.create_node(&owner_token, "CatNode1").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/categories?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "name": "My Category" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["id"].is_string());
    assert_eq!(body["name"], "My Category");
}

#[tokio::test]
async fn test_create_channel_category_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("cat_owner2").await;
    let (_, member_token) = server.register_and_auth("cat_member2").await;
    let node_id = server.create_node(&owner_token, "CatNode2").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/categories?token={}",
            server.base_url, node_id, member_token
        ))
        .json(&json!({ "name": "Unauthorized Category" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_create_channel_category_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("cat_owner3").await;
    let node_id = server.create_node(&owner_token, "CatNode3").await;

    let resp = server
        .client
        .post(&format!("{}/nodes/{}/categories", server.base_url, node_id))
        .json(&json!({ "name": "NoToken" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_update_channel_category_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("cat_upd_owner").await;
    let node_id = server.create_node(&owner_token, "CatUpdNode").await;
    let category_id = server
        .create_category(&owner_token, node_id, "OldName")
        .await;

    let resp = server
        .client
        .patch(&format!(
            "{}/categories/{}?token={}",
            server.base_url, category_id, owner_token
        ))
        .json(&json!({ "name": "NewName" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
}

#[tokio::test]
async fn test_update_channel_category_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("cat_upd_nf").await;
    server.create_node(&owner_token, "CatUpdNfNode").await;

    let fake_id = Uuid::new_v4();
    let resp = server
        .client
        .patch(&format!(
            "{}/categories/{}?token={}",
            server.base_url, fake_id, owner_token
        ))
        .json(&json!({ "name": "Ghost" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_update_channel_category_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("cat_upd_own").await;
    let (_, member_token) = server.register_and_auth("cat_upd_mem").await;
    let node_id = server.create_node(&owner_token, "CatUpdForbNode").await;
    let category_id = server
        .create_category(&owner_token, node_id, "Locked")
        .await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .patch(&format!(
            "{}/categories/{}?token={}",
            server.base_url, category_id, member_token
        ))
        .json(&json!({ "name": "Hacked" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_delete_channel_category_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("cat_del_owner").await;
    let node_id = server.create_node(&owner_token, "CatDelNode").await;
    let category_id = server
        .create_category(&owner_token, node_id, "ToDelete")
        .await;

    let resp = server
        .client
        .delete(&format!(
            "{}/categories/{}?token={}",
            server.base_url, category_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "deleted");
}

#[tokio::test]
async fn test_delete_channel_category_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("cat_del_nf").await;
    server.create_node(&owner_token, "CatDelNfNode").await;

    let fake_id = Uuid::new_v4();
    let resp = server
        .client
        .delete(&format!(
            "{}/categories/{}?token={}",
            server.base_url, fake_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_channel_category_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("cat_del_own2").await;
    let (_, member_token) = server.register_and_auth("cat_del_mem2").await;
    let node_id = server.create_node(&owner_token, "CatDelForbNode").await;
    let category_id = server
        .create_category(&owner_token, node_id, "Protected")
        .await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .delete(&format!(
            "{}/categories/{}?token={}",
            server.base_url, category_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  3. Invite CRUD
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_create_invite_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_owner1").await;
    let node_id = server.create_node(&owner_token, "InvNode1").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/invites?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "max_uses": 5, "expires_in_hours": 48 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["invite_code"].is_string());
    let code = body["invite_code"].as_str().unwrap();
    assert!(!code.is_empty());
    assert_eq!(body["max_uses"], 5);
}

#[tokio::test]
async fn test_create_invite_no_expiry_no_limit() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_owner_nolimit").await;
    let node_id = server.create_node(&owner_token, "InvNodeNoLimit").await;

    // Omitting max_uses and expires_in_hours → unlimited
    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/invites?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["invite_code"].is_string());
    assert!(body["max_uses"].is_null());
    assert!(body["expires_at"].is_null());
}

#[tokio::test]
async fn test_create_invite_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_unauth").await;
    let node_id = server.create_node(&owner_token, "InvNodeUnauth").await;

    let resp = server
        .client
        .post(&format!("{}/nodes/{}/invites", server.base_url, node_id))
        .json(&json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_list_invites_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_list_owner").await;
    let node_id = server.create_node(&owner_token, "InvListNode").await;

    server.create_invite(&owner_token, node_id).await;
    server.create_invite(&owner_token, node_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/invites?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let invites = body["invites"].as_array().unwrap();
    assert!(invites.len() >= 2);
}

#[tokio::test]
async fn test_list_invites_member_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_list_own").await;
    let (_, member_token) = server.register_and_auth("inv_list_mem").await;
    let node_id = server.create_node(&owner_token, "InvListForbNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/invites?token={}",
            server.base_url, node_id, member_token
        ))
        .send()
        .await
        .unwrap();

    // Members without MANAGE_GUILD permission should be forbidden
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_revoke_invite_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_revoke_own").await;
    let node_id = server.create_node(&owner_token, "InvRevokeNode").await;
    let code = server.create_invite(&owner_token, node_id).await;

    // Get the invite ID via list
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/invites?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let invite_id = body["invites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|inv| inv["invite_code"].as_str() == Some(&code))
        .and_then(|inv| inv["id"].as_str())
        .expect("invite not found in list");
    let invite_id = Uuid::parse_str(invite_id).unwrap();

    let resp = server
        .client
        .delete(&format!(
            "{}/invites/{}?token={}",
            server.base_url, invite_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "revoked");
}

#[tokio::test]
async fn test_revoke_invite_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_revoke_nf").await;
    server.create_node(&owner_token, "InvRevokeNfNode").await;

    let fake_id = Uuid::new_v4();
    let resp = server
        .client
        .delete(&format!(
            "{}/invites/{}?token={}",
            server.base_url, fake_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    // Should be 403 (can't revoke invite you didn't create / doesn't exist)
    assert!(
        resp.status() == 403 || resp.status() == 404,
        "Expected 403 or 404, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_invite_preview_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_preview_own").await;
    let node_id = server.create_node(&owner_token, "InvPreviewNode").await;
    let code = server.create_invite(&owner_token, node_id).await;

    let resp = server
        .client
        .get(&format!("{}/invites/{}/preview", server.base_url, code))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["node_name"], "InvPreviewNode");
    assert_eq!(body["node_id"], node_id.to_string());
    assert!(body["member_count"].is_number());
}

#[tokio::test]
async fn test_invite_preview_invalid_code() {
    let server = TestServer::new().await;

    // Path traversal / invalid format
    let resp = server
        .client
        .get(&format!("{}/invites/../etc/preview", server.base_url))
        .send()
        .await
        .unwrap();

    // Either 400 (invalid code format) or 404 (path not matched)
    assert!(
        resp.status() == 400 || resp.status() == 404,
        "Expected 400 or 404, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_invite_preview_nonexistent_code() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(&format!("{}/invites/NOTEXIST/preview", server.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_use_invite_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_use_own").await;
    let (joiner_id, joiner_token) = server.register_and_auth("inv_use_joiner").await;
    let node_id = server.create_node(&owner_token, "InvUseNode").await;
    let code = server.create_invite(&owner_token, node_id).await;

    let resp = server
        .client
        .post(&format!(
            "{}/invites/{}/join?token={}",
            server.base_url, code, joiner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "joined");
    assert_eq!(body["node_id"], node_id.to_string());

    // Confirm membership
    assert!(server
        .state
        .is_node_member(joiner_id, node_id)
        .await
        .unwrap());
}

#[tokio::test]
async fn test_use_invite_exhausted() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_exhaust_own").await;
    let node_id = server.create_node(&owner_token, "InvExhaustNode").await;

    // Create invite with max_uses=1
    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/invites?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "max_uses": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let code = resp.json::<Value>().await.unwrap()["invite_code"]
        .as_str()
        .unwrap()
        .to_string();

    let (_, u1_token) = server.register_and_auth("inv_exhaust_u1").await;
    let (_, u2_token) = server.register_and_auth("inv_exhaust_u2").await;

    // First use — should succeed
    let resp = server
        .client
        .post(&format!(
            "{}/invites/{}/join?token={}",
            server.base_url, code, u1_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second use — should fail (exhausted)
    let resp = server
        .client
        .post(&format!(
            "{}/invites/{}/join?token={}",
            server.base_url, code, u2_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_use_invite_already_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("inv_dup_own").await;
    let (_, member_token) = server.register_and_auth("inv_dup_mem").await;
    let node_id = server.create_node(&owner_token, "InvDupNode").await;
    let code = server.create_invite(&owner_token, node_id).await;

    // Join once
    let resp = server
        .client
        .post(&format!(
            "{}/invites/{}/join?token={}",
            server.base_url, code, member_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Try to join again — should fail (already a member)
    let resp = server
        .client
        .post(&format!(
            "{}/invites/{}/join?token={}",
            server.base_url, code, member_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ═══════════════════════════════════════════════════════════════
//  4. Node Management
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_node_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("get_node_own").await;
    let node_id = server.create_node(&owner_token, "GetNodeTest").await;

    let resp = server
        .client
        .get(&format!("{}/nodes/{}", server.base_url, node_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], node_id.to_string());
    assert_eq!(body["name"], "GetNodeTest");
}

#[tokio::test]
async fn test_get_node_not_found() {
    let server = TestServer::new().await;
    let fake_id = Uuid::new_v4();

    let resp = server
        .client
        .get(&format!("{}/nodes/{}", server.base_url, fake_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_update_node_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("upd_node_own").await;
    let node_id = server.create_node(&owner_token, "OldNodeName").await;

    let resp = server
        .client
        .patch(&format!(
            "{}/nodes/{}?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "name": "NewNodeName", "description": "Updated desc" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    assert_eq!(body["node_id"], node_id.to_string());

    // Verify via get_node_handler
    let resp = server
        .client
        .get(&format!("{}/nodes/{}", server.base_url, node_id))
        .send()
        .await
        .unwrap();
    let info: Value = resp.json().await.unwrap();
    assert_eq!(info["name"], "NewNodeName");
}

#[tokio::test]
async fn test_update_node_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("upd_node_own2").await;
    let (_, member_token) = server.register_and_auth("upd_node_mem").await;
    let node_id = server.create_node(&owner_token, "NodeForUpdate").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .patch(&format!(
            "{}/nodes/{}?token={}",
            server.base_url, node_id, member_token
        ))
        .json(&json!({ "name": "HackedName" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_update_node_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("upd_node_unauth").await;
    let node_id = server
        .create_node(&owner_token, "NodeForUpdateUnauth")
        .await;

    let resp = server
        .client
        .patch(&format!("{}/nodes/{}", server.base_url, node_id))
        .json(&json!({ "name": "NoToken" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_leave_node_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("leave_own").await;
    let (member_id, member_token) = server.register_and_auth("leave_mem").await;
    let node_id = server.create_node(&owner_token, "LeaveNode").await;
    server.join_node(&member_token, node_id).await;

    // Confirm membership before leaving
    assert!(server
        .state
        .is_node_member(member_id, node_id)
        .await
        .unwrap());

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/leave?token={}",
            server.base_url, node_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "left");

    // Confirm no longer a member
    assert!(!server
        .state
        .is_node_member(member_id, node_id)
        .await
        .unwrap());
}

#[tokio::test]
async fn test_leave_node_not_a_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("leave_nf_own").await;
    let (_, stranger_token) = server.register_and_auth("leave_stranger").await;
    let node_id = server.create_node(&owner_token, "LeaveNodeNf").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/leave?token={}",
            server.base_url, node_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    // leave_node is idempotent — returns 200 or 400 depending on implementation
    assert!(
        resp.status() == 200 || resp.status() == 400,
        "Expected 200 or 400, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_kick_user_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("kick_own").await;
    let (member_id, member_token) = server.register_and_auth("kick_mem").await;
    let node_id = server.create_node(&owner_token, "KickNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/members/{}?token={}",
            server.base_url, node_id, member_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "kicked");
    assert_eq!(body["user_id"], member_id.to_string());
}

#[tokio::test]
async fn test_kick_user_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("kick_own2").await;
    let (member1_id, _member1_token) = server.register_and_auth("kick_mem1").await;
    let (_, member2_token) = server.register_and_auth("kick_mem2").await;
    let node_id = server.create_node(&owner_token, "KickForbNode").await;

    // Join both members
    server.state.join_node(member1_id, node_id).await.unwrap();
    let (member2_id, member2_token) = server.register_and_auth("kick_mem2b").await;
    server.join_node(&member2_token, node_id).await;

    // member2 tries to kick member1 — should fail
    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/members/{}?token={}",
            server.base_url, node_id, member1_id, member2_token
        ))
        .send()
        .await
        .unwrap();

    assert!(
        resp.status() == 403 || resp.status() == 400,
        "Expected 403 or 400, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_kick_user_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("kick_unauth_own").await;
    let (member_id, member_token) = server.register_and_auth("kick_unauth_mem").await;
    let node_id = server.create_node(&owner_token, "KickUnauthNode").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/members/{}",
            server.base_url, node_id, member_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  5. Channel Permission Overwrites
// ═══════════════════════════════════════════════════════════════

/// Helper: create a role in a node, return role_id.
async fn create_role(server: &TestServer, token: &str, node_id: Uuid, name: &str) -> Uuid {
    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/roles?token={}",
            server.base_url, node_id, token
        ))
        .json(&json!({ "name": name, "permissions": 0, "color": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create_role failed");
    let body: Value = resp.json().await.unwrap();
    Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn test_set_channel_overwrite_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("overwrite_own").await;
    let node_id = server.create_node(&owner_token, "OverwriteNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "perm-ch")
        .await;
    let role_id = create_role(&server, &owner_token, node_id, "TestRole").await;

    let resp = server
        .client
        .put(&format!(
            "{}/channels/{}/permissions/{}?token={}",
            server.base_url, channel_id, role_id, owner_token
        ))
        .json(&json!({ "allow": 1024, "deny": 0 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_set_channel_overwrite_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("ow_own2").await;
    let (_, member_token) = server.register_and_auth("ow_mem2").await;
    let node_id = server.create_node(&owner_token, "OverwriteNodeFrb").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "perm-ch2")
        .await;
    let role_id = create_role(&server, &owner_token, node_id, "RoleFrb").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .put(&format!(
            "{}/channels/{}/permissions/{}?token={}",
            server.base_url, channel_id, role_id, member_token
        ))
        .json(&json!({ "allow": 1024, "deny": 0 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_set_channel_overwrite_channel_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("ow_nf_own").await;
    let node_id = server.create_node(&owner_token, "OverwriteNodeNf").await;
    let role_id = create_role(&server, &owner_token, node_id, "RoleNf").await;

    let fake_channel = Uuid::new_v4();
    let resp = server
        .client
        .put(&format!(
            "{}/channels/{}/permissions/{}?token={}",
            server.base_url, fake_channel, role_id, owner_token
        ))
        .json(&json!({ "allow": 0, "deny": 0 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_channel_overwrite_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("del_ow_own").await;
    let node_id = server.create_node(&owner_token, "DelOvNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "del-perm-ch")
        .await;
    let role_id = create_role(&server, &owner_token, node_id, "DelOvRole").await;

    // First set an overwrite
    server
        .client
        .put(&format!(
            "{}/channels/{}/permissions/{}?token={}",
            server.base_url, channel_id, role_id, owner_token
        ))
        .json(&json!({ "allow": 512, "deny": 0 }))
        .send()
        .await
        .unwrap();

    // Now delete it
    let resp = server
        .client
        .delete(&format!(
            "{}/channels/{}/permissions/{}?token={}",
            server.base_url, channel_id, role_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_delete_channel_overwrite_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("del_ow_own2").await;
    let (_, member_token) = server.register_and_auth("del_ow_mem2").await;
    let node_id = server.create_node(&owner_token, "DelOvFrbNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "del-perm-ch2")
        .await;
    let role_id = create_role(&server, &owner_token, node_id, "DelOvRole2").await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .delete(&format!(
            "{}/channels/{}/permissions/{}?token={}",
            server.base_url, channel_id, role_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_get_effective_permissions_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("eff_perm_own").await;
    let node_id = server.create_node(&owner_token, "EffPermNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "eff-perm-ch")
        .await;

    // Owner should have all permissions
    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/effective-permissions?token={}",
            server.base_url, channel_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Should include a permissions field (bitmask)
    assert!(
        body["permissions"].is_number() || body["effective_permissions"].is_number(),
        "Expected permissions bitmask in response, got: {}",
        body
    );
}

#[tokio::test]
async fn test_get_effective_permissions_channel_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("eff_perm_nf").await;

    let fake_id = Uuid::new_v4();
    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/effective-permissions?token={}",
            server.base_url, fake_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_effective_permissions_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("eff_perm_unauth").await;
    let node_id = server.create_node(&owner_token, "EffPermUnauthNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "eff-perm-unauth-ch")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/effective-permissions",
            server.base_url, channel_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}
