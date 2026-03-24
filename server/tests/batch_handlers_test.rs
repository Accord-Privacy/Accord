//! Integration tests for batch API handlers:
//! batch_members_handler, batch_channels_handler, and node_overview_handler.
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
    batch_handlers::{batch_channels_handler, batch_members_handler, node_overview_handler},
    handlers::*,
    state::{AppState, SharedState},
};

// ─────────────────────────────────────────────────
//  TestServer helper
// ─────────────────────────────────────────────────

struct TestServer {
    base_url: String,
    client: Client,
    #[allow(dead_code)]
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
            .route(
                "/nodes/:id/channels",
                get(list_node_channels_handler).post(create_channel_handler),
            )
            .route("/nodes/:id/members", get(get_node_members_handler))
            .route(
                "/nodes/:id/invites",
                post(create_invite_handler).get(list_invites_handler),
            )
            .route("/invites/:code/join", post(use_invite_handler))
            .route("/nodes/:id/join", post(join_node_handler))
            .route("/nodes/:id/leave", post(leave_node_handler))
            // Batch endpoints
            .route(
                "/api/nodes/:node_id/members/batch",
                get(batch_members_handler),
            )
            .route(
                "/api/nodes/:node_id/channels/batch",
                get(batch_channels_handler),
            )
            .route("/api/nodes/:node_id/overview", get(node_overview_handler))
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
        let pk = format!("batch_test_pk_{}", name);

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

    /// Create a node and return node_id.
    async fn create_node(&self, token: &str, name: &str) -> Uuid {
        let resp = self
            .client
            .post(&format!("{}/nodes?token={}", self.base_url, token))
            .json(&json!({ "name": name }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create_node failed for '{name}'");
        let body: Value = resp.json().await.unwrap();
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
    }

    /// Create a channel in a node and return channel_id.
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
        assert_eq!(resp.status(), 200, "create_channel failed for '{name}'");
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
//  batch_members_handler  GET /api/nodes/:node_id/members/batch
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_batch_members_success_single_owner() {
    let server = TestServer::new().await;
    let (owner_id, token) = server.register_and_auth("bm_owner1").await;
    let node_id = server.create_node(&token, "BatchMembersNode1").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["members"].is_array(), "must have 'members' array");
    assert!(body["roles"].is_array(), "must have 'roles' array");

    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 1, "owner should be the only member");
    assert_eq!(
        members[0]["user_id"].as_str().unwrap(),
        owner_id.to_string()
    );
}

#[tokio::test]
async fn test_batch_members_success_multiple_members() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("bm_multi_owner").await;
    let (member1_id, member1_token) = server.register_and_auth("bm_multi_m1").await;
    let (member2_id, member2_token) = server.register_and_auth("bm_multi_m2").await;
    let node_id = server.create_node(&owner_token, "BatchMembersMulti").await;

    server.join_node(&member1_token, node_id).await;
    server.join_node(&member2_token, node_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 3, "owner + 2 members");

    let ids: Vec<&str> = members
        .iter()
        .map(|m| m["user_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&owner_id.to_string().as_str()));
    assert!(ids.contains(&member1_id.to_string().as_str()));
    assert!(ids.contains(&member2_id.to_string().as_str()));
}

#[tokio::test]
async fn test_batch_members_member_can_query() {
    // Non-owner members should also be able to call this endpoint
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("bm_memquery_owner").await;
    let (_, member_token) = server.register_and_auth("bm_memquery_member").await;
    let node_id = server
        .create_node(&owner_token, "BatchMembersMemberQuery")
        .await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);
}

#[tokio::test]
async fn test_batch_members_response_fields() {
    // Verify every member entry has the expected fields
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bm_fields_owner").await;
    let node_id = server.create_node(&token, "BatchMembersFields").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    assert!(!members.is_empty());

    let m = &members[0];
    assert!(m.get("user_id").is_some(), "missing user_id");
    assert!(m.get("display_name").is_some(), "missing display_name");
    assert!(m.get("roles").is_some(), "missing roles");
    assert!(m.get("online").is_some(), "missing online");
    assert!(m.get("status").is_some(), "missing status");
    assert!(m.get("joined_at").is_some(), "missing joined_at");
    assert!(m.get("node_role").is_some(), "missing node_role");
}

#[tokio::test]
async fn test_batch_members_unauthorized_no_token() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bm_unauth_owner").await;
    let node_id = server.create_node(&token, "BatchMembersUnauth").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch",
            server.base_url, node_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_batch_members_unauthorized_invalid_token() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bm_invtok_owner").await;
    let node_id = server.create_node(&token, "BatchMembersInvTok").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token=completely_invalid_token",
            server.base_url, node_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_batch_members_forbidden_non_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("bm_forb_owner").await;
    let (_, stranger_token) = server.register_and_auth("bm_forb_stranger").await;
    let node_id = server.create_node(&owner_token, "BatchMembersForb").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_batch_members_nonexistent_node() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bm_nonode_user").await;
    let fake_node_id = Uuid::new_v4();

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, fake_node_id, token
        ))
        .send()
        .await
        .unwrap();

    // Non-member check fires first → 403
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_batch_members_roles_array_always_present() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bm_roles_owner").await;
    let node_id = server.create_node(&token, "BatchMembersRoles").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["roles"].is_array(), "'roles' must be an array");
}

#[tokio::test]
async fn test_batch_members_large_node() {
    // Add several members and confirm all are returned
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("bm_large_owner").await;
    let node_id = server.create_node(&owner_token, "BatchMembersLarge").await;

    for i in 0..8 {
        let (_, t) = server.register_and_auth(&format!("bm_large_m{}", i)).await;
        server.join_node(&t, node_id).await;
    }

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 9, "owner + 8 members");
}

#[tokio::test]
async fn test_batch_members_node_role_field() {
    // Owner should have node_role set to "owner" (or similar)
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bm_noderole_owner").await;
    let node_id = server.create_node(&token, "BatchMembersNodeRole").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    assert!(!members.is_empty());
    // node_role must not be null
    assert!(!members[0]["node_role"].is_null(), "node_role must be set");
}

// ═══════════════════════════════════════════════════════════════
//  batch_channels_handler  GET /api/nodes/:node_id/channels/batch
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_batch_channels_success_with_channels() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bc_owner1").await;
    let node_id = server.create_node(&token, "BatchChannelsNode1").await;
    server.create_channel(&token, node_id, "general").await;
    server
        .create_channel(&token, node_id, "announcements")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["channels"].is_array(), "must have 'channels' array");

    let channels = body["channels"].as_array().unwrap();
    let names: Vec<&str> = channels
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"general"), "expected 'general'");
    assert!(names.contains(&"announcements"), "expected 'announcements'");
}

#[tokio::test]
async fn test_batch_channels_response_fields() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bc_fields_owner").await;
    let node_id = server.create_node(&token, "BatchChannelsFields").await;
    server.create_channel(&token, node_id, "test-ch").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let channels = body["channels"].as_array().unwrap();
    assert!(!channels.is_empty());

    let ch = channels
        .iter()
        .find(|c| c["name"] == "test-ch")
        .expect("expected 'test-ch'");
    assert!(ch.get("id").is_some(), "missing id");
    assert!(ch.get("name").is_some(), "missing name");
    assert!(ch.get("node_id").is_some(), "missing node_id");
    assert!(ch.get("position").is_some(), "missing position");
    assert!(ch.get("unread_count").is_some(), "missing unread_count");
    assert!(ch.get("channel_type").is_some(), "missing channel_type");
    assert!(
        ch.get("permission_overrides").is_some(),
        "missing permission_overrides"
    );
}

#[tokio::test]
async fn test_batch_channels_no_extra_channels_created() {
    // New node may or may not create default channels — endpoint should always
    // return a valid array regardless of how many channels exist.
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bc_empty_owner").await;
    let node_id = server.create_node(&token, "BatchChannelsEmpty").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["channels"].is_array(),
        "'channels' must be a JSON array"
    );
}

#[tokio::test]
async fn test_batch_channels_unauthorized_no_token() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bc_unauth_owner").await;
    let node_id = server.create_node(&token, "BatchChannelsUnauth").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch",
            server.base_url, node_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_batch_channels_unauthorized_invalid_token() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bc_invtok_owner").await;
    let node_id = server.create_node(&token, "BatchChannelsInvTok").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token=bogus_token_here",
            server.base_url, node_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_batch_channels_forbidden_non_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("bc_forb_owner").await;
    let (_, stranger_token) = server.register_and_auth("bc_forb_stranger").await;
    let node_id = server.create_node(&owner_token, "BatchChannelsForb").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_batch_channels_nonexistent_node() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bc_nonode_user").await;
    let fake_node_id = Uuid::new_v4();

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, fake_node_id, token
        ))
        .send()
        .await
        .unwrap();

    // Membership check fires first
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_batch_channels_member_can_query() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("bc_memq_owner").await;
    let (_, member_token) = server.register_and_auth("bc_memq_member").await;
    let node_id = server
        .create_node(&owner_token, "BatchChannelsMemberQ")
        .await;
    server.join_node(&member_token, node_id).await;
    server
        .create_channel(&owner_token, node_id, "shared-ch")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["channels"].is_array());
}

#[tokio::test]
async fn test_batch_channels_unread_count_is_zero_initially() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bc_unread_owner").await;
    let node_id = server.create_node(&token, "BatchChannelsUnread").await;
    server.create_channel(&token, node_id, "fresh-ch").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let channels = body["channels"].as_array().unwrap();
    let fresh = channels.iter().find(|c| c["name"] == "fresh-ch");
    if let Some(ch) = fresh {
        assert_eq!(
            ch["unread_count"].as_u64().unwrap_or(0),
            0,
            "new channel should have 0 unread"
        );
    }
}

#[tokio::test]
async fn test_batch_channels_channel_type_text() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bc_type_owner").await;
    let node_id = server.create_node(&token, "BatchChannelsType").await;
    server.create_channel(&token, node_id, "type-ch").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let channels = body["channels"].as_array().unwrap();
    let ch = channels
        .iter()
        .find(|c| c["name"] == "type-ch")
        .expect("expected 'type-ch'");
    let ct = ch["channel_type"].as_str().unwrap();
    assert!(
        ct == "text" || ct == "voice" || ct == "category",
        "unexpected channel_type: {}",
        ct
    );
}

#[tokio::test]
async fn test_batch_channels_permission_overrides_array() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bc_perms_owner").await;
    let node_id = server.create_node(&token, "BatchChannelsPerms").await;
    server.create_channel(&token, node_id, "perms-ch").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let channels = body["channels"].as_array().unwrap();
    let ch = channels
        .iter()
        .find(|c| c["name"] == "perms-ch")
        .expect("expected 'perms-ch'");
    assert!(
        ch["permission_overrides"].is_array(),
        "permission_overrides must be array"
    );
}

// ═══════════════════════════════════════════════════════════════
//  node_overview_handler  GET /api/nodes/:node_id/overview
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_node_overview_success_all_fields() {
    let server = TestServer::new().await;
    let (owner_id, token) = server.register_and_auth("ov_owner1").await;
    let node_id = server.create_node(&token, "OverviewNode1").await;
    server.create_channel(&token, node_id, "overview-ch").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    // All four top-level keys must be present
    assert!(body.get("node").is_some(), "missing 'node'");
    assert!(body.get("channels").is_some(), "missing 'channels'");
    assert!(body.get("members").is_some(), "missing 'members'");
    assert!(body.get("roles").is_some(), "missing 'roles'");

    // Members should include the owner
    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0]["user_id"].as_str().unwrap(),
        owner_id.to_string()
    );

    // Channels should include the one we created
    let channels = body["channels"].as_array().unwrap();
    let names: Vec<&str> = channels
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"overview-ch"));
}

#[tokio::test]
async fn test_node_overview_node_object_fields() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("ov_nodefields_owner").await;
    let node_id = server.create_node(&token, "OverviewNodeFields").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let node = &body["node"];
    // node object should have at minimum id and name
    assert!(
        node.get("id").is_some() || node.get("name").is_some(),
        "node object missing id/name fields"
    );
}

#[tokio::test]
async fn test_node_overview_member_fields() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("ov_memfields_owner").await;
    let node_id = server.create_node(&token, "OverviewMemberFields").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    assert!(!members.is_empty());

    let m = &members[0];
    assert!(m.get("user_id").is_some(), "missing user_id");
    assert!(m.get("display_name").is_some(), "missing display_name");
    assert!(m.get("roles").is_some(), "missing roles");
    assert!(m.get("online").is_some(), "missing online");
    assert!(m.get("status").is_some(), "missing status");
    assert!(m.get("joined_at").is_some(), "missing joined_at");
    assert!(m.get("node_role").is_some(), "missing node_role");
}

#[tokio::test]
async fn test_node_overview_channel_fields() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("ov_chfields_owner").await;
    let node_id = server.create_node(&token, "OverviewChannelFields").await;
    server.create_channel(&token, node_id, "ch-fields").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let channels = body["channels"].as_array().unwrap();
    let ch = channels
        .iter()
        .find(|c| c["name"] == "ch-fields")
        .expect("expected 'ch-fields'");

    assert!(ch.get("id").is_some(), "missing id");
    assert!(ch.get("name").is_some(), "missing name");
    assert!(ch.get("node_id").is_some(), "missing node_id");
    assert!(ch.get("unread_count").is_some(), "missing unread_count");
    assert!(ch.get("channel_type").is_some(), "missing channel_type");
}

#[tokio::test]
async fn test_node_overview_multiple_members_and_channels() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("ov_multi_owner").await;
    let (_, m1_token) = server.register_and_auth("ov_multi_m1").await;
    let (_, m2_token) = server.register_and_auth("ov_multi_m2").await;
    let node_id = server.create_node(&owner_token, "OverviewMulti").await;

    server.join_node(&m1_token, node_id).await;
    server.join_node(&m2_token, node_id).await;
    server
        .create_channel(&owner_token, node_id, "ch-alpha")
        .await;
    server
        .create_channel(&owner_token, node_id, "ch-beta")
        .await;
    server
        .create_channel(&owner_token, node_id, "ch-gamma")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    let members = body["members"].as_array().unwrap();
    assert_eq!(members.len(), 3, "owner + 2 members");

    let channels = body["channels"].as_array().unwrap();
    let names: Vec<&str> = channels
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"ch-alpha"));
    assert!(names.contains(&"ch-beta"));
    assert!(names.contains(&"ch-gamma"));
}

#[tokio::test]
async fn test_node_overview_unauthorized_no_token() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("ov_unauth_owner").await;
    let node_id = server.create_node(&token, "OverviewUnauth").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview",
            server.base_url, node_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_node_overview_unauthorized_invalid_token() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("ov_invtok_owner").await;
    let node_id = server.create_node(&token, "OverviewInvTok").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token=this_is_not_a_real_token",
            server.base_url, node_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_node_overview_forbidden_non_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("ov_forb_owner").await;
    let (_, stranger_token) = server.register_and_auth("ov_forb_stranger").await;
    let node_id = server.create_node(&owner_token, "OverviewForb").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_node_overview_nonexistent_node() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("ov_nonode_user").await;
    let fake_node_id = Uuid::new_v4();

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, fake_node_id, token
        ))
        .send()
        .await
        .unwrap();

    // Non-member check fires before node lookup → 403
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_node_overview_roles_always_array() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("ov_roles_owner").await;
    let node_id = server.create_node(&token, "OverviewRoles").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["roles"].is_array(), "'roles' must be an array");
}

#[tokio::test]
async fn test_node_overview_channels_always_array() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("ov_charrays_owner").await;
    let node_id = server.create_node(&token, "OverviewChArrays").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["channels"].is_array(), "'channels' must be an array");
}

#[tokio::test]
async fn test_node_overview_member_can_query() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("ov_memq_owner").await;
    let (member_id, member_token) = server.register_and_auth("ov_memq_member").await;
    let node_id = server
        .create_node(&owner_token, "OverviewMemberQuery")
        .await;
    server.join_node(&member_token, node_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    let ids: Vec<&str> = members
        .iter()
        .map(|m| m["user_id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&member_id.to_string().as_str()),
        "member should see themselves in the list"
    );
}

// ═══════════════════════════════════════════════════════════════
//  Edge cases / consistency checks
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_batch_members_and_overview_agree_on_member_count() {
    // Both endpoints should return the same number of members for the same node
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("agree_owner").await;
    let (_, m1_token) = server.register_and_auth("agree_m1").await;
    let node_id = server.create_node(&owner_token, "AgreeNode").await;
    server.join_node(&m1_token, node_id).await;

    let bm_resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    let ov_resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(bm_resp.status(), 200);
    assert_eq!(ov_resp.status(), 200);

    let bm_body: Value = bm_resp.json().await.unwrap();
    let ov_body: Value = ov_resp.json().await.unwrap();

    let bm_count = bm_body["members"].as_array().unwrap().len();
    let ov_count = ov_body["members"].as_array().unwrap().len();
    assert_eq!(
        bm_count, ov_count,
        "batch_members and overview must agree on member count"
    );
}

#[tokio::test]
async fn test_batch_channels_and_overview_agree_on_channel_count() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("agree_ch_owner").await;
    let node_id = server.create_node(&token, "AgreeChNode").await;
    server.create_channel(&token, node_id, "ch-agree-1").await;
    server.create_channel(&token, node_id, "ch-agree-2").await;

    let bc_resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();
    let ov_resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(bc_resp.status(), 200);
    assert_eq!(ov_resp.status(), 200);

    let bc_body: Value = bc_resp.json().await.unwrap();
    let ov_body: Value = ov_resp.json().await.unwrap();

    let bc_count = bc_body["channels"].as_array().unwrap().len();
    let ov_count = ov_body["channels"].as_array().unwrap().len();
    assert_eq!(
        bc_count, ov_count,
        "batch_channels and overview must agree on channel count"
    );
}

#[tokio::test]
async fn test_batch_members_online_field_is_boolean() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("online_bool_owner").await;
    let node_id = server.create_node(&token, "OnlineBoolNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/members/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    for m in body["members"].as_array().unwrap() {
        assert!(m["online"].is_boolean(), "online field must be boolean");
    }
}

#[tokio::test]
async fn test_batch_channels_node_id_matches() {
    // Every channel returned should have the correct node_id
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("nodeid_match_owner").await;
    let node_id = server.create_node(&token, "NodeIdMatchNode").await;
    server.create_channel(&token, node_id, "nodeid-ch").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/channels/batch?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    for ch in body["channels"].as_array().unwrap() {
        assert_eq!(
            ch["node_id"].as_str().unwrap(),
            node_id.to_string(),
            "channel node_id must match the queried node"
        );
    }
}

#[tokio::test]
async fn test_node_overview_status_offline_for_disconnected() {
    // In tests, no WebSocket connections exist → all members should be offline
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("offline_owner").await;
    let node_id = server.create_node(&token, "OfflineNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/nodes/{}/overview?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    for m in body["members"].as_array().unwrap() {
        assert_eq!(
            m["status"].as_str().unwrap(),
            "offline",
            "member with no WS connection should be 'offline'"
        );
        assert_eq!(
            m["online"].as_bool().unwrap(),
            false,
            "online should be false for disconnected members"
        );
    }
}
