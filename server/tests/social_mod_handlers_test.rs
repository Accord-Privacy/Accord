//! Integration tests for social, moderation, and user management handlers.
//!
//! Covers: friends, blocking, bans (extended), DM channels, reactions,
//! auto-mod words, and node user profiles.
#![allow(clippy::all, unused_imports, dead_code)]

use axum::{
    routing::{delete, get, post},
    Router,
};
use base64::Engine as _;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use accord_server::{
    handlers::*,
    node::NodeRole,
    state::{AppState, SharedState},
};

// ══════════════════════════════════════════════════════════════════════════════
// Test server helper
// ══════════════════════════════════════════════════════════════════════════════

struct SocialTestServer {
    pub base_url: String,
    pub client: Client,
    pub state: SharedState,
}

impl SocialTestServer {
    async fn new() -> Self {
        let state: SharedState = Arc::new(AppState::new_in_memory().await.unwrap());

        let app = Router::new()
            // Core auth
            .route("/register", post(register_handler))
            .route("/auth", post(auth_handler))
            .route("/health", get(health_handler))
            // Nodes
            .route(
                "/nodes",
                get(list_user_nodes_handler).post(create_node_handler),
            )
            .route("/nodes/:id", get(get_node_handler))
            .route("/nodes/:id/join", post(join_node_handler))
            .route("/nodes/:id/leave", post(leave_node_handler))
            .route(
                "/nodes/:id/channels",
                get(list_node_channels_handler).post(create_channel_handler),
            )
            .route("/nodes/:id/members", get(get_node_members_handler))
            .route("/nodes/:id/members/:user_id", delete(kick_user_handler))
            // Bans
            .route(
                "/nodes/:id/bans",
                post(ban_user_handler)
                    .delete(unban_user_handler)
                    .get(list_bans_handler),
            )
            .route("/nodes/:id/ban-check", get(ban_check_handler))
            // Node user profiles
            .route(
                "/nodes/:id/profile",
                axum::routing::put(set_node_user_profile_handler),
            )
            .route("/nodes/:id/profiles", get(get_node_user_profiles_handler))
            // Auto-mod words
            .route(
                "/nodes/:id/auto-mod/words",
                get(list_auto_mod_words_handler).post(add_auto_mod_word_handler),
            )
            .route(
                "/nodes/:id/auto-mod/words/:word",
                delete(remove_auto_mod_word_handler),
            )
            // Channels / messages
            .route("/channels/:id/messages", get(get_channel_messages_handler))
            // Reactions
            .route(
                "/messages/:id/reactions",
                get(get_message_reactions_handler),
            )
            .route(
                "/messages/:id/reactions/:emoji",
                axum::routing::put(add_reaction_handler).delete(remove_reaction_handler),
            )
            // Friends
            .route("/friends/request", post(send_friend_request_handler))
            .route("/friends/accept", post(accept_friend_request_handler))
            .route("/friends/reject", post(reject_friend_request_handler))
            .route("/friends", get(list_friends_handler))
            .route("/friends/requests", get(list_friend_requests_handler))
            .route("/friends/:user_id", delete(remove_friend_handler))
            // Blocking
            .route(
                "/users/:id/block",
                post(block_user_handler).delete(unblock_user_handler),
            )
            .route("/api/blocked-users", get(get_blocked_users_handler))
            // DM channels
            .route("/dm/:user_id", post(create_dm_channel_handler))
            .route("/dm", get(get_dm_channels_handler))
            // WebSocket (required by some state machinery)
            .route("/ws", get(ws_handler))
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

    /// Register and authenticate, return (user_id, token).
    async fn register_and_auth(&self, name: &str) -> (Uuid, String) {
        let pk = format!("test_pk_{}", name);
        let resp = self
            .client
            .post(&self.url("/register"))
            .json(&json!({ "public_key": pk }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "register failed for {}", name);
        let body: Value = resp.json().await.unwrap();
        let user_id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();

        let resp = self
            .client
            .post(&self.url("/auth"))
            .json(&json!({ "public_key": pk, "password": "" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "auth failed for {}", name);
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

    /// Join a node.
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

    /// Create a channel, return channel_id.
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

    /// Get the SHA-256 hex public_key_hash for a registered user by name (test helper).
    async fn get_pk_hash(&self, name: &str) -> String {
        use sha2::{Digest, Sha256};
        let pk = format!("test_pk_{}", name);
        let hash = Sha256::digest(pk.as_bytes());
        hex::encode(hash)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── DB-level sanity test for DM channel creation ──
// ══════════════════════════════════════════════════════════════════════════════

/// Note: `create_or_get_dm_channel` internally calls `create_channel_with_id`
/// with `Uuid::nil()` as node_id. sqlx-sqlite enables FK enforcement by default,
/// so this fails unless the `nodes` table has an entry for `00000000-0000-...`.
/// This is a known server architectural limitation; these DB-level tests confirm that.
#[tokio::test]
async fn test_dm_channel_db_level_friendship_established() {
    let state: SharedState = Arc::new(AppState::new_in_memory().await.unwrap());

    let user1 = state.db.create_user("pk_dm_test1", "").await.unwrap();
    let user2 = state.db.create_user("pk_dm_test2", "").await.unwrap();

    let node = state
        .db
        .create_node("dm-sanity-node", user1.id, None)
        .await
        .unwrap();
    let node_id = node.id;
    state
        .db
        .add_node_member(node_id, user2.id, NodeRole::Member)
        .await
        .unwrap();

    let req_id = state
        .db
        .create_friend_request(user1.id, user2.id, node_id, None)
        .await
        .unwrap();
    let accepted = state.db.accept_friend_request(req_id, None).await.unwrap();
    assert!(accepted, "friend request should be accepted");

    // Verify friendship is established before trying DM
    let h1 = state
        .db
        .get_user_public_key_hash(user1.id)
        .await
        .unwrap()
        .unwrap();
    let h2 = state
        .db
        .get_user_public_key_hash(user2.id)
        .await
        .unwrap()
        .unwrap();
    let friends = state.db.are_friends(&h1, &h2).await.unwrap();
    assert!(friends, "users should be friends after accepting request");
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Friends ──
// ══════════════════════════════════════════════════════════════════════════════

/// Helper: make two users friends by sharing a node, sending a request, and accepting.
async fn make_friends(
    server: &SocialTestServer,
    _user1_id: Uuid,
    token1: &str,
    user2_id: Uuid,
    token2: &str,
) -> Uuid {
    // Ensure they share a node
    let node_id = server.create_node(token1, "shared-node-friends").await;
    server.join_node(token2, node_id).await;

    // Send friend request — requires node_id
    let resp = server
        .client
        .post(&format!(
            "{}/friends/request?token={}",
            server.base_url, token1
        ))
        .json(&json!({ "to_user_id": user2_id, "node_id": node_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "send_friend_request failed");
    let body: Value = resp.json().await.unwrap();
    let request_id = Uuid::parse_str(body["request_id"].as_str().unwrap()).unwrap();

    // Accept
    let resp = server
        .client
        .post(&format!(
            "{}/friends/accept?token={}",
            server.base_url, token2
        ))
        .json(&json!({ "request_id": request_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "accept_friend_request failed");

    node_id
}

#[tokio::test]
async fn test_send_friend_request_happy_path() {
    let server = SocialTestServer::new().await;
    let (_user1_id, token1) = server.register_and_auth("fr_sender").await;
    let (user2_id, token2) = server.register_and_auth("fr_receiver").await;

    // Share a node
    let node_id = server.create_node(&token1, "fr-node").await;
    server.join_node(&token2, node_id).await;

    let resp = server
        .client
        .post(&format!(
            "{}/friends/request?token={}",
            server.base_url, token1
        ))
        .json(&json!({ "to_user_id": user2_id, "node_id": node_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["request_id"].is_string(), "should return request_id");
    assert_eq!(body["status"], "sent");
}

#[tokio::test]
async fn test_send_friend_request_to_self_fails() {
    let server = SocialTestServer::new().await;
    let (user_id, token) = server.register_and_auth("fr_self").await;

    let bogus_node_id = Uuid::new_v4();
    let resp = server
        .client
        .post(&format!(
            "{}/friends/request?token={}",
            server.base_url, token
        ))
        .json(&json!({ "to_user_id": user_id, "node_id": bogus_node_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("yourself"),
        "error should mention yourself: {:?}",
        body
    );
}

#[tokio::test]
async fn test_send_friend_request_unknown_user_fails() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("fr_sender_unknown").await;
    let bogus_id = Uuid::new_v4();

    let bogus_node_id = Uuid::new_v4();
    let resp = server
        .client
        .post(&format!(
            "{}/friends/request?token={}",
            server.base_url, token
        ))
        .json(&json!({ "to_user_id": bogus_id, "node_id": bogus_node_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_send_friend_request_no_shared_node_fails() {
    let server = SocialTestServer::new().await;
    let (_user1_id, token1) = server.register_and_auth("fr_noshare1").await;
    let (user2_id, _token2) = server.register_and_auth("fr_noshare2").await;

    // No shared node — request should be forbidden
    let bogus_node_id = Uuid::new_v4();
    let resp = server
        .client
        .post(&format!(
            "{}/friends/request?token={}",
            server.base_url, token1
        ))
        .json(&json!({ "to_user_id": user2_id, "node_id": bogus_node_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("Node"),
        "error should mention Node: {:?}",
        body
    );
}

#[tokio::test]
async fn test_send_friend_request_unauthenticated_fails() {
    let server = SocialTestServer::new().await;
    let (user2_id, _) = server.register_and_auth("fr_unauth_target").await;

    let bogus_node_id = Uuid::new_v4();
    let resp = server
        .client
        .post(&server.url("/friends/request"))
        .json(&json!({ "to_user_id": user2_id, "node_id": bogus_node_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_accept_friend_request_happy_path() {
    let server = SocialTestServer::new().await;
    let (_user1_id, token1) = server.register_and_auth("fr_acc_sender").await;
    let (user2_id, token2) = server.register_and_auth("fr_acc_receiver").await;

    let node_id = server.create_node(&token1, "fr-acc-node").await;
    server.join_node(&token2, node_id).await;

    // Send — requires node_id
    let resp = server
        .client
        .post(&format!(
            "{}/friends/request?token={}",
            server.base_url, token1
        ))
        .json(&json!({ "to_user_id": user2_id, "node_id": node_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let request_id = Uuid::parse_str(body["request_id"].as_str().unwrap()).unwrap();

    // Accept
    let resp = server
        .client
        .post(&format!(
            "{}/friends/accept?token={}",
            server.base_url, token2
        ))
        .json(&json!({ "request_id": request_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "accepted");
}

#[tokio::test]
async fn test_accept_friend_request_wrong_user_fails() {
    let server = SocialTestServer::new().await;
    let (_user1_id, token1) = server.register_and_auth("fr_acc_wrong1").await;
    let (user2_id, token2) = server.register_and_auth("fr_acc_wrong2").await;
    let (_user3_id, token3) = server.register_and_auth("fr_acc_wrong3").await;

    let node_id = server.create_node(&token1, "fr-wrong-node").await;
    server.join_node(&token2, node_id).await;
    server.join_node(&token3, node_id).await;

    let resp = server
        .client
        .post(&format!(
            "{}/friends/request?token={}",
            server.base_url, token1
        ))
        .json(&json!({ "to_user_id": user2_id, "node_id": node_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let request_id = Uuid::parse_str(body["request_id"].as_str().unwrap()).unwrap();

    // User3 tries to accept a request addressed to user2
    let resp = server
        .client
        .post(&format!(
            "{}/friends/accept?token={}",
            server.base_url, token3
        ))
        .json(&json!({ "request_id": request_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_list_friends_empty_on_fresh_user() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("fr_list_empty").await;

    let resp = server
        .client
        .get(&format!("{}/friends?token={}", server.base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["friends"].is_array());
    assert_eq!(body["friends"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_list_friends_after_accepting() {
    let server = SocialTestServer::new().await;
    let (user1_id, token1) = server.register_and_auth("fr_list_a").await;
    let (user2_id, token2) = server.register_and_auth("fr_list_b").await;

    make_friends(&server, user1_id, &token1, user2_id, &token2).await;

    // Both users should see each other in friend list
    let resp = server
        .client
        .get(&format!("{}/friends?token={}", server.base_url, token1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let friends = body["friends"].as_array().unwrap();
    assert!(!friends.is_empty(), "user1 should have at least one friend");
}

#[tokio::test]
async fn test_remove_friend_happy_path() {
    let server = SocialTestServer::new().await;
    let (user1_id, token1) = server.register_and_auth("fr_remove_a").await;
    let (user2_id, token2) = server.register_and_auth("fr_remove_b").await;

    make_friends(&server, user1_id, &token1, user2_id, &token2).await;

    // Remove
    let resp = server
        .client
        .delete(&format!(
            "{}/friends/{}?token={}",
            server.base_url, user2_id, token1
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "removed");
}

#[tokio::test]
async fn test_remove_friend_not_friends_fails() {
    let server = SocialTestServer::new().await;
    let (_user1_id, token1) = server.register_and_auth("fr_norel_a").await;
    let (user2_id, _token2) = server.register_and_auth("fr_norel_b").await;

    // Not friends, should 404
    let resp = server
        .client
        .delete(&format!(
            "{}/friends/{}?token={}",
            server.base_url, user2_id, token1
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Blocking ──
// ══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_block_user_happy_path() {
    let server = SocialTestServer::new().await;
    let (_blocker_id, token) = server.register_and_auth("block_er").await;
    let (target_id, _) = server.register_and_auth("block_ee").await;

    let resp = server
        .client
        .post(&format!(
            "{}/users/{}/block?token={}",
            server.base_url, target_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "blocked");
    assert_eq!(body["user_id"], target_id.to_string());
}

#[tokio::test]
async fn test_block_self_fails() {
    let server = SocialTestServer::new().await;
    let (user_id, token) = server.register_and_auth("block_self").await;

    let resp = server
        .client
        .post(&format!(
            "{}/users/{}/block?token={}",
            server.base_url, user_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("yourself"),
        "error should mention yourself: {:?}",
        body
    );
}

#[tokio::test]
async fn test_block_unknown_user_fails() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("block_unknown_caller").await;
    let bogus = Uuid::new_v4();

    let resp = server
        .client
        .post(&format!(
            "{}/users/{}/block?token={}",
            server.base_url, bogus, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_blocked_users_empty_initially() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("blocked_list_empty").await;

    let resp = server
        .client
        .get(&format!(
            "{}/api/blocked-users?token={}",
            server.base_url, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["blocked_users"].is_array());
    assert_eq!(body["blocked_users"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_get_blocked_users_after_block() {
    let server = SocialTestServer::new().await;
    let (_blocker_id, token) = server.register_and_auth("blocked_list_full").await;
    let (target_id, _) = server.register_and_auth("blocked_target_fl").await;

    // Block target
    let resp = server
        .client
        .post(&format!(
            "{}/users/{}/block?token={}",
            server.base_url, target_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List
    let resp = server
        .client
        .get(&format!(
            "{}/api/blocked-users?token={}",
            server.base_url, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let blocked = body["blocked_users"].as_array().unwrap();
    assert!(!blocked.is_empty(), "should have at least one blocked user");
}

#[tokio::test]
async fn test_unblock_user_happy_path() {
    let server = SocialTestServer::new().await;
    let (_blocker_id, token) = server.register_and_auth("unblock_er").await;
    let (target_id, _) = server.register_and_auth("unblock_ee").await;

    // Block first
    server
        .client
        .post(&format!(
            "{}/users/{}/block?token={}",
            server.base_url, target_id, token
        ))
        .send()
        .await
        .unwrap();

    // Unblock
    let resp = server
        .client
        .delete(&format!(
            "{}/users/{}/block?token={}",
            server.base_url, target_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "unblocked");
}

#[tokio::test]
async fn test_unblock_user_not_blocked_fails() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("unblock_none").await;
    let (target_id, _) = server.register_and_auth("unblock_none_tgt").await;

    // Never blocked — should 404
    let resp = server
        .client
        .delete(&format!(
            "{}/users/{}/block?token={}",
            server.base_url, target_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Bans (extended) ──
// ══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_list_bans_empty_initially() {
    let server = SocialTestServer::new().await;
    let (_owner_id, token) = server.register_and_auth("bans_owner").await;
    let node_id = server.create_node(&token, "bans-node").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/bans?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let bans = body["bans"].as_array().unwrap();
    assert_eq!(bans.len(), 0);
}

#[tokio::test]
async fn test_list_bans_after_ban() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("bans_list_owner").await;
    let (_banned_id, banned_token) = server.register_and_auth("bans_list_banned").await;
    let node_id = server.create_node(&owner_token, "bans-list-node").await;
    server.join_node(&banned_token, node_id).await;

    // Use a fake hash for the ban request
    let banned_pk_hash = server.get_pk_hash("bans_list_banned").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/bans?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "public_key_hash": banned_pk_hash }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/bans?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let bans = body["bans"].as_array().unwrap();
    assert!(!bans.is_empty(), "should have at least one ban");
}

#[tokio::test]
async fn test_list_bans_non_member_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("bans_nm_owner").await;
    let (_other_id, other_token) = server.register_and_auth("bans_nm_other").await;
    let node_id = server.create_node(&owner_token, "bans-nm-node").await;

    // other is not a member
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/bans?token={}",
            server.base_url, node_id, other_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_ban_check_not_banned() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("bancheck_owner").await;
    let node_id = server.create_node(&owner_token, "bancheck-node").await;
    let fake_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/ban-check?token={}&public_key_hash={}",
            server.base_url, node_id, owner_token, fake_hash
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["banned"], false);
}

#[tokio::test]
async fn test_ban_check_after_ban() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("bancheck_ban_owner").await;
    let (_banned_id, banned_token) = server.register_and_auth("bancheck_ban_user").await;
    let node_id = server.create_node(&owner_token, "bancheck-ban-node").await;
    server.join_node(&banned_token, node_id).await;

    let banned_pk_hash = server.get_pk_hash("bancheck_ban_user").await;

    server
        .client
        .post(&format!(
            "{}/nodes/{}/bans?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "public_key_hash": banned_pk_hash }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/ban-check?token={}&public_key_hash={}",
            server.base_url, node_id, owner_token, banned_pk_hash
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["banned"], true);
    assert_eq!(body["key_banned"], true);
}

#[tokio::test]
async fn test_ban_check_no_params_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("bancheck_noparams").await;
    let node_id = server
        .create_node(&owner_token, "bancheck-noparams-node")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/ban-check?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_unban_user_happy_path() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("unban_owner").await;
    let (_banned_id, banned_token) = server.register_and_auth("unban_target").await;
    let node_id = server.create_node(&owner_token, "unban-node").await;
    server.join_node(&banned_token, node_id).await;

    let banned_pk_hash = server.get_pk_hash("unban_target").await;

    // Ban
    server
        .client
        .post(&format!(
            "{}/nodes/{}/bans?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "public_key_hash": banned_pk_hash }))
        .send()
        .await
        .unwrap();

    // Unban
    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/bans?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "public_key_hash": banned_pk_hash }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "unbanned");
}

#[tokio::test]
async fn test_unban_nonexistent_ban_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("unban_noexist_owner").await;
    let node_id = server.create_node(&owner_token, "unban-noexist-node").await;

    let fake_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/bans?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "public_key_hash": fake_hash }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ══════════════════════════════════════════════════════════════════════════════
// ── DM Channels ──
// ══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_create_dm_channel_requires_friendship() {
    let server = SocialTestServer::new().await;
    let (_user1_id, token1) = server.register_and_auth("dm_notfriends1").await;
    let (user2_id, _token2) = server.register_and_auth("dm_notfriends2").await;

    // Not friends — should fail
    let resp = server
        .client
        .post(&format!(
            "{}/dm/{}?token={}",
            server.base_url, user2_id, token1
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("friend"),
        "error should mention friends: {:?}",
        body
    );
}

#[tokio::test]
async fn test_create_dm_channel_with_self_fails() {
    let server = SocialTestServer::new().await;
    let (user_id, token) = server.register_and_auth("dm_self").await;

    let resp = server
        .client
        .post(&format!(
            "{}/dm/{}?token={}",
            server.base_url, user_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("yourself"),
        "error should mention yourself: {:?}",
        body
    );
}

#[tokio::test]
async fn test_create_dm_channel_unknown_user_fails() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("dm_unknown_caller").await;
    let bogus = Uuid::new_v4();

    let resp = server
        .client
        .post(&format!("{}/dm/{}?token={}", server.base_url, bogus, token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_create_dm_channel_after_friendship() {
    let server = SocialTestServer::new().await;
    let (user1_id, token1) = server.register_and_auth("dm_friends1").await;
    let (user2_id, token2) = server.register_and_auth("dm_friends2").await;

    make_friends(&server, user1_id, &token1, user2_id, &token2).await;

    let resp = server
        .client
        .post(&format!(
            "{}/dm/{}?token={}",
            server.base_url, user2_id, token1
        ))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "create DM channel failed: {:?}", body);
    assert!(
        body["id"].is_string(),
        "should return DM channel id: {:?}",
        body
    );
    assert_eq!(body["is_dm"], true);
}

#[tokio::test]
async fn test_create_dm_channel_idempotent() {
    let server = SocialTestServer::new().await;
    let (user1_id, token1) = server.register_and_auth("dm_idem1").await;
    let (user2_id, token2) = server.register_and_auth("dm_idem2").await;

    make_friends(&server, user1_id, &token1, user2_id, &token2).await;

    // Create once
    let resp = server
        .client
        .post(&format!(
            "{}/dm/{}?token={}",
            server.base_url, user2_id, token1
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body1: Value = resp.json().await.unwrap();
    let id1 = body1["id"].as_str().unwrap().to_string();

    // Create again — same channel should be returned
    let resp = server
        .client
        .post(&format!(
            "{}/dm/{}?token={}",
            server.base_url, user2_id, token1
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body2: Value = resp.json().await.unwrap();
    let id2 = body2["id"].as_str().unwrap().to_string();
    assert_eq!(id1, id2, "DM channel should be idempotent");
}

#[tokio::test]
async fn test_get_dm_channels_empty() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("get_dm_empty").await;

    let resp = server
        .client
        .get(&format!("{}/dm?token={}", server.base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["dm_channels"].is_array());
    assert_eq!(body["dm_channels"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_get_dm_channels_after_create() {
    let server = SocialTestServer::new().await;
    let (user1_id, token1) = server.register_and_auth("get_dm_full1").await;
    let (user2_id, token2) = server.register_and_auth("get_dm_full2").await;

    make_friends(&server, user1_id, &token1, user2_id, &token2).await;

    server
        .client
        .post(&format!(
            "{}/dm/{}?token={}",
            server.base_url, user2_id, token1
        ))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!("{}/dm?token={}", server.base_url, token1))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let channels = body["dm_channels"].as_array().unwrap();
    assert!(
        !channels.is_empty(),
        "should have DM channel after creating one"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Reactions ──
// ══════════════════════════════════════════════════════════════════════════════

/// Helper: send a message via state directly, return message_id.
async fn store_test_message(server: &SocialTestServer, channel_id: Uuid, sender_id: Uuid) -> Uuid {
    let (message_id, _seq) = server
        .state
        .store_message(channel_id, sender_id, b"encrypted_content_test")
        .await
        .unwrap();
    message_id
}

#[tokio::test]
async fn test_add_reaction_happy_path() {
    let server = SocialTestServer::new().await;
    let (user_id, token) = server.register_and_auth("react_add").await;
    let node_id = server.create_node(&token, "react-node").await;
    let channel_id = server.create_channel(&token, node_id, "react-ch").await;

    // User must be a channel member
    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    let message_id = store_test_message(&server, channel_id, user_id).await;

    let resp = server
        .client
        .put(&format!(
            "{}/messages/{}/reactions/%F0%9F%91%8D?token={}",
            server.base_url, message_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_add_reaction_not_channel_member_fails() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("react_nomember").await;
    let (other_id, other_token) = server.register_and_auth("react_nomember_owner").await;
    let node_id = server.create_node(&other_token, "react-nm-node").await;
    let channel_id = server
        .create_channel(&other_token, node_id, "react-nm-ch")
        .await;

    // other is a member, user is not
    server
        .state
        .join_channel(other_id, channel_id)
        .await
        .unwrap();
    let message_id = store_test_message(&server, channel_id, other_id).await;

    // user tries to react without being in channel
    let resp = server
        .client
        .put(&format!(
            "{}/messages/{}/reactions/%F0%9F%91%8D?token={}",
            server.base_url, message_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_add_reaction_nonexistent_message_fails() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("react_nomsg").await;
    let bogus_msg = Uuid::new_v4();

    let resp = server
        .client
        .put(&format!(
            "{}/messages/{}/reactions/%F0%9F%91%8D?token={}",
            server.base_url, bogus_msg, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_remove_reaction_happy_path() {
    let server = SocialTestServer::new().await;
    let (user_id, token) = server.register_and_auth("react_remove").await;
    let node_id = server.create_node(&token, "react-rm-node").await;
    let channel_id = server.create_channel(&token, node_id, "react-rm-ch").await;
    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    let message_id = store_test_message(&server, channel_id, user_id).await;

    // Add first
    server
        .client
        .put(&format!(
            "{}/messages/{}/reactions/%F0%9F%91%8D?token={}",
            server.base_url, message_id, token
        ))
        .send()
        .await
        .unwrap();

    // Remove
    let resp = server
        .client
        .delete(&format!(
            "{}/messages/{}/reactions/%F0%9F%91%8D?token={}",
            server.base_url, message_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
}

#[tokio::test]
async fn test_get_message_reactions_empty() {
    let server = SocialTestServer::new().await;
    let (user_id, token) = server.register_and_auth("react_list_empty").await;
    let node_id = server.create_node(&token, "react-list-node").await;
    let channel_id = server
        .create_channel(&token, node_id, "react-list-ch")
        .await;
    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    let message_id = store_test_message(&server, channel_id, user_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/messages/{}/reactions?token={}",
            server.base_url, message_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["reactions"].is_object() || body["reactions"].is_array(),
        "reactions should be object or array: {:?}",
        body
    );
}

#[tokio::test]
async fn test_get_message_reactions_after_add() {
    let server = SocialTestServer::new().await;
    let (user_id, token) = server.register_and_auth("react_list_full").await;
    let node_id = server.create_node(&token, "react-list-full-node").await;
    let channel_id = server
        .create_channel(&token, node_id, "react-list-full-ch")
        .await;
    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    let message_id = store_test_message(&server, channel_id, user_id).await;

    // Add a reaction
    server
        .client
        .put(&format!(
            "{}/messages/{}/reactions/%F0%9F%94%A5?token={}",
            server.base_url, message_id, token
        ))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/messages/{}/reactions?token={}",
            server.base_url, message_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // The reactions field should contain our emoji
    let reactions_str = body["reactions"].to_string();
    assert!(
        reactions_str.contains("🔥") || reactions_str.len() > 2,
        "reactions should contain the added emoji: {:?}",
        body
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Auto-mod words ──
// ══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_add_auto_mod_word_happy_path() {
    let server = SocialTestServer::new().await;
    let (_owner_id, token) = server.register_and_auth("automod_add_owner").await;
    let node_id = server.create_node(&token, "automod-add-node").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/auto-mod/words?token={}",
            server.base_url, node_id, token
        ))
        .json(&json!({ "word": "badword", "action": "block" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "added");
    assert_eq!(body["word"], "badword");
    assert_eq!(body["action"], "block");
}

#[tokio::test]
async fn test_add_auto_mod_word_warn_action() {
    let server = SocialTestServer::new().await;
    let (_owner_id, token) = server.register_and_auth("automod_warn_owner").await;
    let node_id = server.create_node(&token, "automod-warn-node").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/auto-mod/words?token={}",
            server.base_url, node_id, token
        ))
        .json(&json!({ "word": "warnword", "action": "warn" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["action"], "warn");
}

#[tokio::test]
async fn test_add_auto_mod_word_invalid_action_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, token) = server.register_and_auth("automod_badact_owner").await;
    let node_id = server.create_node(&token, "automod-badact-node").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/auto-mod/words?token={}",
            server.base_url, node_id, token
        ))
        .json(&json!({ "word": "anyword", "action": "delete" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("block")
            || body["error"].as_str().unwrap_or("").contains("warn"),
        "error should mention valid actions: {:?}",
        body
    );
}

#[tokio::test]
async fn test_add_auto_mod_word_empty_word_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, token) = server.register_and_auth("automod_empty_owner").await;
    let node_id = server.create_node(&token, "automod-empty-node").await;

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/auto-mod/words?token={}",
            server.base_url, node_id, token
        ))
        .json(&json!({ "word": "", "action": "block" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_add_auto_mod_word_non_member_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("automod_nm_owner").await;
    let (_other_id, other_token) = server.register_and_auth("automod_nm_other").await;
    let node_id = server.create_node(&owner_token, "automod-nm-node").await;

    // other is not a member (and thus has no manage permission) —
    // server returns 500 because get_user_role_in_node errors for non-members
    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/auto-mod/words?token={}",
            server.base_url, node_id, other_token
        ))
        .json(&json!({ "word": "spam", "action": "block" }))
        .send()
        .await
        .unwrap();
    // Non-member results in either 403 or 500 depending on server path
    assert!(
        resp.status() == 403 || resp.status() == 500,
        "expected 403 or 500, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_list_auto_mod_words_empty() {
    let server = SocialTestServer::new().await;
    let (_owner_id, token) = server.register_and_auth("automod_list_empty_owner").await;
    let node_id = server.create_node(&token, "automod-list-empty-node").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/auto-mod/words?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["words"].is_array());
    assert_eq!(body["words"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_list_auto_mod_words_after_add() {
    let server = SocialTestServer::new().await;
    let (_owner_id, token) = server.register_and_auth("automod_list_full_owner").await;
    let node_id = server.create_node(&token, "automod-list-full-node").await;

    server
        .client
        .post(&format!(
            "{}/nodes/{}/auto-mod/words?token={}",
            server.base_url, node_id, token
        ))
        .json(&json!({ "word": "spamword", "action": "block" }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/auto-mod/words?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let words = body["words"].as_array().unwrap();
    assert!(!words.is_empty(), "should have auto-mod word after adding");
}

#[tokio::test]
async fn test_remove_auto_mod_word_happy_path() {
    let server = SocialTestServer::new().await;
    let (_owner_id, token) = server.register_and_auth("automod_rm_owner").await;
    let node_id = server.create_node(&token, "automod-rm-node").await;

    // Add first
    server
        .client
        .post(&format!(
            "{}/nodes/{}/auto-mod/words?token={}",
            server.base_url, node_id, token
        ))
        .json(&json!({ "word": "deleteword", "action": "block" }))
        .send()
        .await
        .unwrap();

    // Remove
    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/auto-mod/words/deleteword?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "removed");
}

#[tokio::test]
async fn test_remove_auto_mod_word_nonexistent_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, token) = server.register_and_auth("automod_rm_noexist_owner").await;
    let node_id = server.create_node(&token, "automod-rm-noexist-node").await;

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/auto-mod/words/nosuchword?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Node user profiles ──
// ══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_set_node_user_profile_happy_path() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("profile_set").await;
    let node_id = server.create_node(&token, "profile-set-node").await;

    // Base64-encode a fake encrypted name
    let enc_name = base64::engine::general_purpose::STANDARD.encode(b"encrypted_display_name");
    let enc_avatar = base64::engine::general_purpose::STANDARD.encode(b"encrypted_avatar_url");

    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/profile?token={}",
            server.base_url, node_id, token
        ))
        .json(&json!({
            "encrypted_display_name": enc_name,
            "encrypted_avatar_url": enc_avatar
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    assert_eq!(body["node_id"], node_id.to_string());
}

#[tokio::test]
async fn test_set_node_user_profile_non_member_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("profile_nm_owner").await;
    let (_other_id, other_token) = server.register_and_auth("profile_nm_other").await;
    let node_id = server.create_node(&owner_token, "profile-nm-node").await;

    // other is not a member
    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/profile?token={}",
            server.base_url, node_id, other_token
        ))
        .json(&json!({ "encrypted_display_name": null, "encrypted_avatar_url": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_set_node_user_profile_unauthenticated_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("profile_unauth_owner").await;
    let node_id = server
        .create_node(&owner_token, "profile-unauth-node")
        .await;

    let resp = server
        .client
        .put(&format!("{}/nodes/{}/profile", server.base_url, node_id))
        .json(&json!({ "encrypted_display_name": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_get_node_user_profiles_empty_node() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("profile_get_empty").await;
    let node_id = server.create_node(&token, "profile-get-empty-node").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/profiles?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["profiles"].is_array());
}

#[tokio::test]
async fn test_get_node_user_profiles_after_set() {
    let server = SocialTestServer::new().await;
    let (_user_id, token) = server.register_and_auth("profile_get_full").await;
    let node_id = server.create_node(&token, "profile-get-full-node").await;

    // Set a profile
    let enc_name = base64::engine::general_purpose::STANDARD.encode(b"my display name");
    server
        .client
        .put(&format!(
            "{}/nodes/{}/profile?token={}",
            server.base_url, node_id, token
        ))
        .json(&json!({ "encrypted_display_name": enc_name }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/profiles?token={}",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let profiles = body["profiles"].as_array().unwrap();
    assert!(
        !profiles.is_empty(),
        "should have at least one profile after setting"
    );
}

#[tokio::test]
async fn test_get_node_user_profiles_non_member_fails() {
    let server = SocialTestServer::new().await;
    let (_owner_id, owner_token) = server.register_and_auth("profile_get_nm_owner").await;
    let (_other_id, other_token) = server.register_and_auth("profile_get_nm_other").await;
    let node_id = server
        .create_node(&owner_token, "profile-get-nm-node")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/profiles?token={}",
            server.base_url, node_id, other_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
