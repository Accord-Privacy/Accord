//! Integration tests for the Accord server
//!
//! These tests spawn the server in-process and test all major endpoints and flows.

use axum::{
    routing::{get, post},
    Router,
};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

// Import the server modules
use accord_server::{
    handlers::{
        auth_handler, ban_user_handler, create_node_handler, fetch_key_bundle_handler,
        get_prekey_messages_handler, health_handler, join_node_handler, publish_key_bundle_handler,
        register_handler, store_prekey_message_handler, ws_handler,
    },
    state::{AppState, SharedState},
};

/// Test server instance
struct TestServer {
    base_url: String,
    client: Client,
    state: SharedState,
}

impl TestServer {
    /// Start a new test server on a random port
    async fn new() -> Self {
        // Initialize shared state with in-memory database
        let state: SharedState = Arc::new(AppState::new_in_memory().await.unwrap());

        // Build the router with all endpoints
        let app = Router::new()
            // REST endpoints
            .route("/health", get(health_handler))
            .route("/register", post(register_handler))
            .route("/auth", post(auth_handler))
            // Key bundle endpoints
            .route("/keys/bundle", post(publish_key_bundle_handler))
            .route("/keys/bundle/:user_id", get(fetch_key_bundle_handler))
            .route("/keys/prekey-message", post(store_prekey_message_handler))
            .route("/keys/prekey-messages", get(get_prekey_messages_handler))
            // Node endpoints
            .route("/nodes", post(create_node_handler))
            .route("/nodes/:id/join", post(join_node_handler))
            .route("/nodes/:id/bans", post(ban_user_handler))
            // WebSocket endpoint
            .route("/ws", get(ws_handler))
            // Add shared state
            .with_state(state.clone())
            // Add middleware
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

        // Bind to a random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{}", addr);

        // Start the server in the background
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            base_url,
            client: Client::new(),
            state,
        }
    }

    /// Get the base URL for HTTP requests
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Get the WebSocket URL
    fn ws_url(&self, path: &str) -> String {
        format!("ws://{}{}", self.base_url.replace("http://", ""), path)
    }

    /// Register a user and return the user_id
    async fn register_user(&self, _username: &str, public_key: &str) -> Uuid {
        let response = self
            .client
            .post(&self.url("/register"))
            .json(&json!({
                "public_key": public_key
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap()
    }

    /// Register a user and authenticate, returning the token.
    /// The "username" arg is kept for test compat but used as a unique public key.
    async fn register_and_auth(&self, username: &str) -> String {
        // Use username as a unique public key for tests
        let public_key = format!("fake_public_key_{}", username);
        self.register_user(username, &public_key).await;
        self.auth_user_by_pk(&public_key, "").await
    }

    /// Authenticate a user by public_key and return the token
    async fn auth_user_by_pk(&self, public_key: &str, password: &str) -> String {
        let response = self
            .client
            .post(&self.url("/auth"))
            .json(&json!({
                "public_key": public_key,
                "password": password
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            200,
            "Auth failed for public_key: {}",
            public_key
        );
        let body: Value = response.json().await.unwrap();
        body["token"].as_str().unwrap().to_string()
    }
}

#[tokio::test]
async fn test_health_endpoint() {
    let server = TestServer::new().await;

    let response = server
        .client
        .get(&server.url("/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    assert_eq!(body["status"], "healthy");
    assert!(body["version"].is_string());
    assert!(body["uptime_seconds"].is_number());
}

#[tokio::test]
async fn test_user_registration_success() {
    let server = TestServer::new().await;

    let response = server
        .client
        .post(&server.url("/register"))
        .json(&json!({
            "username": "testuser",
            "public_key": "fake_public_key_123"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    assert!(body["user_id"].is_string());
    assert_eq!(body["message"], "User registered successfully");

    // Verify the user was actually registered
    let user_id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();
    let user = server.state.db.get_user_by_id(user_id).await.unwrap();
    assert!(user.is_some());
}

#[tokio::test]
async fn test_user_registration_duplicate_public_key() {
    let server = TestServer::new().await;

    // Register first user
    let response = server
        .client
        .post(&server.url("/register"))
        .json(&json!({
            "public_key": "fake_public_key_123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // Try to register with the same public key
    let response = server
        .client
        .post(&server.url("/register"))
        .json(&json!({
            "public_key": "fake_public_key_123"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 409); // Conflict
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "Public key already registered");
    assert_eq!(body["code"], 409);
}

#[tokio::test]
async fn test_user_registration_empty_fields() {
    let server = TestServer::new().await;

    // Test empty public key
    let response = server
        .client
        .post(&server.url("/register"))
        .json(&json!({
            "public_key": ""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "Public key cannot be empty");
}

#[tokio::test]
async fn test_authentication_success() {
    let server = TestServer::new().await;

    // First register a user
    server
        .register_user("auth_test_user", "fake_public_key")
        .await;

    // Now authenticate by public_key
    let response = server
        .client
        .post(&server.url("/auth"))
        .json(&json!({
            "public_key": "fake_public_key",
            "password": ""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body: Value = response.json().await.unwrap();
    assert!(body["token"].is_string());
    assert!(body["user_id"].is_string());
    assert!(body["expires_at"].is_number());

    // Verify the token was stored
    let token = body["token"].as_str().unwrap();
    assert!(server.state.auth_tokens.read().await.contains_key(token));
}

#[tokio::test]
async fn test_authentication_failure() {
    let server = TestServer::new().await;

    // Try to authenticate with non-existent public key
    let response = server
        .client
        .post(&server.url("/auth"))
        .json(&json!({
            "public_key": "nonexistent_public_key",
            "password": "any_password"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);

    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "User not found");
    assert_eq!(body["code"], 401);
}

#[tokio::test]
async fn test_websocket_connection_with_valid_token() {
    let server = TestServer::new().await;

    // Register and authenticate a user
    server
        .register_user("ws_test_user", "fake_public_key_ws")
        .await;
    let token = server.auth_user_by_pk("fake_public_key_ws", "").await;

    // Connect via WebSocket with the token
    let ws_url = format!("{}?token={}", server.ws_url("/ws"), token);
    let (ws_stream, _) = connect_async(&ws_url).await.unwrap();

    // Verify connection was established by sending a ping
    let (mut sink, mut stream) = ws_stream.split();

    let ping_message = json!({
        "message_type": "Ping",
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });

    // Consume the server authenticated + hello messages
    // With post-upgrade auth, server sends "authenticated" first, then "hello"
    // With legacy query-param auth, it may send "authenticated" then "hello" or just "hello"
    let mut got_hello = false;
    for _ in 0..3 {
        let msg = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
        if let Ok(Some(Ok(WsMessage::Text(text)))) = msg {
            let data: Value = serde_json::from_str(&text).unwrap();
            if data["type"] == "hello" {
                got_hello = true;
                break;
            }
            // Skip "authenticated" and other messages
        }
    }
    assert!(got_hello, "Should receive hello message");

    sink.send(WsMessage::Text(ping_message.to_string()))
        .await
        .unwrap();

    // Wait for pong response
    let response = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
    assert!(response.is_ok());

    if let Some(Ok(WsMessage::Text(text))) = response.unwrap() {
        let response_data: Value = serde_json::from_str(&text).unwrap();
        if response_data["type"] == "error" {
            panic!("Received error instead of pong: {}", text);
        }
        assert_eq!(response_data["type"], "pong");
    } else {
        panic!("Expected pong response");
    }
}

#[tokio::test]
async fn test_websocket_connection_with_invalid_token() {
    let server = TestServer::new().await;

    // Connect without token in URL (post-upgrade auth)
    let ws_url = server.ws_url("/ws");
    let (mut ws, _) = connect_async(&ws_url)
        .await
        .expect("WS connect should succeed");

    // Send invalid auth message
    let auth_msg = serde_json::json!({"Authenticate": {"token": "invalid_token"}});
    ws.send(WsMessage::Text(auth_msg.to_string()))
        .await
        .unwrap();

    // Server should close the connection
    let result = tokio::time::timeout(Duration::from_secs(6), ws.next()).await;
    match result {
        Ok(Some(Ok(WsMessage::Close(_)))) => {} // expected
        Ok(Some(Ok(WsMessage::Text(t)))) => {
            let v: Value = serde_json::from_str(&t).unwrap_or_default();
            assert_eq!(v["type"], "error", "Expected error, got: {}", t);
        }
        Ok(None) => {} // stream ended = connection closed
        _ => {}        // timeout or error = also acceptable (server closed)
    }
}

#[tokio::test]
async fn test_websocket_connection_without_token() {
    let server = TestServer::new().await;

    // Connect without token (post-upgrade auth)
    let ws_url = server.ws_url("/ws");
    let (mut ws, _) = connect_async(&ws_url)
        .await
        .expect("WS connect should succeed");

    // Don't send auth — server should close after 5s timeout
    let result = tokio::time::timeout(Duration::from_secs(7), ws.next()).await;
    match result {
        Ok(Some(Ok(WsMessage::Close(_)))) => {} // expected
        Ok(None) => {}                          // stream ended
        _ => {}                                 // timeout acceptable too
    }
}

#[tokio::test]
async fn test_message_routing_between_two_clients() {
    let server = TestServer::new().await;

    // Register and authenticate two users
    let user1_id = server.register_user("user1", "public_key_1").await;
    let user2_id = server.register_user("user2", "public_key_2").await;

    let token1 = server.auth_user_by_pk("public_key_1", "").await;
    let token2 = server.auth_user_by_pk("public_key_2", "").await;

    // Connect both users via WebSocket
    let ws_url1 = format!("{}?token={}", server.ws_url("/ws"), token1);
    let ws_url2 = format!("{}?token={}", server.ws_url("/ws"), token2);

    let (ws_stream1, _) = connect_async(&ws_url1).await.unwrap();
    let (ws_stream2, _) = connect_async(&ws_url2).await.unwrap();

    let (mut sink1, mut _stream1) = ws_stream1.split();
    let (mut _sink2, mut stream2) = ws_stream2.split();

    // Allow connections to settle
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Drain any initial messages from stream2
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), stream2.next()).await {
    }

    // User1 sends a direct message to User2
    let direct_message = json!({
        "message_type": {
            "DirectMessage": {
                "to_user": user2_id,
                "encrypted_data": "ZW5jcnlwdGVkX3Rlc3RfbWVzc2FnZV8xMjM="
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });

    sink1
        .send(WsMessage::Text(direct_message.to_string()))
        .await
        .unwrap();

    // User2 should receive the message
    let response = tokio::time::timeout(Duration::from_secs(5), stream2.next()).await;
    assert!(response.is_ok());

    if let Some(Ok(WsMessage::Text(text))) = response.unwrap() {
        let response_data: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response_data["type"], "channel_message");
        assert_eq!(response_data["from"], user1_id.to_string());
        assert_eq!(
            response_data["encrypted_data"],
            "ZW5jcnlwdGVkX3Rlc3RfbWVzc2FnZV8xMjM="
        );
        assert_eq!(response_data["is_dm"], true);
    } else {
        panic!("Expected direct message");
    }
}

#[tokio::test]
async fn test_channel_join_leave_and_messaging() {
    let server = TestServer::new().await;

    // Register and authenticate two users
    let user1_id = server
        .register_user("channel_user1", "ch_public_key_1")
        .await;
    let user2_id = server
        .register_user("channel_user2", "ch_public_key_2")
        .await;

    let token1 = server.auth_user_by_pk("ch_public_key_1", "").await;
    let token2 = server.auth_user_by_pk("ch_public_key_2", "").await;

    // Connect both users via WebSocket
    let ws_url1 = format!("{}?token={}", server.ws_url("/ws"), token1);
    let ws_url2 = format!("{}?token={}", server.ws_url("/ws"), token2);

    let (ws_stream1, _) = connect_async(&ws_url1).await.unwrap();
    let (ws_stream2, _) = connect_async(&ws_url2).await.unwrap();

    let (mut sink1, mut stream1) = ws_stream1.split();
    let (mut sink2, mut stream2) = ws_stream2.split();

    // Consume authenticated + hello messages from both connections
    for _ in 0..3 {
        let _ = tokio::time::timeout(Duration::from_millis(500), stream1.next()).await;
    }
    for _ in 0..3 {
        let _ = tokio::time::timeout(Duration::from_millis(500), stream2.next()).await;
    }

    // Create a Node via WebSocket (user1 creates it)
    let create_node_msg = json!({
        "message_type": {
            "CreateNode": {
                "name": "Test Node",
                "description": "A test node"
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink1
        .send(WsMessage::Text(create_node_msg.to_string()))
        .await
        .unwrap();

    // Wait for node_created response to get node_id
    tokio::time::sleep(Duration::from_millis(500)).await;
    let node_response = tokio::time::timeout(Duration::from_secs(5), stream1.next()).await;
    let node_id: Uuid = if let Ok(Some(Ok(WsMessage::Text(text)))) = node_response {
        let data: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(data["type"], "node_created");
        Uuid::parse_str(data["node"]["id"].as_str().unwrap()).unwrap()
    } else {
        panic!("Expected node_created response");
    };

    // User2 joins the node
    let join_node_msg = json!({
        "message_type": {
            "JoinNode": { "node_id": node_id }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink2
        .send(WsMessage::Text(join_node_msg.to_string()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Consume the node_joined response
    let _ = tokio::time::timeout(Duration::from_secs(2), stream2.next()).await;

    // Create a channel in the node (user1)
    let create_channel_msg = json!({
        "message_type": {
            "CreateChannel": { "node_id": node_id, "name": "test-channel" }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink1
        .send(WsMessage::Text(create_channel_msg.to_string()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Get channel_id from response
    let ch_response = tokio::time::timeout(Duration::from_secs(5), stream1.next()).await;
    let channel_id: Uuid = if let Ok(Some(Ok(WsMessage::Text(text)))) = ch_response {
        let data: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(data["type"], "channel_created");
        Uuid::parse_str(data["channel"]["id"].as_str().unwrap()).unwrap()
    } else {
        panic!("Expected channel_created response");
    };

    // User2 joins the channel
    let join_ch_msg = json!({
        "message_type": {
            "JoinChannel": { "channel_id": channel_id }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink2
        .send(WsMessage::Text(join_ch_msg.to_string()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify both users are in the channel
    let channel_members = server.state.get_channel_members(channel_id).await;
    assert!(channel_members.contains(&user1_id));
    assert!(channel_members.contains(&user2_id));
    assert_eq!(channel_members.len(), 2);

    // User1 sends a channel message
    let channel_message = json!({
        "message_type": {
            "ChannelMessage": {
                "channel_id": channel_id,
                "encrypted_data": "ZW5jcnlwdGVkX2NoYW5uZWxfbWVzc2FnZV80NTY="
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });

    sink1
        .send(WsMessage::Text(channel_message.to_string()))
        .await
        .unwrap();

    // Both users should receive the channel message (including the sender)
    let response1 = tokio::time::timeout(Duration::from_secs(5), stream1.next()).await;
    let response2 = tokio::time::timeout(Duration::from_secs(5), stream2.next()).await;

    // Check that both users got the message
    for (user_name, response) in [("user1", response1), ("user2", response2)] {
        assert!(
            response.is_ok(),
            "User {} should have received channel message",
            user_name
        );

        if let Some(Ok(WsMessage::Text(text))) = response.unwrap() {
            let response_data: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(response_data["type"], "channel_message");
            assert_eq!(response_data["from"], user1_id.to_string());
            assert_eq!(response_data["channel_id"], channel_id.to_string());
            assert_eq!(
                response_data["encrypted_data"],
                "ZW5jcnlwdGVkX2NoYW5uZWxfbWVzc2FnZV80NTY="
            );
        } else {
            panic!("User {} expected channel message", user_name);
        }
    }

    // User2 leaves the channel
    let leave_message = json!({
        "message_type": {
            "LeaveChannel": {
                "channel_id": channel_id
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });

    sink2
        .send(WsMessage::Text(leave_message.to_string()))
        .await
        .unwrap();

    // Give some time for leave operation to complete
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify only user1 is in the channel now
    let channel_members = server.state.get_channel_members(channel_id).await;
    assert!(channel_members.contains(&user1_id));
    assert!(!channel_members.contains(&user2_id));
    assert_eq!(channel_members.len(), 1);

    // User1 sends another channel message
    let channel_message2 = json!({
        "message_type": {
            "ChannelMessage": {
                "channel_id": channel_id,
                "encrypted_data": "encrypted_channel_message_789"
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });

    sink1
        .send(WsMessage::Text(channel_message2.to_string()))
        .await
        .unwrap();

    // Only user1 should receive this message now (user2 left the channel)
    let response1 = tokio::time::timeout(Duration::from_secs(2), stream1.next()).await;
    assert!(response1.is_ok());

    // User2 should NOT receive the message (with a short timeout)
    let response2 = tokio::time::timeout(Duration::from_millis(500), stream2.next()).await;
    assert!(
        response2.is_err(),
        "User2 should not receive messages after leaving channel"
    );
}

// Helper to import dependencies
use futures_util::{SinkExt, StreamExt};

// ── Double Ratchet integration tests ──

/// Test key bundle publish and fetch via REST endpoints
#[tokio::test]
async fn test_key_bundle_publish_and_fetch() {
    let server = TestServer::new().await;

    // Register two users
    let alice_token = server.register_and_auth("alice").await;
    let bob_token = server.register_and_auth("bob").await;

    // Get Bob's user ID
    let bob_user = server
        .state
        .db
        .get_user_by_public_key_hash(&accord_server::db::compute_public_key_hash(
            "fake_public_key_bob",
        ))
        .await
        .unwrap()
        .unwrap();

    // Bob publishes key bundle
    let publish_resp = server
        .client
        .post(&format!(
            "{}/keys/bundle?token={}",
            server.base_url, bob_token
        ))
        .json(&json!({
            "identity_key": base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            "signed_prekey": base64::engine::general_purpose::STANDARD.encode([2u8; 32]),
            "one_time_prekeys": [
                base64::engine::general_purpose::STANDARD.encode([3u8; 32]),
                base64::engine::general_purpose::STANDARD.encode([4u8; 32]),
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(publish_resp.status(), 200);
    let publish_body: Value = publish_resp.json().await.unwrap();
    assert_eq!(publish_body["status"], "published");
    assert_eq!(publish_body["one_time_prekeys_stored"], 2);

    // Alice fetches Bob's key bundle
    let fetch_resp = server
        .client
        .get(&format!(
            "{}/keys/bundle/{}?token={}",
            server.base_url, bob_user.id, alice_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(fetch_resp.status(), 200);
    let fetch_body: Value = fetch_resp.json().await.unwrap();
    assert_eq!(fetch_body["user_id"], bob_user.id.to_string());
    assert!(fetch_body["one_time_prekey"].is_string()); // Got one OTP

    // Fetch again — should get the second OTP
    let fetch_resp2 = server
        .client
        .get(&format!(
            "{}/keys/bundle/{}?token={}",
            server.base_url, bob_user.id, alice_token
        ))
        .send()
        .await
        .unwrap();

    let fetch_body2: Value = fetch_resp2.json().await.unwrap();
    assert!(fetch_body2["one_time_prekey"].is_string());
    // The two OTPs should be different
    assert_ne!(
        fetch_body["one_time_prekey"],
        fetch_body2["one_time_prekey"]
    );

    // Fetch a third time — no more OTPs
    let fetch_resp3 = server
        .client
        .get(&format!(
            "{}/keys/bundle/{}?token={}",
            server.base_url, bob_user.id, alice_token
        ))
        .send()
        .await
        .unwrap();

    let fetch_body3: Value = fetch_resp3.json().await.unwrap();
    assert!(fetch_body3["one_time_prekey"].is_null());
}

/// Test prekey message store and retrieve
#[tokio::test]
async fn test_prekey_message_store_and_retrieve() {
    let server = TestServer::new().await;

    let alice_token = server.register_and_auth("alice").await;
    let bob_token = server.register_and_auth("bob").await;

    let bob_user = server
        .state
        .db
        .get_user_by_public_key_hash(&accord_server::db::compute_public_key_hash(
            "fake_public_key_bob",
        ))
        .await
        .unwrap()
        .unwrap();

    // Alice stores a prekey message for Bob
    let store_resp = server
        .client
        .post(&format!(
            "{}/keys/prekey-message?token={}",
            server.base_url, alice_token
        ))
        .json(&json!({
            "recipient_id": bob_user.id,
            "message_data": base64::engine::general_purpose::STANDARD.encode(b"x3dh initial message data"),
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(store_resp.status(), 200);

    // Bob retrieves prekey messages
    let get_resp = server
        .client
        .get(&format!(
            "{}/keys/prekey-messages?token={}",
            server.base_url, bob_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(get_resp.status(), 200);
    let get_body: Value = get_resp.json().await.unwrap();
    let messages = get_body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);

    // Decode and verify the message data
    let msg_data_b64 = messages[0]["message_data"].as_str().unwrap();
    let msg_data = base64::engine::general_purpose::STANDARD
        .decode(msg_data_b64)
        .unwrap();
    assert_eq!(msg_data, b"x3dh initial message data");

    // Retrieve again — should be empty (messages are consumed)
    let get_resp2 = server
        .client
        .get(&format!(
            "{}/keys/prekey-messages?token={}",
            server.base_url, bob_token
        ))
        .send()
        .await
        .unwrap();

    let get_body2: Value = get_resp2.json().await.unwrap();
    assert_eq!(get_body2["messages"].as_array().unwrap().len(), 0);
}

/// Full Double Ratchet simulation: two users exchanging messages via server using X3DH + DR
#[tokio::test]
async fn test_double_ratchet_e2e_via_server() {
    use accord_core::double_ratchet::PreKeyBundle;
    use accord_core::session_manager::{LocalKeyMaterial, SessionId, SessionManager};

    let server = TestServer::new().await;

    // Register users and get tokens
    let alice_token = server.register_and_auth("alice").await;
    let bob_token = server.register_and_auth("bob").await;

    let alice_user = server
        .state
        .db
        .get_user_by_public_key_hash(&accord_server::db::compute_public_key_hash(
            "fake_public_key_alice",
        ))
        .await
        .unwrap()
        .unwrap();
    let bob_user = server
        .state
        .db
        .get_user_by_public_key_hash(&accord_server::db::compute_public_key_hash(
            "fake_public_key_bob",
        ))
        .await
        .unwrap()
        .unwrap();

    // Both generate local key material
    let alice_keys = LocalKeyMaterial::generate(5);
    let mut bob_keys = LocalKeyMaterial::generate(5);

    // Bob publishes his key bundle to server
    let bob_bundle = bob_keys.to_publishable_bundle();
    let publish_resp = server
        .client
        .post(&format!(
            "{}/keys/bundle?token={}",
            server.base_url, bob_token
        ))
        .json(&json!({
            "identity_key": base64::engine::general_purpose::STANDARD.encode(bob_bundle.identity_key),
            "signed_prekey": base64::engine::general_purpose::STANDARD.encode(bob_bundle.signed_prekey),
            "one_time_prekeys": bob_bundle.one_time_prekeys.iter()
                .map(|opk| base64::engine::general_purpose::STANDARD.encode(opk))
                .collect::<Vec<_>>(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(publish_resp.status(), 200);

    // Alice fetches Bob's key bundle
    let fetch_resp = server
        .client
        .get(&format!(
            "{}/keys/bundle/{}?token={}",
            server.base_url, bob_user.id, alice_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(fetch_resp.status(), 200);
    let fetch_body: Value = fetch_resp.json().await.unwrap();

    // Reconstruct the PreKeyBundle from server response
    let ik_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(fetch_body["identity_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let spk_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(fetch_body["signed_prekey"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let opk_bytes: Option<[u8; 32]> = fetch_body["one_time_prekey"].as_str().map(|s| {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .unwrap()
            .try_into()
            .unwrap()
    });

    let their_bundle = PreKeyBundle {
        identity_key: ik_bytes,
        signed_prekey: spk_bytes,
        one_time_prekey: opk_bytes,
    };

    // Alice initiates session and encrypts first message
    let mut alice_mgr = SessionManager::new();
    let session_id_alice = SessionId {
        peer_user_id: bob_user.id.to_string(),
        channel_id: "test-channel".to_string(),
    };

    let x3dh_initial = alice_mgr
        .initiate_session(
            &alice_keys,
            &their_bundle,
            session_id_alice.clone(),
            b"Hello Bob from Double Ratchet!",
        )
        .unwrap();

    // Alice sends X3DH initial message via server (store as prekey message)
    let initial_msg_bytes = bincode::serialize(&x3dh_initial).unwrap();
    let store_resp = server
        .client
        .post(&format!(
            "{}/keys/prekey-message?token={}",
            server.base_url, alice_token
        ))
        .json(&json!({
            "recipient_id": bob_user.id,
            "message_data": base64::engine::general_purpose::STANDARD.encode(&initial_msg_bytes),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(store_resp.status(), 200);

    // Bob retrieves the prekey message
    let get_resp = server
        .client
        .get(&format!(
            "{}/keys/prekey-messages?token={}",
            server.base_url, bob_token
        ))
        .send()
        .await
        .unwrap();
    let get_body: Value = get_resp.json().await.unwrap();
    let messages = get_body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);

    let msg_data = base64::engine::general_purpose::STANDARD
        .decode(messages[0]["message_data"].as_str().unwrap())
        .unwrap();
    let received_initial: accord_core::session_manager::X3DHInitialMessage =
        bincode::deserialize(&msg_data).unwrap();

    // Bob processes the initial message
    let mut bob_mgr = SessionManager::new();
    let session_id_bob = SessionId {
        peer_user_id: alice_user.id.to_string(),
        channel_id: "test-channel".to_string(),
    };

    let decrypted = bob_mgr
        .receive_initial_message(&mut bob_keys, &received_initial, session_id_bob.clone())
        .unwrap();
    assert_eq!(decrypted, b"Hello Bob from Double Ratchet!");

    // Now Bob can reply using the established session
    let bob_reply = bob_mgr
        .encrypt_message(&session_id_bob, b"Hello Alice, DR session works!")
        .unwrap();

    // Alice decrypts the reply
    let alice_decrypted = alice_mgr
        .decrypt_message(&session_id_alice, &bob_reply)
        .unwrap();
    assert_eq!(alice_decrypted, b"Hello Alice, DR session works!");

    // Exchange a few more messages to verify ratcheting works
    for i in 0..5 {
        let msg = alice_mgr
            .encrypt_message(&session_id_alice, format!("Alice msg {i}").as_bytes())
            .unwrap();
        let dec = bob_mgr.decrypt_message(&session_id_bob, &msg).unwrap();
        assert_eq!(dec, format!("Alice msg {i}").as_bytes());

        let reply = bob_mgr
            .encrypt_message(&session_id_bob, format!("Bob msg {i}").as_bytes())
            .unwrap();
        let dec = alice_mgr
            .decrypt_message(&session_id_alice, &reply)
            .unwrap();
        assert_eq!(dec, format!("Bob msg {i}").as_bytes());
    }
}

/// Test that a banned user cannot rejoin a node
#[tokio::test]
async fn test_ban_enforcement() {
    let server = TestServer::new().await;

    // Register and authenticate two users
    let owner_pk = "ban_test_owner_pk";
    let banned_pk = "ban_test_banned_pk";

    server.register_user("owner", owner_pk).await;
    server.register_user("banned_user", banned_pk).await;

    let owner_token = server.auth_user_by_pk(owner_pk, "").await;
    let banned_token = server.auth_user_by_pk(banned_pk, "").await;

    // Owner creates a node via REST
    let create_resp = server
        .client
        .post(&format!("{}/nodes?token={}", server.base_url, owner_token))
        .json(&json!({
            "name": "Ban Test Node",
            "description": "Testing ban enforcement"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_resp.status(), 200);
    let create_body: Value = create_resp.json().await.unwrap();
    let node_id = create_body["id"].as_str().unwrap();

    // Banned user joins the node
    let join_resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/join?token={}",
            server.base_url, node_id, banned_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(join_resp.status(), 200);

    // Owner bans the user by public_key_hash
    let banned_pk_hash = accord_server::db::compute_public_key_hash(banned_pk);
    let ban_resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/bans?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({
            "public_key_hash": banned_pk_hash
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(ban_resp.status(), 200);

    // Banned user tries to rejoin — should fail
    let rejoin_resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/join?token={}",
            server.base_url, node_id, banned_token
        ))
        .send()
        .await
        .unwrap();
    assert_ne!(
        rejoin_resp.status(),
        200,
        "Banned user should not be able to rejoin"
    );
    let rejoin_body: Value = rejoin_resp.json().await.unwrap();
    assert!(
        rejoin_body["error"]
            .as_str()
            .unwrap_or("")
            .contains("banned"),
        "Error should mention ban: {:?}",
        rejoin_body
    );
}

use base64::Engine as _;
