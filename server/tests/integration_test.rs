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
        auth_handler, ban_user_handler, create_channel_handler, create_node_handler,
        fetch_key_bundle_handler, get_prekey_messages_handler, health_handler, join_node_handler,
        list_node_channels_handler, publish_key_bundle_handler, register_handler,
        store_prekey_message_handler, ws_handler,
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
            .route(
                "/nodes/:id/channels",
                get(list_node_channels_handler).post(create_channel_handler),
            )
            .route("/nodes/:id/join", post(join_node_handler))
            .route("/nodes/:id/bans", post(ban_user_handler))
            // Bot API v2 endpoints
            .route(
                "/api/nodes/:node_id/bots",
                get(accord_server::bot_api::list_bots_handler)
                    .post(accord_server::bot_api::install_bot_handler),
            )
            .route(
                "/api/nodes/:node_id/bots/:bot_id",
                axum::routing::delete(accord_server::bot_api::uninstall_bot_handler),
            )
            .route(
                "/api/nodes/:node_id/bots/:bot_id/commands",
                get(accord_server::bot_api::get_bot_commands_handler),
            )
            .route(
                "/api/nodes/:node_id/bots/:bot_id/invoke",
                post(accord_server::bot_api::invoke_command_handler),
            )
            .route(
                "/api/bots/respond",
                post(accord_server::bot_api::bot_respond_handler),
            )
            // Batch API endpoints
            .route(
                "/api/nodes/:node_id/members/batch",
                get(accord_server::batch_handlers::batch_members_handler),
            )
            .route(
                "/api/nodes/:node_id/channels/batch",
                get(accord_server::batch_handlers::batch_channels_handler),
            )
            .route(
                "/api/nodes/:node_id/overview",
                get(accord_server::batch_handlers::node_overview_handler),
            )
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
    let _user2_id = server.register_user("user2", "public_key_2").await;

    let token1 = server.auth_user_by_pk("public_key_1", "").await;
    let token2 = server.auth_user_by_pk("public_key_2", "").await;

    // Create a shared Node + channel. Node creation auto-creates owner membership.
    let node_raw = server
        .client
        .post(&format!("{}/nodes?token={}", server.base_url, token1))
        .json(&json!({ "name": "TestNode" }))
        .send()
        .await
        .unwrap();
    let node_status = node_raw.status();
    let node_text = node_raw.text().await.unwrap_or_default();
    assert!(
        node_status.is_success(),
        "create_node: {} {}",
        node_status,
        node_text
    );
    let node_resp: Value = serde_json::from_str(&node_text).unwrap();
    let node_id = Uuid::parse_str(node_resp["id"].as_str().unwrap()).unwrap();

    let ch_raw = server
        .client
        .post(&format!(
            "{}/nodes/{}/channels?token={}",
            server.base_url, node_id, token1
        ))
        .json(&json!({ "name": "general" }))
        .send()
        .await
        .unwrap();
    let ch_status = ch_raw.status();
    let ch_text = ch_raw.text().await.unwrap_or_default();
    assert!(
        ch_status.is_success(),
        "create_channel: {} {}",
        ch_status,
        ch_text
    );
    let ch_resp: Value = serde_json::from_str(&ch_text).unwrap();
    let channel_id = Uuid::parse_str(ch_resp["id"].as_str().unwrap()).unwrap();

    // User2 joins the node
    let join_status = server
        .client
        .post(&format!(
            "{}/nodes/{}/join?token={}",
            server.base_url, node_id, token2
        ))
        .send()
        .await
        .unwrap()
        .status();
    assert!(
        join_status.is_success(),
        "join_node failed: {}",
        join_status
    );

    // Connect both users via WebSocket
    let ws_url1 = format!("{}?token={}", server.ws_url("/ws"), token1);
    let ws_url2 = format!("{}?token={}", server.ws_url("/ws"), token2);

    let (ws_stream1, _) = connect_async(&ws_url1).await.unwrap();
    let (ws_stream2, _) = connect_async(&ws_url2).await.unwrap();

    let (mut sink1, mut _stream1) = ws_stream1.split();
    let (mut _sink2, mut stream2) = ws_stream2.split();

    // Allow connections to settle and join channels
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Both users join the channel
    let join_msg = |ch: Uuid| {
        json!({
            "message_type": { "JoinChannel": { "channel_id": ch } },
            "message_id": Uuid::new_v4(),
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
        })
    };
    sink1
        .send(WsMessage::Text(join_msg(channel_id).to_string()))
        .await
        .unwrap();
    _sink2
        .send(WsMessage::Text(join_msg(channel_id).to_string()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Drain any initial messages from stream2
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), stream2.next()).await {
    }

    // User1 sends a channel message
    let channel_message = json!({
        "message_type": {
            "ChannelMessage": {
                "channel_id": channel_id,
                "encrypted_data": "ZW5jcnlwdGVkX3Rlc3RfbWVzc2FnZV8xMjM=",
                "reply_to": null
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });

    sink1
        .send(WsMessage::Text(channel_message.to_string()))
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
    } else {
        panic!("Expected channel message");
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

// ══════════════════════════════════════════════════════════════════════════════
// NEW INTEGRATION TESTS — Expanded coverage for security & functionality paths
// ══════════════════════════════════════════════════════════════════════════════

/// Extended test server with all routes needed for the new tests
struct FullTestServer {
    base_url: String,
    client: Client,
    state: SharedState,
}

impl FullTestServer {
    async fn new() -> Self {
        use accord_server::handlers::*;
        use axum::routing::{delete, get, post};

        let state: SharedState = Arc::new(AppState::new_in_memory().await.unwrap());

        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/register", post(register_handler))
            .route("/auth", post(auth_handler))
            // Key bundle
            .route("/keys/bundle", post(publish_key_bundle_handler))
            .route("/keys/bundle/:user_id", get(fetch_key_bundle_handler))
            .route("/keys/prekey-message", post(store_prekey_message_handler))
            .route("/keys/prekey-messages", get(get_prekey_messages_handler))
            // Nodes
            .route(
                "/nodes",
                get(list_user_nodes_handler).post(create_node_handler),
            )
            .route("/nodes/:id", get(get_node_handler))
            .route("/nodes/:id/join", post(join_node_handler))
            .route("/nodes/:id/leave", post(leave_node_handler))
            .route("/nodes/:id/bans", post(ban_user_handler))
            .route(
                "/nodes/:id/channels",
                get(list_node_channels_handler).post(create_channel_handler),
            )
            .route("/nodes/:id/members", get(get_node_members_handler))
            .route("/nodes/:id/members/:user_id", delete(kick_user_handler))
            // Invites
            .route("/nodes/:id/invites", post(create_invite_handler))
            .route("/nodes/:id/invites", get(list_invites_handler))
            .route("/invites/:invite_id", delete(revoke_invite_handler))
            .route("/invites/:code/join", post(use_invite_handler))
            // Roles
            .route(
                "/nodes/:id/roles",
                get(list_roles_handler).post(create_role_handler),
            )
            .route(
                "/nodes/:id/roles/:role_id",
                axum::routing::patch(update_role_handler).delete(delete_role_handler),
            )
            .route(
                "/nodes/:id/members/:user_id/roles",
                get(get_member_roles_handler),
            )
            .route(
                "/nodes/:id/members/:user_id/roles/:role_id",
                axum::routing::put(assign_member_role_handler).delete(remove_member_role_handler),
            )
            // Channels
            .route(
                "/channels/:id",
                axum::routing::patch(update_channel_handler).delete(delete_channel_handler),
            )
            .route("/channels/:id/messages", get(get_channel_messages_handler))
            .route(
                "/channels/:id/permissions/:role_id",
                axum::routing::put(set_channel_overwrite_handler),
            )
            .route(
                "/channels/:id/effective-permissions",
                get(get_effective_permissions_handler),
            )
            // Messages
            .route(
                "/messages/:id",
                axum::routing::patch(edit_message_handler).delete(delete_message_handler),
            )
            // Files
            .route("/channels/:id/files", post(upload_file_handler))
            .route("/files/:id", get(download_file_handler))
            // Search
            .route("/nodes/:id/search", get(search_messages_handler))
            // Presence
            .route("/api/presence/:id", get(get_node_presence_handler))
            // Profiles
            .route("/users/:id/profile", get(get_user_profile_handler))
            .route(
                "/users/me/profile",
                axum::routing::patch(update_user_profile_handler),
            )
            // WebSocket
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

    fn ws_url(&self, path: &str) -> String {
        format!("ws://{}{}", self.base_url.replace("http://", ""), path)
    }

    /// Register a user and return (user_id, token)
    async fn register_and_auth_full(&self, name: &str) -> (Uuid, String) {
        let pk = format!("test_pk_{}", name);
        let resp = self
            .client
            .post(&self.url("/register"))
            .json(&json!({ "public_key": pk }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        let user_id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();

        let resp = self
            .client
            .post(&self.url("/auth"))
            .json(&json!({ "public_key": pk, "password": "" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        let token = body["token"].as_str().unwrap().to_string();
        (user_id, token)
    }

    /// Create a node, return node_id
    async fn create_node(&self, token: &str, name: &str) -> Uuid {
        let resp = self
            .client
            .post(&format!("{}/nodes?token={}", self.base_url, token))
            .json(&json!({ "name": name }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
    }

    /// Create a channel in a node, return channel_id
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
        assert_eq!(
            resp.status(),
            200,
            "create_channel failed: {:?}",
            resp.text().await
        );
        let body: Value = resp.json().await.unwrap();
        Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
    }

    /// Join a node
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
        assert_eq!(resp.status(), 200);
    }

    /// Connect WS and consume initial messages, return (sink, stream)
    async fn connect_ws(
        &self,
        token: &str,
    ) -> (
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            WsMessage,
        >,
        futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
    ) {
        let ws_url = format!("{}?token={}", self.ws_url("/ws"), token);
        let (ws, _) = connect_async(&ws_url).await.unwrap();
        let (sink, mut stream) = ws.split();
        // Drain initial messages (authenticated, hello, presence_bulk, etc.)
        for _ in 0..10 {
            if tokio::time::timeout(Duration::from_millis(200), stream.next())
                .await
                .is_err()
            {
                break;
            }
        }
        (sink, stream)
    }

    /// Read next WS text message with timeout
    async fn next_ws_msg(
        stream: &mut futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
        timeout_ms: u64,
    ) -> Option<Value> {
        loop {
            match tokio::time::timeout(Duration::from_millis(timeout_ms), stream.next()).await {
                Ok(Some(Ok(WsMessage::Text(text)))) => {
                    return Some(serde_json::from_str(&text).unwrap());
                }
                Ok(Some(Ok(_))) => continue, // skip non-text
                _ => return None,
            }
        }
    }

    /// Wait for a specific WS message type
    async fn wait_for_ws_type(
        stream: &mut futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
        msg_type: &str,
        timeout_ms: u64,
    ) -> Option<Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, stream.next()).await {
                Ok(Some(Ok(WsMessage::Text(text)))) => {
                    let v: Value = serde_json::from_str(&text).unwrap_or_default();
                    if v["type"] == msg_type {
                        return Some(v);
                    }
                }
                Ok(Some(Ok(_))) => continue,
                _ => return None,
            }
        }
    }
}

// ── Test 1: Voice Channel Join/Leave ──

#[tokio::test]
async fn test_voice_channel_join_leave() {
    let server = FullTestServer::new().await;

    let (user1_id, token1) = server.register_and_auth_full("voice_u1").await;
    let (user2_id, token2) = server.register_and_auth_full("voice_u2").await;

    let node_id = server.create_node(&token1, "VoiceNode").await;
    server.join_node(&token2, node_id).await;
    let channel_id = server.create_channel(&token1, node_id, "voice-room").await;

    // Both users join channel (needed for channel membership)
    // Join via WS
    let (mut sink1, mut stream1) = server.connect_ws(&token1).await;
    let (mut sink2, mut stream2) = server.connect_ws(&token2).await;

    // User1 joins the channel (text) first
    let join_ch = json!({
        "message_type": { "JoinChannel": { "channel_id": channel_id } },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink1
        .send(WsMessage::Text(join_ch.to_string()))
        .await
        .unwrap();
    sink2
        .send(WsMessage::Text(join_ch.to_string()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // User1 joins voice
    let join_voice = json!({
        "message_type": { "JoinVoiceChannel": { "channel_id": channel_id } },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink1
        .send(WsMessage::Text(join_voice.to_string()))
        .await
        .unwrap();

    // User1 should get voice_channel_joined
    let msg = FullTestServer::wait_for_ws_type(&mut stream1, "voice_channel_joined", 3000).await;
    assert!(msg.is_some(), "User1 should receive voice_channel_joined");
    let msg = msg.unwrap();
    assert_eq!(msg["channel_id"], channel_id.to_string());

    // User2 joins voice
    sink2
        .send(WsMessage::Text(join_voice.to_string()))
        .await
        .unwrap();

    // User2 should get voice_channel_joined with user1 in participants
    let msg = FullTestServer::wait_for_ws_type(&mut stream2, "voice_channel_joined", 3000).await;
    assert!(msg.is_some(), "User2 should receive voice_channel_joined");
    let participants = msg.unwrap()["participants"].as_array().unwrap().clone();
    assert!(
        participants
            .iter()
            .any(|p| p.as_str() == Some(&user1_id.to_string())),
        "User1 should be in participants"
    );

    // User1 should receive voice_peer_joined for user2
    let msg = FullTestServer::wait_for_ws_type(&mut stream1, "voice_peer_joined", 3000).await;
    assert!(msg.is_some(), "User1 should receive voice_peer_joined");
    assert_eq!(msg.unwrap()["user_id"], user2_id.to_string());

    // User2 leaves voice
    let leave_voice = json!({
        "message_type": { "LeaveVoiceChannel": { "channel_id": channel_id } },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink2
        .send(WsMessage::Text(leave_voice.to_string()))
        .await
        .unwrap();

    // User1 should receive voice_peer_left
    let msg = FullTestServer::wait_for_ws_type(&mut stream1, "voice_peer_left", 3000).await;
    assert!(msg.is_some(), "User1 should receive voice_peer_left");
    assert_eq!(msg.unwrap()["user_id"], user2_id.to_string());

    // Verify participants via state
    let participants = server
        .state
        .get_voice_channel_participants(channel_id)
        .await;
    assert_eq!(participants.len(), 1);
    assert!(participants.contains(&user1_id));
}

// ── Test 2: Invites — create → use → verify membership ──

#[tokio::test]
async fn test_invite_create_use_join() {
    let server = FullTestServer::new().await;

    let (_owner_id, owner_token) = server.register_and_auth_full("inv_owner").await;
    let (joiner_id, joiner_token) = server.register_and_auth_full("inv_joiner").await;

    let node_id = server.create_node(&owner_token, "InviteNode").await;

    // Owner creates invite
    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/invites?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({ "max_uses": 1, "expires_in_hours": 24 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let invite_code = body["invite_code"].as_str().unwrap().to_string();
    assert!(!invite_code.is_empty());

    // Joiner uses invite
    let resp = server
        .client
        .post(&format!(
            "{}/invites/{}/join?token={}",
            server.base_url, invite_code, joiner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "joined");
    assert_eq!(body["node_id"], node_id.to_string());

    // Verify joiner is a member
    assert!(server
        .state
        .is_node_member(joiner_id, node_id)
        .await
        .unwrap());

    // Invite should be used up (max_uses=1), try again with different user
    let (_u3_id, u3_token) = server.register_and_auth_full("inv_third").await;
    let resp = server
        .client
        .post(&format!(
            "{}/invites/{}/join?token={}",
            server.base_url, invite_code, u3_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "Invite should be exhausted");
}

// ── Test 3: File Upload and Download ──

#[tokio::test]
async fn test_file_upload_download() {
    let server = FullTestServer::new().await;

    let (user_id, token) = server.register_and_auth_full("file_user").await;
    let node_id = server.create_node(&token, "FileNode").await;
    let channel_id = server.create_channel(&token, node_id, "file-ch").await;

    // Join the channel so we have membership
    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    // Upload a file via multipart
    let file_content = b"encrypted_file_data_here_12345";
    let encrypted_filename = b"encrypted_name.bin";

    let form = reqwest::multipart::Form::new()
        .part(
            "encrypted_filename",
            reqwest::multipart::Part::bytes(encrypted_filename.to_vec()),
        )
        .part(
            "file",
            reqwest::multipart::Part::bytes(file_content.to_vec()),
        );

    let resp = server
        .client
        .post(&format!(
            "{}/channels/{}/files?token={}",
            server.base_url, channel_id, token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "Upload should succeed");
    let body: Value = resp.json().await.unwrap();
    let file_id = body["file_id"].as_str().unwrap();

    // Download the file
    let resp = server
        .client
        .get(&format!(
            "{}/files/{}?token={}",
            server.base_url, file_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "Download should succeed");
    let downloaded = resp.bytes().await.unwrap();
    assert_eq!(downloaded.as_ref(), file_content, "Content should match");
}

// ── Test 4: Roles & Hierarchy ──

#[tokio::test]
async fn test_roles_assign_remove() {
    let server = FullTestServer::new().await;

    let (_owner_id, owner_token) = server.register_and_auth_full("role_owner").await;
    let (member_id, member_token) = server.register_and_auth_full("role_member").await;

    let node_id = server.create_node(&owner_token, "RoleNode").await;
    server.join_node(&member_token, node_id).await;

    // Create a role with MANAGE_ROLES permission
    let manage_roles_bit: u64 = 1 << 28; // MANAGE_ROLES
    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/roles?token={}",
            server.base_url, node_id, owner_token
        ))
        .json(&json!({
            "name": "Moderator",
            "permissions": manage_roles_bit,
            "color": 0xFF0000
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let role: Value = resp.json().await.unwrap();
    let role_id = role["id"].as_str().unwrap();

    // Assign role to member
    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/members/{}/roles/{}?token={}",
            server.base_url, node_id, member_id, role_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "Assign role should succeed");

    // Verify member has the role
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
    assert!(
        roles.iter().any(|r| r["id"].as_str() == Some(role_id)),
        "Member should have the Moderator role"
    );

    // Remove role from member
    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/members/{}/roles/{}?token={}",
            server.base_url, node_id, member_id, role_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "Remove role should succeed");

    // Verify role is removed
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/members/{}/roles?token={}",
            server.base_url, node_id, member_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let roles = body["roles"].as_array().unwrap();
    assert!(
        !roles.iter().any(|r| r["id"].as_str() == Some(role_id)),
        "Member should no longer have the Moderator role"
    );
}

// ── Test 5: Channel Permissions — restricted send ──

#[tokio::test]
async fn test_channel_permission_restricted_send() {
    let server = FullTestServer::new().await;

    let (owner_id, owner_token) = server.register_and_auth_full("perm_owner").await;
    let (member_id, member_token) = server.register_and_auth_full("perm_member").await;

    let node_id = server.create_node(&owner_token, "PermNode").await;
    server.join_node(&member_token, node_id).await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "restricted-ch")
        .await;

    // Get the @everyone role (first role in the list, position 0)
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/roles?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let everyone_role_id = body["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["position"] == 0)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Set channel overwrite: deny SEND_MESSAGES for @everyone
    let send_messages_bit: u64 = 1 << 11;
    let resp = server
        .client
        .put(&format!(
            "{}/channels/{}/permissions/{}?token={}",
            server.base_url, channel_id, everyone_role_id, owner_token
        ))
        .json(&json!({ "allow": 0, "deny": send_messages_bit }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "Set overwrite should succeed");

    // Both join the channel
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    server
        .state
        .join_channel(member_id, channel_id)
        .await
        .unwrap();

    // Member tries to send a message via WS — should be denied
    let (mut sink, mut stream) = server.connect_ws(&member_token).await;
    let msg = json!({
        "message_type": {
            "ChannelMessage": {
                "channel_id": channel_id,
                "encrypted_data": base64::engine::general_purpose::STANDARD.encode(b"should fail")
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink.send(WsMessage::Text(msg.to_string())).await.unwrap();

    // Should get an error, not a channel_message broadcast
    let resp = FullTestServer::wait_for_ws_type(&mut stream, "error", 3000).await;
    assert!(
        resp.is_some(),
        "Member should receive error when sending to restricted channel"
    );
}

// ── Test 6: Node Creation → Admin → Channels → Delete ──

#[tokio::test]
async fn test_node_creation_admin_channels() {
    let server = FullTestServer::new().await;

    let (owner_id, owner_token) = server.register_and_auth_full("node_owner").await;

    // Create node
    let node_id = server.create_node(&owner_token, "TestNode").await;

    // Verify owner is admin (node owner)
    let info = server.state.get_node_info(node_id).await.unwrap();
    assert_eq!(info.node.owner_id, owner_id);

    // Create multiple channels
    let _ch1 = server
        .create_channel(&owner_token, node_id, "general")
        .await;
    let ch2 = server.create_channel(&owner_token, node_id, "random").await;

    // Verify channels exist
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/channels?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let channels = body.as_array().unwrap();
    // +1 for the auto-created "general" channel from node creation
    assert!(channels.len() >= 2, "Should have at least 2 channels");

    // Delete a channel
    let resp = server
        .client
        .delete(&format!(
            "{}/channels/{}?token={}",
            server.base_url, ch2, owner_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "Delete channel should succeed");

    // Verify channel is gone
    let ch = server.state.get_channel(ch2).await.unwrap();
    assert!(ch.is_none(), "Deleted channel should not exist");
}

// ── Test 7: Search Messages ──

#[tokio::test]
async fn test_search_messages() {
    let server = FullTestServer::new().await;

    let (user_id, token) = server.register_and_auth_full("search_user").await;
    let node_id = server.create_node(&token, "SearchNode").await;
    let channel_id = server.create_channel(&token, node_id, "search-ch").await;

    // Join channel
    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    // Store some messages directly (the search searches metadata/sender, not encrypted content)
    // Since messages are E2EE, search is on metadata — let's use the store_message directly
    let _msg1 = server
        .state
        .store_message(channel_id, user_id, b"hello world")
        .await
        .unwrap();
    let _msg2 = server
        .state
        .store_message(channel_id, user_id, b"goodbye world")
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Search by channel name (search matches on channel_name and public_key_hash metadata)
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?token={}&q=search-ch",
            server.base_url, node_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let results = body["results"].as_array().unwrap();
    assert!(
        results.len() >= 2,
        "Should find at least 2 messages in channel matching 'search-ch', got {}",
        results.len()
    );

    // Search with author filter
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?token={}&q=search-ch&author={}",
            server.base_url, node_id, token, user_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let results = body["results"].as_array().unwrap();
    assert!(
        results.len() >= 2,
        "Should find at least 2 messages by author filter"
    );
}

// ── Test 8: Presence — online/offline ──

#[tokio::test]
async fn test_presence_online_offline() {
    let server = FullTestServer::new().await;

    let (user1_id, token1) = server.register_and_auth_full("pres_u1").await;
    let (user2_id, token2) = server.register_and_auth_full("pres_u2").await;

    let node_id = server.create_node(&token1, "PresenceNode").await;
    server.join_node(&token2, node_id).await;

    // User1 connects via WS → should go online
    let (sink1, mut stream1) = server.connect_ws(&token1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check presence via REST
    let resp = server
        .client
        .get(&format!(
            "{}/api/presence/{}?token={}",
            server.base_url, node_id, token1
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    let u1_presence = members
        .iter()
        .find(|m| m["user_id"] == user1_id.to_string())
        .unwrap();
    assert_eq!(u1_presence["status"], "online");

    // User2 connects → user1 should get presence_update for user2
    let (_sink2, _stream2) = server.connect_ws(&token2).await;

    // Wait for presence_update
    let msg = FullTestServer::wait_for_ws_type(&mut stream1, "presence_update", 3000).await;
    assert!(msg.is_some(), "Should receive presence_update for user2");
    let msg = msg.unwrap();
    assert_eq!(msg["user_id"], user2_id.to_string());
    assert_eq!(msg["status"], "online");

    // Close user1's WS connection fully to trigger offline
    drop(stream1);
    drop(sink1);
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Check presence again — user1 should be offline
    let resp = server
        .client
        .get(&format!(
            "{}/api/presence/{}?token={}",
            server.base_url, node_id, token2
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let members = body["members"].as_array().unwrap();
    let u1_presence = members
        .iter()
        .find(|m| m["user_id"] == user1_id.to_string())
        .unwrap();
    assert_eq!(u1_presence["status"], "offline");
}

// ── Test 9: Message Editing ──

#[tokio::test]
async fn test_message_editing() {
    let server = FullTestServer::new().await;

    let (user_id, token) = server.register_and_auth_full("edit_user").await;
    let node_id = server.create_node(&token, "EditNode").await;
    let channel_id = server.create_channel(&token, node_id, "edit-ch").await;

    // Join channel
    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    // Store a message
    let original = b"original message content";
    let (msg_id, _seq) = server
        .state
        .store_message(channel_id, user_id, original)
        .await
        .unwrap();

    // Edit via REST
    let new_content = b"edited message content";
    let new_b64 = base64::engine::general_purpose::STANDARD.encode(new_content);
    let resp = server
        .client
        .patch(&format!(
            "{}/messages/{}?token={}",
            server.base_url, msg_id, token
        ))
        .json(&json!({ "encrypted_data": new_b64 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);

    // Verify edited content by fetching messages
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
    let messages = body["messages"].as_array().unwrap();
    let edited_msg = messages
        .iter()
        .find(|m| m["id"] == msg_id.to_string())
        .unwrap();
    assert!(
        edited_msg["edited_at"].is_number(),
        "Should have edited_at timestamp"
    );
}

// ── Test 10: Message Deletion ──

#[tokio::test]
async fn test_message_deletion() {
    let server = FullTestServer::new().await;

    let (user_id, token) = server.register_and_auth_full("del_user").await;
    let node_id = server.create_node(&token, "DelNode").await;
    let channel_id = server.create_channel(&token, node_id, "del-ch").await;

    server
        .state
        .join_channel(user_id, channel_id)
        .await
        .unwrap();

    // Store a message
    let (msg_id, _seq) = server
        .state
        .store_message(channel_id, user_id, b"to be deleted")
        .await
        .unwrap();

    // Connect WS to receive broadcast
    let (_sink, mut stream) = server.connect_ws(&token).await;

    // Delete via REST
    let resp = server
        .client
        .delete(&format!(
            "{}/messages/{}?token={}",
            server.base_url, msg_id, token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Should receive message_delete broadcast
    let msg = FullTestServer::wait_for_ws_type(&mut stream, "message_delete", 3000).await;
    assert!(msg.is_some(), "Should receive message_delete broadcast");
    let msg = msg.unwrap();
    assert_eq!(msg["message_id"], msg_id.to_string());
    assert_eq!(msg["channel_id"], channel_id.to_string());

    // Verify message is gone from history
    let resp = server
        .client
        .get(&format!(
            "{}/channels/{}/messages?token={}",
            server.base_url, channel_id, token
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let messages = body["messages"].as_array().unwrap();
    assert!(
        !messages.iter().any(|m| m["id"] == msg_id.to_string()),
        "Deleted message should not appear in history"
    );
}

// ── Test 11: Rate Limiting ──

#[tokio::test]
async fn test_rate_limiting_registration() {
    let server = FullTestServer::new().await;

    // Registration is rate-limited to 3 per hour per IP
    // Send 4 registration requests — 4th should get 429
    for i in 0..3 {
        let resp = server
            .client
            .post(&server.url("/register"))
            .header("X-Forwarded-For", "10.0.0.99")
            .json(&json!({ "public_key": format!("rate_pk_{}", i) }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "Request {} should succeed", i);
    }

    // 4th request should be rate limited
    let resp = server
        .client
        .post(&server.url("/register"))
        .header("X-Forwarded-For", "10.0.0.99")
        .json(&json!({ "public_key": "rate_pk_overflow" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "Should be rate limited");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], 429);
    assert!(
        body["error"].as_str().unwrap_or("").contains("Rate limit"),
        "Error should mention rate limit"
    );

    // Requests from different IP should still work
    let resp = server
        .client
        .post(&server.url("/register"))
        .header("X-Forwarded-For", "10.0.0.100")
        .json(&json!({ "public_key": "rate_pk_different_ip" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "Different IP should not be rate limited"
    );
}

// ── Test 12: Message Edit/Delete via WebSocket ──

#[tokio::test]
async fn test_message_edit_delete_via_ws() {
    let server = FullTestServer::new().await;

    let (user1_id, token1) = server.register_and_auth_full("ws_ed_u1").await;
    let (user2_id, token2) = server.register_and_auth_full("ws_ed_u2").await;

    let node_id = server.create_node(&token1, "WsEditNode").await;
    server.join_node(&token2, node_id).await;
    let channel_id = server.create_channel(&token1, node_id, "ws-edit-ch").await;

    // Both join channel
    server
        .state
        .join_channel(user1_id, channel_id)
        .await
        .unwrap();
    server
        .state
        .join_channel(user2_id, channel_id)
        .await
        .unwrap();

    // Connect both users
    let (mut sink1, mut stream1) = server.connect_ws(&token1).await;
    let (_sink2, mut stream2) = server.connect_ws(&token2).await;

    // User1 sends a channel message via WS
    let original_data = base64::engine::general_purpose::STANDARD.encode(b"original ws msg");
    let send_msg = json!({
        "message_type": {
            "ChannelMessage": {
                "channel_id": channel_id,
                "encrypted_data": original_data
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink1
        .send(WsMessage::Text(send_msg.to_string()))
        .await
        .unwrap();

    // Both should receive channel_message — extract message_id
    let msg = FullTestServer::wait_for_ws_type(&mut stream1, "channel_message", 3000).await;
    assert!(msg.is_some(), "User1 should receive channel_message");
    let message_id = msg.unwrap()["message_id"].as_str().unwrap().to_string();

    // Drain user2's channel_message
    let _ = FullTestServer::wait_for_ws_type(&mut stream2, "channel_message", 3000).await;

    // User1 edits the message via WS
    let edited_data = base64::engine::general_purpose::STANDARD.encode(b"edited ws msg");
    let edit_msg = json!({
        "message_type": {
            "EditMessage": {
                "message_id": message_id,
                "encrypted_data": edited_data
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink1
        .send(WsMessage::Text(edit_msg.to_string()))
        .await
        .unwrap();

    // User2 should receive message_edit broadcast
    let msg = FullTestServer::wait_for_ws_type(&mut stream2, "message_edit", 3000).await;
    assert!(msg.is_some(), "User2 should receive message_edit");
    let msg = msg.unwrap();
    assert_eq!(msg["message_id"], message_id);
    assert!(msg["edited_at"].is_number());

    // User1 deletes the message via WS
    let del_msg = json!({
        "message_type": {
            "DeleteMessage": {
                "message_id": message_id
            }
        },
        "message_id": Uuid::new_v4(),
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    sink1
        .send(WsMessage::Text(del_msg.to_string()))
        .await
        .unwrap();

    // User2 should receive message_delete broadcast
    let msg = FullTestServer::wait_for_ws_type(&mut stream2, "message_delete", 3000).await;
    assert!(msg.is_some(), "User2 should receive message_delete");
    assert_eq!(msg.unwrap()["message_id"], message_id);
}

// ── Bot API v2 Integration Tests ──

#[tokio::test]
async fn test_bot_api_v2_install_list_invoke() {
    let server = TestServer::new().await;

    // Register and auth as admin
    let token = server.register_and_auth("bot_admin").await;

    // Create a node (creator becomes admin)
    let resp = server
        .client
        .post(&server.url("/nodes"))
        .bearer_auth(&token)
        .json(&json!({ "name": "BotTestNode" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let node_id = body["id"].as_str().unwrap();

    // Create a channel
    let resp = server
        .client
        .post(&server.url(&format!("/nodes/{}/channels", node_id)))
        .bearer_auth(&token)
        .json(&json!({ "name": "general" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let channel_id = body["id"].as_str().unwrap().to_string();

    // Install a bot
    let install_resp = server
        .client
        .post(&server.url(&format!("/api/nodes/{}/bots", node_id)))
        .bearer_auth(&token)
        .json(&json!({
            "manifest": {
                "bot_id": "weather-bot",
                "name": "Weather",
                "icon": "🌤️",
                "description": "Weather forecasts",
                "commands": [{
                    "name": "forecast",
                    "description": "Get weather forecast",
                    "params": [
                        {"name": "location", "type": "string", "required": true, "description": "City"}
                    ]
                }]
            },
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(install_resp.status(), 200);
    let install_body: Value = install_resp.json().await.unwrap();
    assert_eq!(install_body["bot_id"], "weather-bot");
    let bot_token = install_body["bot_token"].as_str().unwrap().to_string();
    assert!(bot_token.starts_with("accord_botv2_"));

    // List bots
    let list_resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/bots", node_id)))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.status(), 200);
    let bots: Vec<Value> = list_resp.json().await.unwrap();
    assert_eq!(bots.len(), 1);
    assert_eq!(bots[0]["bot_id"], "weather-bot");
    assert_eq!(bots[0]["name"], "Weather");
    assert_eq!(bots[0]["commands"][0]["name"], "forecast");

    // Get bot commands
    let cmds_resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/bots/weather-bot/commands", node_id)))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(cmds_resp.status(), 200);
    let cmds: Vec<Value> = cmds_resp.json().await.unwrap();
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0]["name"], "forecast");

    // Invoke command (webhook will fail since it's a fake URL, but invocation should succeed)
    let invoke_resp = server
        .client
        .post(&server.url(&format!("/api/nodes/{}/bots/weather-bot/invoke", node_id)))
        .bearer_auth(&token)
        .json(&json!({
            "command": "forecast",
            "params": {"location": "Grand Rapids"},
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invoke_resp.status(), 200);
    let invoke_body: Value = invoke_resp.json().await.unwrap();
    assert_eq!(invoke_body["status"], "sent");
    let invocation_id = invoke_body["invocation_id"].as_str().unwrap().to_string();

    // Bot responds
    let respond_resp = server
        .client
        .post(&server.url("/api/bots/respond"))
        .bearer_auth(&bot_token)
        .json(&json!({
            "invocation_id": invocation_id,
            "content": {
                "type": "text",
                "text": "Weather in Grand Rapids: 28°F, partly cloudy"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(respond_resp.status(), 200);
    let respond_body: Value = respond_resp.json().await.unwrap();
    assert_eq!(respond_body["status"], "delivered");

    // Uninstall bot
    let uninstall_resp = server
        .client
        .delete(&server.url(&format!("/api/nodes/{}/bots/weather-bot", node_id)))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(uninstall_resp.status(), 200);

    // List bots should be empty now
    let list_resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/bots", node_id)))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.status(), 200);
    let bots: Vec<Value> = list_resp.json().await.unwrap();
    assert_eq!(bots.len(), 0);
}

#[tokio::test]
async fn test_bot_api_v2_auth_checks() {
    let server = TestServer::new().await;

    // Register admin and member
    let admin_token = server.register_and_auth("bot_admin2").await;
    let member_token = server.register_and_auth("bot_member").await;

    // Create node as admin
    let resp = server
        .client
        .post(&server.url("/nodes"))
        .bearer_auth(&admin_token)
        .json(&json!({ "name": "AuthTestNode" }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let node_id = body["id"].as_str().unwrap();

    // Member tries to install bot — should fail (not a member yet)
    let resp = server
        .client
        .post(&server.url(&format!("/api/nodes/{}/bots", node_id)))
        .bearer_auth(&member_token)
        .json(&json!({
            "manifest": {
                "bot_id": "test-bot",
                "name": "Test",
                "commands": []
            },
            "webhook_url": "https://example.com"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Unauthenticated request should fail
    let resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/bots", node_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_node_overview_batch_endpoint() {
    let server = TestServer::new().await;

    // Register and auth a user
    let token = server.register_and_auth("overview_user").await;

    // Create a node
    let resp = server
        .client
        .post(&server.url("/nodes"))
        .bearer_auth(&token)
        .json(&json!({ "name": "OverviewTestNode" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let node_id = body["id"].as_str().unwrap();

    // Create a channel in the node
    let resp = server
        .client
        .post(&server.url(&format!("/nodes/{}/channels", node_id)))
        .bearer_auth(&token)
        .json(&json!({ "name": "general" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Test overview endpoint
    let resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/overview", node_id)))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let overview: Value = resp.json().await.unwrap();

    // Verify structure
    assert!(overview["node"].is_object(), "overview should have node");
    assert!(
        overview["channels"].is_array(),
        "overview should have channels"
    );
    assert!(
        overview["members"].is_array(),
        "overview should have members"
    );
    assert!(overview["roles"].is_array(), "overview should have roles");

    // Verify we have at least 1 member (the creator)
    let members = overview["members"].as_array().unwrap();
    assert!(!members.is_empty(), "should have at least one member");
    assert!(members[0]["user_id"].is_string());
    assert!(members[0]["display_name"].is_string());
    assert!(members[0]["roles"].is_array());

    // Verify channels include the one we created
    let channels = overview["channels"].as_array().unwrap();
    assert!(!channels.is_empty(), "should have at least one channel");

    // Test unauthenticated access
    let resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/overview", node_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Test members/batch endpoint
    let resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/members/batch", node_id)))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let batch: Value = resp.json().await.unwrap();
    assert!(batch["members"].is_array());

    // Test channels/batch endpoint
    let resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/channels/batch", node_id)))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let batch: Value = resp.json().await.unwrap();
    assert!(batch["channels"].is_array());
}
