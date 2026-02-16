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
    handlers::{auth_handler, health_handler, register_handler, ws_handler},
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
    async fn register_user(&self, username: &str, public_key: &str) -> Uuid {
        let response = self
            .client
            .post(&self.url("/register"))
            .json(&json!({
                "username": username,
                "public_key": public_key
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap()
    }

    /// Authenticate a user and return the token
    async fn auth_user(&self, username: &str, password: &str) -> String {
        let response = self
            .client
            .post(&self.url("/auth"))
            .json(&json!({
                "username": username,
                "password": password
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
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
async fn test_user_registration_duplicate_username() {
    let server = TestServer::new().await;

    // Register first user
    let response = server
        .client
        .post(&server.url("/register"))
        .json(&json!({
            "username": "duplicate_test",
            "public_key": "fake_public_key_123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // Try to register with the same username
    let response = server
        .client
        .post(&server.url("/register"))
        .json(&json!({
            "username": "duplicate_test",
            "public_key": "different_public_key_456"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 409); // Conflict
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "Username already exists");
    assert_eq!(body["code"], 409);
}

#[tokio::test]
async fn test_user_registration_empty_fields() {
    let server = TestServer::new().await;

    // Test empty username
    let response = server
        .client
        .post(&server.url("/register"))
        .json(&json!({
            "username": "",
            "public_key": "fake_public_key_123"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "Username cannot be empty");

    // Test empty public key
    let response = server
        .client
        .post(&server.url("/register"))
        .json(&json!({
            "username": "testuser",
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

    // Now authenticate
    let response = server
        .client
        .post(&server.url("/auth"))
        .json(&json!({
            "username": "auth_test_user",
            "password": "any_password_for_now"
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

    // Try to authenticate with non-existent user
    let response = server
        .client
        .post(&server.url("/auth"))
        .json(&json!({
            "username": "nonexistent_user",
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
        .register_user("ws_test_user", "fake_public_key")
        .await;
    let token = server.auth_user("ws_test_user", "password").await;

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

    // Try to connect with an invalid token
    let ws_url = format!("{}?token=invalid_token", server.ws_url("/ws"));

    // This should fail to establish the connection
    let result = tokio::time::timeout(Duration::from_secs(2), connect_async(&ws_url)).await;
    assert!(result.is_err() || result.unwrap().is_err());
}

#[tokio::test]
async fn test_websocket_connection_without_token() {
    let server = TestServer::new().await;

    // Try to connect without a token
    let ws_url = server.ws_url("/ws");

    // This should fail to establish the connection
    let result = tokio::time::timeout(Duration::from_secs(2), connect_async(&ws_url)).await;
    assert!(result.is_err() || result.unwrap().is_err());
}

#[tokio::test]
async fn test_message_routing_between_two_clients() {
    let server = TestServer::new().await;

    // Register and authenticate two users
    let user1_id = server.register_user("user1", "public_key_1").await;
    let user2_id = server.register_user("user2", "public_key_2").await;

    let token1 = server.auth_user("user1", "password").await;
    let token2 = server.auth_user("user2", "password").await;

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
    let user1_id = server.register_user("channel_user1", "public_key_1").await;
    let user2_id = server.register_user("channel_user2", "public_key_2").await;

    let token1 = server.auth_user("channel_user1", "password").await;
    let token2 = server.auth_user("channel_user2", "password").await;

    // Connect both users via WebSocket
    let ws_url1 = format!("{}?token={}", server.ws_url("/ws"), token1);
    let ws_url2 = format!("{}?token={}", server.ws_url("/ws"), token2);

    let (ws_stream1, _) = connect_async(&ws_url1).await.unwrap();
    let (ws_stream2, _) = connect_async(&ws_url2).await.unwrap();

    let (mut sink1, mut stream1) = ws_stream1.split();
    let (mut sink2, mut stream2) = ws_stream2.split();

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
