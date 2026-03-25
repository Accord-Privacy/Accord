//! Integration tests for bot API v2 handlers
//! Tests the airgapped command architecture for bot installation, invocation, and responses.
#![allow(clippy::all, unused_imports, dead_code)]

use axum::{
    routing::{delete, get, post},
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
    bot_api::*,
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
            .route("/nodes/:id/join", post(join_node_handler))
            // Bot API v2 routes
            .route(
                "/api/nodes/:node_id/bots",
                get(list_bots_handler).post(install_bot_handler),
            )
            .route(
                "/api/nodes/:node_id/bots/:bot_id",
                delete(uninstall_bot_handler),
            )
            .route(
                "/api/nodes/:node_id/bots/:bot_id/commands",
                get(get_bot_commands_handler),
            )
            .route(
                "/api/nodes/:node_id/bots/:bot_id/invoke",
                post(invoke_command_handler),
            )
            .route("/api/bots/respond", post(bot_respond_handler))
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
        let pk = format!("bot_test_pk_{}", name);

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
}

// ═══════════════════════════════════════════════════════════════
//  1. Install Bot Tests
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_install_bot_success() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin").await;
    let node_id = server.create_node(&admin_token, "BotNode").await;

    let manifest = json!({
        "bot_id": "test-bot",
        "name": "Test Bot",
        "icon": "🤖",
        "description": "A test bot",
        "commands": [
            {
                "name": "hello",
                "description": "Say hello",
                "params": []
            }
        ]
    });

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["bot_id"], "test-bot");
    assert!(body["bot_token"]
        .as_str()
        .unwrap()
        .starts_with("accord_botv2_"));
    assert_eq!(body["node_x25519_pubkey"], Value::Null); // No E2EE key provided
    assert!(body["message"].as_str().unwrap().contains("installed"));
}

#[tokio::test]
async fn test_install_bot_with_encryption() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_e2ee").await;
    let node_id = server.create_node(&admin_token, "BotNodeE2EE").await;

    // Generate a mock X25519 public key (32 bytes base64)
    let mock_x25519_pubkey =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[1u8; 32]);

    let manifest = json!({
        "bot_id": "secure-bot",
        "name": "Secure Bot",
        "commands": [{ "name": "ping", "description": "Ping", "params": [] }]
    });

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook",
            "x25519_pubkey": mock_x25519_pubkey
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["bot_id"], "secure-bot");
    assert!(body["node_x25519_pubkey"].is_string()); // Node returned its pubkey
}

#[tokio::test]
async fn test_install_bot_missing_bot_id() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_missing").await;
    let node_id = server.create_node(&admin_token, "BotNodeMissing").await;

    let manifest = json!({
        "bot_id": "",
        "name": "Invalid Bot",
        "commands": []
    });

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("bot_id"));
}

#[tokio::test]
async fn test_install_bot_missing_webhook_url() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_no_webhook").await;
    let node_id = server.create_node(&admin_token, "BotNodeNoWebhook").await;

    let manifest = json!({
        "bot_id": "webhook-missing-bot",
        "name": "Bot",
        "commands": []
    });

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": ""
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("webhook_url"));
}

#[tokio::test]
async fn test_install_bot_unauthorized() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_unauth").await;
    let node_id = server.create_node(&admin_token, "BotNodeUnauth").await;

    let manifest = json!({
        "bot_id": "unauth-bot",
        "name": "Bot",
        "commands": []
    });

    // No token
    let resp = server
        .client
        .post(&server.url(&format!("/api/nodes/{}/bots", node_id)))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_install_bot_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_forb").await;
    let (_, member_token) = server.register_and_auth("bot_member_forb").await;
    let node_id = server.create_node(&admin_token, "BotNodeForb").await;
    server.join_node(&member_token, node_id).await;

    let manifest = json!({
        "bot_id": "forbidden-bot",
        "name": "Bot",
        "commands": []
    });

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, member_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_install_bot_duplicate() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_dup").await;
    let node_id = server.create_node(&admin_token, "BotNodeDup").await;

    let manifest = json!({
        "bot_id": "duplicate-bot",
        "name": "Bot",
        "commands": []
    });

    let payload = json!({
        "manifest": manifest,
        "webhook_url": "https://example.com/webhook"
    });

    // First install
    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second install (duplicate) - should fail with 500 or succeed with 200 (depending on DB behavior)
    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&payload)
        .send()
        .await
        .unwrap();
    // Database may allow UPSERT or may fail - both are acceptable
    assert!(
        resp.status() == 500 || resp.status() == 200,
        "Expected 500 or 200, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_install_bot_invalid_x25519_key() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_badkey").await;
    let node_id = server.create_node(&admin_token, "BotNodeBadKey").await;

    let manifest = json!({
        "bot_id": "bad-key-bot",
        "name": "Bot",
        "commands": []
    });

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook",
            "x25519_pubkey": "INVALID_BASE64!@#"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("x25519"));
}

// ═══════════════════════════════════════════════════════════════
//  2. Uninstall Bot Tests
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_uninstall_bot_success() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_uninst").await;
    let node_id = server.create_node(&admin_token, "BotNodeUninst").await;

    let manifest = json!({
        "bot_id": "to-uninstall",
        "name": "Bot",
        "commands": []
    });

    // Install
    server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    // Uninstall
    let resp = server
        .client
        .delete(&server.url(&format!(
            "/api/nodes/{}/bots/to-uninstall?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "uninstalled");
    assert_eq!(body["bot_id"], "to-uninstall");
}

#[tokio::test]
async fn test_uninstall_bot_not_found() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_uninst_nf").await;
    let node_id = server.create_node(&admin_token, "BotNodeUninstNf").await;

    let resp = server
        .client
        .delete(&server.url(&format!(
            "/api/nodes/{}/bots/nonexistent-bot?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_uninstall_bot_unauthorized() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_uninst_unauth").await;
    let node_id = server
        .create_node(&admin_token, "BotNodeUninstUnauth")
        .await;

    let resp = server
        .client
        .delete(&server.url(&format!("/api/nodes/{}/bots/some-bot", node_id)))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_uninstall_bot_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_admin_uninst_forb").await;
    let (_, member_token) = server.register_and_auth("bot_member_uninst_forb").await;
    let node_id = server.create_node(&admin_token, "BotNodeUninstForb").await;
    server.join_node(&member_token, node_id).await;

    let manifest = json!({
        "bot_id": "protected-bot",
        "name": "Bot",
        "commands": []
    });

    server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .delete(&server.url(&format!(
            "/api/nodes/{}/bots/protected-bot?token={}",
            node_id, member_token
        )))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  3. List Bots Tests
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_list_bots_empty() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("bot_list_empty").await;
    let node_id = server.create_node(&token, "BotListEmpty").await;

    let resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/bots?token={}", node_id, token)))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let bots = body.as_array().unwrap();
    assert_eq!(bots.len(), 0);
}

#[tokio::test]
async fn test_list_bots_success() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_list_admin").await;
    let node_id = server.create_node(&admin_token, "BotListNode").await;

    // Install two bots
    for i in 1..=2 {
        let manifest = json!({
            "bot_id": format!("bot-{}", i),
            "name": format!("Bot {}", i),
            "commands": [{ "name": "cmd", "description": "test", "params": [] }]
        });

        server
            .client
            .post(&server.url(&format!(
                "/api/nodes/{}/bots?token={}",
                node_id, admin_token
            )))
            .json(&json!({
                "manifest": manifest,
                "webhook_url": "https://example.com/webhook"
            }))
            .send()
            .await
            .unwrap();
    }

    let resp = server
        .client
        .get(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let bots = body.as_array().unwrap();
    assert_eq!(bots.len(), 2);
    let bot_ids: Vec<&str> = bots.iter().filter_map(|b| b["bot_id"].as_str()).collect();
    assert!(bot_ids.contains(&"bot-1"));
    assert!(bot_ids.contains(&"bot-2"));
}

#[tokio::test]
async fn test_list_bots_unauthorized() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_list_unauth").await;
    let node_id = server.create_node(&admin_token, "BotListUnauth").await;

    let resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/bots", node_id)))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_list_bots_forbidden_for_non_member() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_list_admin_forb").await;
    let (_, stranger_token) = server.register_and_auth("bot_list_stranger").await;
    let node_id = server.create_node(&admin_token, "BotListForb").await;

    let resp = server
        .client
        .get(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, stranger_token
        )))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  4. Get Bot Commands Tests
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_bot_commands_success() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_cmd_admin").await;
    let node_id = server.create_node(&admin_token, "BotCmdNode").await;

    let manifest = json!({
        "bot_id": "cmd-bot",
        "name": "Command Bot",
        "commands": [
            { "name": "hello", "description": "Say hello", "params": [] },
            { "name": "bye", "description": "Say bye", "params": [] }
        ]
    });

    server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&server.url(&format!(
            "/api/nodes/{}/bots/cmd-bot/commands?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let commands = body.as_array().unwrap();
    assert_eq!(commands.len(), 2);
    let names: Vec<&str> = commands.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(names.contains(&"hello"));
    assert!(names.contains(&"bye"));
}

#[tokio::test]
async fn test_get_bot_commands_not_found() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_cmd_nf").await;
    let node_id = server.create_node(&admin_token, "BotCmdNf").await;

    let resp = server
        .client
        .get(&server.url(&format!(
            "/api/nodes/{}/bots/nonexistent-bot/commands?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_bot_commands_unauthorized() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_cmd_unauth").await;
    let node_id = server.create_node(&admin_token, "BotCmdUnauth").await;

    let resp = server
        .client
        .get(&server.url(&format!("/api/nodes/{}/bots/some-bot/commands", node_id)))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_get_bot_commands_forbidden_for_non_member() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_cmd_admin_forb").await;
    let (_, stranger_token) = server.register_and_auth("bot_cmd_stranger").await;
    let node_id = server.create_node(&admin_token, "BotCmdForb").await;

    let manifest = json!({
        "bot_id": "private-cmd-bot",
        "name": "Bot",
        "commands": []
    });

    server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&server.url(&format!(
            "/api/nodes/{}/bots/private-cmd-bot/commands?token={}",
            node_id, stranger_token
        )))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  5. Invoke Command Tests
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_invoke_command_success() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_invoke_admin").await;
    let node_id = server.create_node(&admin_token, "BotInvokeNode").await;

    let manifest = json!({
        "bot_id": "invoke-bot",
        "name": "Invoke Bot",
        "commands": [
            { "name": "ping", "description": "Ping", "params": [] }
        ]
    });

    server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    let channel_id = Uuid::new_v4().to_string();

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots/invoke-bot/invoke?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "command": "ping",
            "params": {},
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["invocation_id"].is_string());
    assert_eq!(body["status"], "sent");
}

#[tokio::test]
async fn test_invoke_command_with_params() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_invoke_params").await;
    let node_id = server.create_node(&admin_token, "BotInvokeParams").await;

    let manifest = json!({
        "bot_id": "param-bot",
        "name": "Param Bot",
        "commands": [
            {
                "name": "greet",
                "description": "Greet someone",
                "params": [
                    { "name": "name", "type": "string", "required": true }
                ]
            }
        ]
    });

    server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    let channel_id = Uuid::new_v4().to_string();

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots/param-bot/invoke?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "command": "greet",
            "params": { "name": "Alice" },
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["invocation_id"].is_string());
}

#[tokio::test]
async fn test_invoke_command_bot_not_found() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_invoke_nf").await;
    let node_id = server.create_node(&admin_token, "BotInvokeNf").await;

    let channel_id = Uuid::new_v4().to_string();

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots/nonexistent-bot/invoke?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "command": "test",
            "params": {},
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_invoke_command_unauthorized() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_invoke_unauth").await;
    let node_id = server.create_node(&admin_token, "BotInvokeUnauth").await;

    let channel_id = Uuid::new_v4().to_string();

    let resp = server
        .client
        .post(&server.url(&format!("/api/nodes/{}/bots/some-bot/invoke", node_id)))
        .json(&json!({
            "command": "test",
            "params": {},
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_invoke_command_forbidden_for_non_member() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_invoke_admin_forb").await;
    let (_, stranger_token) = server.register_and_auth("bot_invoke_stranger").await;
    let node_id = server.create_node(&admin_token, "BotInvokeForb").await;

    let manifest = json!({
        "bot_id": "private-invoke-bot",
        "name": "Bot",
        "commands": [{ "name": "test", "description": "test", "params": [] }]
    });

    server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    let channel_id = Uuid::new_v4().to_string();

    let resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots/private-invoke-bot/invoke?token={}",
            node_id, stranger_token
        )))
        .json(&json!({
            "command": "test",
            "params": {},
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  6. Bot Respond Tests
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_bot_respond_success() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_resp_admin").await;
    let node_id = server.create_node(&admin_token, "BotRespNode").await;

    let manifest = json!({
        "bot_id": "resp-bot",
        "name": "Response Bot",
        "commands": [{ "name": "test", "description": "test", "params": [] }]
    });

    let install_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();
    let install_body: Value = install_resp.json().await.unwrap();
    let bot_token = install_body["bot_token"].as_str().unwrap();

    // Create an invocation
    let channel_id = Uuid::new_v4().to_string();
    let invoke_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots/resp-bot/invoke?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "command": "test",
            "params": {},
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();
    let invoke_body: Value = invoke_resp.json().await.unwrap();
    let invocation_id = invoke_body["invocation_id"].as_str().unwrap();

    // Bot responds
    let resp = server
        .client
        .post(&server.url("/api/bots/respond"))
        .header("Authorization", format!("Bearer {}", bot_token))
        .json(&json!({
            "invocation_id": invocation_id,
            "content": {
                "type": "text",
                "text": "Hello from bot!"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "delivered");
}

#[tokio::test]
async fn test_bot_respond_missing_auth() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .post(&server.url("/api/bots/respond"))
        .json(&json!({
            "invocation_id": "fake-id",
            "content": { "type": "text", "text": "test" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("bot_token"));
}

#[tokio::test]
async fn test_bot_respond_invalid_token() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .post(&server.url("/api/bots/respond"))
        .header("Authorization", "Bearer invalid_token_12345")
        .json(&json!({
            "invocation_id": "fake-id",
            "content": { "type": "text", "text": "test" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Invalid bot token"));
}

#[tokio::test]
async fn test_bot_respond_invocation_not_found() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_resp_inv_nf").await;
    let node_id = server.create_node(&admin_token, "BotRespInvNf").await;

    let manifest = json!({
        "bot_id": "resp-nf-bot",
        "name": "Bot",
        "commands": []
    });

    let install_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();
    let install_body: Value = install_resp.json().await.unwrap();
    let bot_token = install_body["bot_token"].as_str().unwrap();

    let resp = server
        .client
        .post(&server.url("/api/bots/respond"))
        .header("Authorization", format!("Bearer {}", bot_token))
        .json(&json!({
            "invocation_id": "nonexistent-invocation",
            "content": { "type": "text", "text": "test" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Invocation not found"));
}

#[tokio::test]
async fn test_bot_respond_with_embed() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_resp_embed").await;
    let node_id = server.create_node(&admin_token, "BotRespEmbed").await;

    let manifest = json!({
        "bot_id": "embed-bot",
        "name": "Embed Bot",
        "commands": [{ "name": "info", "description": "info", "params": [] }]
    });

    let install_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();
    let install_body: Value = install_resp.json().await.unwrap();
    let bot_token = install_body["bot_token"].as_str().unwrap();

    let channel_id = Uuid::new_v4().to_string();
    let invoke_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots/embed-bot/invoke?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "command": "info",
            "params": {},
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();
    let invoke_body: Value = invoke_resp.json().await.unwrap();
    let invocation_id = invoke_body["invocation_id"].as_str().unwrap();

    let resp = server
        .client
        .post(&server.url("/api/bots/respond"))
        .header("Authorization", format!("Bearer {}", bot_token))
        .json(&json!({
            "invocation_id": invocation_id,
            "content": {
                "type": "embed",
                "title": "Info",
                "sections": [
                    { "type": "text", "text": "Section 1" },
                    { "type": "divider" },
                    {
                        "type": "grid",
                        "columns": ["Name", "Value"],
                        "rows": [["test", "123"]]
                    }
                ]
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "delivered");
}

// ═══════════════════════════════════════════════════════════════
//  7. Edge Cases and Integration Tests
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_bot_full_lifecycle() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_lifecycle").await;
    let node_id = server.create_node(&admin_token, "BotLifecycle").await;

    // 1. Install
    let manifest = json!({
        "bot_id": "lifecycle-bot",
        "name": "Lifecycle Bot",
        "commands": [{ "name": "test", "description": "test", "params": [] }]
    });

    let install_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(install_resp.status(), 200);
    let install_body: Value = install_resp.json().await.unwrap();
    let bot_token = install_body["bot_token"].as_str().unwrap().to_string();

    // 2. List (should show 1 bot)
    let list_resp = server
        .client
        .get(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();
    let list_body: Value = list_resp.json().await.unwrap();
    assert_eq!(list_body.as_array().unwrap().len(), 1);

    // 3. Get commands
    let cmd_resp = server
        .client
        .get(&server.url(&format!(
            "/api/nodes/{}/bots/lifecycle-bot/commands?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(cmd_resp.status(), 200);

    // 4. Invoke
    let channel_id = Uuid::new_v4().to_string();
    let invoke_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots/lifecycle-bot/invoke?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "command": "test",
            "params": {},
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();
    let invoke_body: Value = invoke_resp.json().await.unwrap();
    let invocation_id = invoke_body["invocation_id"].as_str().unwrap().to_string();

    // 5. Respond
    let respond_resp = server
        .client
        .post(&server.url("/api/bots/respond"))
        .header("Authorization", format!("Bearer {}", bot_token))
        .json(&json!({
            "invocation_id": invocation_id,
            "content": { "type": "text", "text": "OK" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(respond_resp.status(), 200);

    // 6. Uninstall
    let uninst_resp = server
        .client
        .delete(&server.url(&format!(
            "/api/nodes/{}/bots/lifecycle-bot?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(uninst_resp.status(), 200);

    // 7. List again (should be empty)
    let list_resp2 = server
        .client
        .get(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();
    let list_body2: Value = list_resp2.json().await.unwrap();
    assert_eq!(list_body2.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_multiple_bots_on_same_node() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("multi_bot_admin").await;
    let node_id = server.create_node(&admin_token, "MultiBotNode").await;

    for i in 1..=3 {
        let manifest = json!({
            "bot_id": format!("multi-bot-{}", i),
            "name": format!("Bot {}", i),
            "commands": [{ "name": "cmd", "description": "test", "params": [] }]
        });

        let resp = server
            .client
            .post(&server.url(&format!(
                "/api/nodes/{}/bots?token={}",
                node_id, admin_token
            )))
            .json(&json!({
                "manifest": manifest,
                "webhook_url": "https://example.com/webhook"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    let list_resp = server
        .client
        .get(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();
    let list_body: Value = list_resp.json().await.unwrap();
    assert_eq!(list_body.as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_bot_token_unique_per_installation() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("unique_token_admin").await;
    let node_id = server.create_node(&admin_token, "UniqueTokenNode").await;

    let manifest = json!({
        "bot_id": "token-test-bot",
        "name": "Token Bot",
        "commands": []
    });

    let resp1 = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();
    let body1: Value = resp1.json().await.unwrap();
    let token1 = body1["bot_token"].as_str().unwrap();

    // Uninstall
    server
        .client
        .delete(&server.url(&format!(
            "/api/nodes/{}/bots/token-test-bot?token={}",
            node_id, admin_token
        )))
        .send()
        .await
        .unwrap();

    // Reinstall same bot
    let resp2 = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();
    let body2: Value = resp2.json().await.unwrap();
    let token2 = body2["bot_token"].as_str().unwrap();

    // Tokens should be different
    assert_ne!(token1, token2);
}

#[tokio::test]
async fn test_bot_respond_with_invalid_channel_id() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("bot_resp_bad_ch").await;
    let node_id = server.create_node(&admin_token, "BotRespBadCh").await;

    let manifest = json!({
        "bot_id": "bad-ch-bot",
        "name": "Bot",
        "commands": [{ "name": "test", "description": "test", "params": [] }]
    });

    let install_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();
    let install_body: Value = install_resp.json().await.unwrap();
    let bot_token = install_body["bot_token"].as_str().unwrap();

    // Invoke with invalid channel ID
    let invoke_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots/bad-ch-bot/invoke?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "command": "test",
            "params": {},
            "channel_id": "not-a-uuid"
        }))
        .send()
        .await
        .unwrap();

    // Invocation should still be created (fire-and-forget webhook)
    assert_eq!(invoke_resp.status(), 200);
    let invoke_body: Value = invoke_resp.json().await.unwrap();
    let invocation_id = invoke_body["invocation_id"].as_str().unwrap();

    // Bot tries to respond - should fail due to invalid channel_id
    let resp = server
        .client
        .post(&server.url("/api/bots/respond"))
        .header("Authorization", format!("Bearer {}", bot_token))
        .json(&json!({
            "invocation_id": invocation_id,
            "content": { "type": "text", "text": "test" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_member_can_invoke_but_not_manage() {
    let server = TestServer::new().await;
    let (_, admin_token) = server.register_and_auth("member_invoke_admin").await;
    let (_, member_token) = server.register_and_auth("member_invoke_member").await;
    let node_id = server.create_node(&admin_token, "MemberInvokeNode").await;
    server.join_node(&member_token, node_id).await;

    let manifest = json!({
        "bot_id": "member-bot",
        "name": "Member Bot",
        "commands": [{ "name": "test", "description": "test", "params": [] }]
    });

    // Admin installs
    server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots?token={}",
            node_id, admin_token
        )))
        .json(&json!({
            "manifest": manifest,
            "webhook_url": "https://example.com/webhook"
        }))
        .send()
        .await
        .unwrap();

    // Member can invoke
    let channel_id = Uuid::new_v4().to_string();
    let invoke_resp = server
        .client
        .post(&server.url(&format!(
            "/api/nodes/{}/bots/member-bot/invoke?token={}",
            node_id, member_token
        )))
        .json(&json!({
            "command": "test",
            "params": {},
            "channel_id": channel_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invoke_resp.status(), 200);

    // Member cannot uninstall
    let uninst_resp = server
        .client
        .delete(&server.url(&format!(
            "/api/nodes/{}/bots/member-bot?token={}",
            node_id, member_token
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(uninst_resp.status(), 403);
}
