//! Integration tests for file, emoji, avatar, icon, and search handlers.
//! Tests: upload_file, download_file, delete_file, upload_custom_emoji,
//!        delete_custom_emoji, list_custom_emojis, get_emoji_image,
//!        upload_user_avatar, get_user_avatar, upload_node_icon,
//!        get_node_icon, search_messages.
#![allow(clippy::all, unused_imports, dead_code)]

use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use reqwest::{multipart, Client};
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
            .route("/nodes/:id", patch(update_node_handler))
            .route("/nodes/:id/join", post(join_node_handler))
            .route("/nodes/:id/leave", post(leave_node_handler))
            .route(
                "/nodes/:id/channels",
                get(list_node_channels_handler).post(create_channel_handler),
            )
            .route("/nodes/:id/members", get(get_node_members_handler))
            .route("/nodes/:id/members/:user_id", delete(kick_user_handler))
            // Search
            .route("/nodes/:id/search", get(search_messages_handler))
            // Files
            .route(
                "/channels/:id/files",
                post(upload_file_handler).get(list_channel_files_handler),
            )
            .route(
                "/files/:id",
                get(download_file_handler).delete(delete_file_handler),
            )
            // Custom emoji
            .route(
                "/nodes/:id/emojis",
                get(list_custom_emojis_handler).post(upload_custom_emoji_handler),
            )
            .route(
                "/nodes/:id/emojis/:emoji_id",
                delete(delete_custom_emoji_handler),
            )
            .route("/api/emojis/:content_hash", get(get_emoji_image_handler))
            // Node icon
            .route(
                "/nodes/:id/icon",
                put(upload_node_icon_handler).get(get_node_icon_handler),
            )
            // User avatar
            .route("/users/me/avatar", put(upload_user_avatar_handler))
            .route("/users/:id/avatar", get(get_user_avatar_handler))
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
        let pk = format!("file_emoji_test_pk_{}", name);

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

    /// Have `token` join `node_id` via HTTP.
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

    /// Upload a file to a channel (channel member required).
    /// Returns file_id.
    async fn upload_file(&self, token: &str, channel_id: Uuid) -> Uuid {
        let form = multipart::Form::new()
            .part(
                "encrypted_filename",
                multipart::Part::bytes(b"encrypted_name_bytes".to_vec())
                    .file_name("encrypted_name"),
            )
            .part(
                "file",
                multipart::Part::bytes(b"fake encrypted file data".to_vec())
                    .file_name("test.bin")
                    .mime_str("application/octet-stream")
                    .unwrap(),
            );

        let resp = self
            .client
            .post(&format!(
                "{}/channels/{}/files?token={}",
                self.base_url, channel_id, token
            ))
            .multipart(form)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "upload_file failed");
        let body: Value = resp.json().await.unwrap();
        Uuid::parse_str(body["file_id"].as_str().unwrap()).unwrap()
    }

    /// Upload a custom emoji to a node.
    /// Returns the emoji body Value.
    async fn upload_emoji(&self, token: &str, node_id: Uuid, name: &str) -> Value {
        // Minimal 1x1 PNG bytes
        let png_bytes = minimal_png();
        let form = multipart::Form::new()
            .part(
                "file",
                multipart::Part::bytes(png_bytes)
                    .file_name("emoji.png")
                    .mime_str("image/png")
                    .unwrap(),
            )
            .part("name", multipart::Part::text(name.to_string()));

        let resp = self
            .client
            .post(&format!(
                "{}/nodes/{}/emojis?token={}",
                self.base_url, node_id, token
            ))
            .multipart(form)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "upload_emoji failed for '{name}'");
        resp.json().await.unwrap()
    }
}

/// Returns a valid minimal 1×1 PNG (67 bytes).
fn minimal_png() -> Vec<u8> {
    // This is a valid 1x1 transparent PNG
    vec![
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
        0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR chunk length + type
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // width=1, height=1
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, // bit depth=8, colortype=2
        0xde, // IHDR CRC
        0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
        0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc,
        0x33, // IDAT CRC
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, // IEND chunk
        0xae, 0x42, 0x60, 0x82, // IEND CRC
    ]
}

// ═══════════════════════════════════════════════════════════════
//  1. File Upload
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_upload_file_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("file_up_owner1").await;
    let node_id = server.create_node(&owner_token, "FileUpNode1").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-ch")
        .await;

    // Owner created the channel — join it so membership is recorded
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();

    let form = multipart::Form::new()
        .part(
            "encrypted_filename",
            multipart::Part::bytes(b"enc_name".to_vec()),
        )
        .part(
            "file",
            multipart::Part::bytes(b"hello world encrypted".to_vec())
                .file_name("data.bin")
                .mime_str("application/octet-stream")
                .unwrap(),
        );

    let resp = server
        .client
        .post(&format!(
            "{}/channels/{}/files?token={}",
            server.base_url, channel_id, owner_token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["file_id"].is_string(), "expected file_id in response");
}

#[tokio::test]
async fn test_upload_file_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("file_up_unauth").await;
    let node_id = server.create_node(&owner_token, "FileUpUnauthNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-ch-unauth")
        .await;

    let form = multipart::Form::new()
        .part(
            "encrypted_filename",
            multipart::Part::bytes(b"name".to_vec()),
        )
        .part("file", multipart::Part::bytes(b"data".to_vec()));

    let resp = server
        .client
        .post(&format!(
            "{}/channels/{}/files",
            server.base_url, channel_id
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_upload_file_not_channel_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("file_up_notmem_own").await;
    let (_, stranger_token) = server.register_and_auth("file_up_stranger").await;
    let node_id = server.create_node(&owner_token, "FileUpNotMemNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-ch-priv")
        .await;

    let form = multipart::Form::new()
        .part(
            "encrypted_filename",
            multipart::Part::bytes(b"name".to_vec()),
        )
        .part("file", multipart::Part::bytes(b"data".to_vec()));

    let resp = server
        .client
        .post(&format!(
            "{}/channels/{}/files?token={}",
            server.base_url, channel_id, stranger_token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    // Stranger not in channel → 403 or 404 (channel found but not member)
    assert!(
        resp.status() == 403 || resp.status() == 404,
        "Expected 403 or 404, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_upload_file_missing_fields() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("file_up_miss").await;
    let node_id = server.create_node(&owner_token, "FileUpMissNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-ch-miss")
        .await;
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();

    // Missing 'file' field
    let form = multipart::Form::new().part(
        "encrypted_filename",
        multipart::Part::bytes(b"name".to_vec()),
    );

    let resp = server
        .client
        .post(&format!(
            "{}/channels/{}/files?token={}",
            server.base_url, channel_id, owner_token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

// ═══════════════════════════════════════════════════════════════
//  2. File Download
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_download_file_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("file_dl_owner").await;
    let node_id = server.create_node(&owner_token, "FileDlNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-dl-ch")
        .await;
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();

    let file_id = server.upload_file(&owner_token, channel_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/files/{}?token={}",
            server.base_url, file_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/octet-stream"),
        "Expected octet-stream, got: {}",
        ct
    );
    let body = resp.bytes().await.unwrap();
    assert!(!body.is_empty());
}

#[tokio::test]
async fn test_download_file_unauthorized() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("file_dl_unauth").await;
    let node_id = server.create_node(&owner_token, "FileDlUnauthNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-dl-unauth-ch")
        .await;
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let file_id = server.upload_file(&owner_token, channel_id).await;

    let resp = server
        .client
        .get(&format!("{}/files/{}", server.base_url, file_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_download_file_not_found() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("file_dl_nf").await;
    let fake_id = Uuid::new_v4();

    let resp = server
        .client
        .get(&format!(
            "{}/files/{}?token={}",
            server.base_url, fake_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_download_file_forbidden_non_member() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("file_dl_frb_own").await;
    let (_, stranger_token) = server.register_and_auth("file_dl_frb_str").await;
    let node_id = server.create_node(&owner_token, "FileDlFrbNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-dl-frb-ch")
        .await;
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let file_id = server.upload_file(&owner_token, channel_id).await;

    let resp = server
        .client
        .get(&format!(
            "{}/files/{}?token={}",
            server.base_url, file_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  3. File Delete
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_delete_file_by_uploader_success() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("file_del_own").await;
    let node_id = server.create_node(&owner_token, "FileDelNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-del-ch")
        .await;
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let file_id = server.upload_file(&owner_token, channel_id).await;

    let resp = server
        .client
        .delete(&format!(
            "{}/files/{}?token={}",
            server.base_url, file_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Response contains either "status": "deleted" or "message": "File deleted successfully"
    assert!(
        body["status"] == "deleted"
            || body["message"]
                .as_str()
                .map(|s| s.contains("deleted"))
                .unwrap_or(false),
        "Expected delete confirmation, got: {}",
        body
    );
}

#[tokio::test]
async fn test_delete_file_unauthorized() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("file_del_unauth").await;
    let node_id = server.create_node(&owner_token, "FileDelUnauthNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-del-unauth-ch")
        .await;
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    let file_id = server.upload_file(&owner_token, channel_id).await;

    let resp = server
        .client
        .delete(&format!("{}/files/{}", server.base_url, file_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_delete_file_not_found() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("file_del_nf").await;
    let fake_id = Uuid::new_v4();

    let resp = server
        .client
        .delete(&format!(
            "{}/files/{}?token={}",
            server.base_url, fake_id, token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_file_forbidden_non_uploader() {
    let server = TestServer::new().await;
    let (owner_id, owner_token) = server.register_and_auth("file_del_frb_own").await;
    let (member_id, member_token) = server.register_and_auth("file_del_frb_mem").await;
    let node_id = server.create_node(&owner_token, "FileDelFrbNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "file-del-frb-ch")
        .await;
    server
        .state
        .join_channel(owner_id, channel_id)
        .await
        .unwrap();
    server.state.join_node(member_id, node_id).await.unwrap();
    server
        .state
        .join_channel(member_id, channel_id)
        .await
        .unwrap();

    let file_id = server.upload_file(&owner_token, channel_id).await;

    // member is not uploader or admin → 403
    let resp = server
        .client
        .delete(&format!(
            "{}/files/{}?token={}",
            server.base_url, file_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  4. Custom Emoji - Upload
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_upload_custom_emoji_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_up_own1").await;
    let node_id = server.create_node(&owner_token, "EmojiUpNode1").await;

    let body = server
        .upload_emoji(&owner_token, node_id, "test_emoji")
        .await;

    assert!(body["id"].is_string());
    assert_eq!(body["name"], "test_emoji");
    assert_eq!(body["node_id"], node_id.to_string());
    assert!(body["content_hash"].is_string());
}

#[tokio::test]
async fn test_upload_custom_emoji_invalid_name_too_short() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_inv_short").await;
    let node_id = server.create_node(&owner_token, "EmojiInvShortNode").await;

    let form = multipart::Form::new()
        .part(
            "file",
            multipart::Part::bytes(minimal_png())
                .file_name("e.png")
                .mime_str("image/png")
                .unwrap(),
        )
        .part("name", multipart::Part::text("x")); // too short (< 2 chars)

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/emojis?token={}",
            server.base_url, node_id, owner_token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_upload_custom_emoji_missing_file() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_miss_file").await;
    let node_id = server.create_node(&owner_token, "EmojiMissFileNode").await;

    let form = multipart::Form::new().part("name", multipart::Part::text("valid_name"));

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/emojis?token={}",
            server.base_url, node_id, owner_token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_upload_custom_emoji_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_unauth_own").await;
    let node_id = server.create_node(&owner_token, "EmojiUnauthNode").await;

    let form = multipart::Form::new()
        .part("file", multipart::Part::bytes(minimal_png()))
        .part("name", multipart::Part::text("valid_emoji"));

    let resp = server
        .client
        .post(&format!("{}/nodes/{}/emojis", server.base_url, node_id))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_upload_custom_emoji_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_frb_own").await;
    let (_, member_token) = server.register_and_auth("emoji_frb_mem").await;
    let node_id = server.create_node(&owner_token, "EmojiFrbNode").await;
    server.join_node(&member_token, node_id).await;

    let form = multipart::Form::new()
        .part(
            "file",
            multipart::Part::bytes(minimal_png())
                .file_name("e.png")
                .mime_str("image/png")
                .unwrap(),
        )
        .part("name", multipart::Part::text("no_perm_emoji"));

    let resp = server
        .client
        .post(&format!(
            "{}/nodes/{}/emojis?token={}",
            server.base_url, node_id, member_token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

// ═══════════════════════════════════════════════════════════════
//  5. Custom Emoji - List
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_list_custom_emojis_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_list_own").await;
    let node_id = server.create_node(&owner_token, "EmojiListNode").await;

    server
        .upload_emoji(&owner_token, node_id, "emoji_alpha")
        .await;
    server
        .upload_emoji(&owner_token, node_id, "emoji_beta")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/emojis?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let emojis = body["emojis"].as_array().unwrap();
    assert!(emojis.len() >= 2);
    let names: Vec<&str> = emojis.iter().filter_map(|e| e["name"].as_str()).collect();
    assert!(names.contains(&"emoji_alpha"));
    assert!(names.contains(&"emoji_beta"));
}

#[tokio::test]
async fn test_list_custom_emojis_empty_node() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_list_empty").await;
    let node_id = server.create_node(&owner_token, "EmojiListEmptyNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/emojis?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let emojis = body["emojis"].as_array().unwrap();
    assert_eq!(emojis.len(), 0);
}

#[tokio::test]
async fn test_list_custom_emojis_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_list_unauth").await;
    let node_id = server
        .create_node(&owner_token, "EmojiListUnauthNode")
        .await;

    let resp = server
        .client
        .get(&format!("{}/nodes/{}/emojis", server.base_url, node_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  6. Custom Emoji - Delete
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_delete_custom_emoji_by_uploader_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_del_own").await;
    let node_id = server.create_node(&owner_token, "EmojiDelNode").await;

    let emoji_body = server
        .upload_emoji(&owner_token, node_id, "del_emoji")
        .await;
    let emoji_id = emoji_body["id"].as_str().unwrap();

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/emojis/{}?token={}",
            server.base_url, node_id, emoji_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "deleted");
}

#[tokio::test]
async fn test_delete_custom_emoji_not_found() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_del_nf").await;
    let node_id = server.create_node(&owner_token, "EmojiDelNfNode").await;
    let fake_emoji_id = Uuid::new_v4();

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/emojis/{}?token={}",
            server.base_url, node_id, fake_emoji_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_custom_emoji_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_del_frb_own").await;
    let (_, member_token) = server.register_and_auth("emoji_del_frb_mem").await;
    let node_id = server.create_node(&owner_token, "EmojiDelFrbNode").await;
    server.join_node(&member_token, node_id).await;

    let emoji_body = server
        .upload_emoji(&owner_token, node_id, "frb_emoji")
        .await;
    let emoji_id = emoji_body["id"].as_str().unwrap();

    // member did not upload and has no ManageEmojis permission → 403
    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/emojis/{}?token={}",
            server.base_url, node_id, emoji_id, member_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_delete_custom_emoji_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_del_unauth").await;
    let node_id = server.create_node(&owner_token, "EmojiDelUnauthNode").await;
    let emoji_body = server
        .upload_emoji(&owner_token, node_id, "unauth_emoji")
        .await;
    let emoji_id = emoji_body["id"].as_str().unwrap();

    let resp = server
        .client
        .delete(&format!(
            "{}/nodes/{}/emojis/{}",
            server.base_url, node_id, emoji_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ═══════════════════════════════════════════════════════════════
//  7. Emoji Image (GET /api/emojis/:content_hash)
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_get_emoji_image_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("emoji_img_own").await;
    let node_id = server.create_node(&owner_token, "EmojiImgNode").await;

    let emoji_body = server
        .upload_emoji(&owner_token, node_id, "img_emoji")
        .await;
    let content_hash = emoji_body["content_hash"].as_str().unwrap();

    let resp = server
        .client
        .get(&format!("{}/api/emojis/{}", server.base_url, content_hash))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("image/"),
        "Expected image content-type, got: {}",
        ct
    );
}

#[tokio::test]
async fn test_get_emoji_image_not_found() {
    let server = TestServer::new().await;
    // Valid hex hash that doesn't exist on disk
    let fake_hash = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";

    let resp = server
        .client
        .get(&format!("{}/api/emojis/{}", server.base_url, fake_hash))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_emoji_image_invalid_hash() {
    let server = TestServer::new().await;
    // Path traversal attempt / non-hex content
    let bad_hash = "../etc/passwd";

    let resp = server
        .client
        .get(&format!("{}/api/emojis/{}", server.base_url, bad_hash))
        .send()
        .await
        .unwrap();

    // Should be 400 (bad request) or 404 (path not matched)
    assert!(
        resp.status() == 400 || resp.status() == 404,
        "Expected 400 or 404, got {}",
        resp.status()
    );
}

// ═══════════════════════════════════════════════════════════════
//  8. User Avatar
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_upload_user_avatar_success() {
    let server = TestServer::new().await;
    let (user_id, token) = server.register_and_auth("avatar_up_user").await;

    let form = multipart::Form::new().part(
        "avatar",
        multipart::Part::bytes(minimal_png())
            .file_name("avatar.png")
            .mime_str("image/png")
            .unwrap(),
    );

    let resp = server
        .client
        .put(&format!(
            "{}/users/me/avatar?token={}",
            server.base_url, token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    assert!(body["avatar_hash"].is_string());
    let _ = user_id; // used above to disambiguate
}

#[tokio::test]
async fn test_upload_user_avatar_unauthorized() {
    let server = TestServer::new().await;

    let form = multipart::Form::new().part(
        "avatar",
        multipart::Part::bytes(minimal_png())
            .mime_str("image/png")
            .unwrap(),
    );

    let resp = server
        .client
        .put(&format!("{}/users/me/avatar", server.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_upload_user_avatar_missing_file() {
    let server = TestServer::new().await;
    let (_, token) = server.register_and_auth("avatar_miss_user").await;

    // Empty multipart — no avatar field
    let form = multipart::Form::new();

    let resp = server
        .client
        .put(&format!(
            "{}/users/me/avatar?token={}",
            server.base_url, token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_get_user_avatar_no_avatar_set() {
    let server = TestServer::new().await;
    let (user_id, _token) = server.register_and_auth("avatar_get_noset").await;

    // No avatar uploaded — expect 204 No Content
    let resp = server
        .client
        .get(&format!("{}/users/{}/avatar", server.base_url, user_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_get_user_avatar_after_upload() {
    let server = TestServer::new().await;
    let (user_id, token) = server.register_and_auth("avatar_get_after").await;

    let form = multipart::Form::new().part(
        "avatar",
        multipart::Part::bytes(minimal_png())
            .file_name("avatar.png")
            .mime_str("image/png")
            .unwrap(),
    );

    let resp = server
        .client
        .put(&format!(
            "{}/users/me/avatar?token={}",
            server.base_url, token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = server
        .client
        .get(&format!("{}/users/{}/avatar", server.base_url, user_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("image/"),
        "Expected image content-type after upload, got: {}",
        ct
    );
}

// ═══════════════════════════════════════════════════════════════
//  9. Node Icon
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_upload_node_icon_success() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("icon_up_own").await;
    let node_id = server.create_node(&owner_token, "IconUpNode").await;

    let form = multipart::Form::new().part(
        "icon",
        multipart::Part::bytes(minimal_png())
            .file_name("icon.png")
            .mime_str("image/png")
            .unwrap(),
    );

    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/icon?token={}",
            server.base_url, node_id, owner_token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    assert!(body["icon_hash"].is_string());
}

#[tokio::test]
async fn test_upload_node_icon_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("icon_unauth_own").await;
    let node_id = server.create_node(&owner_token, "IconUnauthNode").await;

    let form = multipart::Form::new().part(
        "icon",
        multipart::Part::bytes(minimal_png())
            .mime_str("image/png")
            .unwrap(),
    );

    let resp = server
        .client
        .put(&format!("{}/nodes/{}/icon", server.base_url, node_id))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_upload_node_icon_forbidden_for_member() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("icon_frb_own").await;
    let (_, member_token) = server.register_and_auth("icon_frb_mem").await;
    let node_id = server.create_node(&owner_token, "IconFrbNode").await;
    server.join_node(&member_token, node_id).await;

    let form = multipart::Form::new().part(
        "icon",
        multipart::Part::bytes(minimal_png())
            .file_name("icon.png")
            .mime_str("image/png")
            .unwrap(),
    );

    let resp = server
        .client
        .put(&format!(
            "{}/nodes/{}/icon?token={}",
            server.base_url, node_id, member_token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_get_node_icon_not_set() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("icon_get_noset").await;
    let node_id = server.create_node(&owner_token, "IconGetNoSetNode").await;

    let resp = server
        .client
        .get(&format!("{}/nodes/{}/icon", server.base_url, node_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_node_icon_after_upload() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("icon_get_after").await;
    let node_id = server.create_node(&owner_token, "IconGetAfterNode").await;

    let form = multipart::Form::new().part(
        "icon",
        multipart::Part::bytes(minimal_png())
            .file_name("icon.png")
            .mime_str("image/png")
            .unwrap(),
    );

    server
        .client
        .put(&format!(
            "{}/nodes/{}/icon?token={}",
            server.base_url, node_id, owner_token
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(&format!("{}/nodes/{}/icon", server.base_url, node_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("image/"),
        "Expected image content-type, got: {}",
        ct
    );
}

// ═══════════════════════════════════════════════════════════════
//  10. Search Messages
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_search_messages_success_empty_results() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("search_own").await;
    let node_id = server.create_node(&owner_token, "SearchNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?token={}&q=hello",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["results"].is_array());
    assert!(body["total_count"].is_number());
    assert!(body["search_query"].is_string());
}

#[tokio::test]
async fn test_search_messages_missing_q_param() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("search_noq").await;
    let node_id = server.create_node(&owner_token, "SearchNoQNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?token={}",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_search_messages_empty_query() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("search_empty_q").await;
    let node_id = server.create_node(&owner_token, "SearchEmptyQNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?token={}&q=",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_search_messages_unauthorized() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("search_unauth_own").await;
    let node_id = server.create_node(&owner_token, "SearchUnauthNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?q=hello",
            server.base_url, node_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_search_messages_non_member_forbidden() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("search_frb_own").await;
    let (_, stranger_token) = server.register_and_auth("search_frb_str").await;
    let node_id = server.create_node(&owner_token, "SearchFrbNode").await;

    // stranger is not a member of the node
    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?token={}&q=hello",
            server.base_url, node_id, stranger_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_search_messages_with_channel_filter() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("search_ch_filter").await;
    let node_id = server.create_node(&owner_token, "SearchChFilterNode").await;
    let channel_id = server
        .create_channel(&owner_token, node_id, "filter-ch")
        .await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?token={}&q=test&channel={}",
            server.base_url, node_id, owner_token, channel_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["results"].is_array());
}

#[tokio::test]
async fn test_search_messages_with_limit() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("search_limit").await;
    let node_id = server.create_node(&owner_token, "SearchLimitNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?token={}&q=hello&limit=5",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["results"].is_array());
    // With no messages, results should be empty but request succeeds
    assert_eq!(body["total_count"], 0);
}

#[tokio::test]
async fn test_search_messages_response_includes_note() {
    let server = TestServer::new().await;
    let (_, owner_token) = server.register_and_auth("search_note").await;
    let node_id = server.create_node(&owner_token, "SearchNoteNode").await;

    let resp = server
        .client
        .get(&format!(
            "{}/nodes/{}/search?token={}&q=test",
            server.base_url, node_id, owner_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Response should include a 'note' about E2E encryption
    assert!(
        body["note"].is_string(),
        "Expected 'note' field in search response"
    );
}
