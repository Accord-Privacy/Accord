//! Integration tests for admin handlers.
//!
//! Tests admin_page_handler, admin_stats_handler, admin_users_handler,
//! admin_nodes_handler, admin_build_allowlist_*_handler,
//! admin_audit_log_handler, and admin_audit_log_actions_handler.
#![allow(clippy::all, unused_imports, dead_code)]

use axum::{
    routing::{delete, get, post, put},
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

use accord_server::{
    admin::{
        admin_audit_log_actions_handler, admin_audit_log_handler,
        admin_build_allowlist_add_handler, admin_build_allowlist_get_handler,
        admin_build_allowlist_remove_handler, admin_build_allowlist_set_handler,
        admin_nodes_handler, admin_page_handler, admin_stats_handler, admin_users_handler,
    },
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
            // Admin dashboard page (no auth)
            .route("/admin", get(admin_page_handler))
            // Admin JSON endpoints (X-Admin-Token required)
            .route("/admin/stats", get(admin_stats_handler))
            .route("/admin/users", get(admin_users_handler))
            .route("/admin/nodes", get(admin_nodes_handler))
            // Build allowlist
            .route(
                "/api/admin/build-allowlist",
                get(admin_build_allowlist_get_handler)
                    .put(admin_build_allowlist_set_handler)
                    .post(admin_build_allowlist_add_handler),
            )
            .route(
                "/api/admin/build-allowlist/:hash",
                delete(admin_build_allowlist_remove_handler),
            )
            // Audit log
            .route("/api/admin/audit-log", get(admin_audit_log_handler))
            .route(
                "/api/admin/audit-log/actions",
                get(admin_audit_log_actions_handler),
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

    /// Send a GET with X-Admin-Token header.
    async fn get_admin(&self, path: &str, token: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .header("X-Admin-Token", token)
            .send()
            .await
            .unwrap()
    }

    /// Send a GET with no admin token.
    async fn get_no_auth(&self, path: &str) -> reqwest::Response {
        self.client.get(self.url(path)).send().await.unwrap()
    }

    /// Send a PUT with X-Admin-Token header and JSON body.
    async fn put_admin(&self, path: &str, token: &str, body: Value) -> reqwest::Response {
        self.client
            .put(self.url(path))
            .header("X-Admin-Token", token)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// Send a POST with X-Admin-Token header and JSON body.
    async fn post_admin(&self, path: &str, token: &str, body: Value) -> reqwest::Response {
        self.client
            .post(self.url(path))
            .header("X-Admin-Token", token)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// Send a DELETE with X-Admin-Token header.
    async fn delete_admin(&self, path: &str, token: &str) -> reqwest::Response {
        self.client
            .delete(self.url(path))
            .header("X-Admin-Token", token)
            .send()
            .await
            .unwrap()
    }
}

// ─────────────────────────────────────────────────
//  Env-var management
//  Tests set ACCORD_ADMIN_TOKEN via std::env::set_var.
//  We use a static mutex to prevent races between parallel tests.
// ─────────────────────────────────────────────────

static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set ACCORD_ADMIN_TOKEN for the duration of one test.
/// Returns a guard that restores the old value on drop.
fn with_admin_token(token: &str) -> impl Drop + '_ {
    struct Guard {
        prev: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var("ACCORD_ADMIN_TOKEN", v) },
                None => unsafe { std::env::remove_var("ACCORD_ADMIN_TOKEN") },
            }
        }
    }
    let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("ACCORD_ADMIN_TOKEN").ok();
    unsafe { std::env::set_var("ACCORD_ADMIN_TOKEN", token) };
    Guard { prev, _lock: lock }
}

// ═══════════════════════════════════════════════════════════════
//  1. admin_page_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_admin_page_returns_200() {
    let _g = with_admin_token("secret");
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_admin_page_content_type_is_html() {
    let _g = with_admin_token("secret");
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/admin"))
        .send()
        .await
        .unwrap();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/html"), "expected text/html, got: {ct}");
}

#[tokio::test]
async fn test_admin_page_body_contains_accord_admin() {
    let _g = with_admin_token("secret");
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/admin"))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("Accord Admin"),
        "expected 'Accord Admin' in body"
    );
}

#[tokio::test]
async fn test_admin_page_no_auth_required() {
    // The HTML page itself doesn't require the token at the HTTP level —
    // it prompts in the browser JS.
    let _g = with_admin_token("secret");
    let server = TestServer::new().await;

    // Even without the token header, the HTML page should serve.
    let resp = server.get_no_auth("/admin").await;
    assert_eq!(resp.status(), 200);
}

// ═══════════════════════════════════════════════════════════════
//  2. admin_stats_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_stats_success_with_valid_token() {
    let _g = with_admin_token("tok-stats");
    let server = TestServer::new().await;

    let resp = server.get_admin("/admin/stats", "tok-stats").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["user_count"].is_number());
    assert!(body["node_count"].is_number());
    assert!(body["message_count"].is_number());
    assert!(body["connection_count"].is_number());
    assert!(body["uptime_seconds"].is_number());
    assert!(body["version"].is_string());
    assert!(body["memory_bytes"].is_number());
}

#[tokio::test]
async fn test_stats_unauthorized_no_token() {
    let _g = with_admin_token("tok-stats");
    let server = TestServer::new().await;

    let resp = server.get_no_auth("/admin/stats").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_stats_unauthorized_wrong_token() {
    let _g = with_admin_token("tok-stats");
    let server = TestServer::new().await;

    let resp = server.get_admin("/admin/stats", "wrong-token").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_stats_error_body_has_error_field() {
    let _g = with_admin_token("tok-stats");
    let server = TestServer::new().await;

    let resp = server.get_no_auth("/admin/stats").await;
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].is_string(),
        "Expected error field in 401 body"
    );
}

#[tokio::test]
async fn test_stats_version_matches_cargo_pkg() {
    let _g = with_admin_token("tok-stats");
    let server = TestServer::new().await;

    let resp = server.get_admin("/admin/stats", "tok-stats").await;
    let body: Value = resp.json().await.unwrap();
    let version = body["version"].as_str().unwrap();
    // Just verify it's a non-empty semver-like string
    assert!(!version.is_empty());
    assert!(
        version.contains('.'),
        "version '{}' should look like x.y.z",
        version
    );
}

// ═══════════════════════════════════════════════════════════════
//  3. admin_users_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_users_success_with_valid_token() {
    let _g = with_admin_token("tok-users");
    let server = TestServer::new().await;

    let resp = server.get_admin("/admin/users", "tok-users").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["users"].is_array());
}

#[tokio::test]
async fn test_users_unauthorized_no_token() {
    let _g = with_admin_token("tok-users");
    let server = TestServer::new().await;

    let resp = server.get_no_auth("/admin/users").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_users_unauthorized_wrong_token() {
    let _g = with_admin_token("tok-users");
    let server = TestServer::new().await;

    let resp = server.get_admin("/admin/users", "not-the-token").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_users_fresh_db_has_system_user() {
    let _g = with_admin_token("tok-users");
    let server = TestServer::new().await;

    let resp = server.get_admin("/admin/users", "tok-users").await;
    let body: Value = resp.json().await.unwrap();
    let users = body["users"].as_array().unwrap();
    // A fresh DB has the system sentinel user created on init
    assert_eq!(users.len(), 1, "expected exactly 1 system user on fresh DB");
}

// ═══════════════════════════════════════════════════════════════
//  4. admin_nodes_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_nodes_success_with_valid_token() {
    let _g = with_admin_token("tok-nodes");
    let server = TestServer::new().await;

    let resp = server.get_admin("/admin/nodes", "tok-nodes").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["nodes"].is_array());
}

#[tokio::test]
async fn test_nodes_unauthorized_no_token() {
    let _g = with_admin_token("tok-nodes");
    let server = TestServer::new().await;

    let resp = server.get_no_auth("/admin/nodes").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_nodes_unauthorized_wrong_token() {
    let _g = with_admin_token("tok-nodes");
    let server = TestServer::new().await;

    let resp = server.get_admin("/admin/nodes", "bad-tok").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_nodes_fresh_db_has_system_node() {
    let _g = with_admin_token("tok-nodes");
    let server = TestServer::new().await;

    let resp = server.get_admin("/admin/nodes", "tok-nodes").await;
    let body: Value = resp.json().await.unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    // A fresh DB has the system DM node created on init
    assert_eq!(
        nodes.len(),
        1,
        "expected exactly 1 system DM node on fresh DB"
    );
}

// ═══════════════════════════════════════════════════════════════
//  5. admin_build_allowlist_get_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_build_allowlist_get_success() {
    let _g = with_admin_token("tok-allow");
    let server = TestServer::new().await;

    let resp = server
        .get_admin("/api/admin/build-allowlist", "tok-allow")
        .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["allowlist"].is_array());
    assert!(body["enforcement"].is_string());
}

#[tokio::test]
async fn test_build_allowlist_get_no_auth() {
    let _g = with_admin_token("tok-allow");
    let server = TestServer::new().await;

    let resp = server.get_no_auth("/api/admin/build-allowlist").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_build_allowlist_get_wrong_token() {
    let _g = with_admin_token("tok-allow");
    let server = TestServer::new().await;

    let resp = server
        .get_admin("/api/admin/build-allowlist", "wrong")
        .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_build_allowlist_get_empty_on_fresh_db() {
    let _g = with_admin_token("tok-allow");
    let server = TestServer::new().await;

    let resp = server
        .get_admin("/api/admin/build-allowlist", "tok-allow")
        .await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["allowlist"].as_array().unwrap().len(),
        0,
        "fresh DB should have empty allowlist"
    );
}

// ═══════════════════════════════════════════════════════════════
//  6. admin_build_allowlist_add_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_build_allowlist_add_success() {
    let _g = with_admin_token("tok-add");
    let server = TestServer::new().await;

    let resp = server
        .post_admin(
            "/api/admin/build-allowlist",
            "tok-add",
            json!({ "build_hash": "abc123", "label": "v1.0.0" }),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "added");
    assert_eq!(body["build_hash"], "abc123");
}

#[tokio::test]
async fn test_build_allowlist_add_no_auth() {
    let _g = with_admin_token("tok-add");
    let server = TestServer::new().await;

    let resp = server
        .client
        .post(server.url("/api/admin/build-allowlist"))
        .json(&json!({ "build_hash": "abc123", "label": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_build_allowlist_add_wrong_token() {
    let _g = with_admin_token("tok-add");
    let server = TestServer::new().await;

    let resp = server
        .post_admin(
            "/api/admin/build-allowlist",
            "bad-tok",
            json!({ "build_hash": "abc123", "label": null }),
        )
        .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_build_allowlist_add_without_label() {
    let _g = with_admin_token("tok-add");
    let server = TestServer::new().await;

    let resp = server
        .post_admin(
            "/api/admin/build-allowlist",
            "tok-add",
            json!({ "build_hash": "nolabel999", "label": null }),
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "added");
}

#[tokio::test]
async fn test_build_allowlist_add_duplicate_returns_already_exists() {
    let _g = with_admin_token("tok-add");
    let server = TestServer::new().await;

    let payload = json!({ "build_hash": "dupehash", "label": "dup" });

    // First add
    server
        .post_admin("/api/admin/build-allowlist", "tok-add", payload.clone())
        .await;

    // Second add — should be already_exists
    let resp = server
        .post_admin("/api/admin/build-allowlist", "tok-add", payload)
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["status"],
        "already_exists"
    );
}

#[tokio::test]
async fn test_build_allowlist_add_then_get_shows_entry() {
    let _g = with_admin_token("tok-add");
    let server = TestServer::new().await;

    server
        .post_admin(
            "/api/admin/build-allowlist",
            "tok-add",
            json!({ "build_hash": "showme", "label": "visible" }),
        )
        .await;

    let resp = server
        .get_admin("/api/admin/build-allowlist", "tok-add")
        .await;
    let body: Value = resp.json().await.unwrap();
    let list = body["allowlist"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["build_hash"], "showme");
}

// ═══════════════════════════════════════════════════════════════
//  7. admin_build_allowlist_set_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_build_allowlist_set_success() {
    let _g = with_admin_token("tok-set");
    let server = TestServer::new().await;

    let resp = server
        .put_admin(
            "/api/admin/build-allowlist",
            "tok-set",
            json!([
                { "build_hash": "h1", "label": "build-1" },
                { "build_hash": "h2", "label": null }
            ]),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    assert_eq!(body["count"], 2);
}

#[tokio::test]
async fn test_build_allowlist_set_no_auth() {
    let _g = with_admin_token("tok-set");
    let server = TestServer::new().await;

    let resp = server
        .client
        .put(server.url("/api/admin/build-allowlist"))
        .json(&json!([]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_build_allowlist_set_wrong_token() {
    let _g = with_admin_token("tok-set");
    let server = TestServer::new().await;

    let resp = server
        .put_admin("/api/admin/build-allowlist", "wrong", json!([]))
        .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_build_allowlist_set_empty_clears_list() {
    let _g = with_admin_token("tok-set");
    let server = TestServer::new().await;

    // Add something first
    server
        .post_admin(
            "/api/admin/build-allowlist",
            "tok-set",
            json!({ "build_hash": "old1", "label": null }),
        )
        .await;

    // Now set to empty
    let resp = server
        .put_admin("/api/admin/build-allowlist", "tok-set", json!([]))
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["count"], 0);

    // Verify list is empty
    let body: Value = server
        .get_admin("/api/admin/build-allowlist", "tok-set")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["allowlist"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_build_allowlist_set_replaces_existing_entries() {
    let _g = with_admin_token("tok-set");
    let server = TestServer::new().await;

    // Add initial entry
    server
        .post_admin(
            "/api/admin/build-allowlist",
            "tok-set",
            json!({ "build_hash": "old-hash", "label": "old" }),
        )
        .await;

    // Replace with new entries
    server
        .put_admin(
            "/api/admin/build-allowlist",
            "tok-set",
            json!([{ "build_hash": "new-hash", "label": "new" }]),
        )
        .await;

    let body: Value = server
        .get_admin("/api/admin/build-allowlist", "tok-set")
        .await
        .json()
        .await
        .unwrap();
    let list = body["allowlist"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["build_hash"], "new-hash");
}

// ═══════════════════════════════════════════════════════════════
//  8. admin_build_allowlist_remove_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_build_allowlist_remove_success() {
    let _g = with_admin_token("tok-rm");
    let server = TestServer::new().await;

    // Add it first
    server
        .post_admin(
            "/api/admin/build-allowlist",
            "tok-rm",
            json!({ "build_hash": "todelete", "label": null }),
        )
        .await;

    let resp = server
        .delete_admin("/api/admin/build-allowlist/todelete", "tok-rm")
        .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "removed");
    assert_eq!(body["build_hash"], "todelete");
}

#[tokio::test]
async fn test_build_allowlist_remove_no_auth() {
    let _g = with_admin_token("tok-rm");
    let server = TestServer::new().await;

    let resp = server
        .client
        .delete(server.url("/api/admin/build-allowlist/somehash"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_build_allowlist_remove_wrong_token() {
    let _g = with_admin_token("tok-rm");
    let server = TestServer::new().await;

    let resp = server
        .delete_admin("/api/admin/build-allowlist/somehash", "wrong")
        .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_build_allowlist_remove_not_found() {
    let _g = with_admin_token("tok-rm");
    let server = TestServer::new().await;

    let resp = server
        .delete_admin("/api/admin/build-allowlist/doesnotexist", "tok-rm")
        .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_build_allowlist_remove_then_gone_from_get() {
    let _g = with_admin_token("tok-rm");
    let server = TestServer::new().await;

    // Add then remove
    server
        .post_admin(
            "/api/admin/build-allowlist",
            "tok-rm",
            json!({ "build_hash": "ephemeral", "label": null }),
        )
        .await;
    server
        .delete_admin("/api/admin/build-allowlist/ephemeral", "tok-rm")
        .await;

    // Verify it's gone
    let body: Value = server
        .get_admin("/api/admin/build-allowlist", "tok-rm")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["allowlist"].as_array().unwrap().len(), 0);
}

// ═══════════════════════════════════════════════════════════════
//  9. admin_audit_log_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_audit_log_success_with_valid_token() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    let resp = server.get_admin("/api/admin/audit-log", "tok-audit").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["entries"].is_array());
    assert!(body["total"].is_number());
    assert!(body["page"].is_number());
    assert!(body["per_page"].is_number());
    assert!(body["total_pages"].is_number());
}

#[tokio::test]
async fn test_audit_log_no_auth() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    let resp = server.get_no_auth("/api/admin/audit-log").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_audit_log_wrong_token() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    let resp = server.get_admin("/api/admin/audit-log", "wrong-tok").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_audit_log_defaults_page_1_per_page_25() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    let resp = server.get_admin("/api/admin/audit-log", "tok-audit").await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["page"], 1);
    assert_eq!(body["per_page"], 25);
}

#[tokio::test]
async fn test_audit_log_custom_page_and_per_page() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/api/admin/audit-log?page=2&per_page=10"))
        .header("X-Admin-Token", "tok-audit")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["page"], 2);
    assert_eq!(body["per_page"], 10);
}

#[tokio::test]
async fn test_audit_log_per_page_capped_at_100() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/api/admin/audit-log?per_page=999"))
        .header("X-Admin-Token", "tok-audit")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["per_page"], 100);
}

#[tokio::test]
async fn test_audit_log_page_zero_clamped_to_1() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/api/admin/audit-log?page=0"))
        .header("X-Admin-Token", "tok-audit")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["page"], 1);
}

#[tokio::test]
async fn test_audit_log_with_action_filter() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    // Filter with a specific action — may return 0 entries on fresh DB but should not error
    let resp = server
        .client
        .get(server.url("/api/admin/audit-log?action=user_registered"))
        .header("X-Admin-Token", "tok-audit")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["entries"].is_array());
}

#[tokio::test]
async fn test_audit_log_with_time_range_filter() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    // Use a time range far in the past — 0 entries expected but no error
    let resp = server
        .client
        .get(server.url("/api/admin/audit-log?start=0&end=1000"))
        .header("X-Admin-Token", "tok-audit")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["entries"].is_array());
    assert_eq!(body["entries"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_audit_log_invalid_page_treated_as_default() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    // Non-numeric page value — falls back to default (1)
    let resp = server
        .client
        .get(server.url("/api/admin/audit-log?page=notanumber"))
        .header("X-Admin-Token", "tok-audit")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["page"], 1);
}

#[tokio::test]
async fn test_audit_log_empty_action_filter_returns_all() {
    let _g = with_admin_token("tok-audit");
    let server = TestServer::new().await;

    // Empty action filter = no filter applied
    let resp_all = server.get_admin("/api/admin/audit-log", "tok-audit").await;
    let resp_empty_filter = server
        .client
        .get(server.url("/api/admin/audit-log?action="))
        .header("X-Admin-Token", "tok-audit")
        .send()
        .await
        .unwrap();

    let all: Value = resp_all.json().await.unwrap();
    let filtered: Value = resp_empty_filter.json().await.unwrap();
    assert_eq!(all["total"], filtered["total"]);
}

// ═══════════════════════════════════════════════════════════════
//  10. admin_audit_log_actions_handler
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_audit_log_actions_success_with_valid_token() {
    let _g = with_admin_token("tok-actions");
    let server = TestServer::new().await;

    let resp = server
        .get_admin("/api/admin/audit-log/actions", "tok-actions")
        .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["actions"].is_array());
}

#[tokio::test]
async fn test_audit_log_actions_no_auth() {
    let _g = with_admin_token("tok-actions");
    let server = TestServer::new().await;

    let resp = server.get_no_auth("/api/admin/audit-log/actions").await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_audit_log_actions_wrong_token() {
    let _g = with_admin_token("tok-actions");
    let server = TestServer::new().await;

    let resp = server
        .get_admin("/api/admin/audit-log/actions", "bad-tok")
        .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_audit_log_actions_returns_array_on_empty_db() {
    let _g = with_admin_token("tok-actions");
    let server = TestServer::new().await;

    let resp = server
        .get_admin("/api/admin/audit-log/actions", "tok-actions")
        .await;
    let body: Value = resp.json().await.unwrap();
    // Empty DB may have zero or some actions; either way it must be an array
    assert!(body["actions"].is_array());
}

// ═══════════════════════════════════════════════════════════════
//  11. Token edge cases (no env var set, empty env var)
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_stats_no_env_var_always_401() {
    // When ACCORD_ADMIN_TOKEN is unset, all requests should be rejected —
    // even with a non-empty header value.
    {
        // Scope ensures guard is dropped and env is restored before test ends.
        struct Guard {
            prev: Option<String>,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                match &self.prev {
                    Some(v) => unsafe { std::env::set_var("ACCORD_ADMIN_TOKEN", v) },
                    None => unsafe { std::env::remove_var("ACCORD_ADMIN_TOKEN") },
                }
            }
        }
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("ACCORD_ADMIN_TOKEN").ok();
        unsafe { std::env::remove_var("ACCORD_ADMIN_TOKEN") };
        let guard = Guard { prev };

        let server = TestServer::new().await;
        let resp = server.get_admin("/admin/stats", "anything").await;
        assert_eq!(
            resp.status(),
            401,
            "admin endpoint must reject when ACCORD_ADMIN_TOKEN is unset"
        );
        drop(guard);
    }
}

#[tokio::test]
async fn test_header_token_must_not_use_query_param() {
    // The admin token is only valid via X-Admin-Token header, NOT query param.
    let _g = with_admin_token("header-only-secret");
    let server = TestServer::new().await;

    // Pass token as query param — should be rejected
    let resp = server
        .client
        .get(server.url("/admin/stats?admin_token=header-only-secret"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "query param token must not be accepted for non-WS endpoints"
    );
}

// ═══════════════════════════════════════════════════════════════
//  12. Multiple allowlist entries (set + get round-trip)
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_build_allowlist_round_trip_multiple_entries() {
    let _g = with_admin_token("tok-rt");
    let server = TestServer::new().await;

    let entries = json!([
        { "build_hash": "aaa", "label": "build-aaa" },
        { "build_hash": "bbb", "label": null },
        { "build_hash": "ccc", "label": "build-ccc" }
    ]);

    let set_resp = server
        .put_admin("/api/admin/build-allowlist", "tok-rt", entries)
        .await;
    assert_eq!(set_resp.status(), 200);
    assert_eq!(set_resp.json::<Value>().await.unwrap()["count"], 3);

    let get_resp = server
        .get_admin("/api/admin/build-allowlist", "tok-rt")
        .await;
    let body: Value = get_resp.json().await.unwrap();
    let list = body["allowlist"].as_array().unwrap();
    assert_eq!(list.len(), 3);

    let hashes: Vec<&str> = list
        .iter()
        .filter_map(|e| e["build_hash"].as_str())
        .collect();
    assert!(hashes.contains(&"aaa"));
    assert!(hashes.contains(&"bbb"));
    assert!(hashes.contains(&"ccc"));
}

// ═══════════════════════════════════════════════════════════════
//  13. Audit log total_pages calculation
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_audit_log_total_pages_is_consistent() {
    let _g = with_admin_token("tok-tp");
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/api/admin/audit-log?per_page=25"))
        .header("X-Admin-Token", "tok-tp")
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();

    let total = body["total"].as_u64().unwrap_or(0);
    let per_page = body["per_page"].as_u64().unwrap_or(25);
    let total_pages = body["total_pages"].as_u64().unwrap_or(0);

    let expected_pages = if total == 0 {
        0
    } else {
        (total + per_page - 1) / per_page
    };
    assert_eq!(total_pages, expected_pages);
}
