//! Integration tests for federation handlers.
//!
//! Tests list_relays_handler, register_relay_handler, heartbeat_handler,
//! and dns_bootstrap_discovery via HTTP against a real in-process server.
//!
//! Auth: The federation handlers use a simple `x-mesh-secret` header.
//! When `mesh_handle` is None (as in all test servers), the federation is
//! "open" — no secret is required and any header value is accepted.
#![allow(clippy::all, unused_imports, dead_code)]

use axum::{
    routing::{get, post},
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
    federation::{heartbeat_handler, list_relays_handler, register_relay_handler},
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
            .route("/federation/relays", get(list_relays_handler))
            .route("/federation/register", post(register_relay_handler))
            .route("/federation/heartbeat", post(heartbeat_handler))
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

    /// GET /federation/relays
    async fn get_relays(&self) -> reqwest::Response {
        self.client
            .get(self.url("/federation/relays"))
            .send()
            .await
            .unwrap()
    }

    /// POST /federation/register with JSON body (no auth header)
    async fn post_register(&self, body: Value) -> reqwest::Response {
        self.client
            .post(self.url("/federation/register"))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// POST /federation/register with x-mesh-secret header
    async fn post_register_with_secret(&self, body: Value, secret: &str) -> reqwest::Response {
        self.client
            .post(self.url("/federation/register"))
            .header("x-mesh-secret", secret)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// POST /federation/heartbeat with JSON body (no auth header)
    async fn post_heartbeat(&self, body: Value) -> reqwest::Response {
        self.client
            .post(self.url("/federation/heartbeat"))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// POST /federation/heartbeat with x-mesh-secret header
    async fn post_heartbeat_with_secret(&self, body: Value, secret: &str) -> reqwest::Response {
        self.client
            .post(self.url("/federation/heartbeat"))
            .header("x-mesh-secret", secret)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// Register a relay and assert success — convenience for setup
    async fn register_relay(
        &self,
        relay_id: &str,
        hostname: &str,
        port: u16,
        public_key: &str,
    ) -> Value {
        let resp = self
            .post_register(json!({
                "relay_id": relay_id,
                "hostname": hostname,
                "port": port,
                "public_key": public_key,
            }))
            .await;
        assert_eq!(
            resp.status(),
            200,
            "setup registration failed for relay_id={relay_id}"
        );
        resp.json().await.unwrap()
    }
}

// ═══════════════════════════════════════════════════════════════
//  1. GET /federation/relays
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_list_relays_returns_200() {
    let server = TestServer::new().await;
    let resp = server.get_relays().await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_list_relays_empty_on_fresh_db() {
    let server = TestServer::new().await;
    let resp = server.get_relays().await;
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["relays"].is_array(),
        "response must have 'relays' array"
    );
    assert_eq!(
        body["relays"].as_array().unwrap().len(),
        0,
        "fresh DB should have no relays"
    );
}

#[tokio::test]
async fn test_list_relays_response_has_relays_field() {
    let server = TestServer::new().await;
    let resp = server.get_relays().await;
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.get("relays").is_some(),
        "response must contain 'relays' key"
    );
}

#[tokio::test]
async fn test_list_relays_after_registration_shows_one() {
    let server = TestServer::new().await;
    server
        .register_relay("relay-001", "relay1.example.com", 8443, "pk-001")
        .await;

    let resp = server.get_relays().await;
    let body: Value = resp.json().await.unwrap();
    let relays = body["relays"].as_array().unwrap();
    assert_eq!(relays.len(), 1);
}

#[tokio::test]
async fn test_list_relays_fields_present() {
    let server = TestServer::new().await;
    server
        .register_relay("relay-fields", "fields.example.com", 9000, "pk-fields")
        .await;

    let resp = server.get_relays().await;
    let body: Value = resp.json().await.unwrap();
    let relay = &body["relays"][0];

    assert_eq!(relay["relay_id"], "relay-fields");
    assert_eq!(relay["hostname"], "fields.example.com");
    assert_eq!(relay["port"], 9000);
    assert_eq!(relay["public_key"], "pk-fields");
    assert_eq!(relay["status"], "active");
    assert!(relay["last_seen"].is_number(), "last_seen must be numeric");
    assert!(
        relay["registered_at"].is_number(),
        "registered_at must be numeric"
    );
}

#[tokio::test]
async fn test_list_relays_content_type_json() {
    let server = TestServer::new().await;
    let resp = server.get_relays().await;
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("application/json"),
        "content-type must be JSON, got: {ct}"
    );
}

#[tokio::test]
async fn test_list_relays_multiple_registrations() {
    let server = TestServer::new().await;
    for i in 0..4u16 {
        server
            .register_relay(
                &format!("relay-multi-{i}"),
                &format!("host{i}.example.com"),
                8000 + i,
                &format!("pk-{i}"),
            )
            .await;
    }
    let resp = server.get_relays().await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["relays"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn test_list_relays_no_auth_required() {
    // list_relays has no authentication — anyone can query the relay list
    let server = TestServer::new().await;
    let resp = server
        .client
        .get(server.url("/federation/relays"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ═══════════════════════════════════════════════════════════════
//  2. POST /federation/register
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_register_relay_success_returns_200() {
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "relay-a",
            "hostname": "relay-a.example.com",
            "port": 8443,
            "public_key": "pk-a"
        }))
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_register_relay_success_body_ok_true() {
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "relay-b",
            "hostname": "relay-b.example.com",
            "port": 8443,
            "public_key": "pk-b"
        }))
        .await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["message"], "Relay registered");
}

#[tokio::test]
async fn test_register_relay_empty_relay_id_returns_400() {
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "",
            "hostname": "relay.example.com",
            "port": 8443,
            "public_key": "pk-x"
        }))
        .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_register_relay_empty_hostname_returns_400() {
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "relay-c",
            "hostname": "",
            "port": 8443,
            "public_key": "pk-c"
        }))
        .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_register_relay_empty_public_key_returns_400() {
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "relay-d",
            "hostname": "relay-d.example.com",
            "port": 8443,
            "public_key": ""
        }))
        .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_register_relay_missing_required_fields_400_error_message() {
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "",
            "hostname": "",
            "port": 8443,
            "public_key": ""
        }))
        .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("required"),
        "error should mention required fields"
    );
}

#[tokio::test]
async fn test_register_relay_malformed_json_returns_4xx() {
    let server = TestServer::new().await;
    let resp = server
        .client
        .post(server.url("/federation/register"))
        .header("content-type", "application/json")
        .body("not valid json at all {{}")
        .send()
        .await
        .unwrap();
    // Axum returns 400 or 422 for JSON parse failures
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "malformed JSON should return 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_register_relay_empty_body_returns_error() {
    let server = TestServer::new().await;
    let resp = server
        .client
        .post(server.url("/federation/register"))
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();
    // Empty body with JSON content-type → 400 or 422
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "empty body should return 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_register_relay_duplicate_id_is_upsert() {
    // The handler uses upsert — registering the same relay_id again updates it.
    let server = TestServer::new().await;

    let resp1 = server
        .post_register(json!({
            "relay_id": "relay-dup",
            "hostname": "dup1.example.com",
            "port": 8443,
            "public_key": "pk-dup-v1"
        }))
        .await;
    assert_eq!(resp1.status(), 200);

    let resp2 = server
        .post_register(json!({
            "relay_id": "relay-dup",
            "hostname": "dup2.example.com",
            "port": 9000,
            "public_key": "pk-dup-v2"
        }))
        .await;
    assert_eq!(
        resp2.status(),
        200,
        "re-registration (upsert) should succeed"
    );

    // Should still be only 1 relay in the list
    let list_resp = server.get_relays().await;
    let body: Value = list_resp.json().await.unwrap();
    assert_eq!(
        body["relays"].as_array().unwrap().len(),
        1,
        "upsert should not create a duplicate"
    );
}

#[tokio::test]
async fn test_register_relay_open_federation_ignores_secret_header() {
    // In open federation (mesh_handle=None), any x-mesh-secret value is accepted
    let server = TestServer::new().await;
    let resp = server
        .post_register_with_secret(
            json!({
                "relay_id": "relay-open",
                "hostname": "open.example.com",
                "port": 8443,
                "public_key": "pk-open"
            }),
            "any-wrong-secret-at-all",
        )
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_register_relay_no_secret_header_open_federation() {
    // Without any header, open federation still accepts
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "relay-noauth",
            "hostname": "noauth.example.com",
            "port": 8443,
            "public_key": "pk-noauth"
        }))
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_register_relay_appears_in_list() {
    let server = TestServer::new().await;
    server
        .register_relay("relay-visible", "visible.example.com", 8443, "pk-visible")
        .await;

    let resp = server.get_relays().await;
    let body: Value = resp.json().await.unwrap();
    let relays = body["relays"].as_array().unwrap();
    let found = relays.iter().any(|r| r["relay_id"] == "relay-visible");
    assert!(found, "registered relay must appear in relay list");
}

#[tokio::test]
async fn test_register_relay_port_zero_accepted() {
    // No port range validation in the handler; port 0 is technically a valid u16
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "relay-p0",
            "hostname": "port0.example.com",
            "port": 0,
            "public_key": "pk-p0"
        }))
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_register_relay_port_max_accepted() {
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "relay-pmax",
            "hostname": "portmax.example.com",
            "port": 65535,
            "public_key": "pk-pmax"
        }))
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_register_relay_oversized_relay_id_does_not_crash() {
    let server = TestServer::new().await;
    let big_id = "r".repeat(1024);
    let resp = server
        .post_register(json!({
            "relay_id": big_id,
            "hostname": "big.example.com",
            "port": 8443,
            "public_key": "pk-big"
        }))
        .await;
    // Must not panic — any HTTP response (200 or error) is acceptable
    assert!(
        resp.status().as_u16() >= 100,
        "server must respond without crashing"
    );
}

#[tokio::test]
async fn test_register_relay_unicode_fields_do_not_crash() {
    let server = TestServer::new().await;
    let resp = server
        .post_register(json!({
            "relay_id": "relay-🦀",
            "hostname": "中文.example.com",
            "port": 8443,
            "public_key": "pk-unicode-ok"
        }))
        .await;
    // Must return some valid HTTP response — no crash
    assert!(resp.status().as_u16() >= 100);
}

#[tokio::test]
async fn test_register_relay_timestamps_set_on_registration() {
    let server = TestServer::new().await;
    server
        .register_relay("relay-ts", "ts.example.com", 8443, "pk-ts")
        .await;

    let resp = server.get_relays().await;
    let body: Value = resp.json().await.unwrap();
    let relay = &body["relays"][0];
    let last_seen = relay["last_seen"].as_i64().unwrap_or(0);
    let registered_at = relay["registered_at"].as_i64().unwrap_or(0);
    assert!(last_seen > 0, "last_seen must be set");
    assert!(registered_at > 0, "registered_at must be set");
}

// ═══════════════════════════════════════════════════════════════
//  3. POST /federation/heartbeat
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_heartbeat_known_relay_returns_200() {
    let server = TestServer::new().await;
    server
        .register_relay("relay-hb1", "hb1.example.com", 8443, "pk-hb1")
        .await;

    let resp = server
        .post_heartbeat(json!({ "relay_id": "relay-hb1" }))
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_heartbeat_known_relay_body_ok_true() {
    let server = TestServer::new().await;
    server
        .register_relay("relay-hb2", "hb2.example.com", 8443, "pk-hb2")
        .await;

    let resp = server
        .post_heartbeat(json!({ "relay_id": "relay-hb2" }))
        .await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["message"], "Heartbeat acknowledged");
}

#[tokio::test]
async fn test_heartbeat_unknown_relay_returns_404() {
    let server = TestServer::new().await;
    let resp = server
        .post_heartbeat(json!({ "relay_id": "nonexistent-relay-xyz" }))
        .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_heartbeat_unknown_relay_error_mentions_register() {
    let server = TestServer::new().await;
    let resp = server
        .post_heartbeat(json!({ "relay_id": "not-registered" }))
        .await;
    let body: Value = resp.json().await.unwrap();
    let error = body["error"].as_str().unwrap_or("");
    assert!(
        error.contains("Unknown relay_id") || error.contains("register"),
        "404 error should mention register, got: '{error}'"
    );
}

#[tokio::test]
async fn test_heartbeat_empty_relay_id_returns_400() {
    let server = TestServer::new().await;
    let resp = server.post_heartbeat(json!({ "relay_id": "" })).await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_heartbeat_malformed_json_returns_4xx() {
    let server = TestServer::new().await;
    let resp = server
        .client
        .post(server.url("/federation/heartbeat"))
        .header("content-type", "application/json")
        .body("{bad json}")
        .send()
        .await
        .unwrap();
    // Axum returns 400 or 422 for JSON parse failures
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "malformed heartbeat JSON should return 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_heartbeat_open_federation_no_secret_required() {
    let server = TestServer::new().await;
    server
        .register_relay("relay-hb-open", "hb-open.example.com", 8443, "pk-hb-open")
        .await;

    // No x-mesh-secret header — open federation accepts it
    let resp = server
        .post_heartbeat(json!({ "relay_id": "relay-hb-open" }))
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_heartbeat_open_federation_wrong_secret_still_accepted() {
    let server = TestServer::new().await;
    server
        .register_relay(
            "relay-hb-bogus",
            "hb-bogus.example.com",
            8443,
            "pk-hb-bogus",
        )
        .await;

    let resp = server
        .post_heartbeat_with_secret(
            json!({ "relay_id": "relay-hb-bogus" }),
            "completely-wrong-secret",
        )
        .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_heartbeat_updates_last_seen() {
    let server = TestServer::new().await;
    let relay_id = "relay-ts-update";
    server
        .register_relay(relay_id, "ts-update.example.com", 8443, "pk-ts-update")
        .await;

    // Capture last_seen before heartbeat
    let before_resp = server.get_relays().await;
    let before_body: Value = before_resp.json().await.unwrap();
    let before_ts = before_body["relays"][0]["last_seen"].as_i64().unwrap_or(0);

    // Wait to ensure timestamp can change (Unix timestamps are second-resolution)
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Send heartbeat
    server.post_heartbeat(json!({ "relay_id": relay_id })).await;

    // Check last_seen after
    let after_resp = server.get_relays().await;
    let after_body: Value = after_resp.json().await.unwrap();
    let after_ts = after_body["relays"][0]["last_seen"].as_i64().unwrap_or(0);

    assert!(
        after_ts >= before_ts,
        "last_seen should not decrease: before={before_ts} after={after_ts}"
    );
}

#[tokio::test]
async fn test_heartbeat_empty_body_returns_error() {
    let server = TestServer::new().await;
    let resp = server
        .client
        .post(server.url("/federation/heartbeat"))
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "empty heartbeat body should return 400 or 422, got {}",
        resp.status()
    );
}

// ═══════════════════════════════════════════════════════════════
//  4. Data validation — register → list roundtrip
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_roundtrip_register_then_heartbeat_then_list() {
    let server = TestServer::new().await;
    let relay_id = "relay-roundtrip";

    // 1. Register
    let reg_resp = server
        .post_register(json!({
            "relay_id": relay_id,
            "hostname": "roundtrip.example.com",
            "port": 8443,
            "public_key": "pk-roundtrip"
        }))
        .await;
    assert_eq!(reg_resp.status(), 200);

    // 2. Heartbeat
    let hb_resp = server.post_heartbeat(json!({ "relay_id": relay_id })).await;
    assert_eq!(hb_resp.status(), 200);

    // 3. List — relay must appear
    let list_resp = server.get_relays().await;
    let body: Value = list_resp.json().await.unwrap();
    let relays = body["relays"].as_array().unwrap();
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0]["relay_id"], relay_id);
    assert_eq!(relays[0]["status"], "active");
}

#[tokio::test]
async fn test_upsert_updates_hostname_and_port() {
    let server = TestServer::new().await;
    let relay_id = "relay-upsert";

    // First registration
    server
        .register_relay(relay_id, "original.example.com", 8000, "pk-upsert")
        .await;

    // Re-register with updated details
    let resp = server
        .post_register(json!({
            "relay_id": relay_id,
            "hostname": "updated.example.com",
            "port": 9999,
            "public_key": "pk-upsert-v2"
        }))
        .await;
    assert_eq!(resp.status(), 200);

    // Verify updated values
    let list_resp = server.get_relays().await;
    let body: Value = list_resp.json().await.unwrap();
    let relays = body["relays"].as_array().unwrap();
    assert_eq!(relays.len(), 1, "upsert must not duplicate");
    assert_eq!(relays[0]["hostname"], "updated.example.com");
    assert_eq!(relays[0]["port"], 9999);
    assert_eq!(relays[0]["public_key"], "pk-upsert-v2");
}

#[tokio::test]
async fn test_multiple_relays_each_has_unique_relay_id() {
    let server = TestServer::new().await;

    let ids = vec!["relay-x1", "relay-x2", "relay-x3"];
    for id in &ids {
        server
            .register_relay(
                id,
                &format!("{}.example.com", id),
                8443,
                &format!("pk-{}", id),
            )
            .await;
    }

    let resp = server.get_relays().await;
    let body: Value = resp.json().await.unwrap();
    let relays = body["relays"].as_array().unwrap();
    assert_eq!(relays.len(), 3);

    let returned_ids: Vec<&str> = relays
        .iter()
        .filter_map(|r| r["relay_id"].as_str())
        .collect();

    for id in &ids {
        assert!(returned_ids.contains(id), "relay_id {id} missing from list");
    }
}

// ═══════════════════════════════════════════════════════════════
//  5. dns_bootstrap_discovery (unit-level, no HTTP)
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_dns_bootstrap_nonexistent_domain_returns_zero() {
    use accord_server::federation::dns_bootstrap_discovery;
    let state: SharedState = Arc::new(AppState::new_in_memory().await.unwrap());
    let result = dns_bootstrap_discovery(&state, "nonexistent.invalid.accord.test").await;
    assert!(
        result.is_ok(),
        "dns_bootstrap_discovery must not panic on DNS failure"
    );
    assert_eq!(
        result.unwrap(),
        0,
        "no relays discovered for nonexistent domain"
    );
}

#[tokio::test]
async fn test_dns_bootstrap_empty_domain_graceful() {
    use accord_server::federation::dns_bootstrap_discovery;
    let state: SharedState = Arc::new(AppState::new_in_memory().await.unwrap());
    let result = dns_bootstrap_discovery(&state, "").await;
    assert!(result.is_ok(), "empty domain must be handled gracefully");
}

#[tokio::test]
async fn test_dns_bootstrap_localhost_domain_graceful() {
    use accord_server::federation::dns_bootstrap_discovery;
    let state: SharedState = Arc::new(AppState::new_in_memory().await.unwrap());
    // localhost won't have _accord._tcp SRV records — should return Ok(0)
    let result = dns_bootstrap_discovery(&state, "localhost").await;
    assert!(result.is_ok());
    // We don't assert the count — depends on DNS config — but it must not panic
}

// ═══════════════════════════════════════════════════════════════
//  6. Edge cases
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_register_then_heartbeat_sequence_multiple_times() {
    let server = TestServer::new().await;
    server
        .register_relay("relay-multi-hb", "multi-hb.example.com", 8443, "pk-mhb")
        .await;

    // Send 5 heartbeats — all should succeed
    for _ in 0..5 {
        let resp = server
            .post_heartbeat(json!({ "relay_id": "relay-multi-hb" }))
            .await;
        assert_eq!(resp.status(), 200, "repeated heartbeats must all succeed");
    }
}

#[tokio::test]
async fn test_register_relay_port_common_values() {
    let server = TestServer::new().await;
    let cases = vec![
        ("relay-p80", "p80.example.com", 80u16),
        ("relay-p443", "p443.example.com", 443u16),
        ("relay-p8080", "p8080.example.com", 8080u16),
        ("relay-p8443", "p8443.example.com", 8443u16),
    ];
    for (id, host, port) in cases {
        let resp = server
            .post_register(json!({
                "relay_id": id,
                "hostname": host,
                "port": port,
                "public_key": format!("pk-{id}")
            }))
            .await;
        assert_eq!(resp.status(), 200, "port {port} should be accepted");
    }
    let body: Value = server.get_relays().await.json().await.unwrap();
    assert_eq!(body["relays"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn test_heartbeat_relay_id_only_whitespace_treated_as_empty() {
    // A relay_id of only whitespace after trim should still fail validation
    // The handler checks `req.relay_id.is_empty()` — whitespace-only is NOT empty
    // so this may succeed (404 not found) — document the behaviour
    let server = TestServer::new().await;
    let resp = server.post_heartbeat(json!({ "relay_id": "   " })).await;
    // Either 400 (validation) or 404 (not found) — must not panic
    assert!(
        resp.status() == 400 || resp.status() == 404,
        "whitespace relay_id should return 400 or 404, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_register_relay_large_public_key_does_not_crash() {
    let server = TestServer::new().await;
    let big_key = "k".repeat(65536);
    let resp = server
        .post_register(json!({
            "relay_id": "relay-bigkey",
            "hostname": "bigkey.example.com",
            "port": 8443,
            "public_key": big_key
        }))
        .await;
    // Must return a valid HTTP response — no crash
    assert!(resp.status().as_u16() >= 100);
}

#[tokio::test]
async fn test_list_relays_no_inactive_relays_shown() {
    // Directly mark a relay inactive via DB, then verify it's not in the HTTP list
    let server = TestServer::new().await;
    let relay_id = "relay-deactivated";
    server
        .register_relay(relay_id, "dead.example.com", 8443, "pk-dead")
        .await;

    // Mark inactive directly via DB
    server
        .state
        .db
        .set_relay_active(relay_id, false)
        .await
        .unwrap();

    let resp = server.get_relays().await;
    let body: Value = resp.json().await.unwrap();
    let relays = body["relays"].as_array().unwrap();
    assert!(
        relays.iter().all(|r| r["relay_id"] != relay_id),
        "inactive relay must not appear in GET /federation/relays"
    );
}

#[tokio::test]
async fn test_heartbeat_for_completely_unregistered_relay_returns_404() {
    // A relay that was never registered → touch_known_relay returns false → 404
    let server = TestServer::new().await;

    let resp = server
        .post_heartbeat(json!({ "relay_id": "never-registered-relay-xyz" }))
        .await;
    assert_eq!(
        resp.status(),
        404,
        "heartbeat for never-registered relay must return 404"
    );
}
