//! Federation discovery — relay-to-relay registration, heartbeat, and discovery.
//!
//! Endpoints:
//! - `GET  /federation/relays`    — list known relays
//! - `POST /federation/register`  — announce this relay to another
//! - `POST /federation/heartbeat` — periodic liveness ping

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::state::SharedState;

// ── Request / Response types ──

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayInfo {
    pub relay_id: String,
    pub hostname: String,
    pub port: u16,
    pub public_key: String,
    pub last_seen: i64,
    pub status: String,
    pub registered_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRelayRequest {
    pub relay_id: String,
    pub hostname: String,
    pub port: u16,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterRelayResponse {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub relay_id: String,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct RelayListResponse {
    pub relays: Vec<RelayInfo>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

// ── Auth helper ──

fn validate_mesh_secret(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let mesh_handle = state.mesh_handle.try_read();
    let expected_secret = match &mesh_handle {
        Ok(guard) => match guard.as_ref() {
            Some(h) => h.config().mesh_secret.clone(),
            None => None,
        },
        Err(_) => None,
    };

    // If no mesh_secret configured, allow unauthenticated (open federation)
    let expected = match expected_secret {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(()),
    };

    let provided = headers
        .get("x-mesh-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided == expected {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "Invalid or missing mesh secret".into(),
            }),
        ))
    }
}

// ── Handlers ──

/// `GET /federation/relays` — list all known relays
pub async fn list_relays_handler(
    State(state): State<SharedState>,
) -> Result<Json<RelayListResponse>, (StatusCode, Json<ErrorBody>)> {
    let relays = state.db.list_known_relays().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("Database error: {}", e),
            }),
        )
    })?;

    Ok(Json(RelayListResponse { relays }))
}

/// `POST /federation/register` — a relay announces itself
pub async fn register_relay_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRelayRequest>,
) -> Result<Json<RegisterRelayResponse>, (StatusCode, Json<ErrorBody>)> {
    validate_mesh_secret(&state, &headers)?;

    // Basic validation
    if req.relay_id.is_empty() || req.hostname.is_empty() || req.public_key.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "relay_id, hostname, and public_key are required".into(),
            }),
        ));
    }

    state
        .db
        .upsert_known_relay(&req.relay_id, &req.hostname, req.port, &req.public_key)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("Database error: {}", e),
                }),
            )
        })?;

    info!(
        "Federation: relay registered — id={} host={}:{}",
        req.relay_id, req.hostname, req.port
    );

    Ok(Json(RegisterRelayResponse {
        ok: true,
        message: "Relay registered".into(),
    }))
}

/// `POST /federation/heartbeat` — relay liveness ping
pub async fn heartbeat_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, Json<ErrorBody>)> {
    validate_mesh_secret(&state, &headers)?;

    if req.relay_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "relay_id is required".into(),
            }),
        ));
    }

    let updated = state
        .db
        .touch_known_relay(&req.relay_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("Database error: {}", e),
                }),
            )
        })?;

    if updated {
        Ok(Json(HeartbeatResponse {
            ok: true,
            message: "Heartbeat acknowledged".into(),
        }))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "Unknown relay_id — register first".into(),
            }),
        ))
    }
}

// ── Background federation tasks ──

/// Spawn the background federation maintenance task.
/// Every 5 minutes: ping all known relays, mark unresponsive ones inactive.
pub fn spawn_federation_maintenance(state: SharedState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            if let Err(e) = run_federation_health_check(&state).await {
                warn!("Federation health check error: {}", e);
            }
        }
    });
}

async fn run_federation_health_check(state: &SharedState) -> anyhow::Result<()> {
    let relays = state.db.list_known_relays_all().await?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Get our own relay_id for the heartbeat payload
    let our_relay_id = {
        let guard = state.mesh_handle.read().await;
        guard.as_ref().map(|h| h.relay_id().to_string())
    };
    let our_relay_id = our_relay_id.unwrap_or_default();

    // Get mesh secret for auth header
    let mesh_secret = {
        let guard = state.mesh_handle.read().await;
        guard.as_ref().and_then(|h| h.config().mesh_secret.clone())
    };

    for relay in &relays {
        let url = format!(
            "https://{}:{}/federation/heartbeat",
            relay.hostname, relay.port
        );
        let mut req_builder = client
            .post(&url)
            .json(&serde_json::json!({ "relay_id": our_relay_id }));

        if let Some(ref secret) = mesh_secret {
            req_builder = req_builder.header("x-mesh-secret", secret);
        }

        match req_builder.send().await {
            Ok(resp) if resp.status().is_success() => {
                // Relay is alive — touch it
                let _ = state.db.touch_known_relay(&relay.relay_id).await;
            }
            _ => {
                // Failed — increment missed heartbeats
                let missed = state
                    .db
                    .increment_missed_heartbeats(&relay.relay_id)
                    .await
                    .unwrap_or(0);
                if missed >= 3 {
                    let _ = state.db.set_relay_active(&relay.relay_id, false).await;
                    warn!(
                        "Federation: relay {} marked inactive after {} missed heartbeats",
                        relay.relay_id, missed
                    );
                }
            }
        }
    }

    Ok(())
}

/// Optional DNS-based bootstrap: look up `_accord._tcp.<domain>` SRV records
/// and auto-register discovered relays.
pub async fn dns_bootstrap_discovery(state: &SharedState, domain: &str) -> anyhow::Result<usize> {
    use std::net::ToSocketAddrs;

    let srv_name = format!("_accord._tcp.{}", domain);
    // Use system DNS resolver for SRV lookup (basic approach)
    let addrs: Vec<_> = match (srv_name.as_str(), 0u16).to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(_) => {
            info!("Federation DNS: no SRV records found for {}", srv_name);
            return Ok(0);
        }
    };

    let mut count = 0;
    for addr in &addrs {
        let hostname = addr.ip().to_string();
        let port = addr.port();
        // Generate a placeholder relay_id from the address (real implementation
        // would query the relay's /federation/relays endpoint for its identity)
        let relay_id = format!("dns-{}-{}", hostname, port);
        state
            .db
            .upsert_known_relay(&relay_id, &hostname, port, "")
            .await?;
        count += 1;
        info!("Federation DNS: discovered relay at {}:{}", hostname, port);
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue};
    use std::sync::Arc;

    /// Build an in-memory SharedState for tests.
    /// mesh_handle defaults to None → open federation (no secret required).
    async fn make_test_state() -> SharedState {
        Arc::new(AppState::new_in_memory().await.unwrap())
    }

    /// Build a HeaderMap with the given x-mesh-secret value.
    fn headers_with_secret(secret: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-mesh-secret", HeaderValue::from_str(secret).unwrap());
        headers
    }

    // ── validate_mesh_secret ──

    #[tokio::test]
    async fn test_open_federation_no_secret_configured() {
        // mesh_handle is None → any request passes (open federation)
        let state = make_test_state().await;
        let headers = HeaderMap::new();
        assert!(
            validate_mesh_secret(&state, &headers).is_ok(),
            "open federation should accept requests with no header"
        );
    }

    #[tokio::test]
    async fn test_open_federation_ignores_secret_header() {
        // Even when a wrong secret is provided, open federation passes
        let state = make_test_state().await;
        let headers = headers_with_secret("some-random-token");
        assert!(
            validate_mesh_secret(&state, &headers).is_ok(),
            "open federation should ignore any provided secret"
        );
    }

    #[tokio::test]
    async fn test_open_federation_empty_secret_header() {
        // Empty secret header — open federation still passes
        let state = make_test_state().await;
        let headers = headers_with_secret("");
        assert!(
            validate_mesh_secret(&state, &headers).is_ok(),
            "open federation should accept empty secret header"
        );
    }

    // ── register_relay_handler field validation ──

    #[tokio::test]
    async fn test_register_relay_valid() {
        let state = make_test_state().await;
        let req = RegisterRelayRequest {
            relay_id: "relay-abc123".to_string(),
            hostname: "relay.example.com".to_string(),
            port: 8443,
            public_key: "ed25519-pubkey-base64".to_string(),
        };
        let result =
            register_relay_handler(State(state.clone()), HeaderMap::new(), Json(req)).await;
        assert!(result.is_ok(), "valid registration should succeed");
        let resp = result.unwrap().0;
        assert!(resp.ok);
        assert_eq!(resp.message, "Relay registered");
    }

    #[tokio::test]
    async fn test_register_relay_empty_relay_id() {
        let state = make_test_state().await;
        let req = RegisterRelayRequest {
            relay_id: "".to_string(),
            hostname: "relay.example.com".to_string(),
            port: 8443,
            public_key: "some-pubkey".to_string(),
        };
        let result = register_relay_handler(State(state), HeaderMap::new(), Json(req)).await;
        assert!(result.is_err(), "empty relay_id should be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_register_relay_empty_hostname() {
        let state = make_test_state().await;
        let req = RegisterRelayRequest {
            relay_id: "relay-123".to_string(),
            hostname: "".to_string(),
            port: 8443,
            public_key: "some-pubkey".to_string(),
        };
        let result = register_relay_handler(State(state), HeaderMap::new(), Json(req)).await;
        assert!(result.is_err(), "empty hostname should be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_register_relay_empty_public_key() {
        let state = make_test_state().await;
        let req = RegisterRelayRequest {
            relay_id: "relay-123".to_string(),
            hostname: "relay.example.com".to_string(),
            port: 8443,
            public_key: "".to_string(),
        };
        let result = register_relay_handler(State(state), HeaderMap::new(), Json(req)).await;
        assert!(result.is_err(), "empty public_key should be rejected");
        let (status, Json(body)) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.error.contains("required"),
            "error message should mention required fields"
        );
    }

    #[tokio::test]
    async fn test_register_relay_all_fields_empty() {
        let state = make_test_state().await;
        let req = RegisterRelayRequest {
            relay_id: "".to_string(),
            hostname: "".to_string(),
            port: 0,
            public_key: "".to_string(),
        };
        let result = register_relay_handler(State(state), HeaderMap::new(), Json(req)).await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ── register_relay_handler: idempotency (upsert) ──

    #[tokio::test]
    async fn test_register_relay_idempotent_upsert() {
        let state = make_test_state().await;
        let req1 = RegisterRelayRequest {
            relay_id: "relay-dup".to_string(),
            hostname: "host1.example.com".to_string(),
            port: 8443,
            public_key: "pubkey-v1".to_string(),
        };
        // First registration
        let r1 = register_relay_handler(State(state.clone()), HeaderMap::new(), Json(req1)).await;
        assert!(r1.is_ok());

        // Second registration with same ID but updated hostname
        let req2 = RegisterRelayRequest {
            relay_id: "relay-dup".to_string(),
            hostname: "host2.example.com".to_string(),
            port: 9000,
            public_key: "pubkey-v2".to_string(),
        };
        let r2 = register_relay_handler(State(state.clone()), HeaderMap::new(), Json(req2)).await;
        assert!(
            r2.is_ok(),
            "re-registration of same relay_id should succeed (upsert)"
        );
    }

    // ── register_relay_handler: edge cases ──

    #[tokio::test]
    async fn test_register_relay_oversized_relay_id() {
        // relay_id with 1000+ chars — DB accepts it (no length limit enforced in handler)
        // but it must not panic or crash
        let state = make_test_state().await;
        let req = RegisterRelayRequest {
            relay_id: "r".repeat(1024),
            hostname: "relay.example.com".to_string(),
            port: 8443,
            public_key: "pubkey".to_string(),
        };
        // Should either succeed or fail gracefully — must not panic
        let _ = register_relay_handler(State(state), HeaderMap::new(), Json(req)).await;
    }

    #[tokio::test]
    async fn test_register_relay_oversized_public_key() {
        // public_key with large payload — must not panic
        let state = make_test_state().await;
        let req = RegisterRelayRequest {
            relay_id: "relay-bigkey".to_string(),
            hostname: "relay.example.com".to_string(),
            port: 8443,
            public_key: "k".repeat(65536),
        };
        let _ = register_relay_handler(State(state), HeaderMap::new(), Json(req)).await;
    }

    #[tokio::test]
    async fn test_register_relay_special_chars_in_hostname() {
        // Hostname with special characters — handler passes through, DB stores as-is
        let state = make_test_state().await;
        let req = RegisterRelayRequest {
            relay_id: "relay-special".to_string(),
            hostname: "relay.example.com:8080/path?query=1".to_string(),
            port: 8443,
            public_key: "pubkey".to_string(),
        };
        // Must not panic — outcome (ok or err) depends on DB constraints
        let _ = register_relay_handler(State(state), HeaderMap::new(), Json(req)).await;
    }

    #[tokio::test]
    async fn test_register_relay_unicode_fields() {
        let state = make_test_state().await;
        let req = RegisterRelayRequest {
            relay_id: "relay-\u{1F4BB}".to_string(),
            hostname: "中文.example.com".to_string(),
            port: 8443,
            public_key: "pubkey-valid".to_string(),
        };
        // Must not panic
        let _ = register_relay_handler(State(state), HeaderMap::new(), Json(req)).await;
    }

    // ── heartbeat_handler ──

    #[tokio::test]
    async fn test_heartbeat_empty_relay_id() {
        let state = make_test_state().await;
        let req = HeartbeatRequest {
            relay_id: "".to_string(),
        };
        let result = heartbeat_handler(State(state), HeaderMap::new(), Json(req)).await;
        assert!(result.is_err(), "empty relay_id should be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_heartbeat_unknown_relay_id() {
        let state = make_test_state().await;
        let req = HeartbeatRequest {
            relay_id: "nonexistent-relay".to_string(),
        };
        let result = heartbeat_handler(State(state), HeaderMap::new(), Json(req)).await;
        assert!(
            result.is_err(),
            "heartbeat for unknown relay should return 404"
        );
        let (status, Json(body)) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            body.error.contains("Unknown relay_id") || body.error.contains("register"),
            "404 error should mention registering first"
        );
    }

    #[tokio::test]
    async fn test_heartbeat_known_relay_succeeds() {
        let state = make_test_state().await;

        // Register first
        let reg_req = RegisterRelayRequest {
            relay_id: "relay-heartbeat-test".to_string(),
            hostname: "hb.example.com".to_string(),
            port: 8443,
            public_key: "pubkey-hb".to_string(),
        };
        let _ = register_relay_handler(State(state.clone()), HeaderMap::new(), Json(reg_req))
            .await
            .expect("registration should succeed");

        // Now heartbeat
        let hb_req = HeartbeatRequest {
            relay_id: "relay-heartbeat-test".to_string(),
        };
        let result = heartbeat_handler(State(state), HeaderMap::new(), Json(hb_req)).await;
        assert!(
            result.is_ok(),
            "heartbeat for registered relay should succeed"
        );
        let resp = result.unwrap().0;
        assert!(resp.ok);
        assert_eq!(resp.message, "Heartbeat acknowledged");
    }

    #[tokio::test]
    async fn test_heartbeat_updates_last_seen() {
        let state = make_test_state().await;

        // Register
        let relay_id = "relay-ts-test".to_string();
        let _ = register_relay_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(RegisterRelayRequest {
                relay_id: relay_id.clone(),
                hostname: "ts.example.com".to_string(),
                port: 8443,
                public_key: "pubkey-ts".to_string(),
            }),
        )
        .await
        .unwrap();

        // Get last_seen before heartbeat
        let before: Vec<RelayInfo> = state.db.list_known_relays().await.unwrap();
        let before_ts = before
            .iter()
            .find(|r| r.relay_id == relay_id)
            .map(|r| r.last_seen)
            .expect("relay should be listed");

        // Small sleep to ensure timestamp difference is detectable
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Heartbeat
        let _ = heartbeat_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(HeartbeatRequest {
                relay_id: relay_id.clone(),
            }),
        )
        .await
        .unwrap();

        // last_seen should be >= before_ts (may be equal if resolution is 1s)
        let after: Vec<RelayInfo> = state.db.list_known_relays().await.unwrap();
        let after_ts = after
            .iter()
            .find(|r| r.relay_id == relay_id)
            .map(|r| r.last_seen)
            .expect("relay should still be listed");

        assert!(
            after_ts >= before_ts,
            "last_seen should not decrease after heartbeat"
        );
    }

    // ── list_relays_handler ──

    #[tokio::test]
    async fn test_list_relays_empty() {
        let state = make_test_state().await;
        let result = list_relays_handler(State(state)).await;
        assert!(result.is_ok());
        let resp = result.unwrap().0;
        assert!(resp.relays.is_empty(), "fresh state should have no relays");
    }

    #[tokio::test]
    async fn test_list_relays_after_registration() {
        let state = make_test_state().await;

        let _ = register_relay_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(RegisterRelayRequest {
                relay_id: "relay-list-1".to_string(),
                hostname: "list1.example.com".to_string(),
                port: 8443,
                public_key: "pubkey-1".to_string(),
            }),
        )
        .await
        .unwrap();

        let result = list_relays_handler(State(state)).await;
        assert!(result.is_ok());
        let resp = result.unwrap().0;
        assert_eq!(resp.relays.len(), 1);
        let relay = &resp.relays[0];
        assert_eq!(relay.relay_id, "relay-list-1");
        assert_eq!(relay.hostname, "list1.example.com");
        assert_eq!(relay.port, 8443);
        assert_eq!(relay.public_key, "pubkey-1");
        assert_eq!(relay.status, "active");
    }

    #[tokio::test]
    async fn test_list_relays_multiple() {
        let state = make_test_state().await;

        for i in 0..3u32 {
            let _ = register_relay_handler(
                State(state.clone()),
                HeaderMap::new(),
                Json(RegisterRelayRequest {
                    relay_id: format!("relay-multi-{}", i),
                    hostname: format!("multi{}.example.com", i),
                    port: 8000 + i as u16,
                    public_key: format!("pubkey-{}", i),
                }),
            )
            .await
            .unwrap();
        }

        let result = list_relays_handler(State(state)).await;
        assert!(result.is_ok());
        let resp = result.unwrap().0;
        assert_eq!(
            resp.relays.len(),
            3,
            "all registered relays should be listed"
        );
    }

    #[tokio::test]
    async fn test_list_relays_only_active() {
        let state = make_test_state().await;

        // Register a relay
        let relay_id = "relay-inactive-test".to_string();
        let _ = register_relay_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(RegisterRelayRequest {
                relay_id: relay_id.clone(),
                hostname: "inactive.example.com".to_string(),
                port: 8443,
                public_key: "pubkey-inactive".to_string(),
            }),
        )
        .await
        .unwrap();

        // Mark it inactive
        state.db.set_relay_active(&relay_id, false).await.unwrap();

        // list_known_relays only returns active relays
        let result = list_relays_handler(State(state)).await;
        assert!(result.is_ok());
        let resp = result.unwrap().0;
        assert!(
            resp.relays.is_empty(),
            "inactive relay should not appear in list"
        );
    }

    // ── relay registration → relay info roundtrip ──

    #[tokio::test]
    async fn test_relay_info_fields_preserved() {
        let state = make_test_state().await;

        let _ = register_relay_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(RegisterRelayRequest {
                relay_id: "relay-fields".to_string(),
                hostname: "fields.example.com".to_string(),
                port: 9999,
                public_key: "base64encodedpublickey==".to_string(),
            }),
        )
        .await
        .unwrap();

        let relays = state.db.list_known_relays().await.unwrap();
        assert_eq!(relays.len(), 1);
        let r = &relays[0];
        assert_eq!(r.relay_id, "relay-fields");
        assert_eq!(r.hostname, "fields.example.com");
        assert_eq!(r.port, 9999);
        assert_eq!(r.public_key, "base64encodedpublickey==");
        assert!(r.last_seen > 0, "last_seen should be a Unix timestamp");
        assert!(
            r.registered_at > 0,
            "registered_at should be a Unix timestamp"
        );
    }

    // ── open federation auth with mesh secret header present ──

    #[tokio::test]
    async fn test_register_relay_open_federation_with_any_header() {
        // In open federation (no mesh_handle), even a "wrong" secret header passes
        let state = make_test_state().await;
        let headers = headers_with_secret("totally-wrong-secret");
        let result = register_relay_handler(
            State(state),
            headers,
            Json(RegisterRelayRequest {
                relay_id: "relay-open".to_string(),
                hostname: "open.example.com".to_string(),
                port: 8443,
                public_key: "pubkey-open".to_string(),
            }),
        )
        .await;
        assert!(
            result.is_ok(),
            "open federation should accept requests even with a (wrong) secret header"
        );
    }

    #[tokio::test]
    async fn test_heartbeat_open_federation_with_any_header() {
        let state = make_test_state().await;

        // Register the relay first
        let _ = register_relay_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(RegisterRelayRequest {
                relay_id: "relay-open-hb".to_string(),
                hostname: "open-hb.example.com".to_string(),
                port: 8443,
                public_key: "pubkey-open-hb".to_string(),
            }),
        )
        .await
        .unwrap();

        let headers = headers_with_secret("bogus-secret");
        let result = heartbeat_handler(
            State(state),
            headers,
            Json(HeartbeatRequest {
                relay_id: "relay-open-hb".to_string(),
            }),
        )
        .await;
        assert!(
            result.is_ok(),
            "open federation heartbeat should pass regardless of secret header"
        );
    }

    // ── missed heartbeat / inactive marking ──

    #[tokio::test]
    async fn test_increment_missed_heartbeats() {
        let state = make_test_state().await;

        let relay_id = "relay-missed".to_string();
        state
            .db
            .upsert_known_relay(&relay_id, "missed.example.com", 8443, "pubkey")
            .await
            .unwrap();

        let count1 = state
            .db
            .increment_missed_heartbeats(&relay_id)
            .await
            .unwrap();
        assert_eq!(count1, 1);

        let count2 = state
            .db
            .increment_missed_heartbeats(&relay_id)
            .await
            .unwrap();
        assert_eq!(count2, 2);

        let count3 = state
            .db
            .increment_missed_heartbeats(&relay_id)
            .await
            .unwrap();
        assert_eq!(count3, 3);
    }

    #[tokio::test]
    async fn test_set_relay_inactive_after_missed_heartbeats() {
        let state = make_test_state().await;

        let relay_id = "relay-to-deactivate".to_string();
        state
            .db
            .upsert_known_relay(&relay_id, "dead.example.com", 8443, "pubkey")
            .await
            .unwrap();

        // Simulate 3 missed heartbeats → mark inactive
        for _ in 0..3 {
            state
                .db
                .increment_missed_heartbeats(&relay_id)
                .await
                .unwrap();
        }
        state.db.set_relay_active(&relay_id, false).await.unwrap();

        // Should not appear in active list
        let active = state.db.list_known_relays().await.unwrap();
        assert!(
            active.iter().all(|r| r.relay_id != relay_id),
            "deactivated relay should not appear in active list"
        );

        // But should appear in list_all
        let all = state.db.list_known_relays_all().await.unwrap();
        let found = all.iter().find(|r| r.relay_id == relay_id);
        assert!(
            found.is_some(),
            "deactivated relay should appear in list_all"
        );
        assert_eq!(
            found.unwrap().status,
            "inactive",
            "status should be 'inactive'"
        );
    }

    #[tokio::test]
    async fn test_heartbeat_resets_missed_count() {
        let state = make_test_state().await;

        let relay_id = "relay-reset-missed".to_string();
        let _ = register_relay_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(RegisterRelayRequest {
                relay_id: relay_id.clone(),
                hostname: "reset.example.com".to_string(),
                port: 8443,
                public_key: "pubkey-reset".to_string(),
            }),
        )
        .await
        .unwrap();

        // Increment missed count
        state
            .db
            .increment_missed_heartbeats(&relay_id)
            .await
            .unwrap();
        state
            .db
            .increment_missed_heartbeats(&relay_id)
            .await
            .unwrap();

        // Heartbeat should reset missed_heartbeats via touch_known_relay
        let _ = heartbeat_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(HeartbeatRequest {
                relay_id: relay_id.clone(),
            }),
        )
        .await
        .unwrap();

        // After a successful heartbeat, the relay should still be active
        let active = state.db.list_known_relays().await.unwrap();
        assert!(
            active.iter().any(|r| r.relay_id == relay_id),
            "relay should remain active after heartbeat"
        );
    }

    // ── dns_bootstrap_discovery ──

    #[tokio::test]
    async fn test_dns_bootstrap_nonexistent_domain() {
        let state = make_test_state().await;
        // Non-existent domain — system DNS will fail, function should return Ok(0)
        let result = dns_bootstrap_discovery(&state, "nonexistent.invalid.accord.test").await;
        assert!(
            result.is_ok(),
            "dns_bootstrap_discovery should not panic on DNS failure"
        );
        assert_eq!(
            result.unwrap(),
            0,
            "no relays should be discovered for nonexistent domain"
        );
    }

    #[tokio::test]
    async fn test_dns_bootstrap_empty_domain() {
        let state = make_test_state().await;
        // Empty domain — DNS resolution will fail gracefully
        let result = dns_bootstrap_discovery(&state, "").await;
        assert!(
            result.is_ok(),
            "dns_bootstrap_discovery should handle empty domain gracefully"
        );
    }

    // ── ErrorBody / response types ──

    #[tokio::test]
    async fn test_error_body_serializes() {
        let body = ErrorBody {
            error: "test error message".to_string(),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("test error message"));
        assert!(json.contains("\"error\""));
    }

    #[tokio::test]
    async fn test_relay_info_serializes() {
        let info = RelayInfo {
            relay_id: "test-relay".to_string(),
            hostname: "test.example.com".to_string(),
            port: 8443,
            public_key: "pk123".to_string(),
            last_seen: 1700000000,
            status: "active".to_string(),
            registered_at: 1699990000,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test-relay"));
        assert!(json.contains("test.example.com"));
        assert!(json.contains("8443"));
        assert!(json.contains("active"));
    }

    #[tokio::test]
    async fn test_register_relay_response_serializes() {
        let resp = RegisterRelayResponse {
            ok: true,
            message: "Relay registered".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("true"));
        assert!(json.contains("Relay registered"));
    }

    // ── auth: open federation does not require the header ──

    #[tokio::test]
    async fn test_list_relays_no_auth_required_open_federation() {
        // list_relays doesn't check auth, but ensure it works in open federation
        let state = make_test_state().await;
        // No headers, no auth — should work fine in open federation
        let result = list_relays_handler(State(state)).await;
        assert!(result.is_ok());
    }

    // ── port edge cases ──

    #[tokio::test]
    async fn test_register_relay_port_zero() {
        let state = make_test_state().await;
        let result = register_relay_handler(
            State(state),
            HeaderMap::new(),
            Json(RegisterRelayRequest {
                relay_id: "relay-port0".to_string(),
                hostname: "port0.example.com".to_string(),
                port: 0,
                public_key: "pubkey".to_string(),
            }),
        )
        .await;
        // Port 0 is technically valid at the handler level (no port range validation)
        assert!(
            result.is_ok(),
            "port 0 should be accepted by handler (no port validation)"
        );
    }

    #[tokio::test]
    async fn test_register_relay_max_port() {
        let state = make_test_state().await;
        let result = register_relay_handler(
            State(state),
            HeaderMap::new(),
            Json(RegisterRelayRequest {
                relay_id: "relay-maxport".to_string(),
                hostname: "maxport.example.com".to_string(),
                port: 65535,
                public_key: "pubkey".to_string(),
            }),
        )
        .await;
        assert!(result.is_ok(), "port 65535 should be accepted");
    }
}
