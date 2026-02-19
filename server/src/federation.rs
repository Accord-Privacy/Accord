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
