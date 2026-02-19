//! Outbound webhook support for Accord
//!
//! Allows node admins to register webhook URLs that receive HTTP POST
//! notifications when events occur (message_create, message_delete,
//! member_join, member_leave, reaction_add).

use crate::models::ErrorResponse;
use crate::permissions::{has_permission, Permission};
use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use tracing::{error, info, warn};
use uuid::Uuid;

// ── Models ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: Uuid,
    pub node_id: Uuid,
    pub channel_id: Option<Uuid>,
    pub url: String,
    pub secret: String,
    pub events: String,
    pub created_by: Uuid,
    pub created_at: u64,
    pub active: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub events: Vec<String>,
    pub channel_id: Option<Uuid>,
    pub secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub channel_id: Option<Uuid>,
    pub secret: Option<String>,
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event: String,
    pub timestamp: String,
    pub data: serde_json::Value,
}

// ── Valid event types ──

const VALID_EVENTS: &[&str] = &[
    "message_create",
    "message_delete",
    "member_join",
    "member_leave",
    "reaction_add",
];

fn validate_events(events: &[String]) -> Result<(), String> {
    for e in events {
        if !VALID_EVENTS.contains(&e.as_str()) {
            return Err(format!(
                "Invalid event type: {}. Valid types: {:?}",
                e, VALID_EVENTS
            ));
        }
    }
    if events.is_empty() {
        return Err("Must subscribe to at least one event".into());
    }
    Ok(())
}

// ── HMAC-SHA256 signing ──

fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let block_size = 64;
    let mut padded_key = vec![0u8; block_size];

    if key.len() > block_size {
        let hash = Sha256::digest(key);
        padded_key[..32].copy_from_slice(&hash);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    // Inner hash: H((K' ⊕ ipad) || message)
    let mut ipad = vec![0x36u8; block_size];
    for (i, b) in padded_key.iter().enumerate() {
        ipad[i] ^= b;
    }
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H((K' ⊕ opad) || inner_hash)
    let mut opad = vec![0x5cu8; block_size];
    for (i, b) in padded_key.iter().enumerate() {
        opad[i] ^= b;
    }
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(inner_hash);
    let result = outer_hasher.finalize();

    hex::encode(result)
}

// ── Database operations ──

use crate::db::Database;

impl Database {
    pub async fn create_webhook(&self, webhook: &Webhook) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO webhooks (id, node_id, channel_id, url, secret, events, created_by, created_at, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(webhook.id.to_string())
        .bind(webhook.node_id.to_string())
        .bind(webhook.channel_id.map(|id| id.to_string()))
        .bind(&webhook.url)
        .bind(&webhook.secret)
        .bind(&webhook.events)
        .bind(webhook.created_by.to_string())
        .bind(webhook.created_at as i64)
        .bind(webhook.active)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn list_webhooks(&self, node_id: Uuid) -> anyhow::Result<Vec<Webhook>> {
        let rows = sqlx::query(
            "SELECT id, node_id, channel_id, url, secret, events, created_by, created_at, active FROM webhooks WHERE node_id = ? ORDER BY created_at DESC",
        )
        .bind(node_id.to_string())
        .fetch_all(self.pool())
        .await?;

        rows.iter().map(parse_webhook).collect()
    }

    pub async fn get_webhook(&self, webhook_id: Uuid) -> anyhow::Result<Option<Webhook>> {
        let row = sqlx::query(
            "SELECT id, node_id, channel_id, url, secret, events, created_by, created_at, active FROM webhooks WHERE id = ?",
        )
        .bind(webhook_id.to_string())
        .fetch_optional(self.pool())
        .await?;

        row.as_ref().map(parse_webhook).transpose()
    }

    pub async fn delete_webhook(&self, webhook_id: Uuid) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM webhooks WHERE id = ?")
            .bind(webhook_id.to_string())
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_webhook(
        &self,
        webhook_id: Uuid,
        url: Option<&str>,
        events: Option<&str>,
        channel_id: Option<Option<Uuid>>,
        secret: Option<&str>,
        active: Option<bool>,
    ) -> anyhow::Result<bool> {
        // Build dynamic update
        let mut sets = Vec::new();
        let mut binds: Vec<String> = Vec::new();

        if let Some(u) = url {
            sets.push("url = ?");
            binds.push(u.to_string());
        }
        if let Some(e) = events {
            sets.push("events = ?");
            binds.push(e.to_string());
        }
        if let Some(s) = secret {
            sets.push("secret = ?");
            binds.push(s.to_string());
        }
        if let Some(a) = active {
            sets.push("active = ?");
            binds.push(if a { "1".to_string() } else { "0".to_string() });
        }
        if let Some(cid) = channel_id {
            sets.push("channel_id = ?");
            binds.push(cid.map(|id| id.to_string()).unwrap_or_default());
        }

        if sets.is_empty() {
            return Ok(false);
        }

        let sql = format!("UPDATE webhooks SET {} WHERE id = ?", sets.join(", "));
        let mut query = sqlx::query(&sql);
        for b in &binds {
            query = query.bind(b);
        }
        query = query.bind(webhook_id.to_string());
        let result = query.execute(self.pool()).await?;
        Ok(result.rows_affected() > 0)
    }

    /// Get all active webhooks for a node that subscribe to a given event,
    /// optionally filtered by channel_id.
    pub async fn get_matching_webhooks(
        &self,
        node_id: Uuid,
        event: &str,
        channel_id: Option<Uuid>,
    ) -> anyhow::Result<Vec<Webhook>> {
        // Get all active webhooks for this node
        let rows = sqlx::query(
            "SELECT id, node_id, channel_id, url, secret, events, created_by, created_at, active FROM webhooks WHERE node_id = ? AND active = 1",
        )
        .bind(node_id.to_string())
        .fetch_all(self.pool())
        .await?;

        let webhooks: Vec<Webhook> = rows
            .iter()
            .map(parse_webhook)
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(webhooks
            .into_iter()
            .filter(|w| {
                // Check event subscription
                let subscribed = w.events.split(',').any(|e| e.trim() == event);
                if !subscribed {
                    return false;
                }
                // Check channel filter: null channel_id means all channels
                match (w.channel_id, channel_id) {
                    (None, _) => true,                // webhook listens to all channels
                    (Some(wc), Some(ec)) => wc == ec, // must match
                    (Some(_), None) => true, // event has no channel context, deliver anyway
                }
            })
            .collect())
    }

    /// Create the webhooks table (called from run_migrations)
    pub async fn create_webhooks_table(&self) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY NOT NULL,
                node_id TEXT NOT NULL,
                channel_id TEXT,
                url TEXT NOT NULL,
                secret TEXT NOT NULL,
                events TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                active BOOLEAN NOT NULL DEFAULT 1,
                FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(self.pool())
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_webhooks_node ON webhooks (node_id)")
            .execute(self.pool())
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks (node_id, active)")
            .execute(self.pool())
            .await?;

        Ok(())
    }
}

fn parse_webhook(row: &sqlx::sqlite::SqliteRow) -> anyhow::Result<Webhook> {
    Ok(Webhook {
        id: Uuid::parse_str(&row.get::<String, _>("id"))?,
        node_id: Uuid::parse_str(&row.get::<String, _>("node_id"))?,
        channel_id: row.get::<Option<String>, _>("channel_id").and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Uuid::parse_str(&s).ok()
            }
        }),
        url: row.get("url"),
        secret: row.get("secret"),
        events: row.get("events"),
        created_by: Uuid::parse_str(&row.get::<String, _>("created_by"))?,
        created_at: row.get::<i64, _>("created_at") as u64,
        active: row.get::<bool, _>("active"),
    })
}

// ── Helper: extract user + check admin ──

async fn extract_admin_for_node(
    state: &SharedState,
    params: &HashMap<String, String>,
    node_id: Uuid,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let token = params.get("token").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing token".into(),
                code: 401,
            }),
        )
    })?;

    let user_id = state.validate_token(token).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token".into(),
                code: 401,
            }),
        )
    })?;

    let member = state.get_node_member(node_id, user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to check membership: {}", e),
                code: 500,
            }),
        )
    })?;

    match member {
        Some(m) => {
            if !has_permission(m.role, Permission::ManageNode) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Admin permission required".into(),
                        code: 403,
                    }),
                ));
            }
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be a member of the node".into(),
                    code: 403,
                }),
            ));
        }
    }

    Ok(user_id)
}

/// Helper to extract user from webhook ID (looks up webhook's node, then checks admin)
async fn extract_admin_for_webhook(
    state: &SharedState,
    params: &HashMap<String, String>,
    webhook_id: Uuid,
) -> Result<(Uuid, Webhook), (StatusCode, Json<ErrorResponse>)> {
    let token = params.get("token").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing token".into(),
                code: 401,
            }),
        )
    })?;

    let user_id = state.validate_token(token).await.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token".into(),
                code: 401,
            }),
        )
    })?;

    let webhook = state
        .db
        .get_webhook(webhook_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Database error: {}", e),
                    code: 500,
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Webhook not found".into(),
                    code: 404,
                }),
            )
        })?;

    let member = state
        .get_node_member(webhook.node_id, user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to check membership: {}", e),
                    code: 500,
                }),
            )
        })?;

    match member {
        Some(m) => {
            if !has_permission(m.role, Permission::ManageNode) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Admin permission required".into(),
                        code: 403,
                    }),
                ));
            }
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Must be a member of the node".into(),
                    code: 403,
                }),
            ));
        }
    }

    Ok((user_id, webhook))
}

// ── Handlers ──

/// POST /nodes/:id/webhooks — Create a webhook (admin only)
pub async fn create_webhook_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<CreateWebhookRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = extract_admin_for_node(&state, &params, node_id).await?;

    validate_events(&request.events).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e,
                code: 400,
            }),
        )
    })?;

    if request.url.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "URL cannot be empty".into(),
                code: 400,
            }),
        ));
    }

    let secret = request.secret.unwrap_or_else(|| {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().gen();
        hex::encode(bytes)
    });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let webhook = Webhook {
        id: Uuid::new_v4(),
        node_id,
        channel_id: request.channel_id,
        url: request.url,
        secret,
        events: request.events.join(","),
        created_by: user_id,
        created_at: now,
        active: true,
    };

    state.db.create_webhook(&webhook).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to create webhook: {}", e),
                code: 500,
            }),
        )
    })?;

    info!(
        "Webhook {} created for node {} by {}",
        webhook.id, node_id, user_id
    );

    Ok(Json(serde_json::json!({
        "id": webhook.id,
        "node_id": webhook.node_id,
        "channel_id": webhook.channel_id,
        "url": webhook.url,
        "secret": webhook.secret,
        "events": webhook.events,
        "created_by": webhook.created_by,
        "created_at": webhook.created_at,
        "active": webhook.active,
    })))
}

/// GET /nodes/:id/webhooks — List webhooks (admin only)
pub async fn list_webhooks_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let _user_id = extract_admin_for_node(&state, &params, node_id).await?;

    let webhooks = state.db.list_webhooks(node_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to list webhooks: {}", e),
                code: 500,
            }),
        )
    })?;

    let items: Vec<serde_json::Value> = webhooks
        .iter()
        .map(|w| {
            serde_json::json!({
                "id": w.id,
                "node_id": w.node_id,
                "channel_id": w.channel_id,
                "url": w.url,
                "events": w.events,
                "created_by": w.created_by,
                "created_at": w.created_at,
                "active": w.active,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "webhooks": items })))
}

/// DELETE /webhooks/:id — Delete webhook (admin only)
pub async fn delete_webhook_handler(
    State(state): State<SharedState>,
    Path(webhook_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let (user_id, _webhook) = extract_admin_for_webhook(&state, &params, webhook_id).await?;

    state.db.delete_webhook(webhook_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to delete webhook: {}", e),
                code: 500,
            }),
        )
    })?;

    info!("Webhook {} deleted by {}", webhook_id, user_id);

    Ok(Json(serde_json::json!({
        "status": "deleted",
        "id": webhook_id,
    })))
}

/// PATCH /webhooks/:id — Update webhook (admin only)
pub async fn update_webhook_handler(
    State(state): State<SharedState>,
    Path(webhook_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<UpdateWebhookRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let (user_id, _webhook) = extract_admin_for_webhook(&state, &params, webhook_id).await?;

    if let Some(ref events) = request.events {
        validate_events(events).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e,
                    code: 400,
                }),
            )
        })?;
    }

    let events_str = request.events.as_ref().map(|e| e.join(","));

    state
        .db
        .update_webhook(
            webhook_id,
            request.url.as_deref(),
            events_str.as_deref(),
            if request.channel_id.is_some() {
                Some(request.channel_id)
            } else {
                None
            },
            request.secret.as_deref(),
            request.active,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to update webhook: {}", e),
                    code: 500,
                }),
            )
        })?;

    info!("Webhook {} updated by {}", webhook_id, user_id);

    Ok(Json(serde_json::json!({
        "status": "updated",
        "id": webhook_id,
    })))
}

/// POST /webhooks/:id/test — Send test payload
pub async fn test_webhook_handler(
    State(state): State<SharedState>,
    Path(webhook_id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let (_user_id, webhook) = extract_admin_for_webhook(&state, &params, webhook_id).await?;

    let payload = WebhookPayload {
        event: "test".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        data: serde_json::json!({
            "message": "This is a test webhook delivery from Accord",
            "webhook_id": webhook.id,
            "node_id": webhook.node_id,
        }),
    };

    let body = serde_json::to_string(&payload).unwrap();
    let signature = compute_hmac_sha256(webhook.secret.as_bytes(), body.as_bytes());

    let client = reqwest::Client::new();
    let result = client
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .header("X-Accord-Signature", &signature)
        .header("X-Accord-Event", "test")
        .body(body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            Ok(Json(serde_json::json!({
                "status": "sent",
                "response_status": status,
            })))
        }
        Err(e) => Ok(Json(serde_json::json!({
            "status": "failed",
            "error": e.to_string(),
        }))),
    }
}

// ── Event delivery ──

/// Deliver a webhook event to all matching webhooks for a node.
/// Spawns background tasks with retry logic.
pub fn dispatch_webhook_event(
    state: SharedState,
    node_id: Uuid,
    event: &str,
    channel_id: Option<Uuid>,
    data: serde_json::Value,
) {
    let event = event.to_string();
    tokio::spawn(async move {
        let webhooks = match state
            .db
            .get_matching_webhooks(node_id, &event, channel_id)
            .await
        {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to query webhooks for node {}: {}", node_id, e);
                return;
            }
        };

        if webhooks.is_empty() {
            return;
        }

        let payload = WebhookPayload {
            event: event.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data,
        };
        let body = serde_json::to_string(&payload).unwrap();

        for webhook in webhooks {
            let body = body.clone();
            let event = event.clone();
            tokio::spawn(async move {
                deliver_with_retry(&webhook, &body, &event).await;
            });
        }
    });
}

async fn deliver_with_retry(webhook: &Webhook, body: &str, event: &str) {
    let signature = compute_hmac_sha256(webhook.secret.as_bytes(), body.as_bytes());
    let client = reqwest::Client::new();

    for attempt in 0..3u32 {
        if attempt > 0 {
            let delay = std::time::Duration::from_secs(2u64.pow(attempt)); // 2s, 4s
            tokio::time::sleep(delay).await;
        }

        let result = client
            .post(&webhook.url)
            .header("Content-Type", "application/json")
            .header("X-Accord-Signature", &signature)
            .header("X-Accord-Event", event)
            .body(body.to_string())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                return;
            }
            Ok(resp) => {
                warn!(
                    "Webhook {} delivery attempt {} got status {}: {}",
                    webhook.id,
                    attempt + 1,
                    resp.status(),
                    webhook.url
                );
            }
            Err(e) => {
                warn!(
                    "Webhook {} delivery attempt {} failed: {}: {}",
                    webhook.id,
                    attempt + 1,
                    e,
                    webhook.url
                );
            }
        }
    }

    error!(
        "Webhook {} delivery failed after 3 attempts: {}",
        webhook.id, webhook.url
    );
}
