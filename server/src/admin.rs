//! Admin dashboard routes for the Accord relay server.
//!
//! Auth-gated via `X-Admin-Token` header only (query param auth removed for security)
//! matching the `ACCORD_ADMIN_TOKEN` environment variable.

use crate::state::SharedState;
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::broadcast;

/// In-memory broadcast channel for log lines.
/// Handlers subscribe; a tracing layer pushes lines.
pub type LogBroadcast = broadcast::Sender<String>;

/// Create a new log broadcast channel (call once at startup, store in state or as a global).
pub fn new_log_broadcast() -> LogBroadcast {
    broadcast::channel::<String>(256).0
}

// ── Auth helper ──

fn validate_admin_token(headers: &HeaderMap, _params: &HashMap<String, String>) -> bool {
    let expected = match std::env::var("ACCORD_ADMIN_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => return false, // No token configured → admin disabled
    };
    // Only accept token via header — never query params (which leak in logs/history/referers)
    if let Some(hdr) = headers.get("x-admin-token") {
        if let Ok(val) = hdr.to_str() {
            if val.as_bytes().ct_eq(expected.as_bytes()).into() {
                return true;
            }
        }
    }
    false
}

/// WebSocket connections can't set custom headers from browsers, so we allow
/// query param auth ONLY for the admin WebSocket endpoint. This is acceptable
/// because WS upgrade URLs aren't stored in browser history or sent as referers.
fn validate_admin_token_ws(headers: &HeaderMap, params: &HashMap<String, String>) -> bool {
    // Try header first
    if validate_admin_token(headers, params) {
        return true;
    }
    // Fall back to query param for WebSocket only
    let expected = match std::env::var("ACCORD_ADMIN_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => return false,
    };
    if let Some(val) = params.get("admin_token") {
        if val.as_bytes().ct_eq(expected.as_bytes()).into() {
            return true;
        }
    }
    false
}

fn unauthorized() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "Invalid or missing admin token"})),
    )
}

// ── Handlers ──

/// Serve the admin dashboard HTML page
pub async fn admin_page_handler() -> impl IntoResponse {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(ADMIN_HTML))
        .unwrap()
}

/// Return admin stats as JSON
pub async fn admin_stats_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token(&headers, &params) {
        return Err(unauthorized());
    }

    let user_count = state.db.count_users().await.unwrap_or(0);
    let node_count = state.db.count_nodes().await.unwrap_or(0);
    let message_count = state.db.count_messages().await.unwrap_or(0);
    let connection_count = state.connections.read().await.len();
    let uptime = state.uptime();
    let version = env!("CARGO_PKG_VERSION");

    // Memory usage (RSS from /proc/self/statm on Linux)
    let memory_bytes = get_rss_bytes().unwrap_or(0);

    Ok(Json(json!({
        "user_count": user_count,
        "node_count": node_count,
        "message_count": message_count,
        "connection_count": connection_count,
        "uptime_seconds": uptime,
        "version": version,
        "memory_bytes": memory_bytes,
    })))
}

/// Return all users (admin)
pub async fn admin_users_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token(&headers, &params) {
        return Err(unauthorized());
    }
    let users = state.db.get_all_users_admin().await.unwrap_or_default();
    Ok(Json(json!({ "users": users })))
}

/// Return all nodes (admin)
pub async fn admin_nodes_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token(&headers, &params) {
        return Err(unauthorized());
    }
    let nodes = state.db.get_nodes_admin().await.unwrap_or_default();
    Ok(Json(json!({ "nodes": nodes })))
}

/// WebSocket endpoint for live log streaming
pub async fn admin_logs_ws_handler(
    State(log_tx): State<Arc<LogBroadcast>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token_ws(&headers, &params) {
        return Err(unauthorized());
    }
    let rx = log_tx.subscribe();
    Ok(ws.on_upgrade(move |socket| handle_log_ws(socket, rx)))
}

async fn handle_log_ws(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(line) => {
                        if socket.send(Message::Text(line)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        let notice = format!("[... skipped {} log lines ...]", n);
                        let _ = socket.send(Message::Text(notice)).await;
                    }
                    Err(_) => break,
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

/// A MakeWriter that tees output to both stderr and the log broadcast channel.
pub struct TeeWriter {
    tx: LogBroadcast,
}

impl TeeWriter {
    pub fn new(tx: LogBroadcast) -> Self {
        Self { tx }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TeeWriter {
    type Writer = TeeWriterInstance;

    fn make_writer(&'a self) -> Self::Writer {
        TeeWriterInstance {
            tx: self.tx.clone(),
        }
    }
}

pub struct TeeWriterInstance {
    tx: LogBroadcast,
}

impl std::io::Write for TeeWriterInstance {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Write to stderr
        let _ = std::io::Write::write(&mut std::io::stderr(), buf);
        // Broadcast to admin log viewers
        if let Ok(s) = std::str::from_utf8(buf) {
            let _ = self.tx.send(s.to_string());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut std::io::stderr())
    }
}

// ── Relay-level build hash allowlist endpoints ──

/// List relay-level allowed build hashes (GET /api/admin/build-allowlist)
pub async fn admin_build_allowlist_get_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token(&headers, &params) {
        return Err(unauthorized());
    }
    let entries = state
        .db
        .get_relay_build_hash_allowlist()
        .await
        .unwrap_or_default();
    Ok(Json(json!({
        "allowlist": entries,
        "enforcement": state.build_hash_enforcement.to_string(),
    })))
}

/// Set the full relay-level build hash allowlist (PUT /api/admin/build-allowlist)
pub async fn admin_build_allowlist_set_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Json(entries): Json<Vec<crate::models::RelayBuildHashAllowlistInput>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token(&headers, &params) {
        return Err(unauthorized());
    }
    state
        .db
        .set_relay_build_hash_allowlist(&entries)
        .await
        .map_err(|e| {
            tracing::error!("Failed to set allowlist: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
        })?;
    Ok(Json(json!({
        "status": "updated",
        "count": entries.len()
    })))
}

/// Add a build hash to the relay allowlist (POST /api/admin/build-allowlist)
pub async fn admin_build_allowlist_add_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Json(input): Json<crate::models::RelayBuildHashAllowlistInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token(&headers, &params) {
        return Err(unauthorized());
    }
    let added = state
        .db
        .add_relay_build_hash(&input.build_hash, input.label.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("Failed to add build hash: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
        })?;
    Ok(Json(json!({
        "status": if added { "added" } else { "already_exists" },
        "build_hash": input.build_hash
    })))
}

/// Remove a build hash from the relay allowlist (DELETE /api/admin/build-allowlist/:hash)
pub async fn admin_build_allowlist_remove_handler(
    State(state): State<SharedState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token(&headers, &params) {
        return Err(unauthorized());
    }
    let removed = state.db.remove_relay_build_hash(&hash).await.map_err(|e| {
        tracing::error!("Failed to remove build hash: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Internal server error"})),
        )
    })?;
    if removed {
        Ok(Json(json!({
            "status": "removed",
            "build_hash": hash
        })))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Build hash not found in allowlist"})),
        ))
    }
}

// ── Audit Log endpoint ──

/// Return paginated, filterable audit log (GET /api/admin/audit-log)
pub async fn admin_audit_log_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token(&headers, &params) {
        return Err(unauthorized());
    }

    let page = params
        .get("page")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = params
        .get("per_page")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(25)
        .min(100);
    let action_filter = params
        .get("action")
        .filter(|s| !s.is_empty())
        .map(|s| s.as_str());
    let start_time = params.get("start").and_then(|s| s.parse::<i64>().ok());
    let end_time = params.get("end").and_then(|s| s.parse::<i64>().ok());

    match state
        .db
        .get_admin_audit_log(page, per_page, action_filter, start_time, end_time)
        .await
    {
        Ok((entries, total)) => {
            let total_pages = (total as f64 / per_page as f64).ceil() as u64;
            Ok(Json(json!({
                "entries": entries,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
            })))
        }
        Err(e) => {
            tracing::error!("Failed to query audit log: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            ))
        }
    }
}

/// Return distinct action types for filter dropdown (GET /api/admin/audit-log/actions)
pub async fn admin_audit_log_actions_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !validate_admin_token(&headers, &params) {
        return Err(unauthorized());
    }

    let actions = state.db.get_audit_action_types().await.unwrap_or_default();
    Ok(Json(json!({ "actions": actions })))
}

// ── Helpers ──

fn get_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4096) // page size
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

// ── Static HTML ──

const ADMIN_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Accord Admin Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #e0e0e0; min-height: 100vh; }
  .header { background: #16213e; padding: 16px 24px; border-bottom: 1px solid #0f3460; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; }
  .header h1 { font-size: 1.3em; color: #e94560; }
  .header .meta { font-size: 0.82em; color: #888; }
  .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
  .tabs { display: flex; gap: 4px; margin-bottom: 20px; }
  .tab { padding: 8px 18px; background: #16213e; border: 1px solid #0f3460; border-radius: 6px 6px 0 0; cursor: pointer; color: #888; font-size: 0.9em; transition: all .15s; }
  .tab.active { background: #0f3460; color: #e94560; border-bottom-color: #0f3460; }
  .tab:hover { color: #e0e0e0; }
  .panel { display: none; }
  .panel.active { display: block; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 20px; }
  .stat-card { background: #16213e; border-radius: 10px; padding: 18px; border: 1px solid #0f3460; }
  .stat-card .label { font-size: 0.75em; color: #888; text-transform: uppercase; letter-spacing: 1px; }
  .stat-card .value { font-size: 1.8em; font-weight: 700; color: #e94560; margin-top: 2px; }
  .section { background: #16213e; border-radius: 10px; padding: 18px; border: 1px solid #0f3460; margin-bottom: 16px; }
  .section h2 { font-size: 1em; color: #e94560; margin-bottom: 10px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #0f3460; font-size: 0.85em; }
  th { color: #888; font-weight: 600; text-transform: uppercase; font-size: 0.72em; letter-spacing: 1px; }
  .mono { font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; font-size: 0.82em; }
  .badge { display: inline-block; background: #0f3460; padding: 2px 8px; border-radius: 4px; font-size: 0.78em; }
  #log-container { background: #0d0d1a; border: 1px solid #0f3460; border-radius: 8px; height: 500px; overflow-y: auto; padding: 10px; font-family: 'SF Mono', Monaco, monospace; font-size: 0.78em; line-height: 1.5; }
  #log-container .line { white-space: pre-wrap; word-break: break-all; }
  #log-container .line:nth-child(even) { background: rgba(255,255,255,0.02); }
  .log-status { font-size: 0.8em; padding: 6px 0; color: #888; }
  .log-status .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .dot.connected { background: #4caf50; }
  .dot.disconnected { background: #e94560; }
  .login-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.85); display: flex; align-items: center; justify-content: center; z-index: 100; }
  .login-box { background: #16213e; padding: 30px; border-radius: 12px; border: 1px solid #0f3460; width: 360px; }
  .login-box h2 { color: #e94560; margin-bottom: 16px; }
  .login-box input { width: 100%; padding: 10px; background: #1a1a2e; border: 1px solid #0f3460; color: #e0e0e0; border-radius: 6px; font-size: 0.95em; margin-bottom: 12px; }
  .login-box button { width: 100%; padding: 10px; background: #e94560; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 1em; font-weight: 600; }
  .login-box button:hover { background: #c73650; }
  .error { color: #e94560; font-size: 0.85em; margin-bottom: 8px; }
  .search { padding: 6px 12px; background: #1a1a2e; border: 1px solid #0f3460; color: #e0e0e0; border-radius: 6px; font-size: 0.85em; margin-bottom: 12px; width: 260px; }
</style>
</head>
<body>

<div id="login" class="login-overlay">
  <div class="login-box">
    <h2>🔐 Admin Dashboard</h2>
    <p style="color:#888;font-size:0.85em;margin-bottom:14px">Enter the admin token (ACCORD_ADMIN_TOKEN)</p>
    <div id="login-error" class="error"></div>
    <input id="token-input" type="password" placeholder="Admin token" autofocus>
    <button onclick="doLogin()">Connect</button>
  </div>
</div>

<div id="app" style="display:none">
  <div class="header">
    <h1>⚡ Accord Admin</h1>
    <div class="meta">v<span id="version">-</span> · uptime <span id="uptime">-</span></div>
  </div>
  <div class="container">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('stats')">📊 Stats</div>
      <div class="tab" onclick="switchTab('users')">👤 Users</div>
      <div class="tab" onclick="switchTab('nodes')">🏠 Nodes</div>
      <div class="tab" onclick="switchTab('audit')">🔍 Audit Log</div>
      <div class="tab" onclick="switchTab('logs')">📜 Logs</div>
    </div>

    <!-- Stats panel -->
    <div id="panel-stats" class="panel active">
      <div class="stats-grid">
        <div class="stat-card"><div class="label">Uptime</div><div class="value" id="s-uptime">-</div></div>
        <div class="stat-card"><div class="label">Memory (RSS)</div><div class="value" id="s-memory">-</div></div>
        <div class="stat-card"><div class="label">WebSocket Conns</div><div class="value" id="s-conns">-</div></div>
        <div class="stat-card"><div class="label">Users</div><div class="value" id="s-users">-</div></div>
        <div class="stat-card"><div class="label">Nodes</div><div class="value" id="s-nodes">-</div></div>
        <div class="stat-card"><div class="label">Messages</div><div class="value" id="s-messages">-</div></div>
      </div>
    </div>

    <!-- Users panel -->
    <div id="panel-users" class="panel">
      <div class="section">
        <h2>Registered Users</h2>
        <input class="search" placeholder="Search users..." oninput="filterTable('users-table', this.value)">
        <table><thead><tr><th>ID</th><th>Public Key Hash</th><th>Created</th><th>Node Memberships</th></tr></thead>
        <tbody id="users-table"></tbody></table>
      </div>
    </div>

    <!-- Nodes panel -->
    <div id="panel-nodes" class="panel">
      <div class="section">
        <h2>All Nodes</h2>
        <input class="search" placeholder="Search nodes..." oninput="filterTable('nodes-table', this.value)">
        <table><thead><tr><th>Name</th><th>ID</th><th>Members</th><th>Channels</th><th>Created</th><th>Description</th></tr></thead>
        <tbody id="nodes-table"></tbody></table>
      </div>
    </div>

    <!-- Audit Log panel -->
    <div id="panel-audit" class="panel">
      <div class="section">
        <h2>Audit Log</h2>
        <div style="display:flex;gap:10px;margin-bottom:12px;align-items:center;flex-wrap:wrap">
          <select id="audit-action-filter" class="search" style="width:200px" onchange="loadAuditLog(1)">
            <option value="">All actions</option>
          </select>
          <input id="audit-start" type="date" class="search" style="width:160px" onchange="loadAuditLog(1)" title="Start date">
          <input id="audit-end" type="date" class="search" style="width:160px" onchange="loadAuditLog(1)" title="End date">
          <span id="audit-total" style="color:#888;font-size:0.82em"></span>
        </div>
        <table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead>
        <tbody id="audit-table"></tbody></table>
        <div id="audit-pagination" style="display:flex;gap:8px;justify-content:center;margin-top:12px"></div>
      </div>
    </div>

    <!-- Logs panel -->
    <div id="panel-logs" class="panel">
      <div class="section">
        <h2>Live Server Logs</h2>
        <div class="log-status"><span class="dot disconnected" id="log-dot"></span><span id="log-status-text">Disconnected</span></div>
        <div id="log-container"></div>
      </div>
    </div>
  </div>
</div>

<script>
const MAX_LOG_LINES = 100;
let adminToken = '';
let logWs = null;
let pollTimer = null;

function init() {
  const saved = sessionStorage.getItem('accord_admin_token');
  if (saved) { adminToken = saved; tryConnect(); }
  else { document.getElementById('login').style.display = 'flex'; }
}

async function doLogin() {
  const t = document.getElementById('token-input').value.trim();
  if (!t) return;
  adminToken = t;
  // Validate token by hitting stats endpoint
  try {
    const r = await apiFetch('/admin/stats');
    if (!r.ok) { document.getElementById('login-error').textContent = 'Invalid token'; adminToken = ''; return; }
    sessionStorage.setItem('accord_admin_token', t);
    tryConnect();
  } catch(e) { document.getElementById('login-error').textContent = 'Connection failed'; adminToken = ''; }
}

document.getElementById('token-input').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

function tryConnect() {
  document.getElementById('login').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  pollStats();
  pollTimer = setInterval(pollStats, 5000);
}

function apiFetch(path) {
  return fetch(path, { headers: { 'X-Admin-Token': adminToken } });
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'users') loadUsers();
  if (name === 'nodes') loadNodes();
  if (name === 'audit') { loadAuditActions(); loadAuditLog(1); }
  if (name === 'logs') connectLogWs();
}

function fmtUptime(s) {
  const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
  return (d ? d+'d ' : '') + h+'h ' + m+'m';
}

function fmtBytes(b) {
  if (!b || b === 0) return 'N/A';
  if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
  if (b < 1024*1024*1024) return (b/(1024*1024)).toFixed(1) + ' MB';
  return (b/(1024*1024*1024)).toFixed(2) + ' GB';
}

function fmtTime(epoch) {
  if (!epoch) return '-';
  return new Date(epoch * 1000).toLocaleString();
}

function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

async function pollStats() {
  try {
    const r = await apiFetch('/admin/stats');
    if (r.status === 401) { sessionStorage.removeItem('accord_admin_token'); location.reload(); return; }
    const d = await r.json();
    document.getElementById('version').textContent = d.version;
    document.getElementById('uptime').textContent = fmtUptime(d.uptime_seconds);
    document.getElementById('s-uptime').textContent = fmtUptime(d.uptime_seconds);
    document.getElementById('s-memory').textContent = fmtBytes(d.memory_bytes);
    document.getElementById('s-conns').textContent = d.connection_count;
    document.getElementById('s-users').textContent = d.user_count;
    document.getElementById('s-nodes').textContent = d.node_count;
    document.getElementById('s-messages').textContent = d.message_count;
  } catch(e) { console.error('Poll failed:', e); }
}

async function loadUsers() {
  try {
    const r = await apiFetch('/admin/users');
    if (!r.ok) return;
    const d = await r.json();
    const tb = document.getElementById('users-table');
    tb.innerHTML = d.users.map(u =>
      `<tr><td class="mono">${esc(u.id.substring(0,8))}…</td><td class="mono">${esc(u.public_key_hash.substring(0,16))}…</td><td>${fmtTime(u.created_at)}</td><td>${esc(u.node_names || 'None')}</td></tr>`
    ).join('');
  } catch(e) { console.error('Failed to load users:', e); }
}

async function loadNodes() {
  try {
    const r = await apiFetch('/admin/nodes');
    if (!r.ok) return;
    const d = await r.json();
    const tb = document.getElementById('nodes-table');
    tb.innerHTML = d.nodes.map(n =>
      `<tr><td>${esc(n.name)}</td><td class="mono">${esc(n.id.substring(0,8))}…</td><td>${n.member_count}</td><td>${n.channel_count}</td><td>${fmtTime(n.created_at)}</td><td>${esc(n.description || '-')}</td></tr>`
    ).join('');
  } catch(e) { console.error('Failed to load nodes:', e); }
}

function connectLogWs() {
  if (logWs && logWs.readyState <= 1) return; // already connected/connecting
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  logWs = new WebSocket(`${proto}//${location.host}/admin/logs?admin_token=${encodeURIComponent(adminToken)}`);
  logWs.onopen = () => {
    document.getElementById('log-dot').className = 'dot connected';
    document.getElementById('log-status-text').textContent = 'Connected — streaming live logs';
  };
  logWs.onmessage = (e) => {
    const container = document.getElementById('log-container');
    const line = document.createElement('div');
    line.className = 'line';
    line.textContent = e.data;
    container.appendChild(line);
    // Trim to MAX_LOG_LINES
    while (container.children.length > MAX_LOG_LINES) container.removeChild(container.firstChild);
    container.scrollTop = container.scrollHeight;
  };
  logWs.onclose = () => {
    document.getElementById('log-dot').className = 'dot disconnected';
    document.getElementById('log-status-text').textContent = 'Disconnected — will reconnect...';
    setTimeout(connectLogWs, 3000);
  };
  logWs.onerror = () => { logWs.close(); };
}

function filterTable(tableId, query) {
  const q = query.toLowerCase();
  const rows = document.getElementById(tableId).querySelectorAll('tr');
  rows.forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

let auditActionsLoaded = false;
async function loadAuditActions() {
  if (auditActionsLoaded) return;
  try {
    const r = await apiFetch('/api/admin/audit-log/actions');
    if (!r.ok) return;
    const d = await r.json();
    const sel = document.getElementById('audit-action-filter');
    d.actions.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a; opt.textContent = a.replace(/_/g, ' ');
      sel.appendChild(opt);
    });
    auditActionsLoaded = true;
  } catch(e) { console.error('Failed to load audit actions:', e); }
}

async function loadAuditLog(page) {
  try {
    const action = document.getElementById('audit-action-filter').value;
    const startDate = document.getElementById('audit-start').value;
    const endDate = document.getElementById('audit-end').value;
    let url = `/api/admin/audit-log?page=${page}&per_page=25`;
    if (action) url += `&action=${encodeURIComponent(action)}`;
    if (startDate) url += `&start=${Math.floor(new Date(startDate).getTime()/1000)}`;
    if (endDate) url += `&end=${Math.floor(new Date(endDate + 'T23:59:59').getTime()/1000)}`;
    const r = await apiFetch(url);
    if (!r.ok) return;
    const d = await r.json();
    document.getElementById('audit-total').textContent = `${d.total} total entries`;
    const tb = document.getElementById('audit-table');
    tb.innerHTML = d.entries.map(e => {
      const actor = e.actor_display_name || (e.actor_public_key_hash ? e.actor_public_key_hash.substring(0,12)+'…' : e.actor_id.substring(0,8)+'…');
      const target = e.target_id ? e.target_type + ' ' + e.target_id.substring(0,8)+'…' : e.target_type || '-';
      let details = '-';
      if (e.details) { try { const p = JSON.parse(e.details); details = Object.entries(p).map(([k,v])=>k+': '+v).join(', '); } catch { details = e.details; } }
      if (details.length > 80) details = details.substring(0,77)+'…';
      return `<tr><td>${fmtTime(e.created_at)}</td><td class="mono">${esc(actor)}</td><td><span class="badge">${esc(e.action)}</span></td><td class="mono">${esc(target)}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${esc(details)}</td><td class="mono">${esc(e.ip_address||'-')}</td></tr>`;
    }).join('');
    // Pagination
    const pg = document.getElementById('audit-pagination');
    pg.innerHTML = '';
    for (let i = 1; i <= d.total_pages && i <= 20; i++) {
      const btn = document.createElement('button');
      btn.textContent = i;
      btn.className = 'tab' + (i === d.page ? ' active' : '');
      btn.onclick = () => loadAuditLog(i);
      pg.appendChild(btn);
    }
  } catch(e) { console.error('Failed to load audit log:', e); }
}

init();
</script>
</body>
</html>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, HeaderValue};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex as TokioMutex;

    // Serialize all tests that touch ACCORD_ADMIN_TOKEN env var.
    // Using tokio Mutex so we can hold it across await points.
    static ENV_LOCK: std::sync::LazyLock<TokioMutex<()>> =
        std::sync::LazyLock::new(|| TokioMutex::new(()));

    /// RAII guard that sets ACCORD_ADMIN_TOKEN and restores on drop.
    struct AdminTokenGuard {
        prev: Option<String>,
        // Hold the tokio MutexGuard to serialize across tests.
        // We use an Option so we can take it in drop.
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }

    impl Drop for AdminTokenGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var("ACCORD_ADMIN_TOKEN", v) },
                None => unsafe { std::env::remove_var("ACCORD_ADMIN_TOKEN") },
            }
        }
    }

    async fn set_admin_token(token: Option<&str>) -> AdminTokenGuard {
        let lock = ENV_LOCK.lock().await;
        let prev = std::env::var("ACCORD_ADMIN_TOKEN").ok();
        match token {
            Some(t) => unsafe { std::env::set_var("ACCORD_ADMIN_TOKEN", t) },
            None => unsafe { std::env::remove_var("ACCORD_ADMIN_TOKEN") },
        }
        AdminTokenGuard { prev, _lock: lock }
    }

    /// Sync version for non-async tests (uses std Mutex internally).
    fn set_admin_token_sync(token: Option<&str>) -> impl Drop {
        struct SyncGuard {
            prev: Option<String>,
        }
        impl Drop for SyncGuard {
            fn drop(&mut self) {
                match &self.prev {
                    Some(v) => unsafe { std::env::set_var("ACCORD_ADMIN_TOKEN", v) },
                    None => unsafe { std::env::remove_var("ACCORD_ADMIN_TOKEN") },
                }
            }
        }
        // We can't easily hold the tokio mutex from sync. Use a simple
        // blocking approach — sync tests are fast enough.
        let prev = std::env::var("ACCORD_ADMIN_TOKEN").ok();
        match token {
            Some(t) => unsafe { std::env::set_var("ACCORD_ADMIN_TOKEN", t) },
            None => unsafe { std::env::remove_var("ACCORD_ADMIN_TOKEN") },
        }
        SyncGuard { prev }
    }

    fn headers_with_token(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-token", HeaderValue::from_str(token).unwrap());
        headers
    }

    fn empty_params() -> HashMap<String, String> {
        HashMap::new()
    }

    fn params_with_token(token: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("admin_token".to_string(), token.to_string());
        params
    }

    async fn make_test_state() -> SharedState {
        Arc::new(AppState::new_in_memory().await.unwrap())
    }

    // ── validate_admin_token tests ──

    #[tokio::test]
    async fn test_valid_admin_token_via_header() {
        let _g = set_admin_token(Some("test-secret-123")).await;
        let headers = headers_with_token("test-secret-123");
        assert!(validate_admin_token(&headers, &empty_params()));
    }

    #[tokio::test]
    async fn test_invalid_admin_token_via_header() {
        let _g = set_admin_token(Some("test-secret-123")).await;
        let headers = headers_with_token("wrong-token");
        assert!(!validate_admin_token(&headers, &empty_params()));
    }

    #[tokio::test]
    async fn test_missing_admin_token_header() {
        let _g = set_admin_token(Some("test-secret-123")).await;
        let headers = HeaderMap::new();
        assert!(!validate_admin_token(&headers, &empty_params()));
    }

    #[tokio::test]
    async fn test_admin_token_not_configured() {
        let _g = set_admin_token(None).await;
        let headers = headers_with_token("anything");
        assert!(!validate_admin_token(&headers, &empty_params()));
    }

    #[tokio::test]
    async fn test_admin_token_configured_empty() {
        let _g = set_admin_token(Some("")).await;
        let headers = headers_with_token("anything");
        assert!(!validate_admin_token(&headers, &empty_params()));
    }

    #[tokio::test]
    async fn test_admin_token_ignores_query_params() {
        let _g = set_admin_token(Some("secret")).await;
        let headers = HeaderMap::new();
        let params = params_with_token("secret");
        assert!(!validate_admin_token(&headers, &params));
    }

    #[tokio::test]
    async fn test_admin_token_constant_time_comparison() {
        let _g = set_admin_token(Some("secret-token-value")).await;
        // Off by one — shorter
        assert!(!validate_admin_token(
            &headers_with_token("secret-token-valu"),
            &empty_params()
        ));
        // Off by one — longer
        assert!(!validate_admin_token(
            &headers_with_token("secret-token-valuee"),
            &empty_params()
        ));
    }

    // ── validate_admin_token_ws tests ──

    #[tokio::test]
    async fn test_ws_token_via_header() {
        let _g = set_admin_token(Some("ws-secret")).await;
        assert!(validate_admin_token_ws(
            &headers_with_token("ws-secret"),
            &empty_params()
        ));
    }

    #[tokio::test]
    async fn test_ws_token_via_query_param() {
        let _g = set_admin_token(Some("ws-secret")).await;
        assert!(validate_admin_token_ws(
            &HeaderMap::new(),
            &params_with_token("ws-secret")
        ));
    }

    #[tokio::test]
    async fn test_ws_token_wrong_query_param() {
        let _g = set_admin_token(Some("ws-secret")).await;
        assert!(!validate_admin_token_ws(
            &HeaderMap::new(),
            &params_with_token("wrong")
        ));
    }

    #[tokio::test]
    async fn test_ws_token_header_takes_priority() {
        let _g = set_admin_token(Some("ws-secret")).await;
        // Correct header, wrong query — should pass (header wins)
        assert!(validate_admin_token_ws(
            &headers_with_token("ws-secret"),
            &params_with_token("wrong")
        ));
    }

    #[tokio::test]
    async fn test_ws_no_token_configured() {
        let _g = set_admin_token(None).await;
        assert!(!validate_admin_token_ws(
            &HeaderMap::new(),
            &params_with_token("anything")
        ));
    }

    #[tokio::test]
    async fn test_ws_no_credentials_at_all() {
        let _g = set_admin_token(Some("ws-secret")).await;
        assert!(!validate_admin_token_ws(&HeaderMap::new(), &empty_params()));
    }

    // ── Handler authorization tests ──

    #[tokio::test]
    async fn test_stats_handler_rejects_no_auth() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result =
            admin_stats_handler(State(state), HeaderMap::new(), Query(empty_params())).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_stats_handler_rejects_wrong_token() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_stats_handler(
            State(state),
            headers_with_token("wrong"),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_stats_handler_accepts_valid_token() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_stats_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_ok());
        let json = result.unwrap().0;
        assert!(json.get("user_count").is_some());
        assert!(json.get("node_count").is_some());
        assert!(json.get("message_count").is_some());
        assert!(json.get("connection_count").is_some());
        assert!(json.get("uptime_seconds").is_some());
        assert!(json.get("version").is_some());
        assert!(json.get("memory_bytes").is_some());
    }

    #[tokio::test]
    async fn test_stats_handler_returns_zero_counts_on_fresh_db() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_stats_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        let json = result.unwrap().0;
        assert_eq!(json["user_count"], 0);
        assert_eq!(json["node_count"], 0);
        assert_eq!(json["message_count"], 0);
        assert_eq!(json["connection_count"], 0);
    }

    #[tokio::test]
    async fn test_stats_reflects_connections() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let fake_id = uuid::Uuid::new_v4();
        let (tx, _rx) = broadcast::channel(1);
        state.connections.write().await.insert(fake_id, tx);

        let result = admin_stats_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        let json = result.unwrap().0;
        assert_eq!(json["connection_count"], 1);
    }

    // ── Users handler tests ──

    #[tokio::test]
    async fn test_users_handler_rejects_no_auth() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result =
            admin_users_handler(State(state), HeaderMap::new(), Query(empty_params())).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_users_handler_accepts_valid_token() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_users_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_ok());
        let json = result.unwrap().0;
        assert!(json.get("users").is_some());
        assert!(json["users"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_users_handler_returns_registered_users() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        state
            .register_user("test-pubkey-123".into(), "".into())
            .await
            .unwrap();
        let result = admin_users_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        let json = result.unwrap().0;
        let users = json["users"].as_array().unwrap();
        assert_eq!(users.len(), 1);
    }

    // ── Nodes handler tests ──

    #[tokio::test]
    async fn test_nodes_handler_rejects_no_auth() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result =
            admin_nodes_handler(State(state), HeaderMap::new(), Query(empty_params())).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_nodes_handler_accepts_valid_token() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_nodes_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_ok());
        assert!(result.unwrap().0.get("nodes").is_some());
    }

    #[tokio::test]
    async fn test_nodes_handler_returns_created_nodes() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let user_id = state
            .register_user("nodeowner-key".into(), "".into())
            .await
            .unwrap();
        state
            .create_node("TestNode".into(), user_id, Some("A test node".into()))
            .await
            .unwrap();
        let result = admin_nodes_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        let json = result.unwrap().0;
        let nodes = json["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1);
    }

    // ── Build allowlist handler tests ──

    #[tokio::test]
    async fn test_build_allowlist_get_rejects_no_auth() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_build_allowlist_get_handler(
            State(state),
            HeaderMap::new(),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_build_allowlist_get_accepts_valid_token() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_build_allowlist_get_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_ok());
        let json = result.unwrap().0;
        assert!(json.get("allowlist").is_some());
        assert!(json.get("enforcement").is_some());
    }

    #[tokio::test]
    async fn test_build_allowlist_add_rejects_no_auth() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let input = crate::models::RelayBuildHashAllowlistInput {
            build_hash: "abc123".into(),
            label: Some("test".into()),
        };
        let result = admin_build_allowlist_add_handler(
            State(state),
            HeaderMap::new(),
            Query(empty_params()),
            Json(input),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_build_allowlist_add_and_get() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let input = crate::models::RelayBuildHashAllowlistInput {
            build_hash: "deadbeef".into(),
            label: Some("v1.0".into()),
        };
        let result = admin_build_allowlist_add_handler(
            State(state.clone()),
            headers_with_token("admin-pass"),
            Query(empty_params()),
            Json(input),
        )
        .await;
        assert!(result.is_ok());
        let json = result.unwrap().0;
        assert_eq!(json["status"], "added");
        assert_eq!(json["build_hash"], "deadbeef");

        // Verify it shows in get
        let result = admin_build_allowlist_get_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        let json = result.unwrap().0;
        let allowlist = json["allowlist"].as_array().unwrap();
        assert_eq!(allowlist.len(), 1);
    }

    #[tokio::test]
    async fn test_build_allowlist_add_duplicate() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let input = crate::models::RelayBuildHashAllowlistInput {
            build_hash: "deadbeef".into(),
            label: Some("v1.0".into()),
        };
        // Add once
        let _ = admin_build_allowlist_add_handler(
            State(state.clone()),
            headers_with_token("admin-pass"),
            Query(empty_params()),
            Json(input.clone()),
        )
        .await
        .unwrap();

        // Add again
        let result = admin_build_allowlist_add_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
            Json(input),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0["status"], "already_exists");
    }

    #[tokio::test]
    async fn test_build_allowlist_set_replaces_all() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        // Add initial
        let _ = admin_build_allowlist_add_handler(
            State(state.clone()),
            headers_with_token("admin-pass"),
            Query(empty_params()),
            Json(crate::models::RelayBuildHashAllowlistInput {
                build_hash: "hash1".into(),
                label: None,
            }),
        )
        .await
        .unwrap();

        // Set entirely new list
        let new_list = vec![
            crate::models::RelayBuildHashAllowlistInput {
                build_hash: "new1".into(),
                label: Some("new-one".into()),
            },
            crate::models::RelayBuildHashAllowlistInput {
                build_hash: "new2".into(),
                label: None,
            },
        ];
        let result = admin_build_allowlist_set_handler(
            State(state.clone()),
            headers_with_token("admin-pass"),
            Query(empty_params()),
            Json(new_list),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0["count"], 2);

        // Verify old entry is gone
        let result = admin_build_allowlist_get_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        let allowlist = result.unwrap().0["allowlist"].as_array().unwrap().clone();
        assert_eq!(allowlist.len(), 2);
    }

    #[tokio::test]
    async fn test_build_allowlist_set_rejects_no_auth() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_build_allowlist_set_handler(
            State(state),
            HeaderMap::new(),
            Query(empty_params()),
            Json(vec![]),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_build_allowlist_remove() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let _ = admin_build_allowlist_add_handler(
            State(state.clone()),
            headers_with_token("admin-pass"),
            Query(empty_params()),
            Json(crate::models::RelayBuildHashAllowlistInput {
                build_hash: "removeme".into(),
                label: None,
            }),
        )
        .await
        .unwrap();

        let result = admin_build_allowlist_remove_handler(
            State(state),
            axum::extract::Path("removeme".to_string()),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0["status"], "removed");
    }

    #[tokio::test]
    async fn test_build_allowlist_remove_nonexistent() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_build_allowlist_remove_handler(
            State(state),
            axum::extract::Path("doesnotexist".to_string()),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_build_allowlist_remove_rejects_no_auth() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_build_allowlist_remove_handler(
            State(state),
            axum::extract::Path("anything".to_string()),
            HeaderMap::new(),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    // ── Audit log handler tests ──

    #[tokio::test]
    async fn test_audit_log_rejects_no_auth() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result =
            admin_audit_log_handler(State(state), HeaderMap::new(), Query(empty_params())).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_audit_log_accepts_valid_token() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_audit_log_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_ok());
        let json = result.unwrap().0;
        assert!(json.get("entries").is_some());
        assert!(json.get("total").is_some());
        assert!(json.get("page").is_some());
        assert!(json.get("per_page").is_some());
        assert!(json.get("total_pages").is_some());
    }

    #[tokio::test]
    async fn test_audit_log_pagination_defaults() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_audit_log_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        let json = result.unwrap().0;
        assert_eq!(json["page"], 1);
        assert_eq!(json["per_page"], 25);
    }

    #[tokio::test]
    async fn test_audit_log_custom_pagination() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let mut params = HashMap::new();
        params.insert("page".to_string(), "2".to_string());
        params.insert("per_page".to_string(), "10".to_string());
        let result = admin_audit_log_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(params),
        )
        .await;
        let json = result.unwrap().0;
        assert_eq!(json["page"], 2);
        assert_eq!(json["per_page"], 10);
    }

    #[tokio::test]
    async fn test_audit_log_per_page_capped_at_100() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let mut params = HashMap::new();
        params.insert("per_page".to_string(), "500".to_string());
        let result = admin_audit_log_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(params),
        )
        .await;
        let json = result.unwrap().0;
        assert_eq!(json["per_page"], 100);
    }

    #[tokio::test]
    async fn test_audit_log_page_minimum_is_1() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let mut params = HashMap::new();
        params.insert("page".to_string(), "0".to_string());
        let result = admin_audit_log_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(params),
        )
        .await;
        let json = result.unwrap().0;
        assert_eq!(json["page"], 1);
    }

    #[tokio::test]
    async fn test_audit_log_actions_rejects_no_auth() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result =
            admin_audit_log_actions_handler(State(state), HeaderMap::new(), Query(empty_params()))
                .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_audit_log_actions_accepts_valid_token() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let result = admin_audit_log_actions_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        assert!(result.is_ok());
        assert!(result.unwrap().0.get("actions").is_some());
    }

    // ── unauthorized() helper test ──

    #[test]
    fn test_unauthorized_response() {
        let (status, body) = unauthorized();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body.0["error"], "Invalid or missing admin token");
    }

    // ── get_rss_bytes sanity test ──

    #[test]
    fn test_get_rss_bytes_does_not_panic() {
        let _result = get_rss_bytes();
    }

    // ── new_log_broadcast test ──

    #[test]
    fn test_new_log_broadcast_creates_channel() {
        let tx = new_log_broadcast();
        let mut rx = tx.subscribe();
        tx.send("test line".to_string()).unwrap();
        let received = rx.try_recv().unwrap();
        assert_eq!(received, "test line");
    }
}
