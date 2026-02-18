//! Admin dashboard routes for the Accord relay server.
//!
//! Auth-gated via `X-Admin-Token` header (or `?admin_token=` query param)
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
use tokio::sync::broadcast;

/// In-memory broadcast channel for log lines.
/// Handlers subscribe; a tracing layer pushes lines.
pub type LogBroadcast = broadcast::Sender<String>;

/// Create a new log broadcast channel (call once at startup, store in state or as a global).
pub fn new_log_broadcast() -> LogBroadcast {
    broadcast::channel::<String>(256).0
}

// ── Auth helper ──

fn validate_admin_token(headers: &HeaderMap, params: &HashMap<String, String>) -> bool {
    let expected = match std::env::var("ACCORD_ADMIN_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => return false, // No token configured → admin disabled
    };
    if let Some(hdr) = headers.get("x-admin-token") {
        if let Ok(val) = hdr.to_str() {
            if val == expected {
                return true;
            }
        }
    }
    if let Some(val) = params.get("admin_token") {
        if *val == expected {
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
    if !validate_admin_token(&headers, &params) {
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to set allowlist: {}", e)})),
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to add hash: {}", e)})),
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Failed to remove hash: {}", e)})),
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

init();
</script>
</body>
</html>"##;
