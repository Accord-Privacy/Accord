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
//
// The admin dashboard is bound to 127.0.0.1 only (see main.rs), so localhost
// access IS the relay owner — no login needed. `ACCORD_ADMIN_TOKEN` is therefore
// OPTIONAL, defense-in-depth: unset (the norm) → allowed (localhost-trusted); set
// → a matching `x-admin-token` header is still required, for operators who expose
// the port through their own tunnel/reverse proxy and want an extra gate.

fn validate_admin_token(headers: &HeaderMap, _params: &HashMap<String, String>) -> bool {
    let expected = match std::env::var("ACCORD_ADMIN_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => return true, // No token configured → localhost access is authority
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
    let expected = match std::env::var("ACCORD_ADMIN_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => return true, // No token configured → localhost access is authority
    };
    // Try header first
    if let Some(hdr) = headers.get("x-admin-token") {
        if let Ok(val) = hdr.to_str() {
            if val.as_bytes().ct_eq(expected.as_bytes()).into() {
                return true;
            }
        }
    }
    // Fall back to query param for WebSocket only
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
    let connection_count: usize = state
        .connections
        .read()
        .await
        .values()
        .map(|d| d.len())
        .sum();
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

// A relay-wide user list (and its node_names correlation) is deliberately gone:
// the relay owner must not see who is in which node, nor a global roster.

/// Return the node registry (admin): id, name, description, created_at only.
/// No owner, no member/channel counts — the relay owner sees a name and a handle
/// to create/delete, nothing about who is inside.
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

// The relay-wide audit-log aggregate is deliberately gone: per-node governance
// (kicks, bans, role changes) and actor IPs are node business, not the relay's.
// Node owners still read their own node-scoped audit via get_node_audit_log.

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

    <!-- Nodes panel -->
    <div id="panel-nodes" class="panel">
      <div class="section">
        <h2>Node Registry</h2>
        <p style="color:#888;font-size:0.82em;margin-bottom:10px">Names and descriptions only — the relay cannot see who is inside a node.</p>
        <input class="search" placeholder="Search nodes..." oninput="filterTable('nodes-table', this.value)">
        <table><thead><tr><th>Name</th><th>ID</th><th>Created</th><th>Description</th></tr></thead>
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

// Localhost access is the relay owner — connect straight away. A token is only
// needed if the operator set ACCORD_ADMIN_TOKEN (e.g. exposing the port), in
// which case an unauthenticated request 401s and we show the login prompt.
function init() {
  adminToken = sessionStorage.getItem('accord_admin_token') || '';
  tryConnect();
}

function showLogin() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  document.getElementById('app').style.display = 'none';
  document.getElementById('login').style.display = 'flex';
}

async function doLogin() {
  const t = document.getElementById('token-input').value.trim();
  if (!t) return;
  adminToken = t;
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
  if (pollTimer) clearInterval(pollTimer);
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
    if (r.status === 401) { sessionStorage.removeItem('accord_admin_token'); showLogin(); return; }
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

async function loadNodes() {
  try {
    const r = await apiFetch('/admin/nodes');
    if (!r.ok) return;
    const d = await r.json();
    const tb = document.getElementById('nodes-table');
    tb.innerHTML = d.nodes.map(n =>
      `<tr><td>${esc(n.name)}</td><td class="mono">${esc(n.id.substring(0,8))}…</td><td>${fmtTime(n.created_at)}</td><td>${esc(n.description || '-')}</td></tr>`
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
    async fn test_admin_token_not_configured_allows_localhost() {
        // No token set → localhost access is the relay owner, so any request passes.
        let _g = set_admin_token(None).await;
        assert!(validate_admin_token(&HeaderMap::new(), &empty_params()));
    }

    #[tokio::test]
    async fn test_admin_token_configured_empty_allows_localhost() {
        // Empty token is treated as "no token" → localhost-trusted.
        let _g = set_admin_token(Some("")).await;
        assert!(validate_admin_token(&HeaderMap::new(), &empty_params()));
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
    async fn test_ws_no_token_configured_allows_localhost() {
        // No token set → the admin WS accepts localhost connections without creds.
        let _g = set_admin_token(None).await;
        assert!(validate_admin_token_ws(&HeaderMap::new(), &empty_params()));
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
        // Sentinel system user and node are created during DB init for DM channels
        assert_eq!(json["user_count"], 1); // system user
        assert_eq!(json["node_count"], 1); // system DM node
        assert_eq!(json["message_count"], 0);
        assert_eq!(json["connection_count"], 0);
    }

    #[tokio::test]
    async fn test_stats_reflects_connections() {
        let _g = set_admin_token(Some("admin-pass")).await;
        let state = make_test_state().await;
        let fake_id = uuid::Uuid::new_v4();
        let (tx, _rx) = broadcast::channel(1);
        state
            .connections
            .write()
            .await
            .entry(fake_id)
            .or_default()
            .insert(uuid::Uuid::new_v4(), tx);

        let result = admin_stats_handler(
            State(state),
            headers_with_token("admin-pass"),
            Query(empty_params()),
        )
        .await;
        let json = result.unwrap().0;
        assert_eq!(json["connection_count"], 1);
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
        assert_eq!(nodes.len(), 2); // system DM node + created node
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
