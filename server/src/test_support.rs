//! Shared harness for relay tests (SPEC-01 section 10.1).
//!
//! - The relay runs in-process on `127.0.0.1:0` and serves the production
//!   router from [`crate::router`], with connect information, exactly as the
//!   binary does.
//! - Every test account has a password ([`TEST_PASSWORD`]).
//! - Every membership comes from an invite that the node's owner created and
//!   the test user redeemed ([`join_with_owner_invite`],
//!   [`admit_with_owner_invite`]); raw rows for database-level tests come
//!   from `Database::seed_node_member`.
//! - [`LogCapture`] records the log events of the test's own thread.
//!
//! Only compiled for this crate's unit tests and with the `test-helpers`
//! feature, which no release build enables.

use crate::router;
use crate::state::{AppState, SharedState};
use axum::Router;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Password of every test account (registration requires one, REQ-4).
pub const TEST_PASSWORD: &str = "test-password";

/// Serve `app` on `127.0.0.1:0` with connect information, as the binary
/// does, and return its base URL (`http://127.0.0.1:<port>`).
pub async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a test listener");
    let addr = listener.local_addr().expect("listener address");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    format!("http://{addr}")
}

/// Serve the production public router over `state` and return its base URL.
pub async fn spawn_relay(state: SharedState) -> String {
    serve(router::build_public_router(state)).await
}

/// The node's owner creates a single-use invite through the relay's invite
/// creation path and returns its code.
pub async fn owner_invite_code(state: &AppState, node_id: Uuid) -> String {
    let node = state
        .db
        .get_node(node_id)
        .await
        .expect("read node")
        .expect("node exists");
    let (_, code) = state
        .create_invite(node_id, node.owner_id, Some(1), Some(24))
        .await
        .expect("the owner can create an invite");
    code
}

/// Admit `user_id` to `node_id` without HTTP: the owner creates an invite and
/// the user redeems it through the relay's admission entry point.
pub async fn admit_with_owner_invite(
    state: &AppState,
    node_id: Uuid,
    user_id: Uuid,
) -> Result<(), String> {
    let code = owner_invite_code(state, node_id).await;
    crate::admission::join(
        state,
        crate::admission::AdmissionContext::bare(user_id),
        crate::admission::AdmissionEntry::InviteCode { code },
    )
    .await
    .map(|_| ())
    .map_err(|e| e.message())
}

/// Redeem `code` over HTTP as the holder of `token` and return the status
/// and the JSON body. Uses `Authorization: Bearer`.
pub async fn redeem_invite(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    code: &str,
) -> (u16, Value) {
    let response = client
        .post(format!("{base_url}/invites/{code}/join"))
        .bearer_auth(token)
        .send()
        .await
        .expect("redeem request");
    let status = response.status().as_u16();
    let body = response.json().await.unwrap_or(Value::Null);
    (status, body)
}

/// Make the holder of `member_token` a member of `node_id`: the node's owner
/// creates an invite and the member redeems it over HTTP. Panics if the
/// redemption fails.
pub async fn join_with_owner_invite(
    client: &reqwest::Client,
    base_url: &str,
    state: &AppState,
    member_token: &str,
    node_id: Uuid,
) {
    let code = owner_invite_code(state, node_id).await;
    let (status, body) = redeem_invite(client, base_url, member_token, &code).await;
    assert_eq!(status, 200, "invite redemption failed: {body}");
}

/// A relay running in-process on the production router.
pub struct TestRelay {
    pub base_url: String,
    pub client: reqwest::Client,
    pub state: SharedState,
}

impl TestRelay {
    /// A relay over a fresh in-memory database.
    pub async fn start() -> Self {
        let state = Arc::new(
            AppState::new_in_memory()
                .await
                .expect("in-memory relay state"),
        );
        Self::with_state(state).await
    }

    /// A relay serving the given state.
    pub async fn with_state(state: SharedState) -> Self {
        let base_url = spawn_relay(state.clone()).await;
        Self {
            base_url,
            client: reqwest::Client::new(),
            state,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub fn ws_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.replacen("http://", "ws://", 1), path)
    }

    /// Register a v1 account with [`TEST_PASSWORD`] and log it in.
    pub async fn register_and_auth(&self, public_key: &str) -> (Uuid, String) {
        let response = self
            .client
            .post(self.url("/register"))
            .json(&json!({ "public_key": public_key, "password": TEST_PASSWORD }))
            .send()
            .await
            .expect("register request");
        assert_eq!(response.status().as_u16(), 200, "register failed");
        let body: Value = response.json().await.expect("register body");
        let user_id = body["user_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .expect("user_id");

        let response = self
            .client
            .post(self.url("/auth"))
            .json(&json!({ "public_key": public_key, "password": TEST_PASSWORD }))
            .send()
            .await
            .expect("auth request");
        assert_eq!(response.status().as_u16(), 200, "auth failed");
        let body: Value = response.json().await.expect("auth body");
        let token = body["token"].as_str().expect("token").to_string();
        (user_id, token)
    }

    /// Create a node as the holder of `token` and return its id.
    pub async fn create_node(&self, token: &str, name: &str) -> Uuid {
        let response = self
            .client
            .post(self.url("/nodes"))
            .bearer_auth(token)
            .json(&json!({ "name": name }))
            .send()
            .await
            .expect("create node request");
        assert_eq!(response.status().as_u16(), 200, "create node failed");
        let body: Value = response.json().await.expect("node body");
        body["id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .expect("node id")
    }

    /// See [`join_with_owner_invite`].
    pub async fn join_with_owner_invite(&self, member_token: &str, node_id: Uuid) {
        join_with_owner_invite(
            &self.client,
            &self.base_url,
            &self.state,
            member_token,
            node_id,
        )
        .await
    }
}

/// A WebSocket client of the test relay, authenticated after the upgrade as
/// the desktop does. As an observer it records the frames it receives for a
/// while after an action (SPEC-01 section 10.1).
pub struct WsClient {
    sink: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::Message,
    >,
    stream: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    /// The relay's `hello` frame on this connection.
    pub hello: Value,
}

impl WsClient {
    /// Connect to `/ws`, authenticate with `token`, wait until the relay has
    /// registered the connection (its `hello` frame), then drop the initial
    /// presence frames.
    pub async fn connect(relay: &TestRelay, token: &str) -> Self {
        use futures_util::{SinkExt, StreamExt};
        let (ws, _) = tokio_tungstenite::connect_async(relay.ws_url("/ws"))
            .await
            .expect("websocket connect");
        let (mut sink, stream) = ws.split();
        sink.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({ "Authenticate": { "token": token } }).to_string(),
        ))
        .await
        .expect("send Authenticate");
        let mut client = Self {
            sink,
            stream,
            hello: Value::Null,
        };
        client.hello = client
            .wait_for("hello", std::time::Duration::from_secs(5))
            .await
            .expect("hello frame");
        client
            .frames_for(std::time::Duration::from_millis(150))
            .await;
        client
    }

    /// Send a client message in the relay's envelope and return its
    /// `message_id`, which typed answers echo as `request_id`.
    pub async fn send(&mut self, message_type: Value) -> Uuid {
        use futures_util::SinkExt;
        let message_id = Uuid::new_v4();
        let envelope = json!({
            "message_type": message_type,
            "message_id": message_id,
            "timestamp": 0,
        });
        self.sink
            .send(tokio_tungstenite::tungstenite::Message::Text(
                envelope.to_string(),
            ))
            .await
            .expect("send websocket message");
        message_id
    }

    /// The next JSON text frame, or `None` after `timeout`.
    pub async fn next_frame(&mut self, timeout: std::time::Duration) -> Option<Value> {
        use futures_util::StreamExt;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.stream.next()).await {
                Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) => {
                    return Some(serde_json::from_str(&text).unwrap_or(Value::Null));
                }
                Ok(Some(Ok(_))) => continue,
                _ => return None,
            }
        }
    }

    /// Every frame received during `duration`.
    pub async fn frames_for(&mut self, duration: std::time::Duration) -> Vec<Value> {
        let deadline = tokio::time::Instant::now() + duration;
        let mut frames = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return frames;
            }
            match self.next_frame(remaining).await {
                Some(frame) => frames.push(frame),
                None => return frames,
            }
        }
    }

    /// Wait for the first frame of type `frame_type`, dropping others.
    pub async fn wait_for(
        &mut self,
        frame_type: &str,
        timeout: std::time::Duration,
    ) -> Option<Value> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let frame = self.next_frame(remaining).await?;
            if frame["type"] == frame_type {
                return Some(frame);
            }
        }
    }
}

/// Count the frames of type `frame_type`.
pub fn count_frames(frames: &[Value], frame_type: &str) -> usize {
    frames.iter().filter(|f| f["type"] == frame_type).count()
}

/// Captures formatted log events in memory.
///
/// [`LogCapture::start`] installs a formatting subscriber with
/// `tracing::subscriber::set_default`, which covers the current thread: the
/// whole relay when the test runs on tokio's default current-thread runtime.
/// Start it after setup, so that it records only the tested actions.
#[derive(Clone, Default)]
pub struct LogCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
}

/// Writer handed to the formatting layer; appends to the shared buffer.
pub struct CaptureWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for CaptureWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        match self.buffer.lock() {
            Ok(mut buffer) => buffer.extend_from_slice(data),
            Err(poisoned) => poisoned.into_inner().extend_from_slice(data),
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter {
            buffer: self.buffer.clone(),
        }
    }
}

impl LogCapture {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record events at `max_level` and above on this thread until the
    /// returned guard is dropped. Each line carries the level and the target.
    pub fn start(&self, max_level: tracing::Level) -> tracing::subscriber::DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(self.clone())
            .with_ansi(false)
            .with_target(true)
            .with_max_level(max_level)
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    /// Everything captured so far.
    pub fn text(&self) -> String {
        let bytes = match self.buffer.lock() {
            Ok(buffer) => buffer.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Captured lines.
    pub fn lines(&self) -> Vec<String> {
        self.text().lines().map(str::to_string).collect()
    }

    /// Captured lines of events with the given tracing target.
    pub fn lines_with_target(&self, target: &str) -> Vec<String> {
        let needle = format!(" {target}:");
        self.lines()
            .into_iter()
            .filter(|line| line.contains(&needle))
            .collect()
    }

    /// Forget everything captured so far.
    pub fn clear(&self) {
        match self.buffer.lock() {
            Ok(mut buffer) => buffer.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn log_capture_records_only_while_started() {
        let capture = LogCapture::new();
        tracing::warn!(target: "accord::admission", "before");
        {
            let _guard = capture.start(tracing::Level::INFO);
            tracing::warn!(target: "accord::admission", "during {}", 1);
            tracing::debug!(target: "accord::admission", "too verbose");
        }
        tracing::warn!(target: "accord::admission", "after");
        let lines = capture.lines_with_target("accord::admission");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("WARN") && lines[0].contains("during 1"));
    }

    #[tokio::test]
    async fn owner_invite_admits_a_member() {
        let relay = TestRelay::start().await;
        let (_, owner) = relay.register_and_auth("harness-owner").await;
        let (member_id, member) = relay.register_and_auth("harness-member").await;
        let node_id = relay.create_node(&owner, "Harness").await;
        relay.join_with_owner_invite(&member, node_id).await;
        assert!(relay
            .state
            .db
            .is_node_member(node_id, member_id)
            .await
            .unwrap());
        // The invite's creator is the owner, and it was used once.
        let invites = relay.state.db.get_node_invites(node_id).await.unwrap();
        assert_eq!(invites.len(), 1);
        assert_eq!(invites[0].current_uses, 1);
    }
}
