//! SPEC-02 section 11.2 step 2, first part: the relay's version-2 attachment
//! store. Schema (section 6.6.1), directory layout (6.6.2), upload (6.4.1),
//! download (6.4.2), delete (6.4.3), limits (6.6.4), garbage collection
//! (6.6.3) and reconciliation (REQ-42).
//!
//! Tests T-32, T-33, T-34 and T-38 to T-43 of section 10.2, and the relay
//! parts of RG-C150, RG-C156, RG-C160, RG-C161, RG-C001 (DM attachments) and
//! RG-C140 of section 10.3. The claim in `ChannelMessage` is tested in
//! `spec02_claim_legacy_test.rs`; here a claimed attachment is made with a
//! stored message and the `seed_claim_attachment` test helper, so that these
//! tests do not depend on the WebSocket path.
//!
//! Every relay runs the production router on `127.0.0.1:0` over a database,
//! a legacy file directory and an attachments directory in its own temporary
//! directory (section 10.1). Every account has a password and every
//! membership comes from an owner-created invite (SPEC-01 section 10.1).

use accord_server::attachments::{AttachmentConfig, FreeSpaceProbe, MARKER_FILE, TMP_DIR};
use accord_server::db::{DbOptions, DM_SYSTEM_NODE_ID};
use accord_server::faults::FaultKind;
use accord_server::files::FileConfig;
use accord_server::models::permission_bits;
use accord_server::rate_limit::RateLimiter;
use accord_server::state::{AppState, AppStateOptions};
use accord_server::test_support::{LogCapture, TestRelay, WsClient};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;
const OBSERVE: Duration = Duration::from_secs(2);

// ─────────────────────────────────────────────────────────────────────────
//  Harness
// ─────────────────────────────────────────────────────────────────────────

/// Start a relay over `dir`: `relay.db`, the legacy directory `files` and the
/// attachments directory `attachments`. `configure` adjusts the attachment
/// settings; `unlimited_rate` replaces the rate limiter by a disabled one, as
/// the concurrency tests need.
async fn start(
    dir: &tempfile::TempDir,
    configure: impl FnOnce(&mut AttachmentConfig),
    unlimited_rate: bool,
) -> TestRelay {
    let mut config = AttachmentConfig::with_dir(dir.path().join("attachments"));
    configure(&mut config);
    let mut state = AppState::new_with_options(
        dir.path().join("relay.db").to_str().unwrap(),
        options(dir, config),
    )
    .await
    .expect("relay state");
    if unlimited_rate {
        state.rate_limiter = RateLimiter::new_disabled();
    }
    TestRelay::with_state(Arc::new(state)).await
}

fn options(dir: &tempfile::TempDir, config: AttachmentConfig) -> AppStateOptions {
    AppStateOptions {
        database_encryption: false,
        db: DbOptions::default(),
        file_config: Some(FileConfig {
            storage_dir: dir.path().join("files"),
            max_file_size: MIB as u64,
        }),
        attachments: Some(config),
    }
}

fn pool(relay: &TestRelay) -> &SqlitePool {
    relay.state.db.raw_pool()
}

async fn scalar(relay: &TestRelay, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool(relay))
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// The state code of an attachment row, or `None` if there is none.
async fn row_state(relay: &TestRelay, id: Uuid) -> Option<i64> {
    sqlx::query_scalar("SELECT state FROM attachments WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool(relay))
        .await
        .unwrap()
}

async fn row_count(relay: &TestRelay) -> i64 {
    scalar(relay, "SELECT COUNT(*) FROM attachments").await
}

/// The ids of `user`'s upload reservations (state 2).
async fn uploading_ids(relay: &TestRelay, user: Uuid) -> Vec<Uuid> {
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM attachments WHERE state = 2 AND uploader_id = ?")
            .bind(user.to_string())
            .fetch_all(pool(relay))
            .await
            .unwrap();
    ids.iter().map(|id| Uuid::parse_str(id).unwrap()).collect()
}

/// Wait until `user` has exactly one upload reservation and return its id.
async fn wait_for_reservation(relay: &TestRelay, user: Uuid) -> Uuid {
    for _ in 0..100 {
        let ids = uploading_ids(relay, user).await;
        if ids.len() == 1 {
            return ids[0];
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no upload reservation appeared");
}

/// Poll `condition` every 50 ms for up to `within`.
async fn eventually<F, Fut>(within: Duration, mut condition: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if condition().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A deterministic blob of `len` bytes.
fn blob(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i % 251) as u8).wrapping_add(seed))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Names of the entries directly inside `dir`, sorted.
fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// The attachments directory holds only the marker and an empty `.tmp`.
fn assert_store_empty(relay: &TestRelay) {
    let store = &relay.state.attachments;
    assert_eq!(
        listing(store.dir()),
        vec![MARKER_FILE.to_string(), TMP_DIR.to_string()],
        "attachments directory"
    );
    assert!(listing(store.tmp_dir()).is_empty(), "the .tmp directory");
}

/// Set a file's modification time `age` into the past.
fn age_file(path: &Path, age: Duration) {
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::now() - age).unwrap();
}

fn write_file(path: &Path, bytes: &[u8], age: Option<Duration>) {
    std::fs::write(path, bytes).unwrap();
    if let Some(age) = age {
        age_file(path, age);
    }
}

// ── Accounts and channels ──

type Account = (Uuid, String);

/// A node with its owner, a member who joined by the owner's invite, an
/// outsider, and the node's default channel.
struct NodeFixture {
    owner: Account,
    member: Account,
    outsider: Account,
    node: Uuid,
    channel: Uuid,
}

async fn node_fixture(relay: &TestRelay, tag: &str) -> NodeFixture {
    let owner = relay.register_and_auth(&format!("{tag}-owner")).await;
    let member = relay.register_and_auth(&format!("{tag}-member")).await;
    let outsider = relay.register_and_auth(&format!("{tag}-outsider")).await;
    let node = relay.create_node(&owner.1, tag).await;
    relay.join_with_owner_invite(&member.1, node).await;
    let channel = relay.state.db.get_node_channels(node).await.unwrap()[0].id;
    NodeFixture {
        owner,
        member,
        outsider,
        node,
        channel,
    }
}

/// `u` and `v` become friends through a node they share and `u` opens their
/// DM over REST. Returns the DM channel.
async fn open_dm(relay: &TestRelay, u: &Account, v: &Account, shared_node: Uuid) -> Uuid {
    let request = relay
        .state
        .db
        .create_friend_request(u.0, v.0, shared_node, None)
        .await
        .unwrap();
    assert!(relay
        .state
        .db
        .accept_friend_request(request, None)
        .await
        .unwrap());
    let response = relay
        .client
        .post(relay.url(&format!("/dm/{}", v.0)))
        .bearer_auth(&u.1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
}

// ── HTTP ──

/// A JSON answer with its status and `Retry-After` header.
#[derive(Debug)]
struct Answer {
    status: u16,
    body: Value,
    retry_after: Option<u64>,
}

impl Answer {
    async fn read(response: reqwest::Response) -> Self {
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let text = response.text().await.unwrap_or_default();
        Self {
            status,
            body: serde_json::from_str(&text).unwrap_or(Value::Null),
            retry_after,
        }
    }

    fn reason(&self) -> &str {
        self.body["reason"].as_str().unwrap_or("")
    }

    /// The `attachment_id` of a 201 answer.
    fn id(&self) -> Uuid {
        assert_eq!(self.status, 201, "{:?}", self.body);
        Uuid::parse_str(self.body["attachment_id"].as_str().unwrap()).unwrap()
    }
}

async fn upload(relay: &TestRelay, token: &str, channel: Uuid, body: Vec<u8>) -> Answer {
    let response = relay
        .client
        .post(relay.url(&format!("/channels/{channel}/attachments")))
        .bearer_auth(token)
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .unwrap();
    Answer::read(response).await
}

async fn upload_id(relay: &TestRelay, token: &str, channel: Uuid, len: usize) -> Uuid {
    upload(relay, token, channel, blob(len, 7)).await.id()
}

async fn download(relay: &TestRelay, token: &str, id: Uuid) -> reqwest::Response {
    relay
        .client
        .get(relay.url(&format!("/attachments/{id}")))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

async fn download_status(relay: &TestRelay, token: &str, id: Uuid) -> (u16, String) {
    let answer = Answer::read(download(relay, token, id).await).await;
    (answer.status, answer.reason().to_string())
}

async fn delete(relay: &TestRelay, token: &str, id: Uuid) -> Answer {
    let response = relay
        .client
        .delete(relay.url(&format!("/attachments/{id}")))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    Answer::read(response).await
}

/// Store a message from `sender` in `channel` and claim `attachment` for
/// it, as the claim of REQ-35 does. Returns the message id.
async fn claim(
    relay: &TestRelay,
    channel: Uuid,
    sender: Uuid,
    attachment: Uuid,
    expires_at: Option<u64>,
) -> Uuid {
    let (message_id, _) = relay
        .state
        .db
        .store_message(channel, sender, b"sealed payload", None, expires_at)
        .await
        .unwrap();
    assert!(relay
        .state
        .db
        .seed_claim_attachment(attachment, message_id)
        .await
        .unwrap());
    message_id
}

/// Upload a blob as `account` and claim it for a new message of theirs.
/// Returns (attachment id, message id).
async fn attach(
    relay: &TestRelay,
    account: &Account,
    channel: Uuid,
    expires_at: Option<u64>,
) -> (Uuid, Uuid) {
    let id = upload_id(relay, &account.1, channel, 64).await;
    let message = claim(relay, channel, account.0, id, expires_at).await;
    (id, message)
}

// ── Raw HTTP/1.1, for requests whose body is still being sent ──

#[derive(Debug)]
struct RawAnswer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

impl RawAnswer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn reason(&self) -> &str {
        self.body["reason"].as_str().unwrap_or("")
    }
}

/// How a raw upload request authenticates.
#[derive(Clone, Copy)]
enum Auth<'a> {
    Bearer(&'a str),
    QueryOnly(&'a str),
}

/// The head of `POST /channels/{channel}/attachments`.
fn upload_head(channel: Uuid, auth: Auth<'_>, framing: &str, content_type: &str) -> String {
    let (query, authorization) = match auth {
        Auth::Bearer(token) => (String::new(), format!("Authorization: Bearer {token}\r\n")),
        Auth::QueryOnly(token) => (format!("?token={token}"), String::new()),
    };
    format!(
        "POST /channels/{channel}/attachments{query} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         {authorization}Content-Type: {content_type}\r\n{framing}\r\n"
    )
}

fn length(len: usize) -> String {
    format!("Content-Length: {len}\r\n")
}

/// Connect and send `head` followed by `first_bytes` of the body in one
/// write. The rest of the body, if any, is never sent unless the test sends
/// it on the returned stream.
async fn raw_send(relay: &TestRelay, head: &str, first_bytes: &[u8]) -> TcpStream {
    let addr = relay.base_url.trim_start_matches("http://").to_string();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut bytes = head.as_bytes().to_vec();
    bytes.extend_from_slice(first_bytes);
    stream.write_all(&bytes).await.unwrap();
    stream
}

/// Read one HTTP answer from `stream` within 10 s.
async fn read_answer(stream: &mut TcpStream) -> RawAnswer {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        let head_end = loop {
            if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            let read = stream.read(&mut chunk).await.expect("read the answer");
            assert!(read > 0, "the connection closed before an answer");
            buffer.extend_from_slice(&chunk[..read]);
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split(' ').nth(1))
            .and_then(|code| code.parse().ok())
            .expect("status line");
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let body_len: usize = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);
        while buffer.len() < head_end + body_len {
            let read = stream.read(&mut chunk).await.unwrap_or(0);
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let end = (head_end + body_len).min(buffer.len());
        RawAnswer {
            status,
            headers,
            body: serde_json::from_slice(&buffer[head_end..end]).unwrap_or(Value::Null),
        }
    })
    .await
    .expect("an answer within 10 s")
}

/// Send the head of a 50 MiB upload and its first kilobyte, and read the
/// answer the relay gives while the rest of the body is still unsent.
async fn early_answer(relay: &TestRelay, channel: Uuid, auth: Auth<'_>) -> RawAnswer {
    let head = upload_head(channel, auth, &length(50 * MIB), "application/octet-stream");
    let mut stream = raw_send(relay, &head, &blob(KIB, 1)).await;
    read_answer(&mut stream).await
}

// ─────────────────────────────────────────────────────────────────────────
//  T-32 (REQ-32) and RG-C156: upload authorization before the body
// ─────────────────────────────────────────────────────────────────────────

/// T-32 and RG-C156: every refusal arrives while the client is still sending
/// a 50 MiB body, and leaves the attachments directory, `.tmp` and the table
/// empty.
#[tokio::test]
async fn t32_rg_c156_upload_authorization_answers_before_the_body() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, false).await;
    let f = node_fixture(&relay, "t32").await;
    let db = &relay.state.db;
    let everyone = f.node;

    let check = |answer: RawAnswer, status: u16, reason: &str, case: &str| {
        assert_eq!(answer.status, status, "{case}: {answer:?}");
        assert_eq!(answer.reason(), reason, "{case}: {answer:?}");
    };

    // `?token=` only: unauthenticated.
    let answer = early_answer(&relay, f.channel, Auth::QueryOnly(&f.member.1)).await;
    assert_eq!(answer.status, 401, "{answer:?}");

    // SEND_MESSAGES, ATTACH_FILES and VIEW_CHANNEL denied by an overwrite.
    for (bit, case) in [
        (permission_bits::SEND_MESSAGES, "SEND_MESSAGES denied"),
        (permission_bits::ATTACH_FILES, "ATTACH_FILES denied"),
        (permission_bits::VIEW_CHANNEL, "VIEW_CHANNEL denied"),
    ] {
        db.set_channel_overwrite(f.channel, everyone, 0, bit)
            .await
            .unwrap();
        let answer = early_answer(&relay, f.channel, Auth::Bearer(&f.member.1)).await;
        check(answer, 403, "forbidden", case);
        db.delete_channel_overwrite(f.channel, everyone)
            .await
            .unwrap();
    }

    // A DM: an outsider is refused, and so is a blocked participant.
    let dm = open_dm(&relay, &f.owner, &f.member, f.node).await;
    let answer = early_answer(&relay, dm, Auth::Bearer(&f.outsider.1)).await;
    check(answer, 403, "forbidden", "DM non-participant");
    db.block_user(f.owner.0, f.member.0).await.unwrap();
    let answer = early_answer(&relay, dm, Auth::Bearer(&f.member.1)).await;
    check(answer, 403, "blocked", "DM blocked");

    // An active slow-mode cooldown: 429 with the remaining time.
    db.set_channel_slow_mode(f.channel, 60).await.unwrap();
    relay
        .state
        .slow_mode_cooldowns
        .write()
        .await
        .insert((f.channel, f.member.0), unix_now());
    let answer = early_answer(&relay, f.channel, Auth::Bearer(&f.member.1)).await;
    let retry_after = answer.body["retry_after"].as_u64().unwrap_or(0);
    assert!((50..=60).contains(&retry_after), "{answer:?}");
    assert_eq!(
        answer.header("retry-after"),
        Some(retry_after.to_string().as_str())
    );
    check(answer, 429, "slow_mode", "slow mode");
    db.set_channel_slow_mode(f.channel, 0).await.unwrap();

    // The node's build allowlist does not hold the member's build.
    db.add_build_hash_to_allowlist(f.node, "approved-build", f.owner.0, None)
        .await
        .unwrap();
    let answer = early_answer(&relay, f.channel, Auth::Bearer(&f.member.1)).await;
    check(answer, 403, "forbidden", "allowlist mismatch");

    // A channel that does not exist, and a malformed channel id.
    let answer = early_answer(&relay, Uuid::new_v4(), Auth::Bearer(&f.member.1)).await;
    check(answer, 404, "not_found", "unknown channel");

    assert_eq!(row_count(&relay).await, 0);
    assert_store_empty(&relay);

    // An authorization error denies with 500 and keeps nothing.
    db.remove_build_hash_from_allowlist(f.node, "approved-build")
        .await
        .unwrap();
    relay.state.faults().arm("dm:lookup", FaultKind::Busy);
    let answer = early_answer(&relay, f.channel, Auth::Bearer(&f.member.1)).await;
    check(answer, 500, "internal", "DM lookup error");
    assert!(!relay.state.faults().is_armed("dm:lookup"));
    assert_eq!(row_count(&relay).await, 0);
    assert_store_empty(&relay);

    // With every right in place the same request is accepted.
    let ok = upload(&relay, &f.member.1, f.channel, blob(32, 0)).await;
    assert_eq!(ok.status, 201, "{ok:?}");
}

// ─────────────────────────────────────────────────────────────────────────
//  T-33 (REQ-33), RG-C160, RG-C161: limits, checked and reserved atomically
// ─────────────────────────────────────────────────────────────────────────

/// T-33: the request's shape is checked before any body byte is read.
#[tokio::test]
async fn t33_request_shape_is_checked_before_the_body() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |c| c.max_blob_bytes = MIB as u64, true).await;
    let f = node_fixture(&relay, "t33s").await;
    let token = f.member.1.as_str();

    // A chunked body without a length: 411.
    let head = upload_head(
        f.channel,
        Auth::Bearer(token),
        "Transfer-Encoding: chunked\r\n",
        "application/octet-stream",
    );
    let mut chunk = b"10\r\n".to_vec();
    chunk.extend_from_slice(&[0u8; 16]);
    chunk.extend_from_slice(b"\r\n");
    let mut stream = raw_send(&relay, &head, &chunk).await;
    let answer = read_answer(&mut stream).await;
    assert_eq!((answer.status, answer.reason()), (411, "length_required"));

    // Another content type: 415.
    let response = relay
        .client
        .post(relay.url(&format!("/channels/{}/attachments", f.channel)))
        .bearer_auth(token)
        .header("content-type", "text/plain")
        .body(vec![0u8; 32])
        .send()
        .await
        .unwrap();
    let answer = Answer::read(response).await;
    assert_eq!(
        (answer.status, answer.reason()),
        (415, "unsupported_media_type")
    );

    // One byte above the limit: 413 at once, although no body byte was sent.
    let head = upload_head(
        f.channel,
        Auth::Bearer(token),
        &length(MIB + 1),
        "application/octet-stream",
    );
    let mut stream = raw_send(&relay, &head, b"").await;
    let answer = read_answer(&mut stream).await;
    assert_eq!((answer.status, answer.reason()), (413, "too_large"));
    assert_eq!(answer.body["code"], 413);
    assert!(answer.body["error"].is_string());

    // Below the smallest blob: 400.
    let answer = upload(&relay, token, f.channel, vec![0u8; 15]).await;
    assert_eq!((answer.status, answer.reason()), (400, "bad_request"));
    let response = relay
        .client
        .post(relay.url("/channels/not-a-uuid/attachments"))
        .bearer_auth(token)
        .header("content-type", "application/octet-stream")
        .body(vec![0u8; 32])
        .send()
        .await
        .unwrap();
    let answer = Answer::read(response).await;
    assert_eq!((answer.status, answer.reason()), (400, "bad_request"));

    assert_eq!(row_count(&relay).await, 0);
    assert_store_empty(&relay);

    // Exactly the limit: accepted.
    let answer = upload(&relay, token, f.channel, blob(MIB, 3)).await;
    assert_eq!(answer.status, 201, "{answer:?}");
    assert_eq!(answer.body["blob_size"], MIB as u64);
}

/// T-33 and RG-C160: Bearer uploads are rate limited inside the handler; the
/// 11th in a minute gets 429 with `Retry-After`.
#[tokio::test]
async fn t33_rg_c160_bearer_uploads_are_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, false).await;
    let f = node_fixture(&relay, "t33r").await;
    let mut answers = Vec::new();
    for _ in 0..12 {
        answers.push(upload(&relay, &f.member.1, f.channel, blob(16, 0)).await);
    }
    for answer in &answers[..10] {
        assert_eq!(answer.status, 201, "{answer:?}");
    }
    for answer in &answers[10..] {
        assert_eq!((answer.status, answer.reason()), (429, "rate_limited"));
        let retry_after = answer.retry_after.expect("Retry-After");
        assert!((1..=60).contains(&retry_after), "{answer:?}");
        assert_eq!(answer.body["retry_after"], retry_after);
    }
    assert_eq!(row_count(&relay).await, 10);
}

/// T-33: the 33rd pending upload gets 429 `too_many_pending`, with a
/// `Retry-After` equal (within 2 s) to the time until the oldest pending
/// upload expires. Upload reservations count toward the cap.
#[tokio::test]
async fn t33_pending_cap_counts_uploads_and_reservations() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t33p").await;
    let store = &relay.state.attachments;

    let first = upload(&relay, &f.member.1, f.channel, blob(16, 0)).await;
    let first_id = first.id();
    let oldest_expiry = first.body["pending_expires_at"].as_i64().unwrap();
    store.advance_clock(600);
    for _ in 1..32 {
        upload_id(&relay, &f.member.1, f.channel, 16).await;
    }
    let sent_at = store.now();
    let refused = upload(&relay, &f.member.1, f.channel, blob(16, 0)).await;
    let answered_at = store.now();
    assert_eq!(
        (refused.status, refused.reason()),
        (429, "too_many_pending"),
        "{refused:?}"
    );
    // The time until the oldest pending upload expires, as of the request.
    let retry_after = refused.retry_after.expect("Retry-After") as i64;
    assert!(
        (oldest_expiry - answered_at..=oldest_expiry - sent_at).contains(&retry_after),
        "Retry-After {retry_after}, oldest expiry {oldest_expiry}, now {sent_at}..{answered_at}"
    );
    assert!(retry_after > 2900, "{retry_after}");
    assert_eq!(refused.body["retry_after"], retry_after);

    // Deleting one frees a slot, which an upload reservation then fills.
    assert_eq!(delete(&relay, &f.member.1, first_id).await.status, 204);
    let head = upload_head(
        f.channel,
        Auth::Bearer(&f.member.1),
        &length(MIB),
        "application/octet-stream",
    );
    let stream = raw_send(&relay, &head, &blob(KIB, 0)).await;
    wait_for_reservation(&relay, f.member.0).await;
    let refused = upload(&relay, &f.member.1, f.channel, blob(16, 0)).await;
    assert_eq!(
        (refused.status, refused.reason()),
        (429, "too_many_pending")
    );
    drop(stream);
    // Another user is not affected by this user's cap.
    let other = upload(&relay, &f.owner.1, f.channel, blob(16, 0)).await;
    assert_eq!(other.status, 201, "{other:?}");
}

/// T-33: the per-user and per-node quotas (DM channels excluded from the
/// node's) and the free-space floor.
#[tokio::test]
async fn t33_quotas_and_free_space_floor() {
    // User quota 1 MiB: a second 600 KiB upload is refused, until the first
    // is deleted.
    let dir = tempfile::tempdir().unwrap();
    let relay = start(
        &dir,
        |c| {
            c.quota_user_bytes = MIB as u64;
            c.quota_node_bytes = 0;
        },
        true,
    )
    .await;
    let f = node_fixture(&relay, "t33q").await;
    let first = upload_id(&relay, &f.member.1, f.channel, 600 * KIB).await;
    let answer = upload(&relay, &f.member.1, f.channel, blob(600 * KIB, 1)).await;
    assert_eq!((answer.status, answer.reason()), (507, "quota_exceeded"));
    // Claimed bytes count as well.
    claim(&relay, f.channel, f.member.0, first, None).await;
    let answer = upload(&relay, &f.member.1, f.channel, blob(600 * KIB, 1)).await;
    assert_eq!((answer.status, answer.reason()), (507, "quota_exceeded"));
    // Another user has a quota of their own.
    let answer = upload(&relay, &f.owner.1, f.channel, blob(600 * KIB, 1)).await;
    assert_eq!(answer.status, 201, "{answer:?}");

    // Node quota 1 MiB: a second member's 600 KiB upload in the same node is
    // refused; the same upload into their DM is not counted against the node.
    let dir = tempfile::tempdir().unwrap();
    let relay = start(
        &dir,
        |c| {
            c.quota_user_bytes = 0;
            c.quota_node_bytes = MIB as u64;
        },
        true,
    )
    .await;
    let f = node_fixture(&relay, "t33n").await;
    upload_id(&relay, &f.owner.1, f.channel, 600 * KIB).await;
    let answer = upload(&relay, &f.member.1, f.channel, blob(600 * KIB, 1)).await;
    assert_eq!((answer.status, answer.reason()), (507, "quota_exceeded"));
    let dm = open_dm(&relay, &f.owner, &f.member, f.node).await;
    let answer = upload(&relay, &f.member.1, dm, blob(600 * KIB, 1)).await;
    assert_eq!(answer.status, 201, "{answer:?}");

    // Free space below the floor: 507 `storage_full`; a failing probe: 500.
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |c| c.min_free_bytes = MIB as u64, true).await;
    let f = node_fixture(&relay, "t33f").await;
    let store = &relay.state.attachments;
    store.set_free_space_probe(Arc::new(|_: &Path| -> std::io::Result<u64> {
        Ok(MIB as u64 + 100)
    }));
    let answer = upload(&relay, &f.member.1, f.channel, blob(64, 0)).await;
    assert_eq!(answer.status, 201, "{answer:?}");
    let answer = upload(&relay, &f.member.1, f.channel, blob(128, 0)).await;
    assert_eq!((answer.status, answer.reason()), (507, "storage_full"));
    store.set_free_space_probe(Arc::new(|_: &Path| -> std::io::Result<u64> {
        Err(std::io::Error::other("statvfs failed"))
    }));
    let answer = upload(&relay, &f.member.1, f.channel, blob(64, 0)).await;
    assert_eq!((answer.status, answer.reason()), (500, "internal"));
    assert_eq!(row_count(&relay).await, 1);
}

/// Bytes stored in the attachments directory and its `.tmp`, as a disk
/// would see them.
fn bytes_on_disk(dir: &Path) -> u64 {
    let mut total = 0;
    for sub in [dir.to_path_buf(), dir.join(TMP_DIR)] {
        if let Ok(entries) = std::fs::read_dir(&sub) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        total += meta.len();
                    }
                }
            }
        }
    }
    total
}

/// Run `count` uploads of `size` bytes at once, spread over `tokens`, and
/// return the answers.
async fn parallel_uploads(
    relay: &TestRelay,
    tokens: &[String],
    channel: Uuid,
    count: usize,
    size: usize,
) -> Vec<Answer> {
    let body = blob(size, 9);
    futures_util::future::join_all((0..count).map(|i| {
        let token = tokens[i % tokens.len()].clone();
        let body = body.clone();
        async move { upload(relay, &token, channel, body).await }
    }))
    .await
}

/// T-33 and RG-C161: under concurrency the pending cap, the quotas and the
/// free-space floor are never exceeded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t33_rg_c161_concurrent_reservations_respect_every_limit() {
    // 40 uploads at once by one user: at most 32 are accepted.
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t33c").await;
    let answers =
        parallel_uploads(&relay, std::slice::from_ref(&f.member.1), f.channel, 40, 16).await;
    let accepted = answers.iter().filter(|a| a.status == 201).count();
    let capped = answers
        .iter()
        .filter(|a| a.status == 429 && a.reason() == "too_many_pending")
        .count();
    assert_eq!((accepted, capped), (32, 8), "{answers:?}");

    // User quota 10 MiB, 40 parallel 1 MiB uploads.
    let dir = tempfile::tempdir().unwrap();
    let relay = start(
        &dir,
        |c| {
            c.max_pending_per_user = 100;
            c.quota_user_bytes = 10 * MIB as u64;
        },
        true,
    )
    .await;
    let f = node_fixture(&relay, "t33u").await;
    let answers = parallel_uploads(
        &relay,
        std::slice::from_ref(&f.member.1),
        f.channel,
        40,
        MIB,
    )
    .await;
    let accepted = answers.iter().filter(|a| a.status == 201).count();
    assert!(
        answers
            .iter()
            .all(|a| a.status == 201 || (a.status == 507 && a.reason() == "quota_exceeded")),
        "{answers:?}"
    );
    assert_eq!(accepted, 10, "accepted bytes must stay within the quota");
    assert_eq!(
        scalar(&relay, "SELECT SUM(blob_size) FROM attachments").await,
        10 * MIB as i64
    );

    // Node quota 10 MiB, several users.
    let dir = tempfile::tempdir().unwrap();
    let relay = start(
        &dir,
        |c| {
            c.max_pending_per_user = 100;
            c.quota_user_bytes = 0;
            c.quota_node_bytes = 10 * MIB as u64;
        },
        true,
    )
    .await;
    let f = node_fixture(&relay, "t33nq").await;
    let mut tokens = vec![f.owner.1.clone(), f.member.1.clone()];
    for i in 0..2 {
        let extra = relay.register_and_auth(&format!("t33nq-extra-{i}")).await;
        relay.join_with_owner_invite(&extra.1, f.node).await;
        tokens.push(extra.1);
    }
    let answers = parallel_uploads(&relay, &tokens, f.channel, 40, MIB).await;
    let accepted = answers.iter().filter(|a| a.status == 201).count();
    assert!(accepted <= 10, "{accepted} accepted");
    assert_eq!(accepted, 10, "{answers:?}");

    // The free-space floor, with a disk whose free space shrinks as blobs
    // are written: 11 MiB free and a floor of 1 MiB leave room for 10 MiB.
    let dir = tempfile::tempdir().unwrap();
    let relay = start(
        &dir,
        |c| {
            c.max_pending_per_user = 100;
            c.quota_user_bytes = 0;
            c.quota_node_bytes = 0;
            c.min_free_bytes = MIB as u64;
        },
        true,
    )
    .await;
    let f = node_fixture(&relay, "t33fl").await;
    let probe: FreeSpaceProbe = Arc::new(|dir: &Path| -> std::io::Result<u64> {
        Ok((11 * MIB as u64).saturating_sub(bytes_on_disk(dir)))
    });
    relay.state.attachments.set_free_space_probe(probe);
    let mut tokens = vec![f.owner.1.clone(), f.member.1.clone()];
    for i in 0..2 {
        let extra = relay.register_and_auth(&format!("t33fl-extra-{i}")).await;
        relay.join_with_owner_invite(&extra.1, f.node).await;
        tokens.push(extra.1);
    }
    let answers = parallel_uploads(&relay, &tokens, f.channel, 40, MIB).await;
    let accepted = answers.iter().filter(|a| a.status == 201).count();
    assert!(
        answers
            .iter()
            .all(|a| a.status == 201 || (a.status == 507 && a.reason() == "storage_full")),
        "{answers:?}"
    );
    assert!((1..=10).contains(&accepted), "{accepted} accepted");
    assert!(bytes_on_disk(relay.state.attachments.dir()) <= 10 * MIB as u64);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-34 (REQ-34) and RG-C150: streaming upload
// ─────────────────────────────────────────────────────────────────────────

/// T-34 and RG-C150: 3 MiB and 50 MiB uploads stream to disk and answer 201
/// with the relay's size and hash; the body streams through `.tmp` under an
/// upload reservation, and an aborted upload leaves nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t34_rg_c150_uploads_stream_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t34").await;
    let store = &relay.state.attachments;

    for (size, seed) in [(3 * MIB, 1u8), (50 * MIB, 2u8)] {
        let body = blob(size, seed);
        let sent_at = store.now();
        let answer = upload(&relay, &f.member.1, f.channel, body.clone()).await;
        let answered_at = store.now();
        let id = answer.id();
        assert_eq!(answer.body["blob_size"], size as u64);
        assert_eq!(answer.body["blob_sha256"], sha256_hex(&body));
        // `pending_expires_at` is the relay's clock at completion plus the TTL.
        let expires = answer.body["pending_expires_at"].as_i64().unwrap();
        assert!(
            (sent_at + 3600..=answered_at + 3600).contains(&expires),
            "{expires} not within [{sent_at}, {answered_at}] + 3600"
        );
        assert_eq!(
            id.to_string(),
            answer.body["attachment_id"].as_str().unwrap()
        );
        assert_eq!(std::fs::read(store.blob_path(id)).unwrap(), body);
        assert_eq!(row_state(&relay, id).await, Some(0));
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT blob_sha256 FROM attachments WHERE id = ?")
                .bind(id.to_string())
                .fetch_one(pool(&relay))
                .await
                .unwrap();
        assert_eq!(hex::encode(stored), sha256_hex(&body));
    }
    // The handler held at most one body chunk at a time, never the blob.
    let peak = store.peak_upload_chunk_bytes();
    assert!(peak > 0 && peak <= MIB as u64, "peak chunk {peak}");

    // While the body streams, the row is an upload reservation and the bytes
    // are in `.tmp/<id>.part`; the final blob appears only at the end.
    let body = blob(MIB, 5);
    let head = upload_head(
        f.channel,
        Auth::Bearer(&f.member.1),
        &length(MIB),
        "application/octet-stream",
    );
    let mut stream = raw_send(&relay, &head, &body[..MIB / 2]).await;
    let id = wait_for_reservation(&relay, f.member.0).await;
    assert_eq!(row_state(&relay, id).await, Some(2));
    assert!(
        eventually(OBSERVE, || async {
            std::fs::metadata(store.part_path(id))
                .map(|m| m.len() > 0)
                .unwrap_or(false)
        })
        .await
    );
    assert!(!store.blob_path(id).exists());
    stream.write_all(&body[MIB / 2..]).await.unwrap();
    let answer = read_answer(&mut stream).await;
    assert_eq!(answer.status, 201, "{answer:?}");
    assert_eq!(answer.body["attachment_id"], id.to_string());
    assert_eq!(row_state(&relay, id).await, Some(0));
    assert!(!store.part_path(id).exists());
    assert_eq!(std::fs::read(store.blob_path(id)).unwrap(), body);

    // Aborted half-way: no row and no file.
    let mut stream = raw_send(&relay, &head, &body[..MIB / 2]).await;
    let id = wait_for_reservation(&relay, f.member.0).await;
    stream.shutdown().await.ok();
    drop(stream);
    assert!(
        eventually(Duration::from_secs(5), || async {
            row_state(&relay, id).await.is_none()
                && !store.part_path(id).exists()
                && !store.blob_path(id).exists()
        })
        .await,
        "the aborted upload left a row or a file"
    );

    // Above the default 100 MiB limit: a JSON 413 without reading.
    let head = upload_head(
        f.channel,
        Auth::Bearer(&f.member.1),
        &length(100 * MIB + 1),
        "application/octet-stream",
    );
    let mut stream = raw_send(&relay, &head, b"").await;
    let answer = read_answer(&mut stream).await;
    assert_eq!((answer.status, answer.reason()), (413, "too_large"));
    assert_eq!(answer.header("content-type"), Some("application/json"));

    // The row has no name, MIME type or path column.
    let columns: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('attachments')")
            .fetch_all(pool(&relay))
            .await
            .unwrap();
    assert_eq!(
        columns,
        [
            "id",
            "channel_id",
            "node_id",
            "uploader_id",
            "message_id",
            "state",
            "blob_size",
            "blob_sha256",
            "created_at",
            "pending_expires_at"
        ]
    );
}

/// REQ-34: an upload that is not complete within the deadline is aborted,
/// and its reservation and temporary file are removed. (The 30-minute
/// deadline is shortened to 1 s.)
#[tokio::test]
async fn t34_incomplete_uploads_are_aborted_at_the_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |c| c.upload_deadline_secs = 1, true).await;
    let f = node_fixture(&relay, "t34d").await;
    let store = &relay.state.attachments;
    let head = upload_head(
        f.channel,
        Auth::Bearer(&f.member.1),
        &length(MIB),
        "application/octet-stream",
    );
    let mut stream = raw_send(&relay, &head, &blob(KIB, 0)).await;
    let id = wait_for_reservation(&relay, f.member.0).await;
    let answer = read_answer(&mut stream).await;
    assert_eq!(answer.status, 408, "{answer:?}");
    assert_eq!(row_state(&relay, id).await, None);
    assert!(!store.part_path(id).exists());
    assert_store_empty(&relay);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-38 (REQ-38) and RG-C001: download
// ─────────────────────────────────────────────────────────────────────────

/// T-38: members download claimed blobs with the exact headers; everyone
/// else, pending blobs, expired and deleted messages get 404; `?token=` only
/// gets 401.
#[tokio::test]
async fn t38_downloads_serve_only_claimed_blobs_of_live_messages() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t38").await;
    let store = &relay.state.attachments;

    let body = blob(5000, 4);
    let id = upload(&relay, &f.member.1, f.channel, body.clone())
        .await
        .id();
    // Pending: not served, not even to the uploader.
    assert_eq!(
        download_status(&relay, &f.member.1, id).await,
        (404, "not_found".into())
    );
    claim(&relay, f.channel, f.member.0, id, None).await;

    for token in [&f.member.1, &f.owner.1] {
        let response = download(&relay, token, id).await;
        assert_eq!(response.status().as_u16(), 200);
        let headers = response.headers().clone();
        assert_eq!(headers["content-type"], "application/octet-stream");
        assert_eq!(headers["content-length"], body.len().to_string().as_str());
        assert_eq!(
            headers["content-disposition"],
            format!("attachment; filename=\"{id}\"").as_str()
        );
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(response.bytes().await.unwrap().to_vec(), body);
    }
    // A non-member, an unknown id and a malformed id: 404.
    assert_eq!(
        download_status(&relay, &f.outsider.1, id).await,
        (404, "not_found".into())
    );
    assert_eq!(
        download_status(&relay, &f.member.1, Uuid::new_v4()).await.0,
        404
    );
    let response = relay
        .client
        .get(relay.url("/attachments/not-a-uuid"))
        .bearer_auth(&f.member.1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
    // `?token=` only, or no token: 401.
    let response = relay
        .client
        .get(relay.url(&format!("/attachments/{id}?token={}", f.member.1)))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
    let response = relay
        .client
        .get(relay.url(&format!("/attachments/{id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);

    // A member who lost VIEW_CHANNEL: 404.
    relay
        .state
        .db
        .set_channel_overwrite(f.channel, f.node, 0, permission_bits::VIEW_CHANNEL)
        .await
        .unwrap();
    assert_eq!(download_status(&relay, &f.member.1, id).await.0, 404);
    relay
        .state
        .db
        .delete_channel_overwrite(f.channel, f.node)
        .await
        .unwrap();

    // A message whose expiry has passed, before the sweep: 404.
    let expiring = upload_id(&relay, &f.member.1, f.channel, 64).await;
    claim(
        &relay,
        f.channel,
        f.member.0,
        expiring,
        Some(store.now() as u64 + 60),
    )
    .await;
    assert_eq!(download_status(&relay, &f.owner.1, expiring).await.0, 200);
    store.advance_clock(61);
    assert_eq!(download_status(&relay, &f.owner.1, expiring).await.0, 404);
    store.advance_clock(-61);

    // A deleted message, before the GC runs: 404 while the row still exists.
    let (deleted, message) = attach(&relay, &f.member, f.channel, None).await;
    let response = relay
        .client
        .delete(relay.url(&format!("/messages/{message}")))
        .bearer_auth(&f.member.1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(row_state(&relay, deleted).await, Some(1));
    assert_eq!(download_status(&relay, &f.owner.1, deleted).await.0, 404);

    // A claimed row whose blob is missing: 404 (section 8.4).
    let (missing, _) = attach(&relay, &f.member, f.channel, None).await;
    std::fs::remove_file(store.blob_path(missing)).unwrap();
    assert_eq!(download_status(&relay, &f.owner.1, missing).await.0, 404);

    // The original attachment is still served.
    assert_eq!(download_status(&relay, &f.owner.1, id).await.0, 200);
}

/// T-38 and RG-C001 (DM attachments): a DM attachment reaches only the two
/// participants. An outsider planted in the DM's `channel_members` and the
/// DM system node gets 404, also when the DM lookup fails.
#[tokio::test]
async fn t38_rg_c001_dm_downloads_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t38dm").await;
    let dm = open_dm(&relay, &f.owner, &f.member, f.node).await;
    let (id, _) = attach(&relay, &f.owner, dm, None).await;
    assert_eq!(download_status(&relay, &f.member.1, id).await.0, 200);
    assert_eq!(download_status(&relay, &f.outsider.1, id).await.0, 404);

    // The fixture from before SPEC-01: the outsider sits in the DM's
    // `channel_members` and in the DM system node.
    relay.state.db.drop_admission_triggers().await.unwrap();
    for sql in [
        format!(
            "INSERT INTO node_members (node_id, user_id, role, joined_at) \
             VALUES ('{DM_SYSTEM_NODE_ID}', '{}', 'admin', 0)",
            f.outsider.0
        ),
        format!(
            "INSERT INTO channel_members (channel_id, user_id, joined_at) VALUES ('{dm}', '{}', 0)",
            f.outsider.0
        ),
    ] {
        sqlx::query(&sql).execute(pool(&relay)).await.unwrap();
    }
    assert_eq!(
        download_status(&relay, &f.outsider.1, id).await,
        (404, "not_found".into())
    );
    relay.state.faults().arm("dm:lookup", FaultKind::Busy);
    assert_eq!(
        download_status(&relay, &f.outsider.1, id).await,
        (404, "not_found".into())
    );
    assert!(!relay.state.faults().is_armed("dm:lookup"));
    // A participant is also refused while the lookup fails.
    relay.state.faults().arm("dm:lookup", FaultKind::Constraint);
    assert_eq!(download_status(&relay, &f.member.1, id).await.0, 404);
    assert_eq!(download_status(&relay, &f.member.1, id).await.0, 200);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-39 (REQ-39): delete
// ─────────────────────────────────────────────────────────────────────────

/// T-39: only the uploader deletes a pending blob (204); a claimed blob
/// answers 409 only to its uploader; everything else is 404.
#[tokio::test]
async fn t39_delete_reveals_nothing_about_other_uploads() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t39").await;
    let store = &relay.state.attachments;

    let pending = upload_id(&relay, &f.member.1, f.channel, 64).await;
    for token in [&f.owner.1, &f.outsider.1] {
        let answer = delete(&relay, token, pending).await;
        assert_eq!((answer.status, answer.reason()), (404, "not_found"));
    }
    assert!(store.blob_path(pending).exists());
    let answer = delete(&relay, &f.member.1, pending).await;
    assert_eq!(answer.status, 204, "{answer:?}");
    assert!(!store.blob_path(pending).exists());
    assert_eq!(row_state(&relay, pending).await, None);
    assert_eq!(delete(&relay, &f.member.1, pending).await.status, 404);

    let (claimed, _) = attach(&relay, &f.member, f.channel, None).await;
    let answer = delete(&relay, &f.member.1, claimed).await;
    assert_eq!((answer.status, answer.reason()), (409, "claimed"));
    for token in [&f.owner.1, &f.outsider.1] {
        assert_eq!(delete(&relay, token, claimed).await.status, 404);
    }
    assert!(store.blob_path(claimed).exists());
    assert_eq!(row_state(&relay, claimed).await, Some(1));

    // An upload reservation: 404 to its uploader too, and it stays.
    let head = upload_head(
        f.channel,
        Auth::Bearer(&f.member.1),
        &length(MIB),
        "application/octet-stream",
    );
    let stream = raw_send(&relay, &head, &blob(KIB, 0)).await;
    let uploading = wait_for_reservation(&relay, f.member.0).await;
    assert_eq!(delete(&relay, &f.member.1, uploading).await.status, 404);
    assert_eq!(row_state(&relay, uploading).await, Some(2));
    drop(stream);

    // `?token=` only, or no token: 401. A malformed id: 404.
    let other = upload_id(&relay, &f.member.1, f.channel, 64).await;
    let response = relay
        .client
        .delete(relay.url(&format!("/attachments/{other}?token={}", f.member.1)))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
    let response = relay
        .client
        .delete(relay.url("/attachments/not-a-uuid"))
        .bearer_auth(&f.member.1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
    assert_eq!(row_state(&relay, other).await, Some(0));
}

// ─────────────────────────────────────────────────────────────────────────
//  T-40 (REQ-40), T-41 (REQ-41), RG-C140: garbage collection
// ─────────────────────────────────────────────────────────────────────────

/// After one GC run the attachment's row and blob are gone and its download
/// answers 404.
async fn assert_collected(relay: &TestRelay, token: &str, id: Uuid, path: &str) {
    let report = relay
        .state
        .attachments
        .run_gc_now(&relay.state.db)
        .await
        .unwrap();
    assert!(report.rows() >= 1, "{path}: {report:?}");
    assert_eq!(row_state(relay, id).await, None, "{path}: row");
    assert!(
        !relay.state.attachments.blob_path(id).exists(),
        "{path}: blob"
    );
    assert_eq!(download_status(relay, token, id).await.0, 404, "{path}");
}

/// T-40 and RG-C140: every way a message or channel disappears removes its
/// attachments at the next GC run; with the reconciliation, a deleted
/// channel's legacy file goes too, and no blob file is left.
#[tokio::test]
async fn t40_rg_c140_attachments_follow_their_messages() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t40").await;
    let db = &relay.state.db;
    let reader = &f.owner.1;

    // WS DeleteMessage.
    let (id, message) = attach(&relay, &f.member, f.channel, None).await;
    let mut ws = WsClient::connect(&relay, &f.member.1).await;
    ws.send(json!({"DeleteMessage": {"message_id": message}}))
        .await;
    let gone = format!("SELECT COUNT(*) FROM messages WHERE id = '{message}'");
    assert!(eventually(OBSERVE, || async { scalar(&relay, &gone).await == 0 }).await);
    assert_collected(&relay, reader, id, "WS DeleteMessage").await;

    // REST DELETE /messages/{id}.
    let (id, message) = attach(&relay, &f.member, f.channel, None).await;
    let response = relay
        .client
        .delete(relay.url(&format!("/messages/{message}")))
        .bearer_auth(&f.member.1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_collected(&relay, reader, id, "REST delete").await;

    // Expiry: `expires_at` = now + 1, then the sweep.
    let now = unix_now();
    let (id, _) = attach(&relay, &f.member, f.channel, Some(now + 1)).await;
    assert_eq!(relay.state.run_expiry_sweep(now + 2).await.1, 1);
    assert_collected(&relay, reader, id, "expiry").await;

    // Read-gated expiry: the owner reads it, the timer starts, it expires.
    let (id, message) = attach(&relay, &f.member, f.channel, None).await;
    db.set_message_gate(message, &[f.owner.0], &[], 1)
        .await
        .unwrap();
    assert_eq!(relay.state.run_expiry_sweep(now).await, (0, 0));
    db.mark_channel_read(f.owner.0, f.channel, message)
        .await
        .unwrap();
    assert_eq!(relay.state.run_expiry_sweep(now).await.0, 1);
    assert_eq!(relay.state.run_expiry_sweep(now + 2).await.1, 1);
    assert_collected(&relay, reader, id, "read-gated expiry").await;

    // purge_before.
    let (id, _) = attach(&relay, &f.member, f.channel, None).await;
    let response = relay
        .client
        .post(relay.url(&format!("/channels/{}/purge_before", f.channel)))
        .bearer_auth(&f.owner.1)
        .json(&json!({"before": unix_now() + 10}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_collected(&relay, reader, id, "purge_before").await;

    // Channel deletion, with a legacy file of that channel.
    let second = db
        .create_channel("second", f.node, f.owner.0)
        .await
        .unwrap()
        .id;
    let (id, _) = attach(&relay, &f.member, second, None).await;
    let legacy_id = Uuid::new_v4();
    let legacy_path = dir.path().join("files").join(legacy_id.to_string());
    write_file(
        &legacy_path,
        b"legacy blob",
        Some(Duration::from_secs(1200)),
    );
    db.store_file_metadata(
        legacy_id,
        second,
        f.member.0,
        b"name",
        11,
        "hash",
        legacy_path.to_str().unwrap(),
    )
    .await
    .unwrap();
    let response = relay
        .client
        .delete(relay.url(&format!("/channels/{second}")))
        .bearer_auth(&f.owner.1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_collected(&relay, reader, id, "channel deletion").await;

    // Node deletion, called on the database directly.
    let node = relay.create_node(&f.owner.1, "t40-second").await;
    let channel = db.get_node_channels(node).await.unwrap()[0].id;
    let (id, _) = attach(&relay, &f.owner, channel, None).await;
    db.delete_node(node).await.unwrap();
    assert_collected(&relay, &f.owner.1, id, "node deletion").await;

    // The reconciliation removes the deleted channel's legacy file; no
    // version-2 blob is left anywhere.
    let report = relay
        .state
        .attachments
        .run_reconciliation_now(db)
        .await
        .unwrap();
    assert_eq!(report.legacy_orphans, 1, "{report:?}");
    assert!(!legacy_path.exists());
    assert_eq!(row_count(&relay).await, 0);
    assert_store_empty(&relay);
}

/// T-40: with `attachment_gc_interval_secs` = 1 the background task removes
/// a deleted message's blob within 3 s; with a long interval, a deletion
/// through the API triggers the GC at once (REQ-40 SHOULD).
#[tokio::test]
async fn t40_background_gc_runs_on_its_interval_and_on_demand() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |c| c.gc_interval_secs = 1, true).await;
    accord_server::attachments::lifecycle::spawn_background_tasks(&relay.state);
    let f = node_fixture(&relay, "t40b").await;
    let (id, message) = attach(&relay, &f.member, f.channel, None).await;
    // Deleted without any GC request: only the interval can remove it.
    relay
        .state
        .db
        .delete_message(message, f.member.0)
        .await
        .unwrap()
        .unwrap();
    let store = &relay.state.attachments;
    assert!(
        eventually(Duration::from_secs(3), || async {
            row_state(&relay, id).await.is_none() && !store.blob_path(id).exists()
        })
        .await,
        "the background GC did not run within 3 s"
    );

    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |c| c.gc_interval_secs = 3600, true).await;
    accord_server::attachments::lifecycle::spawn_background_tasks(&relay.state);
    let f = node_fixture(&relay, "t40n").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (id, message) = attach(&relay, &f.member, f.channel, None).await;
    let response = relay
        .client
        .delete(relay.url(&format!("/messages/{message}")))
        .bearer_auth(&f.member.1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let store = &relay.state.attachments;
    assert!(
        eventually(Duration::from_secs(2), || async {
            row_state(&relay, id).await.is_none() && !store.blob_path(id).exists()
        })
        .await,
        "the deletion did not trigger the GC"
    );
}

/// T-41: an expired pending row, a pending row whose channel is deleted and
/// an upload reservation past its deadline are removed with their files.
#[tokio::test]
async fn t41_pending_and_uploading_rows_expire() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t41").await;
    let store = &relay.state.attachments;
    let db = &relay.state.db;

    // A pending row in a channel that is then deleted.
    let second = db
        .create_channel("second", f.node, f.owner.0)
        .await
        .unwrap()
        .id;
    let orphaned = upload_id(&relay, &f.member.1, second, 64).await;
    db.delete_channel(second).await.unwrap();
    let report = store.run_gc_now(db).await.unwrap();
    assert_eq!(report.without_channel, 1, "{report:?}");
    assert_eq!(row_state(&relay, orphaned).await, None);
    assert!(!store.blob_path(orphaned).exists());

    // An upload reservation past its 1-hour deadline, with its part file.
    let head = upload_head(
        f.channel,
        Auth::Bearer(&f.member.1),
        &length(MIB),
        "application/octet-stream",
    );
    let stream = raw_send(&relay, &head, &blob(KIB, 0)).await;
    let uploading = wait_for_reservation(&relay, f.member.0).await;
    assert!(eventually(OBSERVE, || async { store.part_path(uploading).exists() }).await);
    store.advance_clock(100);
    let pending = upload_id(&relay, &f.member.1, f.channel, 64).await;
    store.advance_clock(3400);
    assert_eq!(store.run_gc_now(db).await.unwrap().rows(), 0);
    store.advance_clock(101);
    let report = store.run_gc_now(db).await.unwrap();
    assert_eq!(report.expired, 1, "{report:?}");
    assert_eq!(row_state(&relay, uploading).await, None);
    assert!(!store.part_path(uploading).exists());
    // The pending row uploaded a moment later is still within its TTL.
    assert_eq!(row_state(&relay, pending).await, Some(0));
    drop(stream);

    // A pending row past `pending_expires_at`, with its blob.
    store.advance_clock(200);
    let report = store.run_gc_now(db).await.unwrap();
    assert_eq!(report.expired, 1, "{report:?}");
    assert_eq!(row_state(&relay, pending).await, None);
    assert!(!store.blob_path(pending).exists());
    assert_eq!(row_count(&relay).await, 0);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-42 (REQ-42): reconciliation and startup checks
// ─────────────────────────────────────────────────────────────────────────

const OLD: Duration = Duration::from_secs(2 * 3600);

/// T-42: the reconciliation removes exactly the four kinds of orphan and
/// leaves everything else alone.
#[tokio::test]
async fn t42_reconciliation_removes_only_orphans() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t42").await;
    let store = &relay.state.attachments;
    let db = &relay.state.db;
    let attachments = store.dir().to_path_buf();
    let tmp = store.tmp_dir().to_path_buf();
    let legacy = dir.path().join("files");
    let outside = tempfile::tempdir().unwrap();

    // A row created 11 minutes ago whose blob is missing, and one created
    // just now whose blob is missing.
    store.advance_clock(-660);
    let (stale_row, _) = attach(&relay, &f.member, f.channel, None).await;
    store.advance_clock(660);
    std::fs::remove_file(store.blob_path(stale_row)).unwrap();
    let young_row = upload_id(&relay, &f.member.1, f.channel, 64).await;
    std::fs::remove_file(store.blob_path(young_row)).unwrap();
    // A live attachment whose blob is old.
    let (live, _) = attach(&relay, &f.member, f.channel, None).await;
    age_file(&store.blob_path(live), OLD);

    // Entries in the attachments directory.
    let orphan_old = Uuid::new_v4().to_string();
    let orphan_young = Uuid::new_v4().to_string();
    let upper = Uuid::new_v4().to_string().to_uppercase();
    let link = Uuid::new_v4().to_string();
    let subdir = Uuid::new_v4().to_string();
    write_file(&attachments.join(&orphan_old), b"orphan", Some(OLD));
    write_file(&attachments.join(&orphan_young), b"young", None);
    write_file(&attachments.join("notes.txt"), b"not ours", Some(OLD));
    write_file(&attachments.join(&upper), b"upper", Some(OLD));
    let target = outside.path().join("target");
    write_file(&target, b"target", Some(OLD));
    std::os::unix::fs::symlink(&target, attachments.join(&link)).unwrap();
    std::fs::create_dir(attachments.join(&subdir)).unwrap();
    write_file(
        &attachments.join(&subdir).join(Uuid::new_v4().to_string()),
        b"inside",
        Some(OLD),
    );

    // Entries in `.tmp`.
    let part_old = format!("{}.part", Uuid::new_v4());
    let part_recent = format!("{}.part", Uuid::new_v4());
    let not_part = Uuid::new_v4().to_string();
    write_file(&tmp.join(&part_old), b"part", Some(OLD));
    write_file(
        &tmp.join(&part_recent),
        b"part",
        Some(Duration::from_secs(1800)),
    );
    write_file(&tmp.join(&not_part), b"part", Some(OLD));

    // Legacy blobs: one whose `files` row a channel deletion cascaded away,
    // one with a row, a young orphan and a file with a non-UUID name.
    let second = db
        .create_channel("second", f.node, f.owner.0)
        .await
        .unwrap()
        .id;
    let legacy_cascaded = Uuid::new_v4();
    let legacy_kept = Uuid::new_v4();
    for (id, channel) in [(legacy_cascaded, second), (legacy_kept, f.channel)] {
        let path = legacy.join(id.to_string());
        write_file(&path, b"legacy", Some(OLD));
        db.store_file_metadata(
            id,
            channel,
            f.member.0,
            b"n",
            6,
            "h",
            path.to_str().unwrap(),
        )
        .await
        .unwrap();
    }
    db.delete_channel(second).await.unwrap();
    let legacy_young = Uuid::new_v4().to_string();
    write_file(&legacy.join(&legacy_young), b"young", None);
    write_file(&legacy.join("README"), b"not ours", Some(OLD));

    let report = store.run_reconciliation_now(db).await.unwrap();
    assert_eq!(report.orphan_blobs, 1, "{report:?}");
    assert_eq!(report.orphan_parts, 1, "{report:?}");
    assert_eq!(report.rows_without_blob, 1, "{report:?}");
    assert_eq!(report.legacy_orphans, 1, "{report:?}");
    assert!(!report.legacy_skipped);

    // Removed.
    assert!(!attachments.join(&orphan_old).exists());
    assert!(!tmp.join(&part_old).exists());
    assert_eq!(row_state(&relay, stale_row).await, None);
    assert!(!legacy.join(legacy_cascaded.to_string()).exists());
    // Kept.
    for name in [
        &orphan_young,
        &upper,
        &"notes.txt".to_string(),
        &live.to_string(),
    ] {
        assert!(attachments.join(name).is_file(), "{name}");
    }
    assert!(std::fs::symlink_metadata(attachments.join(&link))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read(&target).unwrap(), b"target");
    assert_eq!(listing(&attachments.join(&subdir)).len(), 1);
    assert!(tmp.join(&part_recent).exists());
    assert!(tmp.join(&not_part).exists());
    assert_eq!(row_state(&relay, young_row).await, Some(0));
    assert_eq!(row_state(&relay, live).await, Some(1));
    assert!(legacy.join(legacy_kept.to_string()).exists());
    assert!(legacy.join(&legacy_young).exists());
    assert!(legacy.join("README").exists());
    assert_eq!(download_status(&relay, &f.owner.1, live).await.0, 200);
}

/// T-42: with the `files` table unreadable, the legacy part is skipped with
/// an ERROR and the rest of the reconciliation still runs.
#[tokio::test]
async fn t42_unreadable_files_table_skips_the_legacy_part() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let store = &relay.state.attachments;
    let legacy_orphan = dir.path().join("files").join(Uuid::new_v4().to_string());
    write_file(&legacy_orphan, b"legacy", Some(OLD));
    let orphan = store.dir().join(Uuid::new_v4().to_string());
    write_file(&orphan, b"orphan", Some(OLD));
    sqlx::query("ALTER TABLE files RENAME TO files_unreadable")
        .execute(pool(&relay))
        .await
        .unwrap();

    let capture = LogCapture::new();
    let report = {
        let _guard = capture.start(tracing::Level::INFO);
        store.run_reconciliation_now(&relay.state.db).await.unwrap()
    };
    assert!(report.legacy_skipped, "{report:?}");
    assert_eq!(report.orphan_blobs, 1, "{report:?}");
    assert!(legacy_orphan.exists());
    assert!(!orphan.exists());
    let lines = capture.lines_with_target("accord::attachments");
    assert!(
        lines.iter().any(|l| l.contains("ERROR")),
        "no ERROR logged: {lines:?}"
    );
}

/// The SHA-256 of a file, or `None` if it does not exist.
fn file_digest(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| sha256_hex(&bytes))
}

/// T-42: the relay refuses to start when `attachments_dir` is, or contains,
/// the database's directory, overlaps the legacy directory, or is a
/// non-empty directory without the marker. The error names the setting and
/// the cause, and the database file is untouched. The database-directory
/// check also holds where nothing else would refuse: a directory that already
/// carries the marker, and a fresh install whose directories do not exist.
#[tokio::test]
async fn t42_misconfigured_attachments_dir_stops_the_relay() {
    let dir = tempfile::tempdir().unwrap();
    let db_dir = dir.path().join("relay");
    std::fs::create_dir_all(&db_dir).unwrap();
    let db_path = db_dir.join("relay.db");
    let legacy = dir.path().join("files");
    let file_config = || FileConfig {
        storage_dir: legacy.clone(),
        max_file_size: MIB as u64,
    };
    let open = |attachments: PathBuf| {
        let db_path = db_path.clone();
        let options = AppStateOptions {
            file_config: Some(file_config()),
            attachments: Some(AttachmentConfig::with_dir(attachments)),
            ..AppStateOptions::default()
        };
        async move { AppState::new_with_options(db_path.to_str().unwrap(), options).await }
    };

    // A good configuration creates the database; it is then closed.
    let state = open(dir.path().join("attachments")).await.unwrap();
    state.db.raw_pool().close().await;
    drop(state);
    let before = file_digest(&db_path);
    assert!(before.is_some());
    let db_files = listing(&db_dir);

    let not_ours = dir.path().join("other");
    std::fs::create_dir_all(&not_ours).unwrap();
    std::fs::write(not_ours.join("keep.txt"), b"precious").unwrap();
    std::fs::create_dir_all(&legacy).unwrap();

    for (attachments, cause, case) in [
        (db_dir.clone(), "database", "the database's directory"),
        (
            dir.path().to_path_buf(),
            "database",
            "an ancestor of the database's directory",
        ),
        (legacy.clone(), "legacy", "the legacy directory"),
        (
            legacy.join("inner"),
            "legacy",
            "inside the legacy directory",
        ),
        (
            not_ours.clone(),
            MARKER_FILE,
            "a non-empty directory without the marker",
        ),
    ] {
        let error = open(attachments.clone()).await.unwrap_err().to_string();
        assert!(error.contains("attachments_dir"), "{case}: {error}");
        assert!(error.contains(cause), "{case}: {error}");
        assert_eq!(file_digest(&db_path), before, "{case}: database changed");
        assert_eq!(listing(&db_dir), db_files, "{case}: database opened");
    }
    assert!(!legacy.join("inner").exists());
    assert_eq!(listing(&not_ours), vec!["keep.txt".to_string()]);

    // With the marker in place, the directory would otherwise be adopted:
    // only the database-directory check refuses it.
    let marker = dir.path().join("attachments").join(MARKER_FILE);
    for (attachments, case) in [
        (db_dir.clone(), "the database's directory with the marker"),
        (
            dir.path().to_path_buf(),
            "an ancestor of the database's directory with the marker",
        ),
    ] {
        std::fs::copy(&marker, attachments.join(MARKER_FILE)).unwrap();
        let error = open(attachments.clone()).await.unwrap_err().to_string();
        assert!(error.contains("attachments_dir"), "{case}: {error}");
        assert!(error.contains("database"), "{case}: {error}");
        assert!(!attachments.join(TMP_DIR).exists(), "{case}: adopted");
        std::fs::remove_file(attachments.join(MARKER_FILE)).unwrap();
        assert_eq!(file_digest(&db_path), before, "{case}: database changed");
        assert_eq!(listing(&db_dir), db_files, "{case}: database opened");
    }

    // A fresh install: neither the database nor its directory exists yet,
    // so only the database-directory check stops the relay from creating
    // the attachments directory and then the database inside it.
    let fresh = dir.path().join("fresh");
    for (fresh_db, case) in [
        (fresh.join("relay.db"), "a fresh database's directory"),
        (
            fresh.join("db").join("relay.db"),
            "an ancestor of a fresh database's directory",
        ),
    ] {
        let options = AppStateOptions {
            file_config: Some(file_config()),
            attachments: Some(AttachmentConfig::with_dir(&fresh)),
            ..AppStateOptions::default()
        };
        let error = AppState::new_with_options(fresh_db.to_str().unwrap(), options)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("attachments_dir"), "{case}: {error}");
        assert!(error.contains("database"), "{case}: {error}");
        assert!(!fresh.exists(), "{case}: directory or marker written");
    }

    // The legacy directory inside the attachments directory.
    let parent = dir.path().join("parent");
    let options = AppStateOptions {
        file_config: Some(FileConfig {
            storage_dir: parent.join("files"),
            max_file_size: MIB as u64,
        }),
        attachments: Some(AttachmentConfig::with_dir(&parent)),
        ..AppStateOptions::default()
    };
    let error = AppState::new_with_options(db_path.to_str().unwrap(), options)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("attachments_dir"), "{error}");
    assert_eq!(file_digest(&db_path), before);

    // A settings range error names the setting too.
    let mut config = AttachmentConfig::with_dir(dir.path().join("attachments"));
    config.gc_interval_secs = 0;
    let options = AppStateOptions {
        file_config: Some(file_config()),
        attachments: Some(config),
        ..AppStateOptions::default()
    };
    let error = AppState::new_with_options(db_path.to_str().unwrap(), options)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("attachment_gc_interval_secs"), "{error}");

    // An empty existing directory is adopted and gets the marker; the
    // directory written by the first start is reopened.
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let state = open(empty.clone()).await.unwrap();
    assert!(empty.join(MARKER_FILE).is_file());
    state.db.raw_pool().close().await;
    drop(state);
    let state = open(dir.path().join("attachments")).await.unwrap();
    assert!(state
        .db
        .ledger_applied_at("spec02_attachments_v2")
        .await
        .unwrap()
        .is_some());
}

// ─────────────────────────────────────────────────────────────────────────
//  T-43 (REQ-43): paths, modes and logs
// ─────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// T-43: blob paths are derived from the id; the directory is 0700 and blob
/// files 0600; logs at INFO and above never carry an attachment id.
#[tokio::test]
async fn t43_paths_modes_and_logs() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}, true).await;
    let f = node_fixture(&relay, "t43").await;
    let store = &relay.state.attachments;
    let db = &relay.state.db;

    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::INFO);
    let mut ids: Vec<Uuid> = Vec::new();

    // Upload, claim and download.
    let (claimed, _) = attach(&relay, &f.member, f.channel, None).await;
    ids.push(claimed);
    assert_eq!(download_status(&relay, &f.owner.1, claimed).await.0, 200);
    assert_eq!(download_status(&relay, &f.outsider.1, claimed).await.0, 404);
    assert_eq!(delete(&relay, &f.member.1, claimed).await.status, 409);
    // The part file of an upload in progress is 0600 as well; the upload is
    // then aborted.
    let head = upload_head(
        f.channel,
        Auth::Bearer(&f.member.1),
        &length(MIB),
        "application/octet-stream",
    );
    let stream = raw_send(&relay, &head, &blob(KIB, 0)).await;
    let aborted = wait_for_reservation(&relay, f.member.0).await;
    ids.push(aborted);
    assert!(eventually(OBSERVE, || async { store.part_path(aborted).exists() }).await);
    #[cfg(unix)]
    assert_eq!(mode(&store.part_path(aborted)), 0o600);
    drop(stream);
    assert!(
        eventually(Duration::from_secs(5), || async {
            row_state(&relay, aborted).await.is_none()
        })
        .await
    );
    // Delete a pending upload.
    let deleted = upload_id(&relay, &f.member.1, f.channel, 64).await;
    ids.push(deleted);
    assert_eq!(delete(&relay, &f.member.1, deleted).await.status, 204);
    // GC of an expired upload, with a failing statement on the way.
    let expired = upload_id(&relay, &f.member.1, f.channel, 64).await;
    ids.push(expired);
    store.advance_clock(3601);
    relay.state.faults().arm("attachments:gc", FaultKind::Busy);
    assert!(store.run_gc_now(db).await.is_err());
    assert_eq!(store.run_gc_now(db).await.unwrap().expired, 1);
    store.advance_clock(-3601);
    // Reconciliation of an orphan blob.
    let orphan = Uuid::new_v4();
    ids.push(orphan);
    write_file(&store.blob_path(orphan), b"orphan", Some(OLD));
    assert_eq!(
        store.run_reconciliation_now(db).await.unwrap().orphan_blobs,
        1
    );
    drop(guard);

    let text = capture.text();
    assert!(
        capture
            .lines_with_target("accord::attachments")
            .iter()
            .any(|l| l.contains("WARN")),
        "the capture recorded nothing: {text}"
    );
    for id in &ids {
        assert!(!text.contains(&id.to_string()), "{id} logged:\n{text}");
        assert!(
            !text.contains(&id.simple().to_string()),
            "{id} logged:\n{text}"
        );
    }

    // The blob path is `<attachments_dir>/<id>`, and no path is stored.
    assert!(store.blob_path(claimed).is_file());
    assert_eq!(
        store.blob_path(claimed),
        dir.path()
            .canonicalize()
            .unwrap()
            .join("attachments")
            .join(claimed.to_string())
    );
    let path_columns = scalar(
        &relay,
        "SELECT COUNT(*) FROM pragma_table_info('attachments') \
         WHERE name LIKE '%path%' OR name LIKE '%name%' OR name LIKE '%mime%'",
    )
    .await;
    assert_eq!(path_columns, 0);
    #[cfg(unix)]
    {
        assert_eq!(mode(store.dir()), 0o700);
        assert_eq!(mode(store.tmp_dir()), 0o700);
        assert_eq!(mode(&store.blob_path(claimed)), 0o600);
    }
}
