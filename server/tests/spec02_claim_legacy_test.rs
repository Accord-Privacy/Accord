//! SPEC-02 section 11.2 step 2, second part: the claim in `ChannelMessage`
//! (sections 6.5.1, 6.5.2), its error frames (6.5.3) and the edit guard
//! (6.4.7, REQ-37); the read-only legacy routes (6.4.4, 6.4.5) and legacy
//! retirement (7.7); the `attachments/2` capability (6.4.6).
//!
//! Tests T-30, T-31, T-35, T-36, T-37 and T-44 of section 10.2, and the relay
//! parts of RG-C164 (a), RG-C161 (legacy list), RG-C001 (legacy DM files),
//! RG-C054 and RG-C090 (claim failures carry their ids) of section 10.3,
//! plus T-43 for the claim's logs.
//!
//! Every relay runs the production router on `127.0.0.1:0` over a database,
//! a legacy file directory and an attachments directory in its own temporary
//! directory (section 10.1). Every account has a password and every
//! membership comes from an owner-created invite (SPEC-01 section 10.1).
//! Legacy rows are seeded directly, because legacy uploads answer 410.

use accord_server::attachments::{AttachmentConfig, LegacyAttachmentsMode};
use accord_server::db::attachments::{LEDGER_ATTACHMENTS_V2, LEDGER_LEGACY_RETIRED};
use accord_server::db::{DbOptions, DM_SYSTEM_NODE_ID};
use accord_server::faults::FaultKind;
use accord_server::files::FileConfig;
use accord_server::models::permission_bits;
use accord_server::rate_limit::RateLimiter;
use accord_server::state::{AppState, AppStateOptions};
use accord_server::test_support::{LogCapture, TestRelay, WsClient};
use base64::Engine as _;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

const OBSERVE: Duration = Duration::from_secs(2);
const QUIET: Duration = Duration::from_millis(400);
const MIB: u64 = 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────
//  Harness
// ─────────────────────────────────────────────────────────────────────────

fn options(dir: &Path, config: AttachmentConfig) -> AppStateOptions {
    AppStateOptions {
        database_encryption: false,
        db: DbOptions::default(),
        file_config: Some(FileConfig {
            storage_dir: dir.join("files"),
            max_file_size: MIB,
        }),
        attachments: Some(config),
    }
}

/// Open the relay state over `dir`: `relay.db`, the legacy directory `files`
/// and the attachments directory `attachments`.
async fn open_state(dir: &Path, configure: impl FnOnce(&mut AttachmentConfig)) -> AppState {
    let mut config = AttachmentConfig::with_dir(dir.join("attachments"));
    configure(&mut config);
    let mut state =
        AppState::new_with_options(dir.join("relay.db").to_str().unwrap(), options(dir, config))
            .await
            .expect("relay state");
    // Uploads are rate limited per minute; the tests here upload a lot.
    state.rate_limiter = RateLimiter::new_disabled();
    // Tokens survive a restart, as in the binary.
    state.load_persisted_tokens().await;
    state
}

async fn start(
    dir: &tempfile::TempDir,
    configure: impl FnOnce(&mut AttachmentConfig),
) -> TestRelay {
    let state = open_state(dir.path(), configure).await;
    TestRelay::with_state(Arc::new(state)).await
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

async fn message_count(relay: &TestRelay) -> i64 {
    scalar(relay, "SELECT COUNT(*) FROM messages").await
}

/// The state code and message of an attachment row.
async fn row(relay: &TestRelay, id: Uuid) -> Option<(i64, Option<String>)> {
    sqlx::query_as("SELECT state, message_id FROM attachments WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool(relay))
        .await
        .unwrap()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
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

/// Plant `user` in the DM's `channel_members` and in the DM system node, the
/// fixture from before SPEC-01 (RG-C001).
async fn plant_in_dm(relay: &TestRelay, dm: Uuid, user: Uuid) {
    relay.state.db.drop_admission_triggers().await.unwrap();
    for sql in [
        format!(
            "INSERT INTO node_members (node_id, user_id, role, joined_at) \
             VALUES ('{DM_SYSTEM_NODE_ID}', '{user}', 'admin', 0)"
        ),
        format!(
            "INSERT INTO channel_members (channel_id, user_id, joined_at) VALUES ('{dm}', '{user}', 0)"
        ),
    ] {
        sqlx::query(&sql).execute(pool(relay)).await.unwrap();
    }
}

// ── HTTP ──

#[derive(Debug)]
struct Answer {
    status: u16,
    body: Value,
}

impl Answer {
    async fn read(response: reqwest::Response) -> Self {
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        Self {
            status,
            body: serde_json::from_str(&text).unwrap_or(Value::Null),
        }
    }

    fn reason(&self) -> &str {
        self.body["reason"].as_str().unwrap_or("")
    }
}

async fn call(
    relay: &TestRelay,
    method: reqwest::Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Answer {
    let mut request = relay.client.request(method, relay.url(path));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    Answer::read(request.send().await.unwrap()).await
}

/// Upload a `len`-byte blob as the holder of `token`; returns its id.
async fn upload(relay: &TestRelay, token: &str, channel: Uuid, len: usize) -> Uuid {
    let response = relay
        .client
        .post(relay.url(&format!("/channels/{channel}/attachments")))
        .bearer_auth(token)
        .header("content-type", "application/octet-stream")
        .body(vec![7u8; len])
        .send()
        .await
        .unwrap();
    let answer = Answer::read(response).await;
    assert_eq!(answer.status, 201, "{answer:?}");
    Uuid::parse_str(answer.body["attachment_id"].as_str().unwrap()).unwrap()
}

async fn download_status(relay: &TestRelay, token: &str, id: Uuid) -> u16 {
    call(
        relay,
        reqwest::Method::GET,
        &format!("/attachments/{id}"),
        Some(token),
        None,
    )
    .await
    .status
}

// ── WebSocket ──

/// A `ChannelMessage` claiming `ids` (strings, as sent).
fn claim_message(channel: Uuid, ids: &[String]) -> Value {
    json!({ "ChannelMessage": {
        "channel_id": channel,
        "encrypted_data": b64(b"sealed envelope"),
        "attachment_ids": ids,
    }})
}

fn text_message(channel: Uuid) -> Value {
    json!({ "ChannelMessage": {
        "channel_id": channel,
        "encrypted_data": b64(b"sealed text"),
    }})
}

fn strings(ids: &[Uuid]) -> Vec<String> {
    ids.iter().map(Uuid::to_string).collect()
}

/// Send a claim and return the frames this connection received for it.
async fn send_and_collect(ws: &mut WsClient, message: Value) -> (Uuid, Vec<Value>) {
    let request_id = ws.send(message).await;
    let frames = ws.frames_for(QUIET).await;
    (request_id, frames)
}

/// The frames of `ws` during [`QUIET`], without presence frames, which
/// other connections coming and going cause.
async fn quiet_frames(ws: &mut WsClient) -> Vec<Value> {
    ws.frames_for(QUIET)
        .await
        .into_iter()
        .filter(|f| {
            !f["type"]
                .as_str()
                .is_some_and(|t| t.starts_with("presence_"))
        })
        .collect()
}

/// The `attachment_claim_failed` frames among `frames`.
fn claim_failures(frames: &[Value]) -> Vec<Value> {
    frames
        .iter()
        .filter(|f| f["type"] == "error" && f["code"] == "attachment_claim_failed")
        .cloned()
        .collect()
}

/// The one frame answering a refused claim: a typed failure with `reason`,
/// the request's ids and its `request_id`, and no other error frame.
fn assert_claim_failed(
    frames: &[Value],
    reason: &str,
    requested: &[String],
    request_id: Uuid,
    case: &str,
) -> Value {
    let errors: Vec<&Value> = frames.iter().filter(|f| f["type"] == "error").collect();
    assert_eq!(
        errors.len(),
        1,
        "{case}: exactly one error frame: {frames:?}"
    );
    let frame = errors[0].clone();
    assert_eq!(frame["code"], "attachment_claim_failed", "{case}: {frame}");
    assert_eq!(frame["reason"], reason, "{case}: {frame}");
    assert_eq!(frame["attachment_ids"], json!(requested), "{case}: {frame}");
    assert_eq!(
        frame["request_id"],
        request_id.to_string(),
        "{case}: {frame}"
    );
    assert!(frame["error"].is_string(), "{case}: {frame}");
    assert_eq!(
        frames
            .iter()
            .filter(|f| f["type"] == "channel_message")
            .count(),
        0,
        "{case}: nothing is broadcast: {frames:?}"
    );
    frame
}

// ── Legacy rows ──

/// Seed a legacy file: a blob in the legacy directory and its `files` row.
async fn seed_legacy(
    relay: &TestRelay,
    dir: &Path,
    channel: Uuid,
    uploader: Uuid,
    name: &[u8],
    created_at: i64,
) -> (Uuid, PathBuf) {
    let id = Uuid::new_v4();
    let path = dir.join("files").join(id.to_string());
    std::fs::create_dir_all(dir.join("files")).unwrap();
    std::fs::write(&path, format!("legacy blob {id}")).unwrap();
    sqlx::query(
        "INSERT INTO files (id, channel_id, uploader_id, encrypted_filename, file_size_bytes, \
         content_hash, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(channel.to_string())
    .bind(uploader.to_string())
    .bind(name)
    .bind(48_i64)
    .bind("hash")
    .bind(path.to_str().unwrap())
    .bind(created_at)
    .execute(pool(relay))
    .await
    .unwrap();
    (id, path)
}

async fn legacy_list(relay: &TestRelay, token: &str, channel: Uuid, query: &str) -> Answer {
    call(
        relay,
        reqwest::Method::GET,
        &format!("/channels/{channel}/files{query}"),
        Some(token),
        None,
    )
    .await
}

/// A legacy multipart upload, as clients older than SPEC-02 send it.
async fn legacy_upload(relay: &TestRelay, token: &str, channel: Uuid) -> Answer {
    let form = reqwest::multipart::Form::new()
        .part(
            "encrypted_filename",
            reqwest::multipart::Part::bytes(b"bmFtZQ==".to_vec()),
        )
        .part(
            "file",
            reqwest::multipart::Part::bytes(vec![1u8; 64]).file_name("x.bin"),
        );
    let response = relay
        .client
        .post(relay.url(&format!("/channels/{channel}/files?token={token}")))
        .multipart(form)
        .send()
        .await
        .unwrap();
    Answer::read(response).await
}

// ─────────────────────────────────────────────────────────────────────────
//  T-35 (a), T-36 (REQ-35, REQ-36): a valid claim
// ─────────────────────────────────────────────────────────────────────────

/// T-35 (a) and T-36: a valid claim stores the message, claims every listed
/// row for it, and the sender's echo and the other members' frames carry
/// `attachment_ids` equal to the claimed set. The same in a DM, where the
/// outsider receives nothing.
#[tokio::test]
async fn t35a_t36_valid_claims_store_claim_and_broadcast_the_ids() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t35a").await;
    let ids = vec![
        upload(&relay, &f.member.1, f.channel, 32).await,
        upload(&relay, &f.member.1, f.channel, 64).await,
    ];
    let mut sender = WsClient::connect(&relay, &f.member.1).await;
    let mut other = WsClient::connect(&relay, &f.owner.1).await;

    let requested = strings(&ids);
    sender.send(claim_message(f.channel, &requested)).await;
    let echo = sender
        .wait_for("channel_message", OBSERVE)
        .await
        .expect("the sender's echo");
    let seen = other
        .wait_for("channel_message", OBSERVE)
        .await
        .expect("the other member's frame");
    for frame in [&echo, &seen] {
        assert_eq!(frame["attachment_ids"], json!(requested), "{frame}");
        assert_eq!(frame["from"], f.member.0.to_string());
        assert_eq!(frame["encrypted_data"], b64(b"sealed envelope"));
        assert_eq!(frame["is_dm"], false);
    }
    let message_id = echo["message_id"].as_str().unwrap().to_string();
    assert_eq!(seen["message_id"], echo["message_id"]);
    for id in &ids {
        assert_eq!(row(&relay, *id).await, Some((1, Some(message_id.clone()))));
        assert_eq!(download_status(&relay, &f.owner.1, *id).await, 200);
    }
    let stored = scalar(
        &relay,
        &format!("SELECT COUNT(*) FROM messages WHERE id = '{message_id}' AND seq = 1"),
    )
    .await;
    assert_eq!(stored, 1);

    // A text message carries no `attachment_ids`, and an empty list is an
    // ordinary text message.
    sender.send(text_message(f.channel)).await;
    let text = other.wait_for("channel_message", OBSERVE).await.unwrap();
    assert!(text.get("attachment_ids").is_none(), "{text}");
    assert_eq!(text["seq"], 2);
    sender.send(claim_message(f.channel, &[])).await;
    let empty = other.wait_for("channel_message", OBSERVE).await.unwrap();
    assert!(empty.get("attachment_ids").is_none(), "{empty}");

    // A DM: the peer gets the ids, the outsider gets nothing.
    let dm = open_dm(&relay, &f.owner, &f.member, f.node).await;
    let dm_id = upload(&relay, &f.member.1, dm, 48).await;
    let mut outsider = WsClient::connect(&relay, &f.outsider.1).await;
    sender.send(claim_message(dm, &strings(&[dm_id]))).await;
    let seen = other.wait_for("channel_message", OBSERVE).await.unwrap();
    assert_eq!(seen["attachment_ids"], json!([dm_id.to_string()]));
    assert_eq!(seen["is_dm"], true);
    assert_eq!(row(&relay, dm_id).await.unwrap().0, 1);
    assert!(quiet_frames(&mut outsider).await.is_empty());
    assert_eq!(download_status(&relay, &f.owner.1, dm_id).await, 200);
    assert_eq!(download_status(&relay, &f.outsider.1, dm_id).await, 404);
}

/// T-35 (a): the read gate and the expiry are stored with the claimed
/// message, as for a text message.
#[tokio::test]
async fn t35a_claimed_messages_keep_expiry_and_read_gate() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t35g").await;
    let id = upload(&relay, &f.member.1, f.channel, 32).await;
    let mut ws = WsClient::connect(&relay, &f.member.1).await;
    ws.send(json!({ "ChannelMessage": {
        "channel_id": f.channel,
        "encrypted_data": b64(b"gated"),
        "gate_users": [f.owner.0],
        "gate_ttl_secs": 30,
        "attachment_ids": [id.to_string()],
    }}))
    .await;
    let echo = ws.wait_for("channel_message", OBSERVE).await.unwrap();
    assert_eq!(echo["read_gated"], true);
    assert_eq!(echo["gate_ttl_secs"], 30);
    let message = echo["message_id"].as_str().unwrap();
    let (users, ttl): (String, i64) =
        sqlx::query_as("SELECT gate_users, gate_ttl_secs FROM messages WHERE id = ?")
            .bind(message)
            .fetch_one(pool(&relay))
            .await
            .unwrap();
    assert_eq!(users, json!([f.owner.0]).to_string());
    assert_eq!(ttl, 30);

    let expiring = upload(&relay, &f.member.1, f.channel, 32).await;
    let expires_at = unix_now() + 3600;
    ws.send(json!({ "ChannelMessage": {
        "channel_id": f.channel,
        "encrypted_data": b64(b"expiring"),
        "expires_at": expires_at,
        "attachment_ids": [expiring.to_string()],
    }}))
    .await;
    let echo = ws.wait_for("channel_message", OBSERVE).await.unwrap();
    assert_eq!(echo["expires_at"], expires_at);
    let stored: i64 = sqlx::query_scalar("SELECT expires_at FROM messages WHERE id = ?")
        .bind(echo["message_id"].as_str().unwrap())
        .fetch_one(pool(&relay))
        .await
        .unwrap();
    assert_eq!(stored as u64, expires_at);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-35 (b) to (e): unavailable blobs
// ─────────────────────────────────────────────────────────────────────────

/// T-35 (b) to (e) and RG-C090 (relay part): another user's blob, a blob of
/// another channel, an expired pending blob, an already claimed blob and an
/// unknown id are `unavailable`, listed in `unavailable_ids`; nothing is
/// stored or claimed, no frame reaches other members, and the qualifying
/// blobs of the same request stay pending.
#[tokio::test]
async fn t35bcde_unavailable_blobs_store_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t35b").await;
    let second = relay
        .state
        .db
        .create_channel("second", f.node, f.owner.0)
        .await
        .unwrap()
        .id;
    let mut sender = WsClient::connect(&relay, &f.member.1).await;
    let mut other = WsClient::connect(&relay, &f.owner.1).await;
    let store = &relay.state.attachments;

    let own = upload(&relay, &f.member.1, f.channel, 32).await;
    let owners = upload(&relay, &f.owner.1, f.channel, 32).await;
    let elsewhere = upload(&relay, &f.member.1, second, 32).await;
    let unknown = Uuid::new_v4();
    let cases: [(&str, Uuid); 3] = [
        ("(b) another user's blob", owners),
        ("(c) a blob of another channel", elsewhere),
        ("unknown id", unknown),
    ];
    for (case, bad) in cases {
        let requested = strings(&[own, bad]);
        let (request_id, frames) =
            send_and_collect(&mut sender, claim_message(f.channel, &requested)).await;
        let frame = assert_claim_failed(&frames, "unavailable", &requested, request_id, case);
        assert_eq!(frame["unavailable_ids"], json!([bad.to_string()]), "{case}");
        assert_eq!(message_count(&relay).await, 0, "{case}");
        assert_eq!(row(&relay, own).await, Some((0, None)), "{case}");
        assert!(quiet_frames(&mut other).await.is_empty(), "{case}");
    }
    assert_eq!(row(&relay, owners).await, Some((0, None)));
    assert_eq!(row(&relay, elsewhere).await, Some((0, None)));

    // (d) An expired pending blob, before the GC has removed it.
    store.advance_clock(3601);
    let requested = strings(&[own]);
    let (request_id, frames) =
        send_and_collect(&mut sender, claim_message(f.channel, &requested)).await;
    let frame = assert_claim_failed(&frames, "unavailable", &requested, request_id, "(d)");
    assert_eq!(frame["unavailable_ids"], json!(requested));
    store.advance_clock(-3601);
    assert_eq!(message_count(&relay).await, 0);

    // (e) An already claimed blob.
    sender.send(claim_message(f.channel, &requested)).await;
    assert!(other.wait_for("channel_message", OBSERVE).await.is_some());
    sender.frames_for(QUIET).await;
    let fresh = upload(&relay, &f.member.1, f.channel, 32).await;
    let requested = strings(&[fresh, own]);
    let (request_id, frames) =
        send_and_collect(&mut sender, claim_message(f.channel, &requested)).await;
    let frame = assert_claim_failed(&frames, "unavailable", &requested, request_id, "(e)");
    assert_eq!(frame["unavailable_ids"], json!([own.to_string()]));
    assert_eq!(message_count(&relay).await, 1);
    assert_eq!(row(&relay, fresh).await, Some((0, None)));
    assert!(quiet_frames(&mut other).await.is_empty());

    // Every listed id that does not qualify is reported.
    let requested = strings(&[owners, fresh, unknown]);
    let (request_id, frames) =
        send_and_collect(&mut sender, claim_message(f.channel, &requested)).await;
    let frame = assert_claim_failed(&frames, "unavailable", &requested, request_id, "several");
    assert_eq!(frame["unavailable_ids"], json!(strings(&[owners, unknown])));
}

// ─────────────────────────────────────────────────────────────────────────
//  T-35 (f): invalid lists
// ─────────────────────────────────────────────────────────────────────────

/// T-35 (f): eleven ids, duplicates or a malformed id give `invalid` with
/// the ids echoed (except for more than 10 entries or an entry longer than
/// 36 bytes), and never a generic parse error.
#[tokio::test]
async fn t35f_invalid_lists_are_typed_failures() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t35f").await;
    let id = upload(&relay, &f.member.1, f.channel, 32).await;
    let mut ws = WsClient::connect(&relay, &f.member.1).await;

    let canonical = id.to_string();
    let echoed: Vec<(&str, Vec<String>)> = vec![
        ("duplicates", vec![canonical.clone(), canonical.clone()]),
        ("upper case", vec![canonical.to_uppercase()]),
        ("braces", vec![format!("{{{}}}", &canonical[..34])]),
        ("not a uuid", vec![canonical.clone(), "not-a-uuid".into()]),
        ("simple form", vec![id.simple().to_string()]),
    ];
    for (case, requested) in echoed {
        let (request_id, frames) =
            send_and_collect(&mut ws, claim_message(f.channel, &requested)).await;
        assert_claim_failed(&frames, "invalid", &requested, request_id, case);
    }

    for (case, requested) in [
        (
            "eleven ids",
            (0..11)
                .map(|_| Uuid::new_v4().to_string())
                .collect::<Vec<_>>(),
        ),
        ("an entry over 36 bytes", vec![format!("{canonical}0")]),
    ] {
        let request_id = ws.send(claim_message(f.channel, &requested)).await;
        let frames = ws.frames_for(QUIET).await;
        let errors: Vec<&Value> = frames.iter().filter(|f| f["type"] == "error").collect();
        assert_eq!(errors.len(), 1, "{case}: {frames:?}");
        assert_eq!(errors[0]["code"], "attachment_claim_failed", "{case}");
        assert_eq!(errors[0]["reason"], "invalid", "{case}");
        assert_eq!(errors[0]["request_id"], request_id.to_string());
        assert!(errors[0].get("attachment_ids").is_none(), "{case}");
    }

    // A payload that is not base64 (T-35 (i)).
    let requested = vec![canonical.clone()];
    let (request_id, frames) = send_and_collect(
        &mut ws,
        json!({ "ChannelMessage": {
            "channel_id": f.channel,
            "encrypted_data": "!!! not base64 !!!",
            "attachment_ids": requested,
        }}),
    )
    .await;
    assert_claim_failed(&frames, "invalid", &requested, request_id, "base64");

    assert_eq!(message_count(&relay).await, 0);
    assert_eq!(row(&relay, id).await, Some((0, None)));
}

// ─────────────────────────────────────────────────────────────────────────
//  T-35 (g), (i): the message-path checks, typed
// ─────────────────────────────────────────────────────────────────────────

/// T-35 (g) and (i): each message-path rejection of a frame with
/// `attachment_ids` answers `attachment_claim_failed` with the full ids and
/// the matching reason, and stores nothing; without `attachment_ids` the
/// generic error frame stays.
#[tokio::test]
async fn t35gi_message_path_rejections_are_typed() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t35i").await;
    let db = &relay.state.db;
    let everyone = f.node;
    let id = upload(&relay, &f.member.1, f.channel, 32).await;
    let requested = strings(&[id]);
    let mut ws = WsClient::connect(&relay, &f.member.1).await;

    // (g) ATTACH_FILES revoked between upload and claim; then SEND_MESSAGES.
    for (bit, case) in [
        (permission_bits::ATTACH_FILES, "ATTACH_FILES revoked"),
        (permission_bits::SEND_MESSAGES, "SEND_MESSAGES denied"),
        (permission_bits::VIEW_CHANNEL, "VIEW_CHANNEL denied"),
    ] {
        db.set_channel_overwrite(f.channel, everyone, 0, bit)
            .await
            .unwrap();
        let (request_id, frames) =
            send_and_collect(&mut ws, claim_message(f.channel, &requested)).await;
        assert_claim_failed(&frames, "forbidden", &requested, request_id, case);
        db.delete_channel_overwrite(f.channel, everyone)
            .await
            .unwrap();
    }

    // Slow mode: `retry_after` is the remaining cooldown.
    db.set_channel_slow_mode(f.channel, 60).await.unwrap();
    relay
        .state
        .slow_mode_cooldowns
        .write()
        .await
        .insert((f.channel, f.member.0), unix_now());
    let (request_id, frames) =
        send_and_collect(&mut ws, claim_message(f.channel, &requested)).await;
    let frame = assert_claim_failed(&frames, "slow_mode", &requested, request_id, "slow mode");
    let retry_after = frame["retry_after"].as_u64().unwrap();
    assert!((55..=60).contains(&retry_after), "{frame}");
    relay.state.slow_mode_cooldowns.write().await.clear();
    db.set_channel_slow_mode(f.channel, 0).await.unwrap();

    // The node's build allowlist does not hold the member's build.
    db.add_build_hash_to_allowlist(f.node, "approved-build", f.owner.0, None)
        .await
        .unwrap();
    let (request_id, frames) =
        send_and_collect(&mut ws, claim_message(f.channel, &requested)).await;
    assert_claim_failed(&frames, "allowlist", &requested, request_id, "allowlist");
    db.remove_build_hash_from_allowlist(f.node, "approved-build")
        .await
        .unwrap();

    // No such channel.
    let (request_id, frames) =
        send_and_collect(&mut ws, claim_message(Uuid::new_v4(), &requested)).await;
    assert_claim_failed(&frames, "forbidden", &requested, request_id, "no channel");

    // A DM: an outsider is refused, and so is a blocked participant.
    let dm = open_dm(&relay, &f.owner, &f.member, f.node).await;
    let dm_blob = upload(&relay, &f.member.1, dm, 32).await;
    let dm_requested = strings(&[dm_blob]);
    let mut outsider = WsClient::connect(&relay, &f.outsider.1).await;
    let (request_id, frames) =
        send_and_collect(&mut outsider, claim_message(dm, &dm_requested)).await;
    assert_claim_failed(
        &frames,
        "forbidden",
        &dm_requested,
        request_id,
        "DM outsider",
    );
    db.block_user(f.owner.0, f.member.0).await.unwrap();
    let (request_id, frames) = send_and_collect(&mut ws, claim_message(dm, &dm_requested)).await;
    assert_claim_failed(&frames, "blocked", &dm_requested, request_id, "DM blocked");

    // Without `attachment_ids` the generic frame stays.
    let frames = {
        ws.send(text_message(dm)).await;
        quiet_frames(&mut ws).await
    };
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["type"], "error");
    assert_eq!(
        frames[0]["error"],
        "Cannot send message: you have been blocked by this user"
    );
    assert!(frames[0].get("code").is_none(), "{}", frames[0]);

    assert_eq!(message_count(&relay).await, 0);
    assert_eq!(row(&relay, id).await, Some((0, None)));
    assert_eq!(row(&relay, dm_blob).await, Some((0, None)));

    // With every right restored the claim succeeds.
    ws.send(claim_message(f.channel, &requested)).await;
    let echo = ws.wait_for("channel_message", OBSERVE).await.unwrap();
    assert_eq!(echo["attachment_ids"], json!(requested));
}

// ─────────────────────────────────────────────────────────────────────────
//  T-35 (h): concurrent claims of one blob
// ─────────────────────────────────────────────────────────────────────────

/// T-35 (h): twenty concurrent messages claiming one blob, on twenty
/// connections of its uploader: exactly one is stored, the others get
/// `unavailable` on their own connection, and none gets `internal`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t35h_concurrent_claims_of_one_blob() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t35h").await;
    let id = upload(&relay, &f.member.1, f.channel, 32).await;
    let requested = strings(&[id]);
    let mut clients = Vec::new();
    for _ in 0..20 {
        clients.push(WsClient::connect(&relay, &f.member.1).await);
    }
    futures_util::future::join_all(
        clients
            .iter_mut()
            .map(|ws| ws.send(claim_message(f.channel, &requested))),
    )
    .await;
    let received =
        futures_util::future::join_all(clients.iter_mut().map(|ws| ws.frames_for(OBSERVE))).await;

    let mut failed_connections = 0;
    for frames in &received {
        let failures = claim_failures(frames);
        assert!(failures.len() <= 1, "{frames:?}");
        for failure in &failures {
            assert_eq!(failure["reason"], "unavailable", "{failure}");
            assert_eq!(failure["unavailable_ids"], json!(requested));
            failed_connections += 1;
        }
        // Every connection of the sender sees the one stored message.
        assert_eq!(
            frames
                .iter()
                .filter(|f| f["type"] == "channel_message")
                .count(),
            1,
            "{frames:?}"
        );
    }
    assert_eq!(failed_connections, 19);
    assert_eq!(message_count(&relay).await, 1);
    let (state, message) = row(&relay, id).await.unwrap();
    assert_eq!(state, 1);
    let stored: String = sqlx::query_scalar("SELECT id FROM messages")
        .fetch_one(pool(&relay))
        .await
        .unwrap();
    assert_eq!(message, Some(stored));
}

// ─────────────────────────────────────────────────────────────────────────
//  T-35 (j): database errors
// ─────────────────────────────────────────────────────────────────────────

/// T-35 (j): a database error injected during authorization, then during the
/// transaction, gives `internal`; no message row and no claimed row remain.
#[tokio::test]
async fn t35j_database_errors_are_internal_and_store_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t35j").await;
    let id = upload(&relay, &f.member.1, f.channel, 32).await;
    let requested = strings(&[id]);
    let mut ws = WsClient::connect(&relay, &f.member.1).await;
    let faults = relay.state.faults();

    for point in ["dm:lookup", "permissions:channel", "attachments:claim"] {
        faults.arm(point, FaultKind::Busy);
        let (request_id, frames) =
            send_and_collect(&mut ws, claim_message(f.channel, &requested)).await;
        assert_claim_failed(&frames, "internal", &requested, request_id, point);
        assert!(!faults.is_armed(point), "{point} did not fire");
        assert_eq!(message_count(&relay).await, 0, "{point}");
        assert_eq!(row(&relay, id).await, Some((0, None)), "{point}");
    }
    // A constraint-class error during the transaction rolls back as well.
    faults.arm("attachments:claim", FaultKind::Constraint);
    let (request_id, frames) =
        send_and_collect(&mut ws, claim_message(f.channel, &requested)).await;
    assert_claim_failed(&frames, "internal", &requested, request_id, "constraint");
    assert_eq!(message_count(&relay).await, 0);
    assert_eq!(row(&relay, id).await, Some((0, None)));

    ws.send(claim_message(f.channel, &requested)).await;
    assert!(ws.wait_for("channel_message", OBSERVE).await.is_some());
    assert_eq!(row(&relay, id).await.unwrap().0, 1);
}

/// Section 6.5.3: the failure frame reaches the originating connection only,
/// not the sender's other connections or other members.
#[tokio::test]
async fn claim_failures_reach_only_the_originating_connection() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t35o").await;
    let mut first = WsClient::connect(&relay, &f.member.1).await;
    let mut second = WsClient::connect(&relay, &f.member.1).await;
    let mut other = WsClient::connect(&relay, &f.owner.1).await;
    let requested = strings(&[Uuid::new_v4()]);
    let (request_id, frames) =
        send_and_collect(&mut first, claim_message(f.channel, &requested)).await;
    assert_claim_failed(&frames, "unavailable", &requested, request_id, "origin");
    assert!(quiet_frames(&mut second).await.is_empty());
    assert!(quiet_frames(&mut other).await.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────
//  T-37 (REQ-37): the edit guard
// ─────────────────────────────────────────────────────────────────────────

async fn stored_payload(relay: &TestRelay, message: &str) -> (Vec<u8>, Option<i64>) {
    sqlx::query_as("SELECT encrypted_payload, edited_at FROM messages WHERE id = ?")
        .bind(message)
        .fetch_one(pool(relay))
        .await
        .unwrap()
}

/// T-37: WS `EditMessage` on a message with attachments gets
/// `attachments_not_editable` and PATCH gets 409; the payload is unchanged
/// and nothing is broadcast. Editing a text-only message still works.
#[tokio::test]
async fn t37_messages_with_attachments_are_not_editable() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t37").await;
    let id = upload(&relay, &f.member.1, f.channel, 32).await;
    let mut ws = WsClient::connect(&relay, &f.member.1).await;
    let mut other = WsClient::connect(&relay, &f.owner.1).await;
    ws.send(claim_message(f.channel, &strings(&[id]))).await;
    let echo = ws.wait_for("channel_message", OBSERVE).await.unwrap();
    other.wait_for("channel_message", OBSERVE).await.unwrap();
    let message = echo["message_id"].as_str().unwrap().to_string();
    let before = stored_payload(&relay, &message).await;
    assert_eq!(before, (b"sealed envelope".to_vec(), None));

    // WS: the typed frame, to this connection only.
    let request_id = ws
        .send(json!({ "EditMessage": {
            "message_id": message,
            "encrypted_data": b64(b"edited envelope"),
        }}))
        .await;
    let frames = quiet_frames(&mut ws).await;
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["type"], "error");
    assert_eq!(frames[0]["code"], "attachments_not_editable");
    assert_eq!(frames[0]["reason"], "attachments_not_editable");
    assert_eq!(frames[0]["message_id"], message);
    assert_eq!(frames[0]["request_id"], request_id.to_string());
    assert!(frames[0]["error"].is_string());
    assert!(quiet_frames(&mut other).await.is_empty());
    assert_eq!(stored_payload(&relay, &message).await, before);

    // REST: 409, payload unchanged.
    let answer = call(
        &relay,
        reqwest::Method::PATCH,
        &format!("/messages/{message}"),
        Some(&f.member.1),
        Some(json!({ "encrypted_data": b64(b"edited envelope") })),
    )
    .await;
    assert_eq!(answer.status, 409, "{answer:?}");
    assert_eq!(answer.reason(), "attachments_not_editable");
    assert_eq!(answer.body["code"], 409);
    assert!(answer.body["error"].is_string());
    assert_eq!(stored_payload(&relay, &message).await, before);
    // Another user cannot edit it either, and learns nothing more.
    let answer = call(
        &relay,
        reqwest::Method::PATCH,
        &format!("/messages/{message}"),
        Some(&f.owner.1),
        Some(json!({ "encrypted_data": b64(b"x") })),
    )
    .await;
    assert_eq!(answer.status, 403, "{answer:?}");
    assert!(quiet_frames(&mut other).await.is_empty());

    // A text-only message is edited as before, over WS and REST.
    ws.send(text_message(f.channel)).await;
    let text = ws.wait_for("channel_message", OBSERVE).await.unwrap();
    other.wait_for("channel_message", OBSERVE).await.unwrap();
    let text_id = text["message_id"].as_str().unwrap().to_string();
    ws.send(json!({ "EditMessage": {
        "message_id": text_id,
        "encrypted_data": b64(b"edited text"),
    }}))
    .await;
    let edit = other.wait_for("message_edit", OBSERVE).await.unwrap();
    assert_eq!(edit["message_id"], text_id);
    assert_eq!(edit["sender_id"], f.member.0.to_string());
    assert_eq!(stored_payload(&relay, &text_id).await.0, b"edited text");
    let answer = call(
        &relay,
        reqwest::Method::PATCH,
        &format!("/messages/{text_id}"),
        Some(&f.member.1),
        Some(json!({ "encrypted_data": b64(b"edited again") })),
    )
    .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(stored_payload(&relay, &text_id).await.0, b"edited again");
}

// ─────────────────────────────────────────────────────────────────────────
//  T-43 (REQ-43): the claim's logs
// ─────────────────────────────────────────────────────────────────────────

/// T-43: logs at INFO and above from claims (accepted, unavailable, invalid,
/// failing in the transaction) and from the edit guard carry no attachment
/// id.
#[tokio::test]
async fn t43_claim_logs_carry_no_attachment_ids() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t43c").await;
    let mut ws = WsClient::connect(&relay, &f.member.1).await;
    let ids = vec![
        upload(&relay, &f.member.1, f.channel, 32).await,
        upload(&relay, &f.member.1, f.channel, 32).await,
        upload(&relay, &f.owner.1, f.channel, 32).await,
    ];

    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::INFO);
    relay
        .state
        .faults()
        .arm("attachments:claim", FaultKind::Busy);
    let frames = send_and_collect(&mut ws, claim_message(f.channel, &strings(&ids[..1])))
        .await
        .1;
    assert_eq!(claim_failures(&frames)[0]["reason"], "internal");
    let frames = send_and_collect(&mut ws, claim_message(f.channel, &strings(&ids)))
        .await
        .1;
    assert_eq!(claim_failures(&frames)[0]["reason"], "unavailable");
    let frames = send_and_collect(
        &mut ws,
        claim_message(f.channel, &[ids[0].to_string().to_uppercase()]),
    )
    .await
    .1;
    assert_eq!(claim_failures(&frames)[0]["reason"], "invalid");
    ws.send(claim_message(f.channel, &strings(&ids[..2]))).await;
    let echo = ws.wait_for("channel_message", OBSERVE).await.unwrap();
    ws.send(json!({ "EditMessage": {
        "message_id": echo["message_id"],
        "encrypted_data": b64(b"edit"),
    }}))
    .await;
    assert!(ws.wait_for("error", OBSERVE).await.is_some());
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
            !text.contains(&id.to_string().to_uppercase()),
            "{id} logged:\n{text}"
        );
        assert!(
            !text.contains(&id.simple().to_string()),
            "{id} logged:\n{text}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  T-44 (REQ-44): the capability
// ─────────────────────────────────────────────────────────────────────────

/// T-44: `features` in `GET /health` and in the WS `hello` frame contains
/// `attachments/2` (a membership test), and `GET /health` carries
/// `attachment_limits` with the configured blob limit.
#[tokio::test]
async fn t44_attachments_capability_and_limits() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |c| c.max_blob_bytes = 3 * MIB).await;
    let health = call(&relay, reqwest::Method::GET, "/health", None, None).await;
    assert_eq!(health.status, 200);
    let features = health.body["features"].as_array().expect("features");
    assert!(
        features.iter().any(|t| t == "attachments/2"),
        "{features:?}"
    );
    assert!(features.iter().any(|t| t == "admission/1"), "{features:?}");
    assert_eq!(
        health.body["attachment_limits"],
        json!({ "max_blob_bytes": 3 * MIB, "max_per_message": 10 })
    );

    let (_, token) = relay.register_and_auth("t44-user").await;
    let ws = WsClient::connect(&relay, &token).await;
    assert_eq!(ws.hello["type"], "hello");
    let features = ws.hello["features"].as_array().expect("hello features");
    assert!(
        features.iter().any(|t| t == "attachments/2"),
        "{features:?}"
    );
}

/// T-22 (REQ-22, section 11.1), relay half: the relay-served web client may
/// play audio and video previews from `blob:` URLs (`media-src 'self' blob:`),
/// and `script-src` never allows `blob:`.
#[tokio::test]
async fn t22_relay_csp_allows_blob_media_only() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let response = relay.client.get(relay.url("/health")).send().await.unwrap();
    let csp = response
        .headers()
        .get(reqwest::header::CONTENT_SECURITY_POLICY)
        .expect("CSP header")
        .to_str()
        .unwrap()
        .to_string();
    let directive = |name: &str| {
        csp.split(';')
            .map(str::trim)
            .find(|d| d.starts_with(&format!("{name} ")))
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(directive("media-src"), "media-src 'self' blob:", "{csp}");
    assert!(!directive("script-src").contains("blob:"), "{csp}");
    assert_eq!(directive("default-src"), "default-src 'self'", "{csp}");
}

// ─────────────────────────────────────────────────────────────────────────
//  T-30 (REQ-30): the legacy routes
// ─────────────────────────────────────────────────────────────────────────

/// T-30 (a): a multipart POST to `/files` answers 410
/// `legacy_uploads_removed`, stores no row and leaves the storage
/// directories unchanged.
#[tokio::test]
async fn t30a_legacy_uploads_answer_gone() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t30a").await;
    let legacy_dir = dir.path().join("files");
    let before = (listing(&legacy_dir), listing(relay.state.attachments.dir()));
    for token in [&f.member.1, &f.outsider.1] {
        let answer = legacy_upload(&relay, token, f.channel).await;
        assert_eq!(answer.status, 410, "{answer:?}");
        assert_eq!(answer.reason(), "legacy_uploads_removed");
        assert_eq!(answer.body["code"], 410);
        assert!(answer.body["error"].is_string());
    }
    assert_eq!(scalar(&relay, "SELECT COUNT(*) FROM files").await, 0);
    assert_eq!(
        (listing(&legacy_dir), listing(relay.state.attachments.dir())),
        before
    );
}

/// The `encrypted_filename` of each list item, checking every item's shape:
/// a string name and neither `storage_path` nor `content_hash`.
fn names(page: &Value) -> Vec<String> {
    page.as_array()
        .expect("the list is a JSON array")
        .iter()
        .map(|item| {
            let object = item.as_object().unwrap();
            assert!(!object.contains_key("storage_path"), "{item}");
            assert!(!object.contains_key("content_hash"), "{item}");
            for key in [
                "id",
                "channel_id",
                "uploader_id",
                "file_size_bytes",
                "created_at",
            ] {
                assert!(object.contains_key(key), "{key} missing: {item}");
            }
            item["encrypted_filename"]
                .as_str()
                .expect("a string name")
                .to_string()
        })
        .collect()
}

fn cursor(item: &Value) -> String {
    format!(
        "?before={}:{}",
        item["created_at"].as_u64().unwrap(),
        item["id"].as_str().unwrap()
    )
}

/// T-30 (b) and RG-C164 (a): 60 legacy rows, including a 2 MiB name, a
/// non-UTF-8 name and the 1 060-byte base64 text of a 255-character CJK name.
/// The first page is 50 items with `""` for the first two and the long name
/// intact, without `storage_path` or `content_hash`; the cursor returns the
/// rest; `limit=500` is clamped to 100; rows that share `created_at` are
/// ordered by id and none is skipped or repeated across pages.
#[tokio::test]
async fn t30b_rg_c164_legacy_list_shape_and_pagination() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t30b").await;
    let base = 1_700_000_000_i64;
    // 57 ordinary rows, three per second, then the three special rows newest.
    let mut seeded = Vec::new();
    for i in 0..57 {
        let name = b64(format!("name {i}").as_bytes());
        let (id, _) = seed_legacy(
            &relay,
            dir.path(),
            f.channel,
            f.member.0,
            name.as_bytes(),
            base + i / 3,
        )
        .await;
        seeded.push((base + i / 3, id));
    }
    let cjk = b64(&vec![0x5a_u8; 12 + 765 + 16]);
    assert_eq!(cjk.len(), 1060);
    let specials: [Vec<u8>; 3] = [
        vec![b'A'; 2 * MIB as usize],
        vec![0xff, 0xfe, 0x00, 0x80],
        cjk.clone().into_bytes(),
    ];
    for (i, name) in specials.iter().enumerate() {
        let created_at = base + 100 - i as i64;
        let (id, _) = seed_legacy(&relay, dir.path(), f.channel, f.owner.0, name, created_at).await;
        seeded.push((created_at, id));
    }
    // The expected order: created_at, then id, both descending.
    seeded.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.to_string().cmp(&a.1.to_string())));
    let expected: Vec<String> = seeded.iter().map(|(_, id)| id.to_string()).collect();

    let first = legacy_list(&relay, &f.member.1, f.channel, "").await;
    assert_eq!(first.status, 200, "{first:?}");
    let first_names = names(&first.body);
    assert_eq!(first_names.len(), 50);
    assert_eq!(first_names[0], "");
    assert_eq!(first_names[1], "");
    assert_eq!(first_names[2], cjk);
    assert_eq!(first.body[2]["uploader_id"], f.owner.0.to_string());
    let rest = legacy_list(&relay, &f.member.1, f.channel, &cursor(&first.body[49])).await;
    assert_eq!(rest.status, 200);
    assert_eq!(names(&rest.body).len(), 10);
    let ids = |page: &Value| -> Vec<String> {
        page.as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap().to_string())
            .collect()
    };
    let mut walked = ids(&first.body);
    walked.extend(ids(&rest.body));
    assert_eq!(walked, expected);

    // Small pages across the rows that share a second.
    let mut walked = Vec::new();
    let mut query = "?limit=7".to_string();
    loop {
        let page = legacy_list(&relay, &f.member.1, f.channel, &query).await;
        assert_eq!(page.status, 200);
        let items = page.body.as_array().unwrap().clone();
        walked.extend(ids(&page.body));
        if items.len() < 7 {
            break;
        }
        query = format!("{}&limit=7", cursor(items.last().unwrap()));
    }
    assert_eq!(walked, expected);

    // `limit` above 100 is clamped to 100.
    for i in 0..50 {
        seed_legacy(
            &relay,
            dir.path(),
            f.channel,
            f.member.0,
            b"bmFtZQ==",
            base - 10 - i,
        )
        .await;
    }
    let page = legacy_list(&relay, &f.member.1, f.channel, "?limit=500").await;
    assert_eq!(page.body.as_array().unwrap().len(), 100);
    let page = legacy_list(&relay, &f.member.1, f.channel, "?limit=1").await;
    assert_eq!(page.body.as_array().unwrap().len(), 1);

    // Malformed parameters.
    for query in ["?limit=0", "?limit=x", "?before=12", "?before=1:not-a-uuid"] {
        let answer = legacy_list(&relay, &f.member.1, f.channel, query).await;
        assert_eq!(
            (answer.status, answer.reason()),
            (400, "bad_request"),
            "{query}"
        );
    }
    // A channel the caller cannot access, and one that does not exist.
    for channel in [f.channel, Uuid::new_v4()] {
        let answer = legacy_list(&relay, &f.outsider.1, channel, "").await;
        assert_eq!((answer.status, answer.reason()), (404, "not_found"));
    }
    let answer = call(
        &relay,
        reqwest::Method::GET,
        &format!("/channels/{}/files", f.channel),
        None,
        None,
    )
    .await;
    assert_eq!(answer.status, 401);
}

/// RG-C161 (legacy list): 35 rows carrying 600 KB names come back as `""`
/// in a small response.
#[tokio::test]
async fn rg_c161_oversized_legacy_names_stay_small() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "rgc161").await;
    let name = vec![b'n'; 600 * 1000];
    for i in 0..35 {
        seed_legacy(
            &relay,
            dir.path(),
            f.channel,
            f.member.0,
            &name,
            1_700_000_000 + i,
        )
        .await;
    }
    let response = relay
        .client
        .get(relay.url(&format!("/channels/{}/files", f.channel)))
        .bearer_auth(&f.member.1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let text = response.text().await.unwrap();
    assert!(text.len() < 16 * 1024, "{} bytes", text.len());
    let page: Value = serde_json::from_str(&text).unwrap();
    let names = names(&page);
    assert_eq!(names.len(), 35);
    assert!(names.iter().all(String::is_empty));
}

/// T-30 (c) and RG-C001 (legacy DM files): a user planted in a DM's
/// `channel_members` who is not a participant gets 404 from the legacy list,
/// download and delete; a failed DM lookup denies; in a DM only the uploader
/// may delete.
#[tokio::test]
async fn t30c_rg_c001_legacy_dm_files_reach_only_participants() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t30c").await;
    let dm = open_dm(&relay, &f.owner, &f.member, f.node).await;
    let (file, path) = seed_legacy(
        &relay,
        dir.path(),
        dm,
        f.owner.0,
        b"bmFtZQ==",
        1_700_000_000,
    )
    .await;
    plant_in_dm(&relay, dm, f.outsider.0).await;

    let list = format!("/channels/{dm}/files");
    let blob = format!("/files/{file}");
    for (method, path) in [
        (reqwest::Method::GET, list.as_str()),
        (reqwest::Method::GET, blob.as_str()),
        (reqwest::Method::DELETE, blob.as_str()),
    ] {
        let answer = call(&relay, method.clone(), path, Some(&f.outsider.1), None).await;
        assert_eq!(
            (answer.status, answer.reason()),
            (404, "not_found"),
            "{method} {path}"
        );
        // A failed DM lookup denies a participant too.
        relay.state.faults().arm("dm:lookup", FaultKind::Busy);
        let answer = call(&relay, method.clone(), path, Some(&f.member.1), None).await;
        assert_eq!(answer.status, 404, "{method} {path} during a lookup error");
        assert!(!relay.state.faults().is_armed("dm:lookup"));
    }
    assert!(path.exists());

    // The participants read it.
    let page = legacy_list(&relay, &f.member.1, dm, "").await;
    assert_eq!(names(&page.body), vec!["bmFtZQ==".to_string()]);
    let response = relay
        .client
        .get(relay.url(&blob))
        .bearer_auth(&f.member.1)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        format!("legacy blob {file}").as_bytes()
    );

    // In a DM only the uploader may delete.
    let answer = call(
        &relay,
        reqwest::Method::DELETE,
        &blob,
        Some(&f.member.1),
        None,
    )
    .await;
    assert_eq!((answer.status, answer.reason()), (403, "forbidden"));
    let answer = call(
        &relay,
        reqwest::Method::DELETE,
        &blob,
        Some(&f.owner.1),
        None,
    )
    .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert!(!path.exists());
    assert_eq!(scalar(&relay, "SELECT COUNT(*) FROM files").await, 0);
}

/// T-30 (d) and RG-C054: a custom role with MANAGE_MESSAGES deletes another
/// member's legacy file (200, blob gone). A plain member gets 403, and so
/// does a legacy `admin` role marker without the bit.
#[tokio::test]
async fn t30d_rg_c054_legacy_delete_uses_role_bitflags() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t30d").await;
    let db = &relay.state.db;
    let moderator = relay.register_and_auth("t30d-moderator").await;
    let marker = relay.register_and_auth("t30d-marker").await;
    for account in [&moderator, &marker] {
        relay.join_with_owner_invite(&account.1, f.node).await;
    }
    let role = db
        .create_role(
            f.node,
            "Moderator",
            0,
            permission_bits::MANAGE_MESSAGES,
            1,
            false,
            false,
            None,
        )
        .await
        .unwrap();
    db.assign_member_role(f.node, moderator.0, role.id)
        .await
        .unwrap();
    sqlx::query("UPDATE node_members SET role = 'admin' WHERE node_id = ? AND user_id = ?")
        .bind(f.node.to_string())
        .bind(marker.0.to_string())
        .execute(pool(&relay))
        .await
        .unwrap();

    let (file, path) = seed_legacy(
        &relay,
        dir.path(),
        f.channel,
        f.member.0,
        b"bmFtZQ==",
        1_700_000_000,
    )
    .await;
    let blob = format!("/files/{file}");
    let plain = relay.register_and_auth("t30d-plain").await;
    relay.join_with_owner_invite(&plain.1, f.node).await;
    for (account, case) in [(&plain, "plain member"), (&marker, "legacy admin marker")] {
        let answer = call(
            &relay,
            reqwest::Method::DELETE,
            &blob,
            Some(&account.1),
            None,
        )
        .await;
        assert_eq!(
            (answer.status, answer.reason()),
            (403, "forbidden"),
            "{case}"
        );
        assert!(path.exists(), "{case}");
    }
    let answer = call(
        &relay,
        reqwest::Method::DELETE,
        &blob,
        Some(&moderator.1),
        None,
    )
    .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert!(!path.exists());
    assert!(db.get_file_metadata(file).await.unwrap().is_none());

    // The uploader deletes their own file.
    let (file, path) = seed_legacy(
        &relay,
        dir.path(),
        f.channel,
        f.member.0,
        b"bmFtZQ==",
        1_700_000_001,
    )
    .await;
    let answer = call(
        &relay,
        reqwest::Method::DELETE,
        &format!("/files/{file}"),
        Some(&f.member.1),
        None,
    )
    .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert!(!path.exists());
}

// ─────────────────────────────────────────────────────────────────────────
//  T-31 (REQ-31): legacy retirement
// ─────────────────────────────────────────────────────────────────────────

/// Every legacy route of `relay` answers 410.
async fn assert_legacy_routes_gone(relay: &TestRelay, token: &str, channel: Uuid, file: Uuid) {
    let answer = legacy_upload(relay, token, channel).await;
    assert_eq!(
        (answer.status, answer.reason()),
        (410, "legacy_uploads_removed")
    );
    for (method, path) in [
        (reqwest::Method::GET, format!("/channels/{channel}/files")),
        (reqwest::Method::GET, format!("/files/{file}")),
        (reqwest::Method::DELETE, format!("/files/{file}")),
    ] {
        let answer = call(relay, method.clone(), &path, Some(token), None).await;
        assert_eq!(
            (answer.status, answer.reason()),
            (410, "legacy_retired"),
            "{method} {path}"
        );
    }
}

/// T-31: with `legacy_attachments = "retired"` and a restart, the `files`
/// table is empty, no legacy blob is left, every legacy route answers 410 and
/// the `spec02_legacy_retired` row exists. Retirement is never undone, and
/// version-2 attachments are untouched.
#[tokio::test]
async fn t31_retired_setting_retires_legacy_files_at_restart() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t31").await;
    let dm = open_dm(&relay, &f.owner, &f.member, f.node).await;
    let mut legacy = Vec::new();
    for (i, channel) in [f.channel, f.channel, dm].into_iter().enumerate() {
        legacy.push(
            seed_legacy(
                &relay,
                dir.path(),
                channel,
                f.member.0,
                b"bmFtZQ==",
                1_700_000_000 + i as i64,
            )
            .await,
        );
    }
    // A file that is not a legacy blob stays.
    let unrelated = dir.path().join("files").join("README");
    std::fs::write(&unrelated, b"not a blob").unwrap();
    let attachment = upload(&relay, &f.member.1, f.channel, 32).await;
    let (file, _) = legacy[0];
    let answer = call(
        &relay,
        reqwest::Method::GET,
        &format!("/files/{file}"),
        Some(&f.member.1),
        None,
    )
    .await;
    assert_eq!(answer.status, 200);
    assert!(relay
        .state
        .db
        .ledger_applied_at(LEDGER_LEGACY_RETIRED)
        .await
        .unwrap()
        .is_none());
    relay.state.db.raw_pool().close().await;

    // Restart with the setting.
    let state = open_state(dir.path(), |c| {
        c.legacy_mode = LegacyAttachmentsMode::Retired
    })
    .await;
    let relay = TestRelay::with_state(Arc::new(state)).await;
    assert_eq!(scalar(&relay, "SELECT COUNT(*) FROM files").await, 0);
    for (_, path) in &legacy {
        assert!(!path.exists(), "{path:?}");
    }
    assert!(unrelated.exists());
    assert!(relay
        .state
        .db
        .ledger_applied_at(LEDGER_LEGACY_RETIRED)
        .await
        .unwrap()
        .is_some());
    assert_legacy_routes_gone(&relay, &f.member.1, f.channel, file).await;
    assert_eq!(
        download_status(&relay, &f.member.1, attachment).await,
        404,
        "pending blobs are never served"
    );
    assert_eq!(row(&relay, attachment).await, Some((0, None)));
    relay.state.db.raw_pool().close().await;

    // Back to `read-only`: retirement stays, recorded in the ledger.
    let state = open_state(dir.path(), |_| {}).await;
    let relay = TestRelay::with_state(Arc::new(state)).await;
    assert!(relay.state.attachments.legacy_retired());
    assert_legacy_routes_gone(&relay, &f.member.1, f.channel, file).await;
}

/// T-31 and section 7.7 (OD-33): retirement is reached automatically at T0 +
/// `legacy_attachments_retire_after_days`; the legacy routes answer 410 from
/// that moment and the next check deletes the files (OD-34: delete). Rows
/// that reappear afterwards are deleted at the following check.
#[tokio::test]
async fn t31_legacy_window_ends_at_t0_plus_the_delay() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |c| c.legacy_retire_after_days = 2).await;
    let f = node_fixture(&relay, "t31w").await;
    let store = &relay.state.attachments;
    let db = &relay.state.db;
    let t0 = db
        .ledger_applied_at(LEDGER_ATTACHMENTS_V2)
        .await
        .unwrap()
        .expect("T0");
    assert_eq!(store.legacy_deadline(), Some(t0 + 2 * 86_400));
    let (file, path) = seed_legacy(
        &relay,
        dir.path(),
        f.channel,
        f.member.0,
        b"bmFtZQ==",
        1_700_000_000,
    )
    .await;

    // Before the deadline nothing happens.
    store.advance_clock(2 * 86_400 - 120);
    assert!(!store.legacy_retired());
    assert_eq!(
        store
            .enforce_legacy_retirement(db, &relay.state.file_handler)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        legacy_list(&relay, &f.member.1, f.channel, "").await.status,
        200
    );

    // At the deadline the routes answer 410 at once; the check deletes.
    store.advance_clock(120);
    assert!(store.legacy_retired());
    assert_legacy_routes_gone(&relay, &f.member.1, f.channel, file).await;
    assert!(path.exists());
    let report = store
        .enforce_legacy_retirement(db, &relay.state.file_handler)
        .await
        .unwrap()
        .expect("retired");
    assert_eq!((report.rows, report.blobs, report.blob_failures), (1, 1, 0));
    assert!(!path.exists());
    assert!(db
        .ledger_applied_at(LEDGER_LEGACY_RETIRED)
        .await
        .unwrap()
        .is_some());

    // A row an older relay binary wrote afterwards is deleted at the next
    // check, and the ledger row keeps its first time.
    let first = db.ledger_applied_at(LEDGER_LEGACY_RETIRED).await.unwrap();
    let (_, late) = seed_legacy(
        &relay,
        dir.path(),
        f.channel,
        f.member.0,
        b"bmFtZQ==",
        1_700_000_005,
    )
    .await;
    let report = store
        .enforce_legacy_retirement(db, &relay.state.file_handler)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.rows, 1);
    assert!(!late.exists());
    assert_eq!(
        db.ledger_applied_at(LEDGER_LEGACY_RETIRED).await.unwrap(),
        first
    );
}

/// Section 7.7: `accord-server purge-legacy-attachments` retires at once,
/// whatever the window; it deletes rows and blobs in batches larger than one
/// batch, and a blob that cannot be found does not stop it.
#[tokio::test]
async fn t31_purge_retires_immediately() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t31p").await;
    let count = accord_server::attachments::legacy::RETIREMENT_BATCH as i64 + 20;
    let mut paths = Vec::new();
    for i in 0..count {
        let (_, path) = seed_legacy(
            &relay,
            dir.path(),
            f.channel,
            f.member.0,
            b"bmFtZQ==",
            1_700_000_000 + i,
        )
        .await;
        paths.push(path);
    }
    // One blob is already gone.
    std::fs::remove_file(&paths[0]).unwrap();
    assert!(!relay.state.attachments.legacy_retired());
    let report = relay
        .state
        .attachments
        .retire_legacy_now(&relay.state.db, &relay.state.file_handler)
        .await
        .unwrap();
    assert_eq!(report.rows as i64, count);
    assert_eq!(report.blobs as i64, count - 1);
    assert_eq!(report.blob_failures, 0);
    assert!(paths.iter().all(|p| !p.exists()));
    assert_eq!(scalar(&relay, "SELECT COUNT(*) FROM files").await, 0);
    assert!(relay.state.attachments.legacy_retired());
    assert!(relay
        .state
        .db
        .ledger_applied_at(LEDGER_LEGACY_RETIRED)
        .await
        .unwrap()
        .is_some());
    let file = Uuid::new_v4();
    assert_legacy_routes_gone(&relay, &f.member.1, f.channel, file).await;
}

/// Section 7.7 and REQ-31: `purge-legacy-attachments` run from another
/// process while the relay is up. The subcommand opens its own state on the
/// same database and storage; the running relay answers 410 on every legacy
/// route from its next legacy request, without a restart or a
/// reconciliation.
#[tokio::test]
async fn t31_purge_from_another_process_reaches_a_running_relay() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t31x").await;
    let (file, path) = seed_legacy(
        &relay,
        dir.path(),
        f.channel,
        f.member.0,
        b"bmFtZQ==",
        1_700_000_000,
    )
    .await;
    let answer = call(
        &relay,
        reqwest::Method::GET,
        &format!("/files/{file}"),
        Some(&f.member.1),
        None,
    )
    .await;
    assert_eq!(answer.status, 200, "{answer:?}");

    // The subcommand, as `purge_legacy_attachments` in main.rs runs it.
    let purge = open_state(dir.path(), |_| {}).await;
    let report = purge
        .attachments
        .retire_legacy_now(&purge.db, &purge.file_handler)
        .await
        .unwrap();
    assert_eq!((report.rows, report.blobs, report.blob_failures), (1, 1, 0));
    purge.db.raw_pool().close().await;
    drop(purge);

    // The running relay has not seen it yet; its next legacy request does.
    assert!(!relay.state.attachments.legacy_retired());
    assert!(!path.exists());
    assert_legacy_routes_gone(&relay, &f.member.1, f.channel, file).await;
    assert!(relay.state.attachments.legacy_retired());
}

/// Section 7.7 and REQ-31: a `spec02_legacy_retired` row written by another
/// process is applied by the running relay's next retirement check (the
/// reconciliation path), which deletes the rows and blobs still present.
/// The ledger row keeps its first time.
#[tokio::test]
async fn t31_reconciliation_applies_a_retirement_recorded_elsewhere() {
    let dir = tempfile::tempdir().unwrap();
    let relay = start(&dir, |_| {}).await;
    let f = node_fixture(&relay, "t31r").await;
    let (file, path) = seed_legacy(
        &relay,
        dir.path(),
        f.channel,
        f.member.0,
        b"bmFtZQ==",
        1_700_000_000,
    )
    .await;
    assert_eq!(
        legacy_list(&relay, &f.member.1, f.channel, "").await.status,
        200
    );

    // Another process records the retirement with its own connection.
    let other = SqlitePool::connect(&format!(
        "sqlite://{}",
        dir.path().join("relay.db").display()
    ))
    .await
    .unwrap();
    sqlx::query("INSERT INTO relay_migrations (name, applied_at) VALUES (?, ?)")
        .bind(LEDGER_LEGACY_RETIRED)
        .bind(1_700_000_100_i64)
        .execute(&other)
        .await
        .unwrap();
    other.close().await;
    assert!(!relay.state.attachments.legacy_retired());

    let report = relay
        .state
        .attachments
        .enforce_legacy_retirement(&relay.state.db, &relay.state.file_handler)
        .await
        .unwrap()
        .expect("the ledger row retires");
    assert_eq!((report.rows, report.blobs, report.blob_failures), (1, 1, 0));
    assert!(relay.state.attachments.legacy_retired());
    assert_eq!(scalar(&relay, "SELECT COUNT(*) FROM files").await, 0);
    assert!(!path.exists());
    assert_eq!(
        relay
            .state
            .db
            .ledger_applied_at(LEDGER_LEGACY_RETIRED)
            .await
            .unwrap(),
        Some(1_700_000_100)
    );
    assert_legacy_routes_gone(&relay, &f.member.1, f.channel, file).await;
}
