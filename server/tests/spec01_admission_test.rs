//! SPEC-01 section 11.2 step 5: the admission service and atomic invite
//! consumption (REQ-18 to REQ-28, REQ-36 to REQ-39, REQ-41, REQ-45, REQ-49).
//!
//! Tests T-18 to T-28, T-36 to T-39, T-41, T-45 and T-49 of section 10.2,
//! and the regressions RG-C002-1 to RG-C002-7, RG-C252-1, RG-N008-1 and
//! RG-N014-1 of section 10.3. Every test serves the production router; every
//! account has a password and every membership comes from an owner-created
//! invite. Approvals go through `POST /nodes/:id/join-requests/:user_id/approve`
//! (step 7); the join-request and removal tests are in
//! `spec01_membership_test.rs`.

use accord_server::admission::{AdmissionError, INVITE_CODE_RETRIES};
use accord_server::attachments::AttachmentConfig;
use accord_server::db::{DbOptions, DM_SYSTEM_NODE_ID, DM_SYSTEM_USER_ID};
use accord_server::faults::FaultKind;
use accord_server::files::FileConfig;
use accord_server::models::permission_bits::{CREATE_INVITE, DEFAULT_EVERYONE};
use accord_server::rate_limit::{ActionType, RateLimiter};
use accord_server::router;
use accord_server::state::{AppState, AppStateOptions};
use accord_server::test_support::{count_frames, LogCapture, TestRelay, WsClient, TEST_PASSWORD};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const D: &str = "00000000-0000-0000-0000-000000000001";
const OBSERVE: Duration = Duration::from_secs(1);

// ─────────────────────────────────────────────────────────────────────────
//  Harness
// ─────────────────────────────────────────────────────────────────────────

fn pool(relay: &TestRelay) -> &SqlitePool {
    relay.state.db.raw_pool()
}

async fn exec(pool: &SqlitePool, sql: &str) {
    sqlx::query(sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Register a v1 account with the test password and log it in. Both go
/// through the relay state, because `POST /register` and `POST /auth` are
/// limited per client address and every test request shares one; the
/// tested routes then use the token over HTTP.
async fn account(relay: &TestRelay, public_key: &str) -> (Uuid, String) {
    let user = relay
        .state
        .register_user(public_key.to_string(), TEST_PASSWORD.to_string())
        .await
        .unwrap();
    let pkh = accord_server::db::compute_public_key_hash(public_key);
    let token = relay
        .state
        .authenticate_user(pkh, TEST_PASSWORD.to_string())
        .await
        .unwrap();
    assert_eq!(token.user_id, user);
    (user, token.token)
}

/// A version-1 encrypted metadata blob (version byte, then ciphertext), in
/// base64.
fn metadata_blob() -> String {
    use base64::Engine;
    let mut blob = vec![1u8];
    blob.extend_from_slice(&[0u8; 40]);
    base64::engine::general_purpose::STANDARD.encode(blob)
}

/// A deterministic 64-hex device fingerprint.
fn fp(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

/// A relay over a file-backed database in a temporary directory, as the
/// concurrency tests need (section 10.1).
async fn file_relay(dir: &tempfile::TempDir) -> TestRelay {
    let files = dir.path().join("files");
    std::fs::create_dir_all(&files).unwrap();
    let state = AppState::new_with_options(
        dir.path().join("relay.db").to_str().unwrap(),
        AppStateOptions {
            database_encryption: false,
            db: DbOptions::default(),
            file_config: Some(FileConfig {
                storage_dir: files,
                max_file_size: 1024 * 1024,
            }),
            attachments: Some(AttachmentConfig::with_dir(dir.path().join("attachments"))),
        },
    )
    .await
    .unwrap();
    TestRelay::with_state(Arc::new(state)).await
}

/// Send a request and return the status and the JSON body (`Null` if none).
async fn send(request: reqwest::RequestBuilder) -> (u16, Value) {
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// `POST /nodes/:id/invites` with an optional JSON body.
async fn create_invite(
    relay: &TestRelay,
    token: &str,
    node: Uuid,
    body: Option<Value>,
) -> (u16, Value) {
    let mut request = relay
        .client
        .post(relay.url(&format!("/nodes/{node}/invites")))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    send(request).await
}

/// Create an unlimited, permanent invite and return its code.
async fn invite_code(relay: &TestRelay, token: &str, node: Uuid) -> String {
    let (status, body) = create_invite(relay, token, node, None).await;
    assert_eq!(status, 200, "{body}");
    body["invite_code"].as_str().unwrap().to_string()
}

/// `POST /invites/:code/join` with an optional fingerprint and build hash.
async fn redeem(
    relay: &TestRelay,
    token: &str,
    code: &str,
    fingerprint: Option<&str>,
    build_hash: Option<&str>,
) -> (u16, Value) {
    let mut request = relay
        .client
        .post(relay.url(&format!("/invites/{code}/join")))
        .bearer_auth(token);
    if let Some(fingerprint) = fingerprint {
        request = request.json(&json!({ "device_fingerprint_hash": fingerprint }));
    }
    if let Some(hash) = build_hash {
        request = request.header("X-Build-Hash", hash);
    }
    send(request).await
}

/// `POST /nodes/:id/join` with an optional body and build hash.
async fn join_by_id(
    relay: &TestRelay,
    token: &str,
    node: Uuid,
    body: Option<Value>,
    build_hash: Option<&str>,
) -> (u16, Value) {
    let mut request = relay
        .client
        .post(relay.url(&format!("/nodes/{node}/join")))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    if let Some(hash) = build_hash {
        request = request.header("X-Build-Hash", hash);
    }
    send(request).await
}

/// `POST /nodes/:id/join-requests/:user_id/approve` as the holder of `token`.
async fn approve(relay: &TestRelay, token: &str, node: Uuid, requester: Uuid) -> (u16, Value) {
    send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/join-requests/{requester}/approve")))
            .bearer_auth(token),
    )
    .await
}

async fn is_member(relay: &TestRelay, node: Uuid, user: Uuid) -> bool {
    relay.state.db.is_node_member(node, user).await.unwrap()
}

async fn current_uses(relay: &TestRelay, code: &str) -> i64 {
    count(
        pool(relay),
        &format!("SELECT current_uses FROM node_invites WHERE invite_code = '{code}'"),
    )
    .await
}

/// Give `user` a role holding CREATE_INVITE in `node`.
async fn grant_create_invite(relay: &TestRelay, node: Uuid, user: Uuid) -> Uuid {
    let role = relay
        .state
        .db
        .create_role(node, "Inviter", 0, CREATE_INVITE, 1, false, false, None)
        .await
        .unwrap();
    relay
        .state
        .db
        .assign_member_role(node, user, role.id)
        .await
        .unwrap();
    role.id
}

async fn create_channel(relay: &TestRelay, token: &str, node: Uuid, name: &str) {
    let (status, body) = send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/channels")))
            .bearer_auth(token)
            .json(&json!({ "name": name })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

async fn remove_row(relay: &TestRelay, node: Uuid, user: Uuid) {
    exec(
        pool(relay),
        &format!("DELETE FROM node_members WHERE node_id = '{node}' AND user_id = '{user}'"),
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────
//  T-18: one admission function
// ─────────────────────────────────────────────────────────────────────────

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// T-18 (REQ-18), static part: outside `db::admission`, no source file of the
/// relay calls `add_node_member(` or inserts into `node_members`. The unwired
/// database layers are excluded by an explicit list.
#[test]
fn t18_only_db_admission_inserts_memberships() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let unwired = ["db/relay.rs", "db/node_db.rs", "db/migration.rs"];
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut offenders = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if unwired.contains(&relative.as_str()) || relative == "db/admission.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap().to_lowercase();
        if text.contains("add_node_member(") {
            offenders.push(format!("{relative}: add_node_member("));
        }
        for (i, _) in text.match_indices("insert") {
            let tail: String = text[i..].chars().take(200).collect();
            let statement = tail.split(';').next().unwrap_or("");
            if let Some(into) = statement.find("into") {
                if statement[into + 4..]
                    .trim_start()
                    .starts_with("node_members")
                {
                    offenders.push(format!(
                        "{relative}: {}",
                        &statement[..statement.len().min(80)]
                    ));
                }
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:#?}");
}

// ─────────────────────────────────────────────────────────────────────────
//  T-19, T-20, T-21: the three entry points
// ─────────────────────────────────────────────────────────────────────────

/// T-19 (REQ-19, REQ-25): a redemption answers with the node and broadcasts
/// once per channel.
#[tokio::test]
async fn t19_invite_redemption_broadcasts_once() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "t19-owner").await;
    let (_, observer) = account(&relay, "t19-observer").await;
    let (u, u_token) = account(&relay, "t19-u").await;
    let node = relay.create_node(&owner, "T19").await;
    create_channel(&relay, &owner, node, "two").await;
    create_channel(&relay, &owner, node, "three").await;
    relay.join_with_owner_invite(&observer, node).await;
    let code = invite_code(&relay, &owner, node).await;
    let mut ws = WsClient::connect(&relay, &observer).await;

    let (status, body) = redeem(&relay, &u_token, &code, None, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "joined");
    assert_eq!(body["node_id"], node.to_string());
    assert_eq!(body["node_name"], "T19");
    let frames = ws.frames_for(OBSERVE).await;
    assert_eq!(count_frames(&frames, "member_joined"), 3, "{frames:?}");
    assert_eq!(
        count_frames(&frames, "sender_key_new_member"),
        3,
        "{frames:?}"
    );
    assert!(frames
        .iter()
        .all(|f| f["type"] != "member_joined" || f["user_id"] == u.to_string()));
}

/// T-20 (REQ-20): `POST /nodes/:id/join`.
#[tokio::test]
async fn t20_join_by_node_id() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t20-owner").await;
    let node = relay.create_node(&owner, "T20").await;
    let other = relay.create_node(&owner, "T20-other").await;

    // (a) No invite on an invite-only node.
    let (a_id, a) = account(&relay, "t20-a").await;
    let (status, body) = join_by_id(&relay, &a, node, None, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (403, json!("invite_required"))
    );
    assert!(!is_member(&relay, node, a_id).await);
    // An empty JSON object is the same.
    let (status, _) = join_by_id(&relay, &a, node, Some(json!({})), None).await;
    assert_eq!(status, 403);

    // (b) With a valid code of this node.
    let code = invite_code(&relay, &owner, node).await;
    let (b_id, b) = account(&relay, "t20-b").await;
    let (status, body) =
        join_by_id(&relay, &b, node, Some(json!({"invite_code": code})), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "joined");
    assert!(is_member(&relay, node, b_id).await);

    // (c) With a code of another node: invalid, and not consumed.
    let foreign = invite_code(&relay, &owner, other).await;
    let (c_id, c) = account(&relay, "t20-c").await;
    let (status, body) = join_by_id(
        &relay,
        &c,
        node,
        Some(json!({"invite_code": foreign})),
        None,
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("invite_invalid"))
    );
    assert_eq!(current_uses(&relay, &foreign).await, 0);
    assert!(!is_member(&relay, node, c_id).await);

    // (d) Policy `request`: a join request.
    exec(
        pool(&relay),
        &format!("UPDATE nodes SET join_policy = 'request' WHERE id = '{node}'"),
    )
    .await;
    let (status, body) = join_by_id(&relay, &c, node, None, None).await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["status"], "pending_approval");
    assert!(body["expires_at"].as_u64().unwrap() >= now() as u64 + 1_209_600 - 5);
    assert_eq!(
        count(
            pool(&relay),
            &format!("SELECT COUNT(*) FROM node_join_requests WHERE node_id = '{node}'")
        )
        .await,
        1
    );
    assert!(!is_member(&relay, node, c_id).await);

    // (e) Again as a member.
    let (status, body) = join_by_id(&relay, &b, node, None, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (409, json!("already_member"))
    );

    // (f) The owner, after the owner's row was deleted.
    remove_row(&relay, node, owner_id).await;
    let (status, body) = join_by_id(&relay, &owner, node, None, None).await;
    assert_eq!(status, 200, "{body}");

    // (g) Removed again, with a valid single-use code: nothing is consumed.
    remove_row(&relay, node, owner_id).await;
    let (_, single) = create_invite(&relay, &owner, node, Some(json!({"max_uses": 1}))).await;
    let single = single["invite_code"].as_str().unwrap().to_string();
    let (status, body) = join_by_id(
        &relay,
        &owner,
        node,
        Some(json!({"invite_code": single})),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(current_uses(&relay, &single).await, 0);
}

/// T-21 (REQ-21) and RG-C002-2: WS `JoinNode` answers with exactly one typed
/// frame, never a generic error frame, and broadcasts only on success.
#[tokio::test]
async fn t21_ws_join_node_typed_frames() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "t21-owner").await;
    let (_, observer) = account(&relay, "t21-observer").await;
    let (x_id, x) = account(&relay, "t21-x").await;
    let (_, y) = account(&relay, "t21-y").await;
    let node = relay.create_node(&owner, "T21").await;
    relay.join_with_owner_invite(&observer, node).await;
    let mut watch = WsClient::connect(&relay, &observer).await;
    let mut ws = WsClient::connect(&relay, &x).await;

    // No invite: join_failed invite_required; the observer sees nothing.
    let id = ws.send(json!({"JoinNode": {"node_id": node}})).await;
    let frames = ws.frames_for(Duration::from_millis(500)).await;
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["type"], "join_failed");
    assert_eq!(frames[0]["reason"], "invite_required");
    assert_eq!(frames[0]["error"], "This node requires an invite");
    assert_eq!(frames[0]["request_id"], id.to_string());
    assert!(watch.frames_for(OBSERVE).await.is_empty());

    // A malformed fingerprint: invalid_request, one frame.
    let id = ws
        .send(json!({"JoinNode": {"node_id": node, "device_fingerprint_hash": "XYZ"}}))
        .await;
    let frames = ws.frames_for(Duration::from_millis(500)).await;
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["reason"], "invalid_request");
    assert_eq!(frames[0]["request_id"], id.to_string());

    // With a valid code: node_joined, and the broadcast follows.
    let code = invite_code(&relay, &owner, node).await;
    let id = ws
        .send(json!({"JoinNode": {"node_id": node, "invite_code": code}}))
        .await;
    let joined = ws.wait_for("node_joined", OBSERVE).await.unwrap();
    assert_eq!(joined["request_id"], id.to_string());
    assert_eq!(joined["node_name"], "T21");
    assert!(is_member(&relay, node, x_id).await);
    let frames = watch.frames_for(OBSERVE).await;
    assert_eq!(count_frames(&frames, "member_joined"), 1, "{frames:?}");

    // Policy `request`: join_pending.
    exec(
        pool(&relay),
        &format!("UPDATE nodes SET join_policy = 'request' WHERE id = '{node}'"),
    )
    .await;
    let mut ws_y = WsClient::connect(&relay, &y).await;
    let id = ws_y.send(json!({"JoinNode": {"node_id": node}})).await;
    let frames = ws_y.frames_for(Duration::from_millis(500)).await;
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["type"], "join_pending");
    assert_eq!(frames[0]["request_id"], id.to_string());
    assert!(frames[0]["expires_at"].as_u64().is_some());
    assert!(watch
        .frames_for(Duration::from_millis(300))
        .await
        .is_empty());
}

// ─────────────────────────────────────────────────────────────────────────
//  T-22, T-23: validity and atomic consumption
// ─────────────────────────────────────────────────────────────────────────

/// T-22 (REQ-22): the validity conditions V1 to V6, and their order.
#[tokio::test]
async fn t22_invite_validity() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t22-owner").await;
    let node = relay.create_node(&owner, "T22").await;
    let p = pool(&relay);
    let past = now() - 10;

    let expired = invite_code(&relay, &owner, node).await;
    exec(
        p,
        &format!("UPDATE node_invites SET expires_at = {past} WHERE invite_code = '{expired}'"),
    )
    .await;
    let exhausted = invite_code(&relay, &owner, node).await;
    exec(p, &format!("UPDATE node_invites SET max_uses = 2, current_uses = 2 WHERE invite_code = '{exhausted}'")).await;
    let both = invite_code(&relay, &owner, node).await;
    exec(p, &format!("UPDATE node_invites SET expires_at = {past}, max_uses = 1, current_uses = 1 WHERE invite_code = '{both}'")).await;
    let revoked = invite_code(&relay, &owner, node).await;
    exec(
        p,
        &format!("DELETE FROM node_invites WHERE invite_code = '{revoked}'"),
    )
    .await;

    // A creator who loses CREATE_INVITE, and one who leaves.
    let (demoted_id, demoted) = account(&relay, "t22-demoted").await;
    relay.join_with_owner_invite(&demoted, node).await;
    let role = grant_create_invite(&relay, node, demoted_id).await;
    let by_demoted = invite_code(&relay, &demoted, node).await;
    assert!(relay
        .state
        .db
        .remove_member_role(demoted_id, role)
        .await
        .unwrap());
    let (leaver_id, leaver) = account(&relay, "t22-leaver").await;
    relay.join_with_owner_invite(&leaver, node).await;
    grant_create_invite(&relay, node, leaver_id).await;
    let by_leaver = invite_code(&relay, &leaver, node).await;
    relay.state.leave_node(leaver_id, node).await.unwrap();

    // The owner's invite stays valid while the owner is not a member.
    let by_owner = invite_code(&relay, &owner, node).await;
    remove_row(&relay, node, owner_id).await;

    // An invite created by the reserved user.
    exec(p, &format!(
        "INSERT INTO node_invites (id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at) \
         VALUES ('{}', '{node}', '{DM_SYSTEM_USER_ID}', 'SentinelMade01', NULL, 0, NULL, 0)",
        Uuid::new_v4()
    ))
    .await;

    let cases = [
        (expired.as_str(), 410, "invite_expired"),
        (exhausted.as_str(), 410, "invite_exhausted"),
        (both.as_str(), 410, "invite_expired"),
        (revoked.as_str(), 404, "invite_invalid"),
        (by_demoted.as_str(), 404, "invite_invalid"),
        (by_leaver.as_str(), 404, "invite_invalid"),
        (by_owner.as_str(), 200, ""),
        ("SentinelMade01", 404, "invite_invalid"),
    ];
    for (i, (code, status, reason)) in cases.iter().enumerate() {
        let (_, token) = account(&relay, &format!("t22-joiner-{i}")).await;
        let (got, body) = redeem(&relay, &token, code, None, None).await;
        assert_eq!(got, *status, "case {i}: {body}");
        if !reason.is_empty() {
            assert_eq!(body["reason"], *reason, "case {i}");
        }
    }
}

/// T-23 (REQ-23) and RG-C252-1: concurrent redemptions never exceed
/// `max_uses`, and `current_uses` counts the admissions.
#[tokio::test]
async fn t23_concurrent_redemptions_respect_max_uses() {
    let dir = tempfile::tempdir().unwrap();
    let relay = file_relay(&dir).await;
    let (_, owner) = account(&relay, "t23-owner").await;
    let node = relay.create_node(&owner, "T23").await;
    let mut tokens = Vec::new();
    for i in 0..24 {
        tokens.push(account(&relay, &format!("t23-{i}")).await.1);
    }

    for (max_uses, batch) in [(1, &tokens[..12]), (3, &tokens[12..])] {
        let (_, body) =
            create_invite(&relay, &owner, node, Some(json!({"max_uses": max_uses}))).await;
        let code = body["invite_code"].as_str().unwrap().to_string();
        let results = futures_util::future::join_all(
            batch
                .iter()
                .map(|token| redeem(&relay, token, &code, None, None)),
        )
        .await;
        let joined = results.iter().filter(|(s, _)| *s == 200).count();
        let exhausted = results
            .iter()
            .filter(|(s, b)| *s == 410 && b["reason"] == "invite_exhausted")
            .count();
        assert_eq!(joined, max_uses, "{results:?}");
        assert_eq!(joined + exhausted, 12, "{results:?}");
        assert_eq!(current_uses(&relay, &code).await, max_uses as i64);
    }

    // One user redeeming twice in parallel: one admission, one already_member.
    let (_, solo) = account(&relay, "t23-solo").await;
    let (_, body) = create_invite(&relay, &owner, node, Some(json!({"max_uses": 2}))).await;
    let code = body["invite_code"].as_str().unwrap().to_string();
    let (a, b) = tokio::join!(
        redeem(&relay, &solo, &code, None, None),
        redeem(&relay, &solo, &code, None, None)
    );
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, [200, 409], "{a:?} {b:?}");
    assert_eq!(current_uses(&relay, &code).await, 1);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-24: admission checks on every entry point
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Entry {
    Invite,
    NodeId,
    Ws,
}

/// Attempt an admission through `entry` and return the reason, or "joined".
async fn attempt(
    relay: &TestRelay,
    entry: Entry,
    token: &str,
    node: Uuid,
    code: &str,
    fingerprint: Option<&str>,
    build_hash: Option<&str>,
) -> String {
    let (status, body) = match entry {
        Entry::Invite => redeem(relay, token, code, fingerprint, build_hash).await,
        Entry::NodeId => {
            let mut body = json!({"invite_code": code});
            if let Some(fingerprint) = fingerprint {
                body["device_fingerprint_hash"] = json!(fingerprint);
            }
            join_by_id(relay, token, node, Some(body), build_hash).await
        }
        Entry::Ws => {
            assert!(build_hash.is_none(), "the WS client sends no X-Build-Hash");
            let mut ws = WsClient::connect(relay, token).await;
            let mut message = json!({"JoinNode": {"node_id": node, "invite_code": code}});
            if let Some(fingerprint) = fingerprint {
                message["JoinNode"]["device_fingerprint_hash"] = json!(fingerprint);
            }
            ws.send(message).await;
            let frames = ws.frames_for(Duration::from_millis(500)).await;
            let answer = frames
                .iter()
                .find(|f| f["type"] == "node_joined" || f["type"] == "join_failed")
                .cloned()
                .unwrap_or_else(|| panic!("no answer in {frames:?}"));
            assert_eq!(count_frames(&frames, "error"), 0, "{frames:?}");
            return if answer["type"] == "node_joined" {
                "joined".into()
            } else {
                answer["reason"].as_str().unwrap().to_string()
            };
        }
    };
    if status == 200 {
        "joined".into()
    } else {
        body["reason"].as_str().unwrap_or("?").to_string()
    }
}

/// T-24 (REQ-24): bans, device checks and the build allowlist apply on all
/// three entry points and to approvals; every `admission:*` fault fails
/// closed with no row and no broadcast.
#[tokio::test]
async fn t24_admission_checks_on_every_entry_point() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t24-owner").await;
    let db = &relay.state.db;
    let banned_node = relay.create_node(&owner, "DeviceBans").await;
    let capped_node = relay.create_node(&owner, "Capped").await;
    let open_node = relay.create_node(&owner, "Open").await;
    let allow_node = relay.create_node(&owner, "Allowlist").await;
    db.ban_device_from_node(banned_node, &fp(0xf0), owner_id, None, None)
        .await
        .unwrap();
    db.set_node_max_accounts_per_device(capped_node, 1)
        .await
        .unwrap();
    db.add_build_hash_to_allowlist(allow_node, "H", owner_id, None)
        .await
        .unwrap();
    let banned_code = invite_code(&relay, &owner, banned_node).await;
    let capped_code = invite_code(&relay, &owner, capped_node).await;
    let open_code = invite_code(&relay, &owner, open_node).await;
    let allow_code = invite_code(&relay, &owner, allow_node).await;
    // One member already joined the capped node on fingerprint F2.
    let (_, first) = account(&relay, "t24-first").await;
    assert_eq!(
        redeem(&relay, &first, &capped_code, Some(&fp(0xf2)), None)
            .await
            .0,
        200
    );

    let mut n: u8 = 0;
    async fn fresh(relay: &TestRelay, n: &mut u8) -> (Uuid, String) {
        *n += 1;
        account(relay, &format!("t24-u{n}")).await
    }
    for entry in [Entry::Invite, Entry::NodeId, Entry::Ws] {
        // (c) A key-banned user.
        let (banned_id, banned) = fresh(&relay, &mut n).await;
        let pkh = db
            .get_user_public_key_hash(banned_id)
            .await
            .unwrap()
            .unwrap();
        db.ban_from_node(banned_node, &pkh, owner_id, None, None)
            .await
            .unwrap();
        assert_eq!(
            attempt(
                &relay,
                entry,
                &banned,
                banned_node,
                &banned_code,
                Some(&fp(0x01)),
                None
            )
            .await,
            "banned"
        );
        // (d) device checks.
        let (_, u) = fresh(&relay, &mut n).await;
        assert_eq!(
            attempt(&relay, entry, &u, banned_node, &banned_code, None, None).await,
            "fingerprint_required",
            "{entry:?}"
        );
        assert_eq!(
            attempt(
                &relay,
                entry,
                &u,
                banned_node,
                &banned_code,
                Some(&fp(0xf0)),
                None
            )
            .await,
            "device_banned"
        );
        assert_eq!(
            attempt(
                &relay,
                entry,
                &u,
                capped_node,
                &capped_code,
                Some(&fp(0xf2)),
                None
            )
            .await,
            "device_limit"
        );
        assert_eq!(
            attempt(
                &relay,
                entry,
                &u,
                banned_node,
                &banned_code,
                Some(&fp(0x10 + n)),
                None
            )
            .await,
            "joined"
        );
        let (_, u) = fresh(&relay, &mut n).await;
        assert_eq!(
            attempt(&relay, entry, &u, open_node, &open_code, None, None).await,
            "joined"
        );
        // (e) the build allowlist.
        let (_, u) = fresh(&relay, &mut n).await;
        if !matches!(entry, Entry::Ws) {
            assert_eq!(
                attempt(&relay, entry, &u, allow_node, &allow_code, None, Some("H2")).await,
                "build_not_allowed"
            );
            assert_eq!(
                attempt(&relay, entry, &u, allow_node, &allow_code, None, None).await,
                "build_not_allowed"
            );
            assert_eq!(
                attempt(&relay, entry, &u, allow_node, &allow_code, None, Some("H")).await,
                "joined"
            );
        } else {
            assert_eq!(
                attempt(&relay, entry, &u, allow_node, &allow_code, None, None).await,
                "build_not_allowed"
            );
        }
    }

    // An approval of a request made without a fingerprint, before the node
    // had device bans.
    let (requester, _) = fresh(&relay, &mut n).await;
    let requests_node = relay.create_node(&owner, "Requests").await;
    exec(pool(&relay), &format!(
        "INSERT INTO node_join_requests (node_id, user_id, created_at, expires_at) VALUES ('{requests_node}', '{requester}', 0, {})",
        now() + 1000
    ))
    .await;
    db.ban_device_from_node(requests_node, &fp(0xee), owner_id, None, None)
        .await
        .unwrap();
    let (status, body) = approve(&relay, &owner, requests_node, requester).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (403, json!("fingerprint_required")),
        "{body}"
    );
    assert!(!is_member(&relay, requests_node, requester).await);
    assert_eq!(
        count(pool(&relay), "SELECT COUNT(*) FROM node_join_requests").await,
        0
    );

    // Every admission fault point fails closed: 503, no row, no broadcast.
    let (_, observer) = fresh(&relay, &mut n).await;
    relay.join_with_owner_invite(&observer, open_node).await;
    let mut watch = WsClient::connect(&relay, &observer).await;
    for point in [
        "admission:invite_consume",
        "admission:ban_check",
        "admission:device_check",
        "admission:allowlist",
        "admission:authority",
    ] {
        let (u_id, u) = fresh(&relay, &mut n).await;
        let uses = current_uses(&relay, &open_code).await;
        relay.state.faults().arm(point, FaultKind::Busy);
        let (status, body) = redeem(&relay, &u, &open_code, None, None).await;
        assert_eq!(
            (status, body["reason"].clone()),
            (503, json!("unavailable")),
            "{point}"
        );
        assert!(
            !relay.state.faults().is_armed(point),
            "{point} did not fire"
        );
        assert!(!is_member(&relay, open_node, u_id).await, "{point}");
        assert_eq!(current_uses(&relay, &open_code).await, uses, "{point}");
    }
    assert!(watch.frames_for(OBSERVE).await.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────
//  T-25, T-26: clean slate and owner self-admission
// ─────────────────────────────────────────────────────────────────────────

/// T-25 (REQ-25) and RG-C033-1: a kicked member re-admitted by a new invite
/// starts with no roles and no stale key deliveries, subscribed to every
/// channel, with one broadcast set.
#[tokio::test]
async fn t25_readmission_starts_from_a_clean_slate() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t25-owner").await;
    let (k_id, k) = account(&relay, "t25-k").await;
    let (_, observer) = account(&relay, "t25-observer").await;
    let node = relay.create_node(&owner, "T25").await;
    create_channel(&relay, &owner, node, "second").await;
    relay.join_with_owner_invite(&k, node).await;
    relay.join_with_owner_invite(&observer, node).await;
    relay
        .state
        .db
        .assign_named_role(node, k_id, "Admin")
        .await
        .unwrap();
    let channels = relay.state.db.get_node_channels(node).await.unwrap();
    for channel in &channels {
        exec(pool(&relay), &format!(
            "INSERT INTO sender_key_distributions (id, channel_id, from_user_id, to_user_id, encrypted_payload, created_at) \
             VALUES ('{}', '{}', '{owner_id}', '{k_id}', x'00', 0)",
            Uuid::new_v4(),
            channel.id
        ))
        .await;
    }
    let (status, _) = send(
        relay
            .client
            .delete(relay.url(&format!("/nodes/{node}/members/{k_id}")))
            .bearer_auth(&owner),
    )
    .await;
    assert_eq!(status, 200);
    assert!(!is_member(&relay, node, k_id).await);

    let mut watch = WsClient::connect(&relay, &observer).await;
    let code = invite_code(&relay, &owner, node).await;
    assert_eq!(redeem(&relay, &k, &code, None, None).await.0, 200);
    assert!(relay
        .state
        .db
        .get_member_roles(node, k_id)
        .await
        .unwrap()
        .is_empty());
    let marker = relay
        .state
        .db
        .get_node_member(node, k_id)
        .await
        .unwrap()
        .unwrap()
        .role;
    assert_eq!(marker.as_str(), "member");
    assert_eq!(
        count(
            pool(&relay),
            &format!("SELECT COUNT(*) FROM sender_key_distributions WHERE to_user_id = '{k_id}'")
        )
        .await,
        0
    );
    for channel in &channels {
        assert!(relay
            .state
            .db
            .get_channel_members(channel.id)
            .await
            .unwrap()
            .contains(&k_id));
    }
    let frames = watch.frames_for(OBSERVE).await;
    assert_eq!(
        count_frames(&frames, "member_joined"),
        channels.len(),
        "{frames:?}"
    );
    assert_eq!(
        count_frames(&frames, "sender_key_new_member"),
        channels.len(),
        "{frames:?}"
    );
}

/// T-26 (REQ-26): the owner re-admits themselves on every entry point,
/// even when banned, without consuming an invite, with the `admin` marker and
/// the Admin role restored.
#[tokio::test]
async fn t26_owner_self_admission() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t26-owner").await;
    let node = relay.create_node(&owner, "T26").await;
    let (_, single) = create_invite(&relay, &owner, node, Some(json!({"max_uses": 1}))).await;
    let single = single["invite_code"].as_str().unwrap().to_string();
    let expired = invite_code(&relay, &owner, node).await;
    exec(
        pool(&relay),
        &format!(
            "UPDATE node_invites SET expires_at = {} WHERE invite_code = '{expired}'",
            now() - 10
        ),
    )
    .await;
    let pkh = relay
        .state
        .db
        .get_user_public_key_hash(owner_id)
        .await
        .unwrap()
        .unwrap();
    relay
        .state
        .db
        .ban_from_node(node, &pkh, owner_id, None, None)
        .await
        .unwrap();

    // (a) Redeeming a valid invite.
    remove_row(&relay, node, owner_id).await;
    let (status, body) = redeem(&relay, &owner, &single, None, None).await;
    assert_eq!(status, 200, "{body}");
    let member = relay
        .state
        .db
        .get_node_member(node, owner_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.role.as_str(), "admin");
    let roles = relay
        .state
        .db
        .get_member_roles(node, owner_id)
        .await
        .unwrap();
    assert!(roles.iter().any(|r| r.name == "Admin"));
    assert_eq!(current_uses(&relay, &single).await, 0);
    let (status, body) = send(
        relay
            .client
            .put(relay.url(&format!("/api/nodes/{node}/metadata/encrypted")))
            .bearer_auth(&owner)
            .json(&json!({"node": {"encrypted_name": metadata_blob()}})),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // (b) Redeeming an expired invite.
    remove_row(&relay, node, owner_id).await;
    assert_eq!(redeem(&relay, &owner, &expired, None, None).await.0, 200);
    // (c) By node id, with no body.
    remove_row(&relay, node, owner_id).await;
    assert_eq!(join_by_id(&relay, &owner, node, None, None).await.0, 200);
    // (d) Over WebSocket.
    remove_row(&relay, node, owner_id).await;
    let mut ws = WsClient::connect(&relay, &owner).await;
    ws.send(json!({"JoinNode": {"node_id": node}})).await;
    assert!(ws.wait_for("node_joined", OBSERVE).await.is_some());
    assert!(is_member(&relay, node, owner_id).await);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-27: rate limits
// ─────────────────────────────────────────────────────────────────────────

/// T-27 (a) to (d), (f) (REQ-27): membership actions are charged per user on
/// every entry point; join requests are charged twice; redemptions are no
/// longer counted as invite creation, and the middleware's 429 is JSON.
#[tokio::test]
async fn t27_membership_actions_are_rate_limited() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "t27-owner").await;
    let node = relay.create_node(&owner, "T27").await;

    // (a) 11 actions mixing REST join, WS JoinNode and leave.
    let (_, a) = account(&relay, "t27-a").await;
    let mut ws = WsClient::connect(&relay, &a).await;
    for _ in 0..4 {
        assert_eq!(join_by_id(&relay, &a, node, None, None).await.0, 403);
    }
    for _ in 0..3 {
        ws.send(json!({"JoinNode": {"node_id": node}})).await;
        assert_eq!(
            ws.wait_for("join_failed", OBSERVE).await.unwrap()["reason"],
            "invite_required"
        );
    }
    for _ in 0..3 {
        let (status, _) = send(
            relay
                .client
                .post(relay.url(&format!("/nodes/{node}/leave")))
                .bearer_auth(&a),
        )
        .await;
        assert_ne!(status, 429);
    }
    let (status, body) = join_by_id(&relay, &a, node, None, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (429, json!("rate_limited"))
    );
    assert!(body["retry_after"].as_u64().unwrap() >= 1);
    ws.send(json!({"JoinNode": {"node_id": node}})).await;
    let frame = ws.wait_for("join_failed", OBSERVE).await.unwrap();
    assert_eq!(frame["reason"], "rate_limited");
    assert!(frame["retry_after"].as_u64().is_some());

    // (b) 10 successful invite joins across nodes, then an 11th.
    let (_, b) = account(&relay, "t27-b").await;
    let mut codes = Vec::new();
    for i in 0..11 {
        let n = relay.create_node(&owner, &format!("T27-{i}")).await;
        codes.push(invite_code(&relay, &owner, n).await);
    }
    for code in &codes[..10] {
        assert_eq!(redeem(&relay, &b, code, None, None).await.0, 200);
    }
    let (status, body) = redeem(&relay, &b, &codes[10], None, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (429, json!("rate_limited"))
    );
    assert_eq!(current_uses(&relay, &codes[10]).await, 0);

    // (c) 11 kicks by one moderator.
    for i in 0..10 {
        let (status, _) = send(
            relay
                .client
                .delete(relay.url(&format!("/nodes/{node}/members/{}", Uuid::new_v4())))
                .bearer_auth(&owner),
        )
        .await;
        assert_ne!(status, 429, "kick {i}");
    }
    let (status, body) = send(
        relay
            .client
            .delete(relay.url(&format!("/nodes/{node}/members/{}", Uuid::new_v4())))
            .bearer_auth(&owner),
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (429, json!("rate_limited"))
    );

    // (d) 6 join requests: the 6th is refused by JoinRequestCreate, and each
    // attempt also used a MembershipChange token.
    let (_, owner2) = account(&relay, "t27-owner2").await;
    let (_, r) = account(&relay, "t27-r").await;
    let mut request_nodes = Vec::new();
    for i in 0..6 {
        let n = relay.create_node(&owner2, &format!("T27-req-{i}")).await;
        exec(
            pool(&relay),
            &format!("UPDATE nodes SET join_policy = 'request' WHERE id = '{n}'"),
        )
        .await;
        request_nodes.push(n);
    }
    for n in &request_nodes[..5] {
        assert_eq!(join_by_id(&relay, &r, *n, None, None).await.0, 202);
    }
    let (status, body) = join_by_id(&relay, &r, request_nodes[5], None, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (429, json!("rate_limited"))
    );
    for _ in 0..4 {
        assert_eq!(join_by_id(&relay, &r, node, None, None).await.0, 403);
    }
    assert_eq!(join_by_id(&relay, &r, node, None, None).await.0, 429);

    // (f) `?token=` redemptions are not counted as InviteCreate.
    let (f_id, f) = account(&relay, "t27-f").await;
    let mut f_codes = Vec::new();
    for i in 0..10 {
        let n = relay.create_node(&owner2, &format!("T27-f-{i}")).await;
        f_codes.push(invite_code(&relay, &owner2, n).await);
    }
    for code in &f_codes {
        let (status, body) = send(
            relay
                .client
                .post(relay.url(&format!("/invites/{code}/join?token={f}"))),
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }
    assert_eq!(
        relay
            .state
            .rate_limiter
            .get_status(f_id, ActionType::InviteCreate)
            .await
            .0,
        0
    );
    // The middleware's 429 on invite creation carries the JSON body.
    let (_, c) = account(&relay, "t27-c").await;
    let own = relay.create_node(&c, "T27-own").await;
    for _ in 0..10 {
        assert_eq!(
            send(
                relay
                    .client
                    .post(relay.url(&format!("/nodes/{own}/invites?token={c}")))
            )
            .await
            .0,
            200
        );
    }
    let (status, body) = send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{own}/invites?token={c}"))),
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(body["reason"], "rate_limited");
    assert_eq!(body["code"], 429);
    assert!(body["retry_after"].as_u64().unwrap() >= 1);
}

/// One preview request through the production router, with the given
/// socket peer (or none) and headers.
async fn preview(
    state: &accord_server::state::SharedState,
    code: &str,
    peer: Option<&str>,
    xff: Option<&str>,
) -> u16 {
    use tower::Service;
    let app = router::build_public_router(state.clone());
    let app = match peer {
        Some(peer) => app.layer(axum::extract::connect_info::MockConnectInfo(
            peer.parse::<SocketAddr>().unwrap(),
        )),
        None => app,
    };
    let mut request = axum::http::Request::builder().uri(format!("/invites/{code}/preview"));
    if let Some(xff) = xff {
        request = request.header("X-Forwarded-For", xff);
    }
    let mut app = app;
    let response = app
        .call(request.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    response.status().as_u16()
}

/// T-27 (e) and (g) (REQ-27, REQ-39): the preview limit keys on the socket
/// peer's IPv4 address or IPv6 /64, ignores forwarded headers, and never
/// applies to loopback peers or without connect information.
#[tokio::test]
async fn t27_preview_limit_keys_on_the_socket_peer() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "t27e-owner").await;
    let node = relay.create_node(&owner, "T27e").await;
    let code = invite_code(&relay, &owner, node).await;
    let state = relay.state.clone();
    let run = |peer: &'static str, n: usize| {
        let state = state.clone();
        let code = code.clone();
        async move {
            let mut statuses = Vec::new();
            for _ in 0..n {
                statuses.push(preview(&state, &code, Some(peer), None).await);
            }
            statuses
        }
    };
    let first = run("203.0.113.1:4000", 31).await;
    assert!(first[..30].iter().all(|s| *s == 200), "{first:?}");
    assert_eq!(first[30], 429);
    assert!(run("203.0.113.2:4000", 30).await.iter().all(|s| *s == 200));
    assert_eq!(
        preview(
            &state,
            &code,
            Some("203.0.113.1:4001"),
            Some("198.51.100.7")
        )
        .await,
        429
    );
    assert!(run("[2001:db8:1:2::1]:4000", 20)
        .await
        .iter()
        .all(|s| *s == 200));
    let same64 = run("[2001:db8:1:2::2]:4000", 11).await;
    assert!(same64[..10].iter().all(|s| *s == 200), "{same64:?}");
    assert_eq!(same64[10], 429);
    assert_eq!(
        preview(&state, &code, Some("[2001:db8:1:3::1]:4000"), None).await,
        200
    );
    // An IPv4-mapped IPv6 peer shares its IPv4 address's bucket.
    assert_eq!(
        preview(&state, &code, Some("[::ffff:203.0.113.1]:4000"), None).await,
        429
    );
    assert!(run("127.0.0.1:4000", 40).await.iter().all(|s| *s == 200));
    assert!(run("[::1]:4000", 40).await.iter().all(|s| *s == 200));
    for _ in 0..40 {
        assert_eq!(preview(&state, &code, None, None).await, 200);
    }

    // (g) `--preview-rate-limit 0`, then `--disable-rate-limits`.
    let mut unlimited = AppState::new_in_memory().await.unwrap();
    unlimited.rate_limiter.set_preview_limit(0);
    let relay = TestRelay::with_state(Arc::new(unlimited)).await;
    let (_, owner) = account(&relay, "t27g-owner").await;
    let node = relay.create_node(&owner, "T27g").await;
    let code = invite_code(&relay, &owner, node).await;
    for _ in 0..40 {
        assert_eq!(
            preview(&relay.state, &code, Some("203.0.113.9:1"), None).await,
            200
        );
    }
    let (_, a) = account(&relay, "t27g-a").await;
    assert_eq!(join_by_id(&relay, &a, node, None, None).await.0, 403);

    let mut disabled = AppState::new_in_memory().await.unwrap();
    disabled.rate_limiter = RateLimiter::new_disabled();
    let relay = TestRelay::with_state(Arc::new(disabled)).await;
    let (_, owner) = account(&relay, "t27g2-owner").await;
    let node = relay.create_node(&owner, "T27g2").await;
    let code = invite_code(&relay, &owner, node).await;
    for _ in 0..40 {
        assert_eq!(
            preview(&relay.state, &code, Some("203.0.113.9:1"), None).await,
            200
        );
    }
    let (_, a) = account(&relay, "t27g2-a").await;
    for _ in 0..12 {
        assert_eq!(join_by_id(&relay, &a, node, None, None).await.0, 403);
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  T-28, T-45: reasons and check order
// ─────────────────────────────────────────────────────────────────────────

/// T-28 (REQ-28): refusals carry their reason, success bodies are JSON, and
/// a failure writes no audit row and broadcasts nothing. The shared token
/// extractor's 401 and axum's rejection of a malformed id keep their bodies.
#[tokio::test]
async fn t28_refusals_carry_reasons() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t28-owner").await;
    let (_, plain) = account(&relay, "t28-plain").await;
    let (_, observer) = account(&relay, "t28-observer").await;
    let node = relay.create_node(&owner, "T28").await;
    relay.join_with_owner_invite(&plain, node).await;
    relay.join_with_owner_invite(&observer, node).await;
    let mut watch = WsClient::connect(&relay, &observer).await;
    let audit = || count(pool(&relay), "SELECT COUNT(*) FROM audit_log");
    let audit_before = audit().await;

    let (_, x) = account(&relay, "t28-x").await;
    let checks: Vec<(u16, Value, u16, &str)> = vec![
        {
            let (s, b) = join_by_id(
                &relay,
                &x,
                node,
                Some(json!({"device_fingerprint_hash": "nothex"})),
                None,
            )
            .await;
            (s, b, 400, "invalid_request")
        },
        {
            let (s, b) = join_by_id(&relay, &x, Uuid::new_v4(), None, None).await;
            (s, b, 404, "node_not_found")
        },
        {
            let (s, b) = join_by_id(&relay, &x, node, None, None).await;
            (s, b, 403, "invite_required")
        },
        {
            let (s, b) = redeem(&relay, &x, "UnknownCode1", None, None).await;
            (s, b, 404, "invite_invalid")
        },
        {
            let (s, b) = create_invite(&relay, &plain, node, None).await;
            (s, b, 403, "forbidden")
        },
        {
            let (s, b) = create_invite(&relay, &owner, node, Some(json!({"foo": 1}))).await;
            (s, b, 400, "invalid_request")
        },
        {
            let (s, b) = redeem(
                &relay,
                &plain,
                &invite_code(&relay, &owner, node).await,
                None,
                None,
            )
            .await;
            (s, b, 409, "already_member")
        },
    ];
    for (status, body, want_status, want_reason) in checks {
        assert_eq!(status, want_status, "{body}");
        assert_eq!(body["reason"], want_reason, "{body}");
        assert_eq!(body["code"], want_status);
        assert!(body["error"].is_string());
    }
    // join_requests_full: 200 pending requests from others fill the node.
    exec(
        pool(&relay),
        &format!("UPDATE nodes SET join_policy = 'request' WHERE id = '{node}'"),
    )
    .await;
    for i in 0..200 {
        let user = relay
            .state
            .register_user(format!("t28-req-{i}"), "pw".into())
            .await
            .unwrap();
        exec(pool(&relay), &format!(
            "INSERT INTO node_join_requests (node_id, user_id, created_at, expires_at) VALUES ('{node}', '{user}', 0, {})",
            now() + 1000
        ))
        .await;
    }
    let (status, body) = join_by_id(&relay, &x, node, None, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (403, json!("join_requests_full"))
    );
    // An expired request does not count.
    exec(pool(&relay), &format!("UPDATE node_join_requests SET expires_at = 1 WHERE node_id = '{node}' AND user_id != '{owner_id}' AND rowid = (SELECT MIN(rowid) FROM node_join_requests)")).await;
    let (status, _) = join_by_id(&relay, &x, node, None, None).await;
    assert_eq!(status, 202);

    assert_eq!(
        audit().await,
        audit_before + 1,
        "only the setup invite was audited"
    );
    let frames = watch.frames_for(OBSERVE).await;
    assert_eq!(count_frames(&frames, "member_joined"), 0, "{frames:?}");

    // Bodies kept by REQ-28.
    let (status, body) = send(relay.client.post(relay.url(&format!("/nodes/{node}/join")))).await;
    assert_eq!(status, 401);
    assert!(body.get("reason").is_none(), "{body}");
    let response = relay
        .client
        .post(relay.url("/nodes/not-a-uuid/join"))
        .bearer_auth(&x)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    assert!(!response.text().await.unwrap().contains("reason"));
}

/// T-45 (REQ-45): the first failure in the defined order is reported.
#[tokio::test]
async fn t45_check_order() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t45-owner").await;
    let node = relay.create_node(&owner, "T45").await;
    let (_, m) = account(&relay, "t45-m").await;
    relay.join_with_owner_invite(&m, node).await;
    let expired = invite_code(&relay, &owner, node).await;
    exec(
        pool(&relay),
        &format!(
            "UPDATE node_invites SET expires_at = {} WHERE invite_code = '{expired}'",
            now() - 10
        ),
    )
    .await;
    let (_, body) = create_invite(&relay, &owner, node, Some(json!({"max_uses": 1}))).await;
    let exhausted = body["invite_code"].as_str().unwrap().to_string();
    exec(
        pool(&relay),
        &format!("UPDATE node_invites SET current_uses = 1 WHERE invite_code = '{exhausted}'"),
    )
    .await;
    let valid = invite_code(&relay, &owner, node).await;
    let (b_id, b) = account(&relay, "t45-b").await;
    let pkh = relay
        .state
        .db
        .get_user_public_key_hash(b_id)
        .await
        .unwrap()
        .unwrap();
    relay
        .state
        .db
        .ban_from_node(node, &pkh, owner_id, None, None)
        .await
        .unwrap();
    let (r_id, r) = account(&relay, "t45-r").await;
    for _ in 0..10 {
        relay
            .state
            .rate_limiter
            .check(r_id, ActionType::MembershipChange)
            .await
            .unwrap();
    }

    let reason = |r: (u16, Value)| (r.0, r.1["reason"].as_str().unwrap_or("").to_string());
    assert_eq!(
        reason(redeem(&relay, &m, &expired, None, None).await),
        (409, "already_member".into())
    );
    assert_eq!(
        reason(redeem(&relay, &m, "UnknownCode2", None, None).await),
        (404, "invite_invalid".into())
    );
    let bad_fp = json!({"device_fingerprint_hash": "ABC"});
    let (status, body) = send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{D}/join")))
            .bearer_auth(&m)
            .json(&bad_fp),
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (400, json!("invalid_request"))
    );
    assert_eq!(
        reason(redeem(&relay, &r, "UnknownCode3", None, None).await),
        (429, "rate_limited".into())
    );
    assert_eq!(
        reason(redeem(&relay, &b, &exhausted, None, None).await),
        (410, "invite_exhausted".into())
    );
    let uses = current_uses(&relay, &valid).await;
    assert_eq!(
        reason(redeem(&relay, &b, &valid, None, None).await),
        (403, "banned".into())
    );
    assert_eq!(current_uses(&relay, &valid).await, uses);

    // Approvals through the endpoint: (g) a non-authority approver of a
    // request that does not exist, (h) a requester who joined meanwhile.
    let (_, x) = account(&relay, "t45-x").await;
    assert_eq!(
        reason(approve(&relay, &x, node, Uuid::new_v4()).await),
        (403, "forbidden".into())
    );
    let (h_id, h) = account(&relay, "t45-h").await;
    exec(pool(&relay), &format!(
        "INSERT INTO node_join_requests (node_id, user_id, created_at, expires_at) VALUES ('{node}', '{h_id}', 0, {})",
        now() + 1000
    ))
    .await;
    relay.join_with_owner_invite(&h, node).await;
    assert_eq!(
        reason(approve(&relay, &owner, node, h_id).await),
        (409, "already_member".into())
    );
    assert_eq!(
        count(pool(&relay), "SELECT COUNT(*) FROM node_join_requests").await,
        0
    );
    // A missing (consumed) request, and the reserved node.
    assert_eq!(
        reason(approve(&relay, &owner, node, h_id).await),
        (404, "request_not_found".into())
    );
    assert_eq!(
        reason(approve(&relay, &owner, DM_SYSTEM_NODE_ID, h_id).await),
        (404, "node_not_found".into())
    );
    // The database transaction reports the same reasons.
    assert_eq!(
        relay
            .state
            .db
            .approve_join_request(owner_id, node, h_id)
            .await,
        Err(AdmissionError::RequestNotFound)
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  T-36 to T-39: the invite lifecycle
// ─────────────────────────────────────────────────────────────────────────

/// T-36 (REQ-36), integration part: a legacy 8-character code with an expiry
/// still redeems, and exhausted code collisions give 503 and no invite.
#[tokio::test]
async fn t36_legacy_codes_and_collisions() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t36-owner").await;
    let node = relay.create_node(&owner, "T36").await;
    exec(pool(&relay), &format!(
        "INSERT INTO node_invites (id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at) \
         VALUES ('{}', '{node}', '{owner_id}', 'Legacy08', NULL, 0, {}, 0)",
        Uuid::new_v4(),
        now() + 3600
    ))
    .await;
    let (_, u) = account(&relay, "t36-u").await;
    assert_eq!(redeem(&relay, &u, "Legacy08", None, None).await.0, 200);

    // The generator repeats one code while the fault point is armed: the
    // first creation stores it, the second collides on every attempt.
    let invites = || count(pool(&relay), "SELECT COUNT(*) FROM node_invites");
    relay
        .state
        .faults()
        .arm("admission:code_collision", FaultKind::Constraint);
    let (status, _) = create_invite(&relay, &owner, node, None).await;
    assert_eq!(status, 200);
    let before = invites().await;
    let attempts = relay.state.faults().counter("admission:code_attempt");
    relay
        .state
        .faults()
        .arm("admission:code_collision", FaultKind::Constraint);
    let (status, body) = create_invite(&relay, &owner, node, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (503, json!("unavailable"))
    );
    assert_eq!(
        relay.state.faults().counter("admission:code_attempt") - attempts,
        1 + INVITE_CODE_RETRIES as u64
    );
    assert_eq!(invites().await, before);
}

/// T-37 (REQ-37) and RG-N008-1: strict invite-creation bodies.
#[tokio::test]
async fn t37_strict_invite_bodies() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "t37-owner").await;
    let node = relay.create_node(&owner, "T37").await;
    let invites = || count(pool(&relay), "SELECT COUNT(*) FROM node_invites");

    // Empty body with a JSON content type: unlimited and permanent.
    let (status, body) = send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/invites")))
            .bearer_auth(&owner)
            .header("Content-Type", "application/json"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["max_uses"].is_null() && body["expires_at"].is_null());

    let ok: Vec<(Value, Option<i64>, Option<u64>)> = vec![
        (json!({"expires_hours": 0.5}), Some(1800), None),
        (json!({"expires_hours": 0.1}), Some(360), None),
        (json!({"expires_in_hours": 24}), Some(86_400), None),
        (
            json!({"expires_in_seconds": 120, "expires_hours": 5}),
            Some(120),
            None,
        ),
        (
            json!({"expires_in_seconds": null, "expires_hours": 0.5}),
            Some(1800),
            None,
        ),
        (json!({"max_uses": null}), None, None),
        (
            json!({"max_uses": 7, "expires_in_seconds": 60}),
            Some(60),
            Some(7),
        ),
    ];
    for (request, lifetime, max_uses) in ok {
        let (status, body) = create_invite(&relay, &owner, node, Some(request.clone())).await;
        assert_eq!(status, 200, "{request}: {body}");
        let stored: Option<i64> =
            sqlx::query_scalar("SELECT expires_at FROM node_invites WHERE invite_code = ?")
                .bind(body["invite_code"].as_str().unwrap())
                .fetch_one(pool(&relay))
                .await
                .unwrap();
        assert_eq!(body["expires_at"].as_i64(), stored, "{request}");
        match lifetime {
            None => assert!(stored.is_none(), "{request}"),
            Some(secs) => {
                let created = body["created_at"].as_i64().unwrap();
                assert_eq!(stored.unwrap() - created, secs, "{request}");
            }
        }
        assert_eq!(body["max_uses"].as_u64(), max_uses, "{request}");
    }

    let before = invites().await;
    for request in [
        json!({"expires_in_seconds": 120, "expires_hours": -5}),
        json!({"expires_hours": "abc"}),
        json!({"max_uses": 0}),
        json!({"max_uses": 100_001}),
        json!({"foo": 1}),
        json!({"expires_in_seconds": 30}),
        json!({"expires_in_hours": 0.01}),
        json!({"expires_in_seconds": 31_536_001}),
        json!([1, 2]),
    ] {
        let (status, body) = create_invite(&relay, &owner, node, Some(request.clone())).await;
        assert_eq!(
            (status, body["reason"].clone()),
            (400, json!("invalid_request")),
            "{request}"
        );
    }
    let (status, _) = send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/invites")))
            .bearer_auth(&owner)
            .header("Content-Type", "application/json")
            .body("{not json"),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(invites().await, before, "a refused body created an invite");
}

/// T-38 (REQ-38) and RG-N008-1: list aliases and revocation by code.
#[tokio::test]
async fn t38_invite_management() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "t38-owner").await;
    let (c_id, c) = account(&relay, "t38-c").await;
    let (_, plain) = account(&relay, "t38-plain").await;
    let node = relay.create_node(&owner, "T38").await;
    relay.join_with_owner_invite(&c, node).await;
    relay.join_with_owner_invite(&plain, node).await;
    let role = grant_create_invite(&relay, node, c_id).await;
    let owner_code = invite_code(&relay, &owner, node).await;
    let c_code = invite_code(&relay, &c, node).await;
    let other_code = invite_code(&relay, &owner, node).await;

    let (status, body) = send(
        relay
            .client
            .get(relay.url(&format!("/nodes/{node}/invites")))
            .bearer_auth(&owner),
    )
    .await;
    assert_eq!(status, 200);
    for item in body["invites"].as_array().unwrap() {
        assert_eq!(item["code"], item["invite_code"]);
        assert_eq!(item["uses"], item["current_uses"]);
    }
    // Plain members can neither list nor revoke.
    let (status, body) = send(
        relay
            .client
            .get(relay.url(&format!("/nodes/{node}/invites")))
            .bearer_auth(&plain),
    )
    .await;
    assert_eq!((status, body["reason"].clone()), (403, json!("forbidden")));

    let revoke = |token: String, code: String| {
        let relay = &relay;
        async move {
            send(
                relay
                    .client
                    .delete(relay.url(&format!("/nodes/{node}/invites/{code}")))
                    .bearer_auth(token),
            )
            .await
        }
    };
    assert_eq!(revoke(owner.clone(), owner_code.clone()).await.0, 200);
    // C, no longer holding CREATE_INVITE, may still revoke their own invite.
    assert!(relay.state.db.remove_member_role(c_id, role).await.unwrap());
    let (status, body) = revoke(c.clone(), c_code.clone()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "revoked");
    // A plain member cannot revoke someone else's invite, nor probe codes.
    assert_eq!(revoke(plain.clone(), other_code.clone()).await.0, 403);
    assert_eq!(revoke(plain.clone(), "NoSuchCode9".into()).await.0, 403);
    // An authority holder gets invite_invalid for an unknown code.
    let (status, body) = revoke(owner.clone(), "NoSuchCode9".into()).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("invite_invalid"))
    );

    let (_, u) = account(&relay, "t38-u").await;
    for code in [&owner_code, &c_code] {
        let (status, body) = redeem(&relay, &u, code, None, None).await;
        assert_eq!(
            (status, body["reason"].clone()),
            (404, json!("invite_invalid"))
        );
    }
    // `DELETE /invites/:id` still works, and audits the id only.
    let id = relay
        .state
        .db
        .get_node_invite_by_code(&other_code)
        .await
        .unwrap()
        .unwrap()
        .id;
    let (status, body) = send(
        relay
            .client
            .delete(relay.url(&format!("/invites/{id}")))
            .bearer_auth(&owner),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["invite_id"], id.to_string());
    let (status, body) = send(
        relay
            .client
            .delete(relay.url(&format!("/invites/{id}")))
            .bearer_auth(&owner),
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("invite_invalid"))
    );
    let details: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_log WHERE action IN ('invite_create', 'invite_revoke')",
    )
    .fetch_all(pool(&relay))
    .await
    .unwrap();
    // Five creations (two setup invites, three in the test) and three
    // revocations.
    assert_eq!(details.len(), 5 + 3, "{details:?}");
    for d in details {
        let v: Value = serde_json::from_str(&d).unwrap();
        assert!(
            v.get("invite_code").is_none() && v.get("invite_id").is_some(),
            "{d}"
        );
    }
}

/// T-39 (REQ-39): the preview applies REQ-22 without consuming.
#[tokio::test]
async fn t39_preview_applies_validity() {
    let relay = TestRelay::start().await;
    let (user, owner) = account(&relay, "t39-owner").await;
    let (d_id, demoted) = account(&relay, "t39-demoted").await;
    let node = relay.create_node(&owner, "T39").await;
    relay.join_with_owner_invite(&demoted, node).await;
    let role = grant_create_invite(&relay, node, d_id).await;
    let by_demoted = invite_code(&relay, &demoted, node).await;
    relay.state.db.remove_member_role(d_id, role).await.unwrap();
    let (_, body) = create_invite(&relay, &owner, node, Some(json!({"max_uses": 1}))).await;
    let exhausted = body["invite_code"].as_str().unwrap().to_string();
    exec(
        pool(&relay),
        &format!("UPDATE node_invites SET current_uses = 1 WHERE invite_code = '{exhausted}'"),
    )
    .await;
    let valid = invite_code(&relay, &owner, node).await;
    relay.state.db.drop_admission_triggers().await.unwrap();
    exec(pool(&relay), &format!(
        "INSERT INTO node_invites (id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at) \
         VALUES ('{}', '{D}', '{user}', 'ReservedInvite03', NULL, 0, NULL, 0)",
        Uuid::new_v4()
    ))
    .await;

    let get = |code: String| {
        let relay = &relay;
        async move {
            send(
                relay
                    .client
                    .get(relay.url(&format!("/invites/{code}/preview"))),
            )
            .await
        }
    };
    let (status, body) = get(by_demoted).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("invite_invalid"))
    );
    let (status, body) = get(exhausted).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (410, json!("invite_exhausted"))
    );
    let (status, body) = get("ReservedInvite03".into()).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("invite_invalid"))
    );
    let (status, body) = get(valid.clone()).await;
    assert_eq!(status, 200);
    assert_eq!(body["node_name"], "T39");
    assert_eq!(current_uses(&relay, &valid).await, 0);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-41: logging and audit hygiene
// ─────────────────────────────────────────────────────────────────────────

/// T-41 (REQ-41): no INFO-or-higher admission event names an invite code, a
/// user id or the node id; new audit entries carry `invite_id` only.
#[tokio::test]
async fn t41_admission_logs_carry_no_ids_or_codes() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t41-owner").await;
    let (u_id, u) = account(&relay, "t41-u").await;
    let (k_id, k) = account(&relay, "t41-k").await;
    let (q_id, q) = account(&relay, "t41-q").await;
    let node = relay.create_node(&owner, "T41").await;
    let requests = relay.create_node(&owner, "T41-requests").await;
    relay.join_with_owner_invite(&k, node).await;
    let (status, body) = send(
        relay
            .client
            .patch(relay.url(&format!("/nodes/{requests}")))
            .bearer_auth(&owner)
            .json(&json!({"join_policy": "request"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::INFO);
    let code = invite_code(&relay, &owner, node).await;
    assert_eq!(redeem(&relay, &u, &code, None, None).await.0, 200);
    let id = relay
        .state
        .db
        .get_node_invite_by_code(&code)
        .await
        .unwrap()
        .unwrap()
        .id;
    assert_eq!(
        send(
            relay
                .client
                .delete(relay.url(&format!("/invites/{id}")))
                .bearer_auth(&owner)
        )
        .await
        .0,
        200
    );
    assert_eq!(
        send(
            relay
                .client
                .post(relay.url(&format!("/nodes/{node}/leave")))
                .bearer_auth(&u)
        )
        .await
        .0,
        200
    );
    assert_eq!(
        send(
            relay
                .client
                .delete(relay.url(&format!("/nodes/{node}/members/{k_id}")))
                .bearer_auth(&owner)
        )
        .await
        .0,
        200
    );
    // A join request and its approval.
    assert_eq!(join_by_id(&relay, &q, requests, None, None).await.0, 202);
    assert_eq!(approve(&relay, &owner, requests, q_id).await.0, 200);
    drop(guard);

    let secrets = [
        code.clone(),
        owner_id.to_string(),
        u_id.to_string(),
        k_id.to_string(),
        q_id.to_string(),
        node.to_string(),
        requests.to_string(),
    ];
    for line in capture.lines_with_target("accord::admission") {
        if line.contains(" INFO ") || line.contains(" WARN ") || line.contains("ERROR") {
            for secret in &secrets {
                assert!(!line.contains(secret.as_str()), "{line}");
            }
        }
    }
    for line in capture.lines() {
        if secrets.iter().any(|s| line.contains(s.as_str())) {
            eprintln!("T-41 (C036, not failing): {line}");
        }
    }
    let details: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_log WHERE action IN ('invite_create', 'invite_revoke') AND target_id = ?")
        .bind(id.to_string())
        .fetch_all(pool(&relay))
        .await
        .unwrap();
    assert_eq!(details.len(), 2);
    for d in details {
        assert!(!d.contains(&code), "{d}");
        let v: Value = serde_json::from_str(&d).unwrap();
        assert_eq!(v["invite_id"], id.to_string());
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  T-49, RG-N014-1: template import
// ─────────────────────────────────────────────────────────────────────────

/// T-49 (REQ-49) and RG-N014-1: a template cannot give CREATE_INVITE or
/// ADMINISTRATOR to @everyone.
#[tokio::test]
async fn t49_template_import_writes_only_safe_everyone_bits() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t49-owner").await;
    let (_, plain) = account(&relay, "t49-plain").await;
    let (requester, _) = account(&relay, "t49-requester").await;
    let node = relay.create_node(&owner, "T49").await;
    relay.join_with_owner_invite(&plain, node).await;
    let plain_id = relay.state.validate_token(&plain).await.unwrap();
    exec(pool(&relay), &format!(
        "INSERT INTO node_join_requests (node_id, user_id, created_at, expires_at) VALUES ('{node}', '{requester}', 0, {})",
        now() + 1000
    ))
    .await;
    for (raw, stripped) in [("1", "CREATE_INVITE"), ("8", "ADMINISTRATOR")] {
        let template = json!({"template_json": {"roles": [{"id": 0, "name": "@everyone", "permissions": raw}]}});
        let (status, body) = send(
            relay
                .client
                .post(relay.url(&format!("/nodes/{node}/import-discord-template")))
                .bearer_auth(&owner)
                .json(&template),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body["everyone_permissions_stripped"]
                .as_array()
                .unwrap()
                .contains(&json!(stripped)),
            "{body}"
        );
        let everyone = relay
            .state
            .db
            .get_everyone_role(node)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(everyone.permissions, DEFAULT_EVERYONE);
        let (status, body) = create_invite(&relay, &plain, node, None).await;
        assert_eq!((status, body["reason"].clone()), (403, json!("forbidden")));
        let (status, body) = approve(&relay, &plain, node, requester).await;
        assert_eq!((status, body["reason"].clone()), (403, json!("forbidden")));
        assert_eq!(
            relay
                .state
                .db
                .approve_join_request(plain_id, node, requester)
                .await,
            Err(AdmissionError::Forbidden)
        );
        assert!(!is_member(&relay, node, requester).await);
    }
    assert_eq!(
        relay
            .state
            .db
            .compute_node_permissions(node, owner_id)
            .await
            .unwrap()
            & CREATE_INVITE,
        CREATE_INVITE
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  Regressions RG-C002-1 to RG-C002-7, RG-N008-1
// ─────────────────────────────────────────────────────────────────────────

/// RG-C002-1, RG-C002-6: an outsider's join by UUID creates no row, and no
/// `sender_key_new_member` names them.
#[tokio::test]
async fn rg_c002_1_join_by_uuid_is_refused() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "rg1-owner").await;
    let (_, member) = account(&relay, "rg1-member").await;
    let (x_id, x) = account(&relay, "rg1-x").await;
    let node = relay.create_node(&owner, "RG1").await;
    relay.join_with_owner_invite(&member, node).await;
    let mut watch = WsClient::connect(&relay, &member).await;
    let (status, body) = join_by_id(&relay, &x, node, None, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (403, json!("invite_required"))
    );
    let mut ws = WsClient::connect(&relay, &x).await;
    ws.send(json!({"JoinNode": {"node_id": node}})).await;
    assert_eq!(
        ws.wait_for("join_failed", OBSERVE).await.unwrap()["reason"],
        "invite_required"
    );
    assert!(!is_member(&relay, node, x_id).await);
    let frames = watch.frames_for(OBSERVE).await;
    assert!(
        frames
            .iter()
            .all(|f| f["new_user_id"] != x_id.to_string() && f["user_id"] != x_id.to_string()),
        "{frames:?}"
    );
}

/// RG-C002-3, RG-C002-4: an exhausted single-use invite cannot be bypassed
/// through `/nodes/:id/join`, and a kicked member cannot rejoin by UUID.
#[tokio::test]
async fn rg_c002_3_and_4_no_bypass_through_node_id() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "rg3-owner").await;
    let node = relay.create_node(&owner, "RG3").await;
    let (_, body) = create_invite(&relay, &owner, node, Some(json!({"max_uses": 1}))).await;
    let code = body["invite_code"].as_str().unwrap().to_string();
    let (k_id, k) = account(&relay, "rg3-k").await;
    assert_eq!(redeem(&relay, &k, &code, None, None).await.0, 200);
    let (_, x) = account(&relay, "rg3-x").await;
    let (status, body) =
        join_by_id(&relay, &x, node, Some(json!({"invite_code": code})), None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (410, json!("invite_exhausted"))
    );
    assert_eq!(join_by_id(&relay, &x, node, None, None).await.0, 403);

    let (status, _) = send(
        relay
            .client
            .delete(relay.url(&format!("/nodes/{node}/members/{k_id}")))
            .bearer_auth(&owner),
    )
    .await;
    assert_eq!(status, 200);
    let (status, body) = join_by_id(&relay, &k, node, None, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (403, json!("invite_required"))
    );
    assert!(!is_member(&relay, node, k_id).await);
}

/// RG-C002-5: a key-banned user's fresh account needs an invite, and on a
/// node with device bans the invite path needs a fingerprint.
#[tokio::test]
async fn rg_c002_5_banned_users_cannot_slip_back() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "rg5-owner").await;
    let node = relay.create_node(&owner, "RG5").await;
    let (banned_id, banned) = account(&relay, "rg5-banned").await;
    relay.join_with_owner_invite(&banned, node).await;
    let pkh = relay
        .state
        .db
        .get_user_public_key_hash(banned_id)
        .await
        .unwrap()
        .unwrap();
    relay
        .state
        .db
        .ban_from_node_with_fingerprint(node, &pkh, owner_id, None, None, Some(&fp(0xaa)))
        .await
        .unwrap();
    remove_row(&relay, node, banned_id).await;

    let (_, fresh) = account(&relay, "rg5-fresh").await;
    let mut ws = WsClient::connect(&relay, &fresh).await;
    ws.send(json!({"JoinNode": {"node_id": node}})).await;
    assert_eq!(
        ws.wait_for("join_failed", OBSERVE).await.unwrap()["reason"],
        "invite_required"
    );
    let code = invite_code(&relay, &owner, node).await;
    let (status, body) = redeem(&relay, &fresh, &code, None, None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (403, json!("fingerprint_required"))
    );
    let (status, body) = redeem(&relay, &fresh, &code, Some(&fp(0xaa)), None).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (403, json!("device_banned"))
    );
}

/// RG-C002-7: the unauthenticated preview still returns `node_id`. This is
/// an open item of the C002 fix, owned by roadmap item 3 (Q11, residual risk
/// 13). Tag: residual-until-roadmap-3. The target assertion (no `node_id` in
/// the body) fails today, so the test is expected to panic; when roadmap
/// item 3 removes the field, the panic stops, this test fails, and the
/// `should_panic` attribute and the tag must be removed.
#[tokio::test]
#[should_panic(expected = "residual-until-roadmap-3")]
async fn rg_c002_7_residual_until_roadmap_3_preview_hides_node_id() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "rg7-owner").await;
    let node = relay.create_node(&owner, "RG7").await;
    let code = invite_code(&relay, &owner, node).await;
    let (status, body) = send(
        relay
            .client
            .get(relay.url(&format!("/invites/{code}/preview"))),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.get("node_id").is_none(),
        "residual-until-roadmap-3: the preview still returns node_id"
    );
}

/// RG-N008-1: the desktop's `expires_hours` sets an expiry, a malformed
/// body creates nothing, and the desktop's revoke route works.
#[tokio::test]
async fn rg_n008_1_desktop_invites_expire_and_revoke() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "rgn8-owner").await;
    let node = relay.create_node(&owner, "RGN8").await;
    let (status, body) = create_invite(
        &relay,
        &owner,
        node,
        Some(json!({"expires_hours": 24, "max_uses": null})),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body["expires_at"].as_u64().is_some());
    let code = body["invite_code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 22);
    let before = count(pool(&relay), "SELECT COUNT(*) FROM node_invites").await;
    let (status, _) = create_invite(
        &relay,
        &owner,
        node,
        Some(json!({"expires_hours": "1 day"})),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        count(pool(&relay), "SELECT COUNT(*) FROM node_invites").await,
        before
    );
    let (status, _) = send(
        relay
            .client
            .delete(relay.url(&format!("/nodes/{node}/invites/{code}")))
            .bearer_auth(&owner),
    )
    .await;
    assert_eq!(status, 200);
    let (_, u) = account(&relay, "rgn8-u").await;
    assert_eq!(redeem(&relay, &u, &code, None, None).await.0, 404);
}
