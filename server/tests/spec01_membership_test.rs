//! SPEC-01 section 11.2 steps 6 and 7: leave, kick and the single removal
//! routine with its hook list (REQ-34, REQ-35, REQ-50), and join requests
//! with their approval (Stage 1b, REQ-29 to REQ-33).
//!
//! Tests T-29 to T-35 and T-50 of section 10.2, the step 6 and 7 part of
//! T-28, and the regressions RG-N002-1 to RG-N002-3 and RG-C033-2 of
//! section 10.3. Every test serves the production router; every account has
//! a password and every membership comes from an owner-created invite or an
//! approved join request. The removal-hook counter and the fault points come
//! from the `fault-injection` feature (section 10.1).

use accord_server::admission::REMOVAL_HOOKS_COUNTER;
use accord_server::db::DbOptions;
use accord_server::faults::FaultKind;
use accord_server::files::FileConfig;
use accord_server::models::permission_bits::{CREATE_INVITE, KICK_MEMBERS, MANAGE_NODE};
use accord_server::rate_limit::ActionType;
use accord_server::state::{AppState, AppStateOptions};
use accord_server::test_support::{count_frames, TestRelay, WsClient, TEST_PASSWORD};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const OBSERVE: Duration = Duration::from_secs(1);
const ROTATION: &str = "sender_key_rotation_required";
/// Join request lifetime (REQ-30).
const REQUEST_LIFETIME: i64 = 1_209_600;

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

/// Register a v1 account with the test password and log it in, through the
/// relay state: `POST /register` and `POST /auth` are limited per client
/// address, which every test request shares. The tested routes then use the
/// token over HTTP.
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

fn pkh(public_key: &str) -> String {
    accord_server::db::compute_public_key_hash(public_key)
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

/// The status and `reason` of a response.
fn reason(response: &(u16, Value)) -> (u16, String) {
    (
        response.0,
        response.1["reason"].as_str().unwrap_or("").to_string(),
    )
}

/// A node with three channels: `general` and two more.
async fn three_channel_node(relay: &TestRelay, owner: &str, name: &str) -> Uuid {
    let node = relay.create_node(owner, name).await;
    for channel in ["second", "third"] {
        let (status, body) = send(
            relay
                .client
                .post(relay.url(&format!("/nodes/{node}/channels")))
                .bearer_auth(owner)
                .json(&json!({ "name": channel })),
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }
    node
}

async fn channel_ids(relay: &TestRelay, node: Uuid) -> BTreeSet<Uuid> {
    relay
        .state
        .db
        .get_node_channels(node)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.id)
        .collect()
}

/// Give `user` a role with `permissions` in `node`.
async fn grant(relay: &TestRelay, node: Uuid, user: Uuid, name: &str, permissions: u64) {
    let role = relay
        .state
        .db
        .create_role(node, name, 0, permissions, 1, false, false, None)
        .await
        .unwrap();
    relay
        .state
        .db
        .assign_member_role(node, user, role.id)
        .await
        .unwrap();
}

/// Queue one sender-key distribution from `user` to `peer` and one from
/// `peer` to `user` in every channel of `node`.
async fn queue_both_ways(relay: &TestRelay, node: Uuid, user: Uuid, peer: Uuid) {
    for channel in channel_ids(relay, node).await {
        for (from, to) in [(user, peer), (peer, user)] {
            exec(
                pool(relay),
                &format!(
                    "INSERT INTO sender_key_distributions (id, channel_id, from_user_id, to_user_id, encrypted_payload, created_at) \
                     VALUES ('{}', '{channel}', '{from}', '{to}', x'00', 0)",
                    Uuid::new_v4()
                ),
            )
            .await;
        }
    }
}

/// Queued distributions to or from `user` in the channels of `node`.
async fn distributions(relay: &TestRelay, node: Uuid, user: Uuid) -> i64 {
    count(
        pool(relay),
        &format!(
            "SELECT COUNT(*) FROM sender_key_distributions WHERE (from_user_id = '{user}' OR to_user_id = '{user}') \
             AND channel_id IN (SELECT id FROM channels WHERE node_id = '{node}')"
        ),
    )
    .await
}

async fn is_member(relay: &TestRelay, node: Uuid, user: Uuid) -> bool {
    relay.state.db.is_node_member(node, user).await.unwrap()
}

/// Runs of the removal-hook list so far (section 10.1).
fn hooks(relay: &TestRelay) -> u64 {
    relay.state.faults().counter(REMOVAL_HOOKS_COUNTER)
}

/// Assert that `frames` hold exactly one rotation frame per channel of the
/// node, each naming `removed`.
fn assert_rotations(frames: &[Value], removed: Uuid, channels: &BTreeSet<Uuid>) {
    let rotations: Vec<&Value> = frames.iter().filter(|f| f["type"] == ROTATION).collect();
    assert_eq!(rotations.len(), channels.len(), "{frames:?}");
    let named: BTreeSet<Uuid> = rotations
        .iter()
        .map(|f| {
            assert_eq!(f["removed_user_id"], removed.to_string(), "{f}");
            Uuid::parse_str(f["channel_id"].as_str().unwrap()).unwrap()
        })
        .collect();
    assert_eq!(&named, channels);
}

async fn leave(relay: &TestRelay, token: &str, node: Uuid) -> (u16, Value) {
    send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/leave")))
            .bearer_auth(token),
    )
    .await
}

async fn kick(relay: &TestRelay, token: &str, node: Uuid, target: Uuid) -> (u16, Value) {
    send(
        relay
            .client
            .delete(relay.url(&format!("/nodes/{node}/members/{target}")))
            .bearer_auth(token),
    )
    .await
}

async fn ban(relay: &TestRelay, token: &str, node: Uuid, public_key_hash: &str) -> (u16, Value) {
    send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/bans")))
            .bearer_auth(token)
            .json(&json!({ "public_key_hash": public_key_hash })),
    )
    .await
}

async fn join_by_id(relay: &TestRelay, token: &str, node: Uuid) -> (u16, Value) {
    send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/join")))
            .bearer_auth(token),
    )
    .await
}

async fn patch_node(relay: &TestRelay, token: &str, node: Uuid, body: Value) -> (u16, Value) {
    send(
        relay
            .client
            .patch(relay.url(&format!("/nodes/{node}")))
            .bearer_auth(token)
            .json(&body),
    )
    .await
}

/// `PATCH /nodes/:id {"join_policy": value}`.
async fn policy_patch(relay: &TestRelay, token: &str, node: Uuid, value: Value) -> (u16, Value) {
    patch_node(relay, token, node, json!({ "join_policy": value })).await
}

async fn set_policy(relay: &TestRelay, token: &str, node: Uuid, policy: &str) {
    let (status, body) = patch_node(relay, token, node, json!({ "join_policy": policy })).await;
    assert_eq!(status, 200, "{body}");
}

async fn list_requests(relay: &TestRelay, token: &str, node: Uuid) -> (u16, Value) {
    send(
        relay
            .client
            .get(relay.url(&format!("/nodes/{node}/join-requests")))
            .bearer_auth(token),
    )
    .await
}

async fn approve(relay: &TestRelay, token: &str, node: Uuid, requester: Uuid) -> (u16, Value) {
    send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/join-requests/{requester}/approve")))
            .bearer_auth(token),
    )
    .await
}

async fn deny(relay: &TestRelay, token: &str, node: Uuid, requester: Uuid) -> (u16, Value) {
    send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/join-requests/{requester}/deny")))
            .bearer_auth(token),
    )
    .await
}

async fn withdraw(relay: &TestRelay, token: &str, node: Uuid) -> (u16, Value) {
    send(
        relay
            .client
            .delete(relay.url(&format!("/nodes/{node}/join-request")))
            .bearer_auth(token),
    )
    .await
}

async fn requests_of(relay: &TestRelay, node: Uuid) -> i64 {
    count(
        pool(relay),
        &format!("SELECT COUNT(*) FROM node_join_requests WHERE node_id = '{node}'"),
    )
    .await
}

async fn device_cap(relay: &TestRelay, node: Uuid) -> i64 {
    relay
        .state
        .db
        .get_node_max_accounts_per_device(node)
        .await
        .unwrap()
}

async fn node_name(relay: &TestRelay, node: Uuid) -> String {
    relay.state.db.get_node(node).await.unwrap().unwrap().name
}

async fn audit_rows(relay: &TestRelay, node: Uuid, action: &str) -> i64 {
    count(
        pool(relay),
        &format!("SELECT COUNT(*) FROM audit_log WHERE node_id = '{node}' AND action = '{action}'"),
    )
    .await
}

async fn ban_rows(relay: &TestRelay, node: Uuid, public_key_hash: &str) -> i64 {
    count(
        pool(relay),
        &format!(
            "SELECT COUNT(*) FROM node_bans WHERE node_id = '{node}' AND public_key_hash = '{public_key_hash}'"
        ),
    )
    .await
}

/// After a leave: no membership, no distribution to or from the leaver in
/// the node, no channel subscription and no role assignment there; the
/// leaver's other node is untouched.
async fn assert_left_cleanly(relay: &TestRelay, node: Uuid, other: Uuid, user: Uuid) {
    assert!(!is_member(relay, node, user).await);
    assert_eq!(distributions(relay, node, user).await, 0);
    assert_eq!(
        count(
            pool(relay),
            &format!(
                "SELECT COUNT(*) FROM channel_members WHERE user_id = '{user}' \
                 AND channel_id IN (SELECT id FROM channels WHERE node_id = '{node}')"
            )
        )
        .await,
        0
    );
    assert_eq!(
        count(
            pool(relay),
            &format!(
                "SELECT COUNT(*) FROM member_roles WHERE member_id = '{user}' AND node_id = '{node}'"
            )
        )
        .await,
        0
    );
    assert!(is_member(relay, other, user).await);
    assert_eq!(
        distributions(relay, other, user).await,
        2 * channel_ids(relay, other).await.len() as i64
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  T-34, RG-N002-1, RG-N002-2: one leave routine
// ─────────────────────────────────────────────────────────────────────────

/// T-34 (REQ-34), RG-N002-1 and the REST-leave part of RG-C033-2: a
/// non-member's WS or REST leave changes nothing and rotates nothing; a
/// member's leave, over REST or WS, rotates every channel once, deletes the
/// queued distributions in both directions, the subscriptions and the role
/// assignments, and runs the hooks once; the owner cannot leave.
#[tokio::test]
async fn t34_one_leave_routine_for_rest_and_ws() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t34-owner").await;
    let (_, observer) = account(&relay, "t34-observer").await;
    let (l1_id, l1) = account(&relay, "t34-rest-leaver").await;
    let (l2_id, l2) = account(&relay, "t34-ws-leaver").await;
    let (_, outsider) = account(&relay, "t34-outsider").await;
    let node = three_channel_node(&relay, &owner, "T34").await;
    let other = relay.create_node(&owner, "T34-other").await;
    for token in [&observer, &l1, &l2] {
        relay.join_with_owner_invite(token, node).await;
    }
    for (id, token) in [(l1_id, &l1), (l2_id, &l2)] {
        relay.join_with_owner_invite(token, other).await;
        grant(&relay, node, id, &format!("Leaver-{id}"), 0).await;
        queue_both_ways(&relay, node, id, owner_id).await;
        queue_both_ways(&relay, other, id, owner_id).await;
    }
    let channels = channel_ids(&relay, node).await;
    assert_eq!(channels.len(), 3);
    let mut watch = WsClient::connect(&relay, &observer).await;
    let mut outsider_ws = WsClient::connect(&relay, &outsider).await;
    let mut l2_ws = WsClient::connect(&relay, &l2).await;
    watch.frames_for(Duration::from_millis(300)).await;
    let all_distributions = || {
        count(
            pool(&relay),
            "SELECT COUNT(*) FROM sender_key_distributions",
        )
    };
    let distributions_before = all_distributions().await;

    // RG-N002-1: a forged WS leave by a non-member.
    let id = outsider_ws
        .send(json!({"LeaveNode": {"node_id": node}}))
        .await;
    let frames = outsider_ws.frames_for(Duration::from_millis(500)).await;
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["type"], "leave_failed");
    assert_eq!(frames[0]["reason"], "not_member");
    assert_eq!(frames[0]["error"], "You are not a member of this node");
    assert_eq!(frames[0]["node_id"], node.to_string());
    assert_eq!(frames[0]["request_id"], id.to_string());
    // The same over REST.
    let response = leave(&relay, &outsider, node).await;
    assert_eq!(reason(&response), (404, "not_member".into()));
    assert_eq!(response.1["code"], 404);
    assert_eq!(count_frames(&watch.frames_for(OBSERVE).await, ROTATION), 0);
    assert_eq!(hooks(&relay), 0);
    assert_eq!(all_distributions().await, distributions_before);

    // A member leaves over REST.
    let (status, body) = leave(&relay, &l1, node).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, json!({"status": "left", "node_id": node}));
    assert_rotations(&watch.frames_for(OBSERVE).await, l1_id, &channels);
    assert_eq!(hooks(&relay), 1);
    assert_left_cleanly(&relay, node, other, l1_id).await;

    // Another member leaves over WS: one `node_left` answering the message,
    // and the leaver, no longer subscribed, receives no rotation frame. (Its
    // socket still holds the rotation frames of the REST leave above.)
    l2_ws.frames_for(Duration::from_millis(300)).await;
    let id = l2_ws.send(json!({"LeaveNode": {"node_id": node}})).await;
    let frames = l2_ws.frames_for(OBSERVE).await;
    let answers: Vec<&Value> = frames
        .iter()
        .filter(|f| {
            ["node_left", "leave_failed", "error"].contains(&f["type"].as_str().unwrap_or(""))
        })
        .collect();
    assert_eq!(answers.len(), 1, "{frames:?}");
    assert_eq!(answers[0]["type"], "node_left");
    assert_eq!(answers[0]["node_id"], node.to_string());
    assert_eq!(answers[0]["request_id"], id.to_string());
    assert_eq!(count_frames(&frames, ROTATION), 0, "{frames:?}");
    assert_rotations(&watch.frames_for(OBSERVE).await, l2_id, &channels);
    assert_eq!(hooks(&relay), 2);
    assert_left_cleanly(&relay, node, other, l2_id).await;

    // The owner cannot leave; nothing changes.
    let response = leave(&relay, &owner, node).await;
    assert_eq!(reason(&response), (400, "owner_cannot_leave".into()));
    assert_eq!(
        response.1["error"],
        "Node owner cannot leave their own node"
    );
    assert!(is_member(&relay, node, owner_id).await);
    assert_eq!(count_frames(&watch.frames_for(OBSERVE).await, ROTATION), 0);
    assert_eq!(hooks(&relay), 2);

    // A second leave of the same member is `not_member` again.
    assert_eq!(
        reason(&leave(&relay, &l1, node).await),
        (404, "not_member".into())
    );
    assert_eq!(hooks(&relay), 2);
}

/// RG-N002-2: a banned, already-removed account sends `LeaveNode`: one
/// `leave_failed not_member`, no rotation.
#[tokio::test]
async fn rg_n002_2_banned_account_leave_causes_no_rotation() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "rgn2-owner").await;
    let (_, observer) = account(&relay, "rgn2-observer").await;
    let (b_id, b) = account(&relay, "rgn2-banned").await;
    let node = three_channel_node(&relay, &owner, "RGN2").await;
    relay.join_with_owner_invite(&observer, node).await;
    relay.join_with_owner_invite(&b, node).await;
    let mut watch = WsClient::connect(&relay, &observer).await;
    let mut b_ws = WsClient::connect(&relay, &b).await;

    assert_eq!(ban(&relay, &owner, node, &pkh("rgn2-banned")).await.0, 200);
    assert!(!is_member(&relay, node, b_id).await);
    // The ban itself removed a member and rotated once per channel.
    assert_rotations(
        &watch.frames_for(OBSERVE).await,
        b_id,
        &channel_ids(&relay, node).await,
    );
    assert_eq!(hooks(&relay), 1);
    b_ws.frames_for(Duration::from_millis(300)).await;

    let id = b_ws.send(json!({"LeaveNode": {"node_id": node}})).await;
    let frames = b_ws.frames_for(Duration::from_millis(500)).await;
    let answers: Vec<&Value> = frames.iter().filter(|f| f["type"] != ROTATION).collect();
    assert_eq!(answers.len(), 1, "{frames:?}");
    assert_eq!(answers[0]["type"], "leave_failed");
    assert_eq!(answers[0]["reason"], "not_member");
    assert_eq!(answers[0]["request_id"], id.to_string());
    assert_eq!(count_frames(&watch.frames_for(OBSERVE).await, ROTATION), 0);
    assert_eq!(hooks(&relay), 1);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-35, RG-N002-3: kick
// ─────────────────────────────────────────────────────────────────────────

/// T-35 (REQ-35): a kick of a non-member is 404 `not_member` with no
/// effect; a kick of a member rotates every channel, writes one audit row,
/// deletes the distributions in both directions and runs the hooks once.
#[tokio::test]
async fn t35_kick_uses_the_row_count() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t35-owner").await;
    let (k_id, k) = account(&relay, "t35-moderator").await;
    let (_, observer) = account(&relay, "t35-observer").await;
    let (t_id, t) = account(&relay, "t35-target").await;
    let (p_id, p) = account(&relay, "t35-plain").await;
    let (_, outsider) = account(&relay, "t35-outsider").await;
    let node = three_channel_node(&relay, &owner, "T35").await;
    for token in [&k, &observer, &t, &p] {
        relay.join_with_owner_invite(token, node).await;
    }
    grant(&relay, node, k_id, "Moderator-ish", KICK_MEMBERS).await;
    queue_both_ways(&relay, node, t_id, owner_id).await;
    let channels = channel_ids(&relay, node).await;
    let mut watch = WsClient::connect(&relay, &observer).await;
    let all_distributions = || {
        count(
            pool(&relay),
            "SELECT COUNT(*) FROM sender_key_distributions",
        )
    };
    let distributions_before = all_distributions().await;

    // A random UUID that is not a member.
    let response = kick(&relay, &k, node, Uuid::new_v4()).await;
    assert_eq!(reason(&response), (404, "not_member".into()));
    assert_eq!(
        response.1["error"],
        "That user is not a member of this node"
    );
    assert_eq!(count_frames(&watch.frames_for(OBSERVE).await, ROTATION), 0);
    assert_eq!(audit_rows(&relay, node, "member_kick").await, 0);
    assert_eq!(all_distributions().await, distributions_before);
    assert_eq!(hooks(&relay), 0);

    // Today's authorization and owner guard are kept.
    assert_eq!(
        reason(&kick(&relay, &p, node, t_id).await),
        (403, "forbidden".into())
    );
    assert_eq!(
        reason(&kick(&relay, &outsider, node, t_id).await),
        (403, "forbidden".into())
    );
    let response = kick(&relay, &k, node, owner_id).await;
    assert_eq!(response.0, 400, "{}", response.1);
    assert_eq!(response.1["error"], "Cannot kick the node owner");
    assert!(is_member(&relay, node, t_id).await);
    assert!(is_member(&relay, node, owner_id).await);
    assert_eq!(hooks(&relay), 0);

    // A real member.
    let (status, body) = kick(&relay, &k, node, t_id).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"status": "kicked", "node_id": node, "user_id": t_id})
    );
    assert_rotations(&watch.frames_for(OBSERVE).await, t_id, &channels);
    assert_eq!(audit_rows(&relay, node, "member_kick").await, 1);
    assert_eq!(distributions(&relay, node, t_id).await, 0);
    assert!(!is_member(&relay, node, t_id).await);
    assert_eq!(hooks(&relay), 1);
    // The plain member is still there.
    assert!(is_member(&relay, node, p_id).await);
}

/// RG-N002-3: kicks of UUIDs that are not members rotate nothing, and the
/// 11th membership action in a minute is refused.
#[tokio::test]
async fn rg_n002_3_kicks_of_non_members_cause_no_rotation() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "rgn3-owner").await;
    let (k_id, k) = account(&relay, "rgn3-moderator").await;
    let (_, observer) = account(&relay, "rgn3-observer").await;
    let node = three_channel_node(&relay, &owner, "RGN3").await;
    relay.join_with_owner_invite(&k, node).await;
    relay.join_with_owner_invite(&observer, node).await;
    grant(&relay, node, k_id, "Kicker", KICK_MEMBERS).await;
    let mut watch = WsClient::connect(&relay, &observer).await;

    // The moderator's own invite redemption was its first membership action
    // of the minute; kicks use up the rest.
    let used = relay
        .state
        .rate_limiter
        .get_status(k_id, ActionType::MembershipChange)
        .await
        .0;
    assert_eq!(used, 1);
    for _ in used..10 {
        assert_eq!(
            reason(&kick(&relay, &k, node, Uuid::new_v4()).await),
            (404, "not_member".into())
        );
    }
    let (status, body) = kick(&relay, &k, node, Uuid::new_v4()).await;
    assert_eq!(
        (status, body["reason"].clone()),
        (429, json!("rate_limited"))
    );
    assert!(body["retry_after"].as_u64().unwrap() >= 1);
    assert_eq!(count_frames(&watch.frames_for(OBSERVE).await, ROTATION), 0);
    assert_eq!(audit_rows(&relay, node, "member_kick").await, 0);
    assert_eq!(hooks(&relay), 0);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-50, RG-C033-2: one removal routine for leave, kick and ban
// ─────────────────────────────────────────────────────────────────────────

/// T-50 (REQ-50) and the ban part of RG-C033-2: a ban of a member rotates
/// and deletes distributions in both directions; a ban of a non-member only
/// writes the ban row; a malformed hash (non-ASCII, non-hex, wrong length or
/// upper case) gets 400 with no ban row, audit row or hook; a kick deletes
/// distributions in both directions; a fault in the routine's delete leaves
/// no ban row and runs no hook.
#[tokio::test]
async fn t50_ban_and_kick_share_the_removal_routine() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t50-owner").await;
    let (_, observer) = account(&relay, "t50-observer").await;
    let (x_id, x) = account(&relay, "t50-x").await;
    let (_, _y) = account(&relay, "t50-y").await;
    let (z_id, z) = account(&relay, "t50-z").await;
    let (w_id, w) = account(&relay, "t50-w").await;
    let node = three_channel_node(&relay, &owner, "T50").await;
    let other = relay.create_node(&owner, "T50-other").await;
    for token in [&observer, &x, &z, &w] {
        relay.join_with_owner_invite(token, node).await;
    }
    for (id, token) in [(x_id, &x), (z_id, &z)] {
        relay.join_with_owner_invite(token, other).await;
        queue_both_ways(&relay, node, id, owner_id).await;
        queue_both_ways(&relay, other, id, owner_id).await;
    }
    let channels = channel_ids(&relay, node).await;
    let mut watch = WsClient::connect(&relay, &observer).await;

    // Ban of member X.
    let (status, body) = ban(&relay, &owner, node, &pkh("t50-x")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "banned");
    assert_eq!(ban_rows(&relay, node, &pkh("t50-x")).await, 1);
    assert_eq!(audit_rows(&relay, node, "user_ban").await, 1);
    assert_rotations(&watch.frames_for(OBSERVE).await, x_id, &channels);
    assert_eq!(distributions(&relay, node, x_id).await, 0);
    assert_eq!(distributions(&relay, other, x_id).await, 2);
    assert!(!is_member(&relay, node, x_id).await);
    assert!(is_member(&relay, other, x_id).await);
    assert_eq!(hooks(&relay), 1);

    // Ban of Y, who is not a member: only the ban row.
    let (status, body) = ban(&relay, &owner, node, &pkh("t50-y")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(ban_rows(&relay, node, &pkh("t50-y")).await, 1);
    assert_eq!(audit_rows(&relay, node, "user_ban").await, 2);
    assert_eq!(count_frames(&watch.frames_for(OBSERVE).await, ROTATION), 0);
    assert_eq!(hooks(&relay), 1);

    // A ban of a hash no account has: only the ban row.
    let (status, _) = ban(&relay, &owner, node, &pkh("t50-nobody")).await;
    assert_eq!(status, 200);
    assert_eq!(ban_rows(&relay, node, &pkh("t50-nobody")).await, 1);
    assert_eq!(audit_rows(&relay, node, "user_ban").await, 3);
    assert_eq!(hooks(&relay), 1);

    // A hash that is not 64 lowercase hex characters: 400 before anything
    // is written. The first has a two-byte character across byte 16 (the
    // old log line sliced there), the last is W's own hash in upper case.
    let w_upper = pkh("t50-w").to_uppercase();
    let bad = [
        format!("{}\u{e9}{}", "a".repeat(15), "b".repeat(47)),
        "no-such-account-hash".to_string(),
        "a".repeat(63),
        "a".repeat(65),
        w_upper.clone(),
    ];
    for hash in &bad {
        let response = ban(&relay, &owner, node, hash).await;
        assert_eq!(reason(&response), (400, "invalid_request".into()), "{hash}");
        assert_eq!(response.1["code"], 400, "{hash}");
        assert_eq!(ban_rows(&relay, node, hash).await, 0, "{hash}");
    }
    assert_eq!(
        count(
            pool(&relay),
            &format!("SELECT COUNT(*) FROM node_bans WHERE node_id = '{node}'")
        )
        .await,
        3
    );
    assert_eq!(audit_rows(&relay, node, "user_ban").await, 3);
    assert!(is_member(&relay, node, w_id).await);
    assert_eq!(count_frames(&watch.frames_for(OBSERVE).await, ROTATION), 0);
    assert_eq!(hooks(&relay), 1);

    // Kick of Z: distributions in both directions deleted, in this node only.
    assert_eq!(kick(&relay, &owner, node, z_id).await.0, 200);
    assert_eq!(distributions(&relay, node, z_id).await, 0);
    assert_eq!(distributions(&relay, other, z_id).await, 2);
    assert_rotations(&watch.frames_for(OBSERVE).await, z_id, &channels);
    assert_eq!(hooks(&relay), 2);

    // A fault in the routine's delete: 503, no ban row, no hook, still a
    // member.
    relay
        .state
        .faults()
        .arm("removal:delete", FaultKind::Constraint);
    let response = ban(&relay, &owner, node, &pkh("t50-w")).await;
    assert_eq!(reason(&response), (503, "unavailable".into()));
    assert!(!relay.state.faults().is_armed("removal:delete"));
    assert_eq!(ban_rows(&relay, node, &pkh("t50-w")).await, 0);
    assert_eq!(audit_rows(&relay, node, "user_ban").await, 3);
    assert!(is_member(&relay, node, w_id).await);
    assert_eq!(count_frames(&watch.frames_for(OBSERVE).await, ROTATION), 0);
    assert_eq!(hooks(&relay), 2);

    // The same fault on kick and leave: 503 and nothing changes.
    relay.state.faults().arm("removal:delete", FaultKind::Busy);
    assert_eq!(
        reason(&kick(&relay, &owner, node, w_id).await),
        (503, "unavailable".into())
    );
    relay
        .state
        .faults()
        .arm("removal:delete", FaultKind::Constraint);
    assert_eq!(
        reason(&leave(&relay, &w, node).await),
        (503, "unavailable".into())
    );
    assert!(is_member(&relay, node, w_id).await);
    assert_eq!(count_frames(&watch.frames_for(OBSERVE).await, ROTATION), 0);
    assert_eq!(audit_rows(&relay, node, "member_kick").await, 1);
    assert_eq!(hooks(&relay), 2);
}

/// RG-C033-2: distributions queued to a kicked member are no longer
/// fetchable, and REST leave rotates (T-34 covers the leave in full).
#[tokio::test]
async fn rg_c033_2_removed_members_keep_no_queued_keys() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "rgc33-owner").await;
    let (k_id, k) = account(&relay, "rgc33-kicked").await;
    let node = three_channel_node(&relay, &owner, "RGC33").await;
    relay.join_with_owner_invite(&k, node).await;
    queue_both_ways(&relay, node, k_id, owner_id).await;
    let pending = |token: String| {
        let relay = &relay;
        async move {
            let (status, body) = send(
                relay
                    .client
                    .get(relay.url("/sender-keys/pending"))
                    .bearer_auth(token),
            )
            .await;
            assert_eq!(status, 200, "{body}");
            body["distributions"].as_array().unwrap().len()
        }
    };
    assert_eq!(pending(k.clone()).await, 3);
    assert_eq!(kick(&relay, &owner, node, k_id).await.0, 200);
    assert_eq!(pending(k.clone()).await, 0);
    assert_eq!(distributions(&relay, node, k_id).await, 0);
}

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

/// T-50 (REQ-50), static part: the only caller of `remove_node_member` is the
/// removal routine in `db::admission`, and no other relay source file deletes
/// `node_members` rows (the boot repair's B5 aside). The unwired database
/// layers are excluded by an explicit list.
#[test]
fn t50_only_the_removal_routine_removes_memberships() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let unwired = ["db/relay.rs", "db/node_db.rs", "db/migration.rs"];
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut offenders = Vec::new();
    let mut in_admission = (0, 0);
    for file in files {
        let relative = file
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if unwired.contains(&relative.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap().to_lowercase();
        let calls = text.matches("remove_node_member(").count();
        let deletes = text.matches("delete from node_members").count();
        match relative.as_str() {
            "db/admission.rs" => in_admission = (calls, deletes),
            "db/repair.rs" => {
                if calls > 0 {
                    offenders.push(format!("{relative}: remove_node_member("));
                }
            }
            _ => {
                if calls > 0 {
                    offenders.push(format!("{relative}: remove_node_member("));
                }
                if deletes > 0 {
                    offenders.push(format!("{relative}: delete from node_members"));
                }
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:#?}");
    // In `db::admission`: the definition and its one call, and one delete.
    assert_eq!(in_admission, (2, 1));
}

// ─────────────────────────────────────────────────────────────────────────
//  T-29 to T-33: join requests (Stage 1b)
// ─────────────────────────────────────────────────────────────────────────

/// T-29 (REQ-29): the owner and a MANAGE_NODE member may change the join
/// policy, a plain member and a non-member may not, other values are
/// refused, switching back to `invite` deletes pending requests, and
/// `GET /nodes` reports each node's policy. A PATCH applies all of its
/// fields or none: a database failure rolls every field back, and an owner
/// without a membership row may change the policy alone but not together
/// with the name.
#[tokio::test]
async fn t29_join_policy() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t29-owner").await;
    let (m_id, m) = account(&relay, "t29-manager").await;
    let (p_id, p) = account(&relay, "t29-plain").await;
    let (_, q) = account(&relay, "t29-outsider").await;
    let (_, r) = account(&relay, "t29-requester").await;
    let node = relay.create_node(&owner, "T29").await;
    let second = relay.create_node(&owner, "T29-second").await;
    relay.join_with_owner_invite(&m, node).await;
    relay.join_with_owner_invite(&p, node).await;
    grant(&relay, node, m_id, "Manager", MANAGE_NODE).await;

    let request_policy =
        format!("SELECT COUNT(*) FROM nodes WHERE id = '{node}' AND join_policy = 'request'");
    let policy = || count(pool(&relay), &request_policy);
    let (status, body) = policy_patch(&relay, &owner, node, json!("request")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(policy().await, 1);
    let (status, body) = policy_patch(&relay, &m, node, json!("request")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        reason(&policy_patch(&relay, &p, node, json!("invite")).await),
        (403, "forbidden".into())
    );
    assert_eq!(policy().await, 1);
    for bad in [json!("x"), json!("public"), json!(5), json!(true)] {
        assert_eq!(
            reason(&policy_patch(&relay, &owner, node, bad.clone()).await),
            (400, "invalid_request".into()),
            "{bad}"
        );
    }
    assert_eq!(policy().await, 1);
    // A non-member's @everyone bits never count.
    exec(
        pool(&relay),
        &format!("UPDATE roles SET permissions = permissions | {MANAGE_NODE} WHERE id = '{node}'"),
    )
    .await;
    assert_eq!(
        reason(&policy_patch(&relay, &q, node, json!("invite")).await),
        (403, "forbidden".into())
    );
    exec(
        pool(&relay),
        &format!("UPDATE roles SET permissions = permissions & ~{MANAGE_NODE} WHERE id = '{node}'"),
    )
    .await;

    // GET /nodes and GET /nodes/:id report the policy.
    let (status, nodes) = send(relay.client.get(relay.url("/nodes")).bearer_auth(&owner)).await;
    assert_eq!(status, 200);
    let nodes = nodes.as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    for n in nodes {
        let want = if n["id"] == node.to_string() {
            "request"
        } else {
            assert_eq!(n["id"], second.to_string());
            "invite"
        };
        assert_eq!(n["join_policy"], want, "{n}");
    }
    let (_, info) = send(
        relay
            .client
            .get(relay.url(&format!("/nodes/{node}")))
            .bearer_auth(&owner),
    )
    .await;
    assert_eq!(info["join_policy"], "request");

    // A pending request, then back to `invite`: the request is deleted.
    assert_eq!(join_by_id(&relay, &r, node).await.0, 202);
    assert_eq!(requests_of(&relay, node).await, 1);
    let (status, body) = policy_patch(&relay, &m, node, json!("invite")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(policy().await, 0);
    assert_eq!(requests_of(&relay, node).await, 0);
    assert_eq!(
        reason(&join_by_id(&relay, &r, node).await),
        (403, "invite_required".into())
    );
    let (_, nodes) = send(relay.client.get(relay.url("/nodes")).bearer_auth(&owner)).await;
    for n in nodes.as_array().unwrap() {
        assert_eq!(n["join_policy"], "invite", "{n}");
    }

    // The policy change is audited with the other settings, and other
    // fields still update alongside it.
    let (status, body) = patch_node(
        &relay,
        &owner,
        node,
        json!({"name": "T29-renamed", "max_accounts_per_device": 5, "join_policy": "request"}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(policy().await, 1);
    assert_eq!(node_name(&relay, node).await, "T29-renamed");
    assert_eq!(device_cap(&relay, node).await, 5);
    assert_eq!(audit_rows(&relay, node, "node_settings_update").await, 4);

    // A database failure after the writes rolls every field back: 503
    // `unavailable` with the fixed text, the pending request survives the
    // failed switch to `invite`, and no audit row is written.
    assert_eq!(join_by_id(&relay, &r, node).await.0, 202);
    assert_eq!(requests_of(&relay, node).await, 1);
    relay
        .state
        .faults()
        .arm("admission:node_settings", FaultKind::Constraint);
    let response = patch_node(
        &relay,
        &owner,
        node,
        json!({"name": "T29-fault", "max_accounts_per_device": 7, "join_policy": "invite"}),
    )
    .await;
    assert_eq!(reason(&response), (503, "unavailable".into()));
    assert_eq!(response.1["error"], "Service temporarily unavailable");
    assert!(!relay.state.faults().is_armed("admission:node_settings"));
    assert_eq!(policy().await, 1);
    assert_eq!(node_name(&relay, node).await, "T29-renamed");
    assert_eq!(requests_of(&relay, node).await, 1);
    assert_eq!(device_cap(&relay, node).await, 5);
    assert_eq!(audit_rows(&relay, node, "node_settings_update").await, 4);

    // The owner loses the membership row: a KICK_MEMBERS holder bans the
    // owner's key (ban has no owner guard).
    grant(&relay, node, p_id, "Kicker", KICK_MEMBERS).await;
    let (status, body) = ban(&relay, &p, node, &pkh("t29-owner")).await;
    assert_eq!(status, 200, "{body}");
    assert!(!is_member(&relay, node, owner_id).await);
    // The policy together with the name is refused as a whole: the name
    // keeps the member rule, so nothing changes and nothing is audited.
    for body in [
        json!({"join_policy": "invite", "name": "T29-half"}),
        json!({"join_policy": "invite", "max_accounts_per_device": 7}),
        json!({"name": "T29-half"}),
    ] {
        assert_eq!(
            reason(&patch_node(&relay, &owner, node, body.clone()).await),
            (403, "forbidden".into()),
            "{body}"
        );
    }
    assert_eq!(policy().await, 1);
    assert_eq!(node_name(&relay, node).await, "T29-renamed");
    assert_eq!(device_cap(&relay, node).await, 5);
    assert_eq!(requests_of(&relay, node).await, 1);
    assert_eq!(audit_rows(&relay, node, "node_settings_update").await, 4);
    // The policy alone is still the owner's to change.
    let (status, body) = policy_patch(&relay, &owner, node, json!("invite")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(policy().await, 0);
    assert_eq!(requests_of(&relay, node).await, 0);
    assert_eq!(audit_rows(&relay, node, "node_settings_update").await, 5);
}

/// T-30 (REQ-30): a request is created and refreshed as one row, refused
/// while banned, capped at 200 pending requests under concurrency (a
/// refresh is always allowed), and announced to online approvers.
#[tokio::test]
async fn t30_join_request_creation() {
    let dir = tempfile::tempdir().unwrap();
    let relay = file_relay(&dir).await;
    let (_, owner) = account(&relay, "t30-owner").await;
    let (c_id, c) = account(&relay, "t30-inviter").await;
    let (_, p) = account(&relay, "t30-plain").await;
    let (r_id, r) = account(&relay, "t30-requester").await;
    let (b_id, b) = account(&relay, "t30-banned").await;
    let node = relay.create_node(&owner, "T30").await;
    relay.join_with_owner_invite(&c, node).await;
    relay.join_with_owner_invite(&p, node).await;
    grant(&relay, node, c_id, "Inviter", CREATE_INVITE).await;
    set_policy(&relay, &owner, node, "request").await;
    let mut owner_ws = WsClient::connect(&relay, &owner).await;
    let mut c_ws = WsClient::connect(&relay, &c).await;
    let mut p_ws = WsClient::connect(&relay, &p).await;
    for ws in [&mut owner_ws, &mut c_ws, &mut p_ws] {
        ws.frames_for(Duration::from_millis(200)).await;
    }

    // Request.
    let (status, body) = join_by_id(&relay, &r, node).await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["status"], "pending_approval");
    assert_eq!(body["node_id"], node.to_string());
    let expires_at = body["expires_at"].as_i64().unwrap();
    assert!((expires_at - (now() + REQUEST_LIFETIME)).abs() <= 2);
    assert_eq!(requests_of(&relay, node).await, 1);
    for ws in [&mut owner_ws, &mut c_ws] {
        let frame = ws
            .wait_for("join_request_created", OBSERVE)
            .await
            .expect("approvers are told");
        assert_eq!(frame["node_id"], node.to_string());
        assert_eq!(frame["user_id"], r_id.to_string());
        assert_eq!(
            frame["created_at"].as_i64().unwrap(),
            expires_at - REQUEST_LIFETIME
        );
    }
    assert_eq!(
        count_frames(&p_ws.frames_for(OBSERVE).await, "join_request_created"),
        0
    );

    // Repeat: the row is refreshed, not duplicated.
    exec(
        pool(&relay),
        &format!(
            "UPDATE node_join_requests SET created_at = 1, expires_at = {} WHERE user_id = '{r_id}'",
            now() + 100
        ),
    )
    .await;
    assert_eq!(join_by_id(&relay, &r, node).await.0, 202);
    assert_eq!(requests_of(&relay, node).await, 1);
    let refreshed = count(
        pool(&relay),
        &format!("SELECT expires_at FROM node_join_requests WHERE user_id = '{r_id}'"),
    )
    .await;
    assert!(refreshed >= now() + REQUEST_LIFETIME - 2, "{refreshed}");

    // A build hash longer than 128 characters is refused.
    let (_, long) = account(&relay, "t30-long-hash").await;
    let (status, body) = send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/join")))
            .bearer_auth(&long)
            .header("X-Build-Hash", "h".repeat(129)),
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (400, json!("invalid_request"))
    );

    // Banned.
    assert_eq!(ban(&relay, &owner, node, &pkh("t30-banned")).await.0, 200);
    assert_eq!(
        reason(&join_by_id(&relay, &b, node).await),
        (403, "banned".into())
    );
    assert_eq!(
        count(
            pool(&relay),
            &format!("SELECT COUNT(*) FROM node_join_requests WHERE user_id = '{b_id}'")
        )
        .await,
        0
    );

    // Fill to 199 pending requests (R's included), then 5 new requesters in
    // parallel: exactly one fits.
    let mut users = Vec::new();
    let mut requests = Vec::new();
    for i in 0..198 {
        let id = Uuid::new_v4();
        users.push(format!(
            "('{id}', 't30-filler-{i}', 't30-filler-{i}', '!locked', 0)"
        ));
        requests.push(format!("('{node}', '{id}', {}, {})", now(), now() + 1000));
    }
    exec(
        pool(&relay),
        &format!(
            "INSERT INTO users (id, public_key_hash, public_key, password_hash, created_at) VALUES {}",
            users.join(", ")
        ),
    )
    .await;
    exec(
        pool(&relay),
        &format!(
            "INSERT INTO node_join_requests (node_id, user_id, created_at, expires_at) VALUES {}",
            requests.join(", ")
        ),
    )
    .await;
    assert_eq!(requests_of(&relay, node).await, 199);
    let mut tokens = Vec::new();
    for i in 0..5 {
        tokens.push(account(&relay, &format!("t30-parallel-{i}")).await.1);
    }
    let results =
        futures_util::future::join_all(tokens.iter().map(|token| join_by_id(&relay, token, node)))
            .await;
    let accepted = results.iter().filter(|(s, _)| *s == 202).count();
    let full = results
        .iter()
        .filter(|(s, b)| *s == 403 && b["reason"] == "join_requests_full")
        .count();
    assert_eq!((accepted, full), (1, 4), "{results:?}");
    assert_eq!(requests_of(&relay, node).await, 200);

    // An existing requester may always refresh.
    assert_eq!(join_by_id(&relay, &r, node).await.0, 202);
    assert_eq!(requests_of(&relay, node).await, 200);
}

/// T-31 (REQ-31): only admission authority lists, approves and denies; a
/// non-member's @everyone bits never count; deny deletes the row and tells
/// the requester; the requester can withdraw, once.
#[tokio::test]
async fn t31_approvers_and_endpoints() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "t31-owner").await;
    let (c_id, c) = account(&relay, "t31-inviter").await;
    let (_, p) = account(&relay, "t31-plain").await;
    let (_, q) = account(&relay, "t31-outsider").await;
    let node = relay.create_node(&owner, "T31").await;
    relay.join_with_owner_invite(&c, node).await;
    relay.join_with_owner_invite(&p, node).await;
    grant(&relay, node, c_id, "Inviter", CREATE_INVITE).await;
    set_policy(&relay, &owner, node, "request").await;
    let mut requesters = Vec::new();
    for i in 0..5 {
        let (id, token) = account(&relay, &format!("t31-requester-{i}")).await;
        assert_eq!(join_by_id(&relay, &token, node).await.0, 202);
        exec(
            pool(&relay),
            &format!(
                "UPDATE node_join_requests SET created_at = {} WHERE user_id = '{id}'",
                now() - 100 + i as i64
            ),
        )
        .await;
        requesters.push((id, token));
    }
    let (r1, r2, r3, r4) = (
        requesters[0].0,
        requesters[1].0,
        requesters[2].0,
        requesters[3].0,
    );

    // Listing.
    for token in [&owner, &c] {
        let (status, body) = list_requests(&relay, token, node).await;
        assert_eq!(status, 200, "{body}");
        let list = body["join_requests"].as_array().unwrap();
        let ids: Vec<String> = list
            .iter()
            .map(|e| e["user_id"].as_str().unwrap().to_string())
            .collect();
        let want: Vec<String> = requesters.iter().map(|(id, _)| id.to_string()).collect();
        assert_eq!(ids, want, "oldest first");
        for (entry, i) in list.iter().zip(0..) {
            assert_eq!(entry["public_key_hash"], pkh(&format!("t31-requester-{i}")));
            assert!(entry["display_name"].is_string() || entry["display_name"].is_null());
            assert!(entry["created_at"].as_u64().is_some());
            assert!(entry["expires_at"].as_u64().unwrap() > entry["created_at"].as_u64().unwrap());
        }
    }

    // A member without CREATE_INVITE.
    assert_eq!(
        reason(&list_requests(&relay, &p, node).await),
        (403, "forbidden".into())
    );
    assert_eq!(
        reason(&approve(&relay, &p, node, r1).await),
        (403, "forbidden".into())
    );
    assert_eq!(
        reason(&deny(&relay, &p, node, r1).await),
        (403, "forbidden".into())
    );
    // A non-member while @everyone holds CREATE_INVITE.
    exec(
        pool(&relay),
        &format!(
            "UPDATE roles SET permissions = permissions | {CREATE_INVITE} WHERE id = '{node}'"
        ),
    )
    .await;
    assert_eq!(
        reason(&list_requests(&relay, &q, node).await),
        (403, "forbidden".into())
    );
    assert_eq!(
        reason(&approve(&relay, &q, node, r1).await),
        (403, "forbidden".into())
    );
    assert_eq!(
        reason(&deny(&relay, &q, node, r1).await),
        (403, "forbidden".into())
    );
    exec(
        pool(&relay),
        &format!(
            "UPDATE roles SET permissions = permissions & ~{CREATE_INVITE} WHERE id = '{node}'"
        ),
    )
    .await;
    assert_eq!(requests_of(&relay, node).await, 5);

    // Approvals by the owner and by the member with CREATE_INVITE.
    let (status, body) = approve(&relay, &owner, node, r1).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"status": "approved", "node_id": node, "user_id": r1})
    );
    let (status, body) = approve(&relay, &c, node, r2).await;
    assert_eq!(status, 200, "{body}");
    for id in [r1, r2] {
        assert!(is_member(&relay, node, id).await);
        let member = relay
            .state
            .db
            .get_node_member(node, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.role.as_str(), "member");
        assert!(relay
            .state
            .db
            .get_member_roles(node, id)
            .await
            .unwrap()
            .is_empty());
    }

    // Denials: the row is deleted and the requester is told.
    let mut r3_ws = WsClient::connect(&relay, &requesters[2].1).await;
    let (status, body) = deny(&relay, &owner, node, r3).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"status": "denied", "node_id": node, "user_id": r3})
    );
    let frame = r3_ws
        .wait_for("join_request_denied", OBSERVE)
        .await
        .expect("the requester is told");
    assert_eq!(
        frame,
        json!({"type": "join_request_denied", "node_id": node})
    );
    assert_eq!(deny(&relay, &c, node, r4).await.0, 200);
    assert_eq!(
        reason(&deny(&relay, &c, node, r4).await),
        (404, "request_not_found".into())
    );
    assert!(!is_member(&relay, node, r3).await);
    assert!(!is_member(&relay, node, r4).await);

    // Withdrawal, charged as a membership action.
    let (r5, r5_token) = &requesters[4];
    let (status, body) = withdraw(&relay, r5_token, node).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, json!({"status": "withdrawn", "node_id": node}));
    assert_eq!(
        reason(&withdraw(&relay, r5_token, node).await),
        (404, "request_not_found".into())
    );
    assert_eq!(
        relay
            .state
            .rate_limiter
            .get_status(*r5, ActionType::MembershipChange)
            .await
            .0,
        3,
        "one request and two withdrawals"
    );
    assert_eq!(requests_of(&relay, node).await, 0);
    let (_, body) = list_requests(&relay, &owner, node).await;
    assert_eq!(body, json!({"join_requests": []}));
}

/// T-32 (REQ-32): of two concurrent approvals exactly one admits; the
/// requester sees `member_joined` before `node_joined`, which arrives once;
/// a requester banned meanwhile is refused and the request is gone.
#[tokio::test]
async fn t32_atomic_approval() {
    let dir = tempfile::tempdir().unwrap();
    let relay = file_relay(&dir).await;
    let (_, owner) = account(&relay, "t32-owner").await;
    let (c_id, c) = account(&relay, "t32-inviter").await;
    let (r_id, r) = account(&relay, "t32-requester").await;
    let (r2_id, r2) = account(&relay, "t32-banned").await;
    let node = relay.create_node(&owner, "T32").await;
    relay.join_with_owner_invite(&c, node).await;
    grant(&relay, node, c_id, "Inviter", CREATE_INVITE).await;
    set_policy(&relay, &owner, node, "request").await;
    let channels = channel_ids(&relay, node).await.len();
    assert_eq!(join_by_id(&relay, &r, node).await.0, 202);
    let mut r_ws = WsClient::connect(&relay, &r).await;
    r_ws.frames_for(Duration::from_millis(200)).await;

    let (a, b) = tokio::join!(
        approve(&relay, &owner, node, r_id),
        approve(&relay, &c, node, r_id)
    );
    let mut outcomes = vec![reason(&a), reason(&b)];
    outcomes.sort();
    assert_eq!(
        outcomes,
        vec![(200, String::new()), (404, "request_not_found".into())],
        "{a:?} {b:?}"
    );
    assert!(is_member(&relay, node, r_id).await);
    assert_eq!(requests_of(&relay, node).await, 0);

    let frames = r_ws.frames_for(OBSERVE).await;
    let first_member_joined = frames
        .iter()
        .position(|f| f["type"] == "member_joined" && f["user_id"] == r_id.to_string())
        .expect("member_joined reaches the new member");
    let node_joined: Vec<usize> = frames
        .iter()
        .enumerate()
        .filter(|(_, f)| f["type"] == "node_joined")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(node_joined.len(), 1, "{frames:?}");
    assert!(first_member_joined < node_joined[0], "{frames:?}");
    let pushed = &frames[node_joined[0]];
    assert_eq!(pushed["node_id"], node.to_string());
    assert_eq!(pushed["node_name"], "T32");
    assert!(pushed.get("request_id").is_none(), "{pushed}");
    assert_eq!(count_frames(&frames, "member_joined"), channels);

    // A requester banned before the approval.
    assert_eq!(join_by_id(&relay, &r2, node).await.0, 202);
    assert_eq!(ban(&relay, &owner, node, &pkh("t32-banned")).await.0, 200);
    assert_eq!(
        reason(&approve(&relay, &owner, node, r2_id).await),
        (403, "banned".into())
    );
    assert_eq!(requests_of(&relay, node).await, 0);
    assert!(!is_member(&relay, node, r2_id).await);
}

/// T-33 (REQ-33): an expired request is ignored by every read and every
/// approval, a new request replaces it, and the maintenance purge deletes
/// expired rows only.
#[tokio::test]
async fn t33_expired_requests_are_ignored_and_purged() {
    let relay = TestRelay::start().await;
    let (_, owner) = account(&relay, "t33-owner").await;
    let (e_id, e) = account(&relay, "t33-expired").await;
    let (e2_id, e2) = account(&relay, "t33-expired-again").await;
    let (l_id, l) = account(&relay, "t33-live").await;
    let node = relay.create_node(&owner, "T33").await;
    set_policy(&relay, &owner, node, "request").await;
    for id in [e_id, e2_id] {
        exec(
            pool(&relay),
            &format!(
                "INSERT INTO node_join_requests (node_id, user_id, created_at, expires_at) VALUES ('{node}', '{id}', {}, {})",
                now() - REQUEST_LIFETIME - 10,
                now() - 10
            ),
        )
        .await;
    }
    assert_eq!(join_by_id(&relay, &l, node).await.0, 202);

    let (_, body) = list_requests(&relay, &owner, node).await;
    let listed: Vec<String> = body["join_requests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["user_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(listed, vec![l_id.to_string()]);
    assert_eq!(
        reason(&approve(&relay, &owner, node, e_id).await),
        (404, "request_not_found".into())
    );
    assert!(!is_member(&relay, node, e_id).await);
    assert_eq!(
        reason(&deny(&relay, &owner, node, e_id).await),
        (404, "request_not_found".into())
    );
    assert_eq!(
        reason(&withdraw(&relay, &e, node).await),
        (404, "request_not_found".into())
    );
    // A new request replaces an expired row.
    assert_eq!(join_by_id(&relay, &e2, node).await.0, 202);
    assert_eq!(requests_of(&relay, node).await, 3);

    let purged = relay
        .state
        .db
        .purge_expired_join_requests(now() as u64)
        .await
        .unwrap();
    assert_eq!(purged, 1);
    assert_eq!(
        count(
            pool(&relay),
            &format!("SELECT COUNT(*) FROM node_join_requests WHERE user_id = '{e_id}'")
        )
        .await,
        0
    );
    assert_eq!(requests_of(&relay, node).await, 2);
    assert_eq!(approve(&relay, &owner, node, e2_id).await.0, 200);
    assert!(is_member(&relay, node, e2_id).await);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-28 (steps 6 and 7): reasons, and no effects on failure
// ─────────────────────────────────────────────────────────────────────────

/// T-28 (REQ-28) for leave, kick, `PATCH /nodes/:id` (the join policy and
/// the other settings) and the join-request endpoints: every refusal
/// carries its reason, and none writes an audit row, changes the node,
/// broadcasts, rotates or runs a removal hook.
#[tokio::test]
async fn t28_removal_and_request_refusals_carry_reasons() {
    let relay = TestRelay::start().await;
    let (owner_id, owner) = account(&relay, "t28r-owner").await;
    let (m_id, m) = account(&relay, "t28r-member").await;
    let (_, p) = account(&relay, "t28r-plain").await;
    let (x_id, x) = account(&relay, "t28r-outsider").await;
    let (_, observer) = account(&relay, "t28r-observer").await;
    let node = relay.create_node(&owner, "T28R").await;
    for token in [&m, &p, &observer] {
        relay.join_with_owner_invite(token, node).await;
    }
    let mut watch = WsClient::connect(&relay, &observer).await;
    let audit = || count(pool(&relay), "SELECT COUNT(*) FROM audit_log");
    let audit_before = audit().await;
    let missing = Uuid::new_v4();

    let checks = vec![
        (leave(&relay, &x, node).await, 404, "not_member"),
        (leave(&relay, &owner, node).await, 400, "owner_cannot_leave"),
        (leave(&relay, &x, missing).await, 404, "node_not_found"),
        (kick(&relay, &p, node, m_id).await, 403, "forbidden"),
        (kick(&relay, &owner, node, x_id).await, 404, "not_member"),
        (
            kick(&relay, &owner, node, owner_id).await,
            400,
            "invalid_request",
        ),
        (
            kick(&relay, &owner, missing, m_id).await,
            404,
            "node_not_found",
        ),
        (
            patch_node(&relay, &owner, node, json!({"join_policy": "public"})).await,
            400,
            "invalid_request",
        ),
        (
            patch_node(&relay, &p, node, json!({"join_policy": "request"})).await,
            403,
            "forbidden",
        ),
        // The other fields of the same route carry reasons too.
        (
            patch_node(&relay, &p, node, json!({"name": "x"})).await,
            403,
            "forbidden",
        ),
        (
            patch_node(&relay, &x, node, json!({"name": "x"})).await,
            403,
            "forbidden",
        ),
        (
            patch_node(&relay, &owner, node, json!({"name": "a".repeat(101)})).await,
            400,
            "invalid_request",
        ),
        (
            patch_node(&relay, &owner, node, json!({"name": "  "})).await,
            400,
            "invalid_request",
        ),
        (
            patch_node(&relay, &owner, missing, json!({"name": "x"})).await,
            404,
            "node_not_found",
        ),
        (list_requests(&relay, &p, node).await, 403, "forbidden"),
        (
            list_requests(&relay, &p, missing).await,
            404,
            "node_not_found",
        ),
        (
            approve(&relay, &owner, node, x_id).await,
            404,
            "request_not_found",
        ),
        (
            approve(&relay, &owner, missing, x_id).await,
            404,
            "node_not_found",
        ),
        (
            deny(&relay, &owner, node, x_id).await,
            404,
            "request_not_found",
        ),
        (withdraw(&relay, &x, node).await, 404, "request_not_found"),
        (withdraw(&relay, &x, missing).await, 404, "node_not_found"),
    ];
    for ((status, body), want_status, want_reason) in checks {
        assert_eq!(status, want_status, "{want_reason}: {body}");
        assert_eq!(body["reason"], want_reason, "{body}");
        assert_eq!(body["code"], want_status, "{body}");
        assert!(body["error"].is_string(), "{body}");
    }
    assert_eq!(audit().await, audit_before);
    let frames = watch.frames_for(OBSERVE).await;
    for kind in [ROTATION, "member_joined", "sender_key_new_member"] {
        assert_eq!(count_frames(&frames, kind), 0, "{frames:?}");
    }
    assert_eq!(hooks(&relay), 0);
    assert!(is_member(&relay, node, m_id).await);
    assert_eq!(
        count(
            pool(&relay),
            &format!("SELECT COUNT(*) FROM nodes WHERE id = '{node}' AND join_policy = 'invite'")
        )
        .await,
        1
    );
    assert_eq!(node_name(&relay, node).await, "T28R");

    // Bodies kept by REQ-28: no token, and a malformed id.
    let (status, body) = send(
        relay
            .client
            .post(relay.url(&format!("/nodes/{node}/leave"))),
    )
    .await;
    assert_eq!(status, 401);
    assert!(body.get("reason").is_none(), "{body}");
    let response = relay
        .client
        .post(relay.url(&format!("/nodes/{node}/join-requests/not-a-uuid/approve")))
        .bearer_auth(&owner)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    assert!(!response.text().await.unwrap().contains("reason"));
}
