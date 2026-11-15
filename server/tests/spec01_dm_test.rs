//! SPEC-01 section 11.2 step 4: the reserved DM system node on every node
//! surface (REQ-7) and DM conversations without a joinable node (REQ-16,
//! REQ-17).
//!
//! Tests T-6 (REQ-7 part), T-7, T-7b, T-16, T-17, T-17b and T-17c of section
//! 10.2, and the regressions RG-C001-2, RG-C001-3, RG-C001-4, RG-C001-5,
//! RG-C001-6 (the REST and WS calls after the restart), RG-C001-7, RG-C001-9
//! and RG-C001-10 of section 10.3. Every test serves the production router; every account
//! has a password and every membership comes from an owner-created invite.

use accord_server::db::{DbOptions, DM_SYSTEM_NODE_ID, DM_SYSTEM_USER_ID};
use accord_server::faults::FaultKind;
use accord_server::files::FileConfig;
use accord_server::state::{AppState, AppStateOptions};
use accord_server::test_support::{count_frames, TestRelay, WsClient};
use base64::Engine;
use serde_json::{json, Value};
use sqlx::SqlitePool;
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

async fn exec(pool: &SqlitePool, sql: &str) -> Result<u64, sqlx::Error> {
    sqlx::query(sql)
        .execute(pool)
        .await
        .map(|r| r.rows_affected())
}

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// Row counts of every table an admission or DM path could write.
async fn snapshot(pool: &SqlitePool) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for table in [
        "nodes",
        "node_members",
        "channels",
        "channel_members",
        "node_invites",
        "node_join_requests",
        "roles",
        "member_roles",
        "audit_log",
        "messages",
        "bot_invocations",
        "dm_channels",
        "node_bans",
        "custom_emojis",
        "channel_categories",
        "webhooks",
        "installed_bots",
        "node_user_profiles",
        "node_build_hash_allowlist",
    ] {
        out.push((
            table.to_string(),
            count(pool, &format!("SELECT COUNT(*) FROM {table}")).await,
        ));
    }
    let owner: String = sqlx::query_scalar(&format!("SELECT owner_id FROM nodes WHERE id = '{D}'"))
        .fetch_one(pool)
        .await
        .unwrap();
    out.push((
        "reserved owner".into(),
        i64::from(owner == DM_SYSTEM_USER_ID.to_string()),
    ));
    out
}

/// Send `method path` with a bearer token and an optional JSON body; return
/// the status and the parsed body (`Null` when it is not JSON).
async fn call(
    relay: &TestRelay,
    method: reqwest::Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let mut request = relay.client.request(method, relay.url(path));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// Users U and V become friends through the friend-request flow, which
/// requires a shared node: U owns a node and V joins it by invite.
async fn make_friends(relay: &TestRelay, u: Uuid, u_token: &str, v: Uuid, v_token: &str) -> Uuid {
    let node = relay.create_node(u_token, "Friends").await;
    relay.join_with_owner_invite(v_token, node).await;
    let request = relay
        .state
        .db
        .create_friend_request(u, v, node, None)
        .await
        .unwrap();
    assert!(relay
        .state
        .db
        .accept_friend_request(request, None)
        .await
        .unwrap());
    node
}

/// A DM between two fresh users U and V, and a third user W.
struct DmFixture {
    relay: TestRelay,
    u: (Uuid, String),
    v: (Uuid, String),
    w: (Uuid, String),
    dm: Uuid,
}

async fn dm_fixture() -> DmFixture {
    let relay = TestRelay::start().await;
    let u = relay.register_and_auth("dm-u").await;
    let v = relay.register_and_auth("dm-v").await;
    let w = relay.register_and_auth("dm-w").await;
    make_friends(&relay, u.0, &u.1, v.0, &v.1).await;
    let (status, body) = call(
        &relay,
        reqwest::Method::POST,
        &format!("/dm/{}", v.0),
        Some(&u.1),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let dm = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    DmFixture { relay, u, v, w, dm }
}

fn channel_message(channel_id: Uuid) -> Value {
    json!({ "ChannelMessage": {
        "channel_id": channel_id,
        "encrypted_data": base64::engine::general_purpose::STANDARD.encode(b"ciphertext"),
    }})
}

// ─────────────────────────────────────────────────────────────────────────
//  T-7, T-6, RG-C001-2, RG-C001-7: the MUST surfaces of section 6.7
// ─────────────────────────────────────────────────────────────────────────

/// The MUST routes of section 6.7, each as (method, path, body).
fn must_routes(node: Uuid) -> Vec<(reqwest::Method, String, Option<Value>)> {
    use reqwest::Method;
    vec![
        (Method::GET, format!("/nodes/{node}"), None),
        (
            Method::PATCH,
            format!("/nodes/{node}"),
            Some(json!({"name": "renamed"})),
        ),
        (Method::GET, format!("/nodes/{node}/channels"), None),
        (
            Method::POST,
            format!("/nodes/{node}/channels"),
            Some(json!({"name": "x"})),
        ),
        (Method::POST, format!("/nodes/{node}/join"), None),
        (Method::POST, format!("/nodes/{node}/leave"), None),
        (Method::POST, format!("/nodes/{node}/invites"), None),
        (Method::GET, format!("/nodes/{node}/invites"), None),
        (
            Method::DELETE,
            format!("/nodes/{node}/invites/ABCDEFGH"),
            None,
        ),
        (Method::GET, format!("/nodes/{node}/join-requests"), None),
        (
            Method::POST,
            format!("/nodes/{node}/join-requests/{node}/approve"),
            None,
        ),
        (
            Method::POST,
            format!("/nodes/{node}/join-requests/{node}/deny"),
            None,
        ),
        (Method::DELETE, format!("/nodes/{node}/join-request"), None),
        (
            Method::PATCH,
            format!("/nodes/{node}"),
            Some(json!({"join_policy": "request"})),
        ),
    ]
}

/// T-7 (REQ-7), RG-C001-2, RG-C001-7: every MUST route and WS message
/// refuses the reserved node exactly like a node that does not exist, and
/// changes nothing. T-6 (REQ-7 part): renaming the reserved node changes
/// nothing, because the predicate compares ids.
#[tokio::test]
async fn t7_reserved_node_is_inert_on_every_must_surface() {
    let relay = TestRelay::start().await;
    let (user, token) = relay.register_and_auth("t7-user").await;
    let missing = Uuid::new_v4();
    let before = snapshot(pool(&relay)).await;

    for (method, path, body) in must_routes(DM_SYSTEM_NODE_ID) {
        let reserved = call(&relay, method.clone(), &path, Some(&token), body.clone()).await;
        let other = path.replace(D, &missing.to_string());
        let absent = call(&relay, method.clone(), &other, Some(&token), body).await;
        assert_eq!(reserved.0, 404, "{method} {path}: {}", reserved.1);
        assert_eq!(reserved.1["reason"], "node_not_found", "{method} {path}");
        assert_eq!(
            reserved, absent,
            "{method} {path} differs from a missing node"
        );
    }
    // RG-C001-7: the unauthenticated node card leaks nothing.
    let (status, body) = call(
        &relay,
        reqwest::Method::GET,
        &format!("/nodes/{D}"),
        None,
        None,
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("node_not_found"))
    );

    // WebSocket: typed failure frames for JoinNode and LeaveNode, the
    // generic error frame "Node not found" for GetNodeInfo and CreateChannel.
    let mut ws = WsClient::connect(&relay, &token).await;
    for node in [DM_SYSTEM_NODE_ID, missing] {
        let id = ws.send(json!({"JoinNode": {"node_id": node}})).await;
        let frames = ws.frames_for(Duration::from_millis(500)).await;
        assert_eq!(frames.len(), 1, "{frames:?}");
        assert_eq!(frames[0]["type"], "join_failed");
        assert_eq!(frames[0]["reason"], "node_not_found");
        assert_eq!(frames[0]["request_id"], id.to_string());

        let id = ws.send(json!({"LeaveNode": {"node_id": node}})).await;
        let frames = ws.frames_for(Duration::from_millis(500)).await;
        assert_eq!(frames.len(), 1, "{frames:?}");
        assert_eq!(frames[0]["type"], "leave_failed");
        assert_eq!(frames[0]["reason"], "node_not_found");
        assert_eq!(frames[0]["request_id"], id.to_string());

        for message in [
            json!({"GetNodeInfo": {"node_id": node}}),
            json!({"CreateChannel": {"node_id": node, "name": "x"}}),
        ] {
            ws.send(message.clone()).await;
            let frames = ws.frames_for(Duration::from_millis(500)).await;
            assert_eq!(frames.len(), 1, "{message}: {frames:?}");
            assert_eq!(frames[0]["type"], "error");
            assert_eq!(frames[0]["error"], "Node not found");
        }
    }
    assert_eq!(snapshot(pool(&relay)).await, before);

    // An invite of the reserved node, raw-seeded with the triggers dropped,
    // is invalid for preview and redemption, and is not consumed.
    relay.state.db.drop_admission_triggers().await.unwrap();
    exec(pool(&relay), &format!(
        "INSERT INTO node_invites (id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at) \
         VALUES ('{}', '{D}', '{user}', 'ReservedInvite01', NULL, 0, NULL, 0)",
        Uuid::new_v4()
    ))
    .await
    .unwrap();
    let (status, body) = call(
        &relay,
        reqwest::Method::GET,
        "/invites/ReservedInvite01/preview",
        None,
        None,
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("invite_invalid"))
    );
    // A fresh account redeems: the first one has spent its REQ-27
    // MembershipChange budget on the join, leave and withdrawal routes above.
    let (_, redeemer) = relay.register_and_auth("t7-redeemer").await;
    let (status, body) = call(
        &relay,
        reqwest::Method::POST,
        "/invites/ReservedInvite01/join",
        Some(&redeemer),
        None,
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("invite_invalid"))
    );
    assert_eq!(
        count(
            pool(&relay),
            "SELECT current_uses FROM node_invites WHERE invite_code = 'ReservedInvite01'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            pool(&relay),
            &format!("SELECT COUNT(*) FROM node_members WHERE node_id = '{D}'")
        )
        .await,
        0
    );

    // T-6: renamed to an ordinary name, the reserved node is still refused.
    // A fresh account runs these calls: the first one has spent most of its
    // REQ-27 MembershipChange budget above, and a 429 would hide whether the
    // node guard still applies to join and leave.
    exec(
        pool(&relay),
        &format!("UPDATE nodes SET name = 'general' WHERE id = '{D}'"),
    )
    .await
    .unwrap();
    let (renamed_user, renamed_token) = relay.register_and_auth("t7-renamed").await;
    let before = snapshot(pool(&relay)).await;
    for (method, path, body) in must_routes(DM_SYSTEM_NODE_ID) {
        let reserved = call(
            &relay,
            method.clone(),
            &path,
            Some(&renamed_token),
            body.clone(),
        )
        .await;
        let other = path.replace(D, &missing.to_string());
        let absent = call(&relay, method.clone(), &other, Some(&renamed_token), body).await;
        assert_eq!(
            (reserved.0, reserved.1["reason"].clone()),
            (404, json!("node_not_found")),
            "{method} {path} after the rename: {}",
            reserved.1
        );
        assert_eq!(
            reserved, absent,
            "{method} {path} after the rename differs from a missing node"
        );
    }
    let mut ws = WsClient::connect(&relay, &renamed_token).await;
    for (message, failed) in [
        (
            json!({"JoinNode": {"node_id": DM_SYSTEM_NODE_ID}}),
            "join_failed",
        ),
        (
            json!({"LeaveNode": {"node_id": DM_SYSTEM_NODE_ID}}),
            "leave_failed",
        ),
    ] {
        ws.send(message.clone()).await;
        let frames = ws.frames_for(Duration::from_millis(500)).await;
        assert_eq!(frames.len(), 1, "{message}: {frames:?}");
        assert_eq!(frames[0]["type"], failed);
        assert_eq!(frames[0]["reason"], "node_not_found");
    }
    assert_eq!(snapshot(pool(&relay)).await, before);
    // REQ-8 still applies after the rename.
    assert_eq!(
        relay
            .state
            .db
            .compute_node_permissions(DM_SYSTEM_NODE_ID, renamed_user)
            .await
            .unwrap(),
        0
    );
}

/// RG-C001-2: listing the reserved node's channels (every DM) is refused.
#[tokio::test]
async fn rg_c001_2_reserved_node_channels_are_not_listed() {
    let fixture = dm_fixture().await;
    let (status, body) = call(
        &fixture.relay,
        reqwest::Method::GET,
        &format!("/nodes/{D}/channels"),
        Some(&fixture.w.1),
        None,
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(body["reason"], "node_not_found");
    assert!(!body.to_string().contains(&fixture.dm.to_string()));
}

// ─────────────────────────────────────────────────────────────────────────
//  T-7b: the SHOULD surfaces of section 6.7
// ─────────────────────────────────────────────────────────────────────────

/// T-7b (REQ-7, SHOULD): every SHOULD route answers the reserved node with a
/// non-2xx status, or with an empty result and no rows created. Routes that
/// answer 2xx (that is, that do not use the reserved-node predicate) are
/// reported on stderr.
#[tokio::test]
async fn t7b_should_routes_create_nothing_for_the_reserved_node() {
    use reqwest::Method;
    let relay = TestRelay::start().await;
    let (_, token) = relay.register_and_auth("t7b-user").await;
    let x = Uuid::new_v4();
    let n = D;
    let routes: Vec<(Method, String, Option<Value>)> = vec![
        (Method::DELETE, format!("/nodes/{n}/members/{x}"), None),
        (
            Method::POST,
            format!("/nodes/{n}/bans"),
            Some(json!({"public_key_hash": "abc"})),
        ),
        (
            Method::DELETE,
            format!("/nodes/{n}/bans"),
            Some(json!({"public_key_hash": "abc"})),
        ),
        (Method::GET, format!("/nodes/{n}/bans"), None),
        (Method::GET, format!("/nodes/{n}/ban-check"), None),
        (Method::GET, format!("/api/presence/{n}"), None),
        (Method::GET, format!("/nodes/{n}/build-allowlist"), None),
        (
            Method::PUT,
            format!("/nodes/{n}/build-allowlist"),
            Some(json!({"entries": [{"build_hash": "h"}]})),
        ),
        (
            Method::POST,
            format!("/nodes/{n}/build-allowlist"),
            Some(json!({"build_hash": "h"})),
        ),
        (
            Method::DELETE,
            format!("/nodes/{n}/build-allowlist/h"),
            None,
        ),
        (Method::PUT, format!("/nodes/{n}/profile"), Some(json!({}))),
        (Method::GET, format!("/nodes/{n}/profiles"), None),
        (
            Method::POST,
            format!("/nodes/{n}/categories"),
            Some(json!({"name": "c"})),
        ),
        (Method::GET, format!("/nodes/{n}/roles"), None),
        (
            Method::POST,
            format!("/nodes/{n}/roles"),
            Some(json!({"name": "r", "permissions": 1})),
        ),
        (
            Method::PATCH,
            format!("/nodes/{n}/roles/reorder"),
            Some(json!({"roles": []})),
        ),
        (
            Method::PATCH,
            format!("/nodes/{n}/roles/{x}"),
            Some(json!({"name": "r"})),
        ),
        (Method::DELETE, format!("/nodes/{n}/roles/{x}"), None),
        (
            Method::POST,
            format!("/nodes/{n}/import-discord-template"),
            Some(json!({"template_json": {"roles": []}})),
        ),
        (Method::GET, format!("/nodes/{n}/members/{x}/roles"), None),
        (
            Method::PUT,
            format!("/nodes/{n}/members/{x}/roles/{x}"),
            None,
        ),
        (
            Method::DELETE,
            format!("/nodes/{n}/members/{x}/roles/{x}"),
            None,
        ),
        (Method::GET, format!("/nodes/{n}/emojis"), None),
        (Method::DELETE, format!("/nodes/{n}/emojis/{x}"), None),
        (
            Method::PUT,
            format!("/nodes/{n}/channels/reorder"),
            Some(json!({"channels": []})),
        ),
        (Method::GET, format!("/nodes/{n}/search?q=x"), None),
        (Method::GET, format!("/nodes/{n}/icon"), None),
        (Method::GET, format!("/nodes/{n}/members"), None),
        (Method::GET, format!("/nodes/{n}/audit-log"), None),
        (Method::GET, format!("/nodes/{n}/webhooks"), None),
        (
            Method::POST,
            format!("/nodes/{n}/webhooks"),
            Some(json!({"name": "w", "url": "https://example.com"})),
        ),
        (Method::GET, format!("/api/nodes/{n}/members/batch"), None),
        (Method::GET, format!("/api/nodes/{n}/channels/batch"), None),
        (Method::GET, format!("/api/nodes/{n}/overview"), None),
        (
            Method::GET,
            format!("/api/nodes/{n}/metadata/encrypted"),
            None,
        ),
        (
            Method::PUT,
            format!("/api/nodes/{n}/metadata/encrypted"),
            Some(json!({})),
        ),
        (Method::GET, format!("/api/nodes/{n}/bots"), None),
        (
            Method::POST,
            format!("/api/nodes/{n}/bots"),
            Some(
                json!({"manifest": {"bot_id": "b", "name": "b", "commands": []}, "webhook_url": "https://example.com"}),
            ),
        ),
    ];
    let before = snapshot(pool(&relay)).await;
    let mut without_predicate = Vec::new();
    for (method, path, body) in routes {
        let (status, body) = call(&relay, method.clone(), &path, Some(&token), body).await;
        if (200..300).contains(&status) {
            without_predicate.push(format!("{method} {path} -> {status} {body}"));
            // A 2xx must carry no data of the reserved node.
            let text = body.to_string();
            assert!(!text.contains("__dm_system__"), "{method} {path}: {text}");
        }
    }
    for line in &without_predicate {
        eprintln!("T-7b: route answered the reserved node with 2xx: {line}");
    }
    assert_eq!(
        snapshot(pool(&relay)).await,
        before,
        "a SHOULD route created rows"
    );
    // Every SHOULD route listed above refuses the reserved node today.
    assert!(without_predicate.is_empty(), "{without_predicate:#?}");
}

// ─────────────────────────────────────────────────────────────────────────
//  T-16: DM creation
// ─────────────────────────────────────────────────────────────────────────

/// T-16 (REQ-16): the reserved user is no DM or friend target, and two
/// concurrent first `POST /dm/:user_id` calls return the same conversation.
#[tokio::test]
async fn t16_dm_creation_is_atomic_and_never_involves_the_reserved_user() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relay.db");
    let files = dir.path().join("files");
    std::fs::create_dir_all(&files).unwrap();
    let state = AppState::new_with_options(
        db_path.to_str().unwrap(),
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
    let relay = TestRelay::with_state(Arc::new(state)).await;
    let u = relay.register_and_auth("t16-u").await;
    let v = relay.register_and_auth("t16-v").await;
    make_friends(&relay, u.0, &u.1, v.0, &v.1).await;

    let (status, body) = call(
        &relay,
        reqwest::Method::POST,
        &format!("/dm/{DM_SYSTEM_USER_ID}"),
        Some(&u.1),
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].clone()),
        (404, json!("Target user not found"))
    );
    let (status, _) = call(
        &relay,
        reqwest::Method::POST,
        "/friends/request",
        Some(&u.1),
        Some(json!({"to_user_id": DM_SYSTEM_USER_ID, "node_id": Uuid::new_v4()})),
    )
    .await;
    assert_eq!(status, 404);

    let dm_path = format!("/dm/{}", v.0);
    let first = call(&relay, reqwest::Method::POST, &dm_path, Some(&u.1), None);
    let second = call(&relay, reqwest::Method::POST, &dm_path, Some(&u.1), None);
    let (a, b) = tokio::join!(first, second);
    assert_eq!(a.0, 200, "{}", a.1);
    assert_eq!(b.0, 200, "{}", b.1);
    assert_eq!(a.1["id"], b.1["id"]);
    let dm = a.1["id"].as_str().unwrap().to_string();
    let p = pool(&relay);
    assert_eq!(count(p, "SELECT COUNT(*) FROM dm_channels").await, 1);
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM channels WHERE id = '{dm}'")
        )
        .await,
        1
    );
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM channel_members WHERE channel_id = '{dm}'")
        )
        .await,
        2
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  T-17, T-17b, T-17c: access by participation only
// ─────────────────────────────────────────────────────────────────────────

/// T-17 (REQ-17(a), (b), (e)): a non-participant cannot subscribe to a DM,
/// cannot be inserted into it even with raw SQL, and receives none of its
/// frames.
#[tokio::test]
async fn t17_dm_access_is_by_participation_only() {
    let f = dm_fixture().await;
    let mut w = WsClient::connect(&f.relay, &f.w.1).await;
    let mut v = WsClient::connect(&f.relay, &f.v.1).await;
    let mut u = WsClient::connect(&f.relay, &f.u.1).await;

    w.send(json!({"JoinChannel": {"channel_id": f.dm}})).await;
    let frames = w.frames_for(Duration::from_millis(500)).await;
    assert_eq!(count_frames(&frames, "error"), 1, "{frames:?}");

    let raw = exec(
        pool(&f.relay),
        &format!(
            "INSERT INTO channel_members (channel_id, user_id, joined_at) VALUES ('{}', '{}', 0)",
            f.dm, f.w.0
        ),
    )
    .await;
    assert!(raw
        .unwrap_err()
        .to_string()
        .contains("dm_participants_only"));

    u.send(channel_message(f.dm)).await;
    let delivered = v.wait_for("channel_message", OBSERVE).await;
    assert!(delivered.is_some(), "the participant receives the DM");
    let seen = w.frames_for(OBSERVE).await;
    assert!(seen.is_empty(), "the outsider received {seen:?}");
    let message_id = delivered.unwrap()["message_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Pins authorize by participation (REQ-17(a)), over REST and WS: the
    // participants may pin and unpin, the outsider may not, and a failed DM
    // lookup denies (REQ-17(c)).
    let pin_path = format!("/messages/{message_id}/pin");
    let pinned_sql = format!(
        "SELECT COUNT(*) FROM messages WHERE id = '{message_id}' AND pinned_at IS NOT NULL"
    );
    let pinned = || count(pool(&f.relay), &pinned_sql);
    let (status, body) = call(
        &f.relay,
        reqwest::Method::PUT,
        &pin_path,
        Some(&f.w.1),
        None,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(pinned().await, 0);
    f.relay.state.faults().arm("dm:lookup", FaultKind::Busy);
    let (status, body) = call(
        &f.relay,
        reqwest::Method::PUT,
        &pin_path,
        Some(&f.u.1),
        None,
    )
    .await;
    assert_eq!(status, 500, "{body}");
    assert!(!f.relay.state.faults().is_armed("dm:lookup"));
    assert_eq!(pinned().await, 0);
    let (status, body) = call(
        &f.relay,
        reqwest::Method::PUT,
        &pin_path,
        Some(&f.u.1),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(pinned().await, 1);
    assert!(v.wait_for("message_pin", OBSERVE).await.is_some());
    let (status, body) = call(
        &f.relay,
        reqwest::Method::DELETE,
        &pin_path,
        Some(&f.w.1),
        None,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(pinned().await, 1);
    let (status, body) = call(
        &f.relay,
        reqwest::Method::DELETE,
        &pin_path,
        Some(&f.v.1),
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(pinned().await, 0);
    // Drop the participants' queued pin events before the WS half.
    u.frames_for(Duration::from_millis(300)).await;
    v.frames_for(Duration::from_millis(300)).await;

    w.send(json!({"PinMessage": {"message_id": message_id}}))
        .await;
    let frames = w.frames_for(Duration::from_millis(500)).await;
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["error"], "Not a participant of this DM channel");
    assert_eq!(pinned().await, 0);
    v.send(json!({"PinMessage": {"message_id": message_id}}))
        .await;
    assert!(u.wait_for("message_pin", OBSERVE).await.is_some());
    assert_eq!(pinned().await, 1);
    w.send(json!({"UnpinMessage": {"message_id": message_id}}))
        .await;
    let frames = w.frames_for(Duration::from_millis(500)).await;
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["error"], "Not a participant of this DM channel");
    assert_eq!(pinned().await, 1);
    f.relay.state.faults().arm("dm:lookup", FaultKind::Busy);
    u.send(json!({"UnpinMessage": {"message_id": message_id}}))
        .await;
    let frames = u.frames_for(Duration::from_millis(500)).await;
    assert_eq!(count_frames(&frames, "error"), 1, "{frames:?}");
    assert_eq!(count_frames(&frames, "message_unpin"), 0, "{frames:?}");
    assert_eq!(pinned().await, 1);
    u.send(json!({"UnpinMessage": {"message_id": message_id}}))
        .await;
    assert!(v.wait_for("message_unpin", OBSERVE).await.is_some());
    assert_eq!(pinned().await, 0);
    // DM pins leave no audit row in the reserved node.
    assert_eq!(
        count(
            pool(&f.relay),
            &format!("SELECT COUNT(*) FROM audit_log WHERE node_id = '{D}'")
        )
        .await,
        0
    );
    // The outsider saw none of the pin events.
    assert!(w
        .frames_for(Duration::from_millis(200))
        .await
        .iter()
        .all(|f| f["type"] != "message_pin" && f["type"] != "message_unpin"));

    // History and files are refused to the outsider too.
    let (status, _) = call(
        &f.relay,
        reqwest::Method::GET,
        &format!("/channels/{}/messages", f.dm),
        Some(&f.w.1),
        None,
    )
    .await;
    assert!(status == 403 || status == 404, "{status}");
    let (status, _) = call(
        &f.relay,
        reqwest::Method::GET,
        &format!("/channels/{}/files", f.dm),
        Some(&f.w.1),
        None,
    )
    .await;
    assert_eq!(status, 403);
}

/// T-17b (REQ-17(c)), RG-C001-9: DM authorization fails closed. A send
/// during a failed DM lookup, and a send to an ordinary channel during a
/// failed permission computation, are refused; nothing is stored or
/// delivered.
#[tokio::test]
async fn t17b_dm_checks_fail_closed() {
    let f = dm_fixture().await;
    let owner = f.relay.register_and_auth("t17b-owner").await;
    let node = f.relay.create_node(&owner.1, "Ordinary").await;
    f.relay.join_with_owner_invite(&f.w.1, node).await;
    f.relay.join_with_owner_invite(&f.u.1, node).await;
    let ordinary = f.relay.state.db.get_node_channels(node).await.unwrap()[0].id;

    let mut u = WsClient::connect(&f.relay, &f.u.1).await;
    let mut v = WsClient::connect(&f.relay, &f.v.1).await;
    let mut w = WsClient::connect(&f.relay, &f.w.1).await;
    let messages = || count(pool(&f.relay), "SELECT COUNT(*) FROM messages");
    let before = messages().await;

    // The refusal names the failed lookup: an outsider's send would also be
    // refused by a fail-open fallback (the ordinary-channel branch or
    // REQ-8), so only the specific error shows that the lookup decided.
    f.relay.state.faults().arm("dm:lookup", FaultKind::Busy);
    w.send(channel_message(f.dm)).await;
    let frames = w.frames_for(Duration::from_millis(500)).await;
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(frames[0]["type"], "error");
    assert_eq!(frames[0]["error"], "Message refused: channel lookup failed");
    assert!(!f.relay.state.faults().is_armed("dm:lookup"));

    // A participant's send would succeed on any fail-open path, so this case
    // tells fail-closed from fail-open.
    f.relay.state.faults().arm("dm:lookup", FaultKind::Busy);
    u.send(channel_message(f.dm)).await;
    let frames = u.frames_for(Duration::from_millis(500)).await;
    let errors: Vec<&Value> = frames.iter().filter(|f| f["type"] == "error").collect();
    assert_eq!(errors.len(), 1, "{frames:?}");
    assert_eq!(errors[0]["error"], "Message refused: channel lookup failed");
    assert_eq!(count_frames(&frames, "channel_message"), 0, "{frames:?}");
    assert!(!f.relay.state.faults().is_armed("dm:lookup"));

    f.relay
        .state
        .faults()
        .arm("permissions:channel", FaultKind::Busy);
    w.send(channel_message(ordinary)).await;
    let frames = w.frames_for(Duration::from_millis(500)).await;
    assert_eq!(count_frames(&frames, "error"), 1, "{frames:?}");
    assert_eq!(count_frames(&frames, "channel_message"), 0, "{frames:?}");

    assert_eq!(messages().await, before);
    assert!(u
        .frames_for(OBSERVE)
        .await
        .iter()
        .all(|f| f["type"] != "channel_message"));
    assert!(v.frames_for(Duration::from_millis(100)).await.is_empty());

    // The same send without a fault is delivered (W holds SEND_MESSAGES).
    w.send(channel_message(ordinary)).await;
    assert!(u.wait_for("channel_message", OBSERVE).await.is_some());

    // POST /channels/:id/purge_before, a DM delete, fails closed too: a
    // participant's purge during a failed DM lookup removes nothing.
    u.send(channel_message(f.dm)).await;
    assert!(v.wait_for("channel_message", OBSERVE).await.is_some());
    let dm_messages_sql = format!(
        "SELECT COUNT(*) FROM messages WHERE channel_id = '{}'",
        f.dm
    );
    let dm_messages = || count(pool(&f.relay), &dm_messages_sql);
    assert_eq!(dm_messages().await, 1);
    let purge = |token: String| {
        let relay = &f.relay;
        let path = format!("/channels/{}/purge_before", f.dm);
        async move {
            call(
                relay,
                reqwest::Method::POST,
                &path,
                Some(&token),
                Some(json!({"before": 4_102_444_800u64})),
            )
            .await
        }
    };
    f.relay.state.faults().arm("dm:lookup", FaultKind::Busy);
    let (status, body) = purge(f.u.1.clone()).await;
    assert_eq!(status, 500, "{body}");
    assert!(!f.relay.state.faults().is_armed("dm:lookup"));
    assert_eq!(dm_messages().await, 1);
    // Without the fault an outsider is refused and a participant may purge.
    let (status, body) = purge(f.w.1.clone()).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(dm_messages().await, 1);
    let (status, body) = purge(f.u.1.clone()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["removed"], 1);
    assert_eq!(dm_messages().await, 0);
}

/// T-17c (REQ-17(d)), RG-C001-10: a bot can be invoked only on a non-DM
/// channel of its own node, and each invocation accepts one response.
#[tokio::test]
async fn t17c_bots_cannot_post_into_dms() {
    let f = dm_fixture().await;
    let a = f.relay.register_and_auth("t17c-a").await;
    let x = f.relay.create_node(&a.1, "X").await;
    let other = f.relay.register_and_auth("t17c-other").await;
    let y = f.relay.create_node(&other.1, "Y").await;
    let x_channel = f.relay.state.db.get_node_channels(x).await.unwrap()[0].id;
    let y_channel = f.relay.state.db.get_node_channels(y).await.unwrap()[0].id;

    let (status, body) = call(
        &f.relay,
        reqwest::Method::POST,
        &format!("/api/nodes/{x}/bots"),
        Some(&a.1),
        Some(json!({
            "manifest": {"bot_id": "b", "name": "B", "commands": [{"name": "c", "description": "c", "params": []}]},
            "webhook_url": "https://example.com/webhook"
        })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let bot_token = body["bot_token"].as_str().unwrap().to_string();
    let invocations = || count(pool(&f.relay), "SELECT COUNT(*) FROM bot_invocations");

    for channel in [f.dm, y_channel] {
        let (status, _) = call(
            &f.relay,
            reqwest::Method::POST,
            &format!("/api/nodes/{x}/bots/b/invoke"),
            Some(&a.1),
            Some(json!({"command": "c", "params": {}, "channel_id": channel})),
        )
        .await;
        assert_eq!(status, 404);
        assert_eq!(invocations().await, 0);
    }

    let mut a_ws = WsClient::connect(&f.relay, &a.1).await;
    let mut u_ws = WsClient::connect(&f.relay, &f.u.1).await;
    let (status, body) = call(
        &f.relay,
        reqwest::Method::POST,
        &format!("/api/nodes/{x}/bots/b/invoke"),
        Some(&a.1),
        Some(json!({"command": "c", "params": {}, "channel_id": x_channel})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let invocation = body["invocation_id"].as_str().unwrap().to_string();
    let respond = |id: String| {
        let relay = &f.relay;
        let token = bot_token.clone();
        async move {
            relay
                .client
                .post(relay.url("/api/bots/respond"))
                .bearer_auth(token)
                .json(&json!({"invocation_id": id, "content": {"type": "text", "text": "hi"}}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(respond(invocation.clone()).await, 200);
    let frames = a_ws.frames_for(Duration::from_millis(500)).await;
    assert_eq!(count_frames(&frames, "bot_response"), 1, "{frames:?}");
    assert_eq!(respond(invocation).await, 404);
    assert_eq!(
        count_frames(
            &a_ws.frames_for(Duration::from_millis(500)).await,
            "bot_response"
        ),
        0
    );

    // Another accepted spelling of the channel id (uppercase) is stored in
    // canonical form, so its response passes the channel re-check.
    let (status, body) = call(
        &f.relay,
        reqwest::Method::POST,
        &format!("/api/nodes/{x}/bots/b/invoke"),
        Some(&a.1),
        Some(json!({
            "command": "c",
            "params": {},
            "channel_id": x_channel.to_string().to_uppercase(),
        })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let upper = body["invocation_id"].as_str().unwrap().to_string();
    let stored: String =
        sqlx::query_scalar("SELECT channel_id FROM bot_invocations WHERE invocation_id = ?")
            .bind(&upper)
            .fetch_one(pool(&f.relay))
            .await
            .unwrap();
    assert_eq!(stored, x_channel.to_string());
    assert_eq!(respond(upper).await, 200);
    let frames = a_ws.frames_for(Duration::from_millis(500)).await;
    assert_eq!(count_frames(&frames, "bot_response"), 1, "{frames:?}");

    // A pending invocation that targets the DM, seeded raw, is refused.
    exec(
        pool(&f.relay),
        &format!(
            "INSERT INTO bot_invocations (invocation_id, bot_id, node_id, channel_id, invoker_user_id, command_name, status, created_at) \
             VALUES ('seeded', 'b', '{x}', '{}', '{}', 'c', 'pending', 0)",
            f.dm, a.0
        ),
    )
    .await
    .unwrap();
    assert_eq!(respond("seeded".into()).await, 404);
    assert!(u_ws
        .frames_for(OBSERVE)
        .await
        .iter()
        .all(|f| f["type"] != "bot_response"));
}

// ─────────────────────────────────────────────────────────────────────────
//  RG-C001-3, RG-C001-5, RG-C001-6
// ─────────────────────────────────────────────────────────────────────────

/// RG-C001-3: joining the reserved node to read every DM fails at the join;
/// no subscription is added, the outsider's socket gets no DM frame and a
/// DM attachment cannot be downloaded.
#[tokio::test]
async fn rg_c001_3_reserved_node_join_reaches_no_dm() {
    let f = dm_fixture().await;
    let file = Uuid::new_v4();
    f.relay
        .state
        .db
        .store_file_metadata(file, f.dm, f.u.0, b"name", 3, "hash", "/nonexistent/blob")
        .await
        .unwrap();
    let mut w = WsClient::connect(&f.relay, &f.w.1).await;
    let mut v = WsClient::connect(&f.relay, &f.v.1).await;
    let subscriptions_sql = format!(
        "SELECT COUNT(*) FROM channel_members WHERE user_id = '{}'",
        f.w.0
    );
    let subscriptions = || count(pool(&f.relay), &subscriptions_sql);
    let before = subscriptions().await;

    let (status, body) = call(
        &f.relay,
        reqwest::Method::POST,
        &format!("/nodes/{D}/join"),
        Some(&f.w.1),
        None,
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("node_not_found"))
    );
    w.send(json!({"JoinNode": {"node_id": DM_SYSTEM_NODE_ID}}))
        .await;
    assert_eq!(
        w.wait_for("join_failed", OBSERVE).await.unwrap()["reason"],
        "node_not_found"
    );
    assert_eq!(subscriptions().await, before);

    let mut u = WsClient::connect(&f.relay, &f.u.1).await;
    u.send(channel_message(f.dm)).await;
    assert!(v.wait_for("channel_message", OBSERVE).await.is_some());
    assert!(w.frames_for(OBSERVE).await.is_empty());

    let (status, _) = call(
        &f.relay,
        reqwest::Method::GET,
        &format!("/files/{file}"),
        Some(&f.w.1),
        None,
    )
    .await;
    assert_eq!(status, 403);
}

/// The reply to `Authenticate` with `token` on a fresh socket, after which
/// the test tries `then` on the same socket anyway.
async fn ws_authenticate_then(relay: &TestRelay, token: &str, then: Value) -> Value {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (ws, _) = tokio_tungstenite::connect_async(relay.ws_url("/ws"))
        .await
        .unwrap();
    let (mut sink, mut stream) = ws.split();
    sink.send(Message::Text(
        json!({ "Authenticate": { "token": token } }).to_string(),
    ))
    .await
    .unwrap();
    let reply = loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                break serde_json::from_str::<Value>(&text).unwrap()
            }
            Ok(Some(Ok(_))) => continue,
            other => panic!("no auth reply: {other:?}"),
        }
    };
    let envelope = json!({
        "message_type": then,
        "message_id": Uuid::new_v4(),
        "timestamp": 0,
    });
    // The relay may already have closed the socket; either way nothing runs.
    let _ = sink.send(Message::Text(envelope.to_string())).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    reply
}

/// RG-C001-4 (C001): a sentinel session deletes a DM message (WS
/// `DeleteMessage`) and a DM channel (`DELETE /channels/:id`). No sentinel
/// session can be obtained; an injected sentinel token is refused by WS auth
/// and by REST, and `compute_*` returns 0 for the reserved node's forced
/// owner (T-8), so the DM and its message stay.
#[tokio::test]
async fn rg_c001_4_sentinel_cannot_delete_dms() {
    let f = dm_fixture().await;
    let (message, _) = f
        .relay
        .state
        .db
        .store_message(f.dm, f.u.0, b"ciphertext", None, None)
        .await
        .unwrap();

    // No session: the sentinel's login is refused like a wrong password.
    let response = f
        .relay
        .client
        .post(f.relay.url("/auth"))
        .json(&json!({ "public_key_hash": "SYSTEM", "password": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    // An injected token (T-3) is refused on both paths.
    let token = "tok_sentinel_rg_c001_4";
    let plant = || async {
        f.relay.state.auth_tokens.write().await.insert(
            token.to_string(),
            accord_server::models::AuthToken {
                token: token.to_string(),
                user_id: DM_SYSTEM_USER_ID,
                expires_at: u64::MAX / 2,
            },
        );
    };
    plant().await;
    let reply = ws_authenticate_then(
        &f.relay,
        token,
        json!({ "DeleteMessage": { "message_id": message } }),
    )
    .await;
    assert_eq!(reply["type"], "error", "{reply}");
    assert_eq!(reply["code"], "auth_failed", "{reply}");
    plant().await;
    let (status, _) = call(
        &f.relay,
        reqwest::Method::DELETE,
        &format!("/channels/{}", f.dm),
        Some(token),
        None,
    )
    .await;
    assert_eq!(status, 401);

    // The sentinel owns the reserved node, and still holds no permission.
    let db = &f.relay.state.db;
    assert_eq!(
        db.compute_node_permissions(DM_SYSTEM_NODE_ID, DM_SYSTEM_USER_ID)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        db.compute_channel_permissions(DM_SYSTEM_NODE_ID, DM_SYSTEM_USER_ID, f.dm)
            .await
            .unwrap(),
        0
    );

    assert_eq!(
        count(
            pool(&f.relay),
            &format!("SELECT COUNT(*) FROM messages WHERE id = '{message}'")
        )
        .await,
        1
    );
    assert_eq!(
        count(
            pool(&f.relay),
            &format!("SELECT COUNT(*) FROM channels WHERE id = '{}'", f.dm)
        )
        .await,
        1
    );
}

/// RG-C001-5: an invite for the reserved node can be neither created nor
/// inserted, and a raw-seeded one does not hand out ownership.
#[tokio::test]
async fn rg_c001_5_reserved_node_invites_grant_nothing() {
    let relay = TestRelay::start().await;
    let (user, token) = relay.register_and_auth("rg5-user").await;
    let (status, body) = call(
        &relay,
        reqwest::Method::POST,
        &format!("/nodes/{D}/invites"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("node_not_found"))
    );
    let insert = format!(
        "INSERT INTO node_invites (id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at) \
         VALUES ('{}', '{D}', '{user}', 'ReservedInvite02', NULL, 0, NULL, 0)",
        Uuid::new_v4()
    );
    assert!(exec(pool(&relay), &insert)
        .await
        .unwrap_err()
        .to_string()
        .contains("reserved_node"));

    relay.state.db.drop_admission_triggers().await.unwrap();
    exec(pool(&relay), &insert).await.unwrap();
    let (status, body) = call(
        &relay,
        reqwest::Method::POST,
        "/invites/ReservedInvite02/join",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(
        (status, body["reason"].clone()),
        (404, json!("invite_invalid"))
    );
    let owner: String = sqlx::query_scalar(&format!("SELECT owner_id FROM nodes WHERE id = '{D}'"))
        .fetch_one(pool(&relay))
        .await
        .unwrap();
    assert_eq!(owner, DM_SYSTEM_USER_ID.to_string());
}

/// RG-C001-6 (the REST and WS part): after a hijacked database is restarted,
/// the attacker's calls against the reserved node give 404.
#[tokio::test]
async fn rg_c001_6_hijacker_reaches_nothing_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relay.db").to_str().unwrap().to_string();
    let files = dir.path().join("files");
    std::fs::create_dir_all(&files).unwrap();
    let options = || AppStateOptions {
        database_encryption: false,
        db: DbOptions::default(),
        file_config: Some(FileConfig {
            storage_dir: files.clone(),
            max_file_size: 1024 * 1024,
        }),
    };
    let state = AppState::new_with_options(&db_path, options())
        .await
        .unwrap();
    let attacker = state
        .register_user(
            "rg6-attacker".into(),
            accord_server::test_support::TEST_PASSWORD.into(),
        )
        .await
        .unwrap();
    state.db.drop_admission_triggers().await.unwrap();
    let p = state.db.raw_pool();
    exec(
        p,
        &format!("UPDATE nodes SET owner_id = '{attacker}' WHERE id = '{D}'"),
    )
    .await
    .unwrap();
    exec(p, &format!("INSERT INTO node_members (node_id, user_id, role, joined_at) VALUES ('{D}', '{attacker}', 'admin', 0)")).await.unwrap();
    state.db.raw_pool().close().await;

    let state = AppState::new_with_options(&db_path, options())
        .await
        .unwrap();
    let relay = TestRelay::with_state(Arc::new(state)).await;
    let response = relay
        .client
        .post(relay.url("/auth"))
        .json(&json!({"public_key": "rg6-attacker", "password": accord_server::test_support::TEST_PASSWORD}))
        .send()
        .await
        .unwrap();
    let token = response.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    for (method, path) in [
        (reqwest::Method::GET, format!("/nodes/{D}")),
        (reqwest::Method::GET, format!("/nodes/{D}/channels")),
        (reqwest::Method::POST, format!("/nodes/{D}/join")),
        (reqwest::Method::GET, format!("/nodes/{D}/invites")),
    ] {
        let (status, body) = call(&relay, method.clone(), &path, Some(&token), None).await;
        assert_eq!(
            (status, body["reason"].clone()),
            (404, json!("node_not_found")),
            "{method} {path}"
        );
    }
    let mut ws = WsClient::connect(&relay, &token).await;
    ws.send(json!({"JoinNode": {"node_id": DM_SYSTEM_NODE_ID}}))
        .await;
    assert_eq!(
        ws.wait_for("join_failed", OBSERVE).await.unwrap()["reason"],
        "node_not_found"
    );
    ws.send(json!({"GetNodeInfo": {"node_id": DM_SYSTEM_NODE_ID}}))
        .await;
    assert_eq!(
        ws.wait_for("error", OBSERVE).await.unwrap()["error"],
        "Node not found"
    );
}
