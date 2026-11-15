//! SPEC-01 hotfix: the DM sentinel and password-less accounts cannot log in,
//! registration requires a password, and invite redemption never hands out
//! ownership (T-1, T-2, T-3, T-4 and T-9 of SPEC-01 section 10.2, and the
//! regressions RG-C001-1 and RG-C001-8 of section 10.3).
//!
//! The relay runs in-process on `127.0.0.1:0` over a file-backed database in a
//! temporary directory, so the tests can plant raw rows through a second
//! SQLite connection, the way a database from before the upgrade looks.

use accord_server::{
    admission::{hash_new_password, LOCK_MARKER},
    db::{DM_SYSTEM_NODE_ID, DM_SYSTEM_USER_ID},
    models::AuthToken,
    node::NodeRole,
    state::{AppState, SharedState},
};
use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use uuid::Uuid;

const PASSWORD: &str = "test-password";

struct Spec01Server {
    base_url: String,
    client: Client,
    state: SharedState,
    /// A second connection to the relay's database, for raw fixtures.
    raw: SqlitePool,
    _dir: tempfile::TempDir,
}

impl Spec01Server {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relay.db");
        let state: SharedState = Arc::new(
            AppState::new(db_path.to_str().unwrap())
                .await
                .expect("relay state"),
        );
        let raw = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&db_path)
                    .busy_timeout(Duration::from_secs(5)),
            )
            .await
            .unwrap();

        // The production route table and middleware (SPEC-01 §10.1).
        let base_url = accord_server::test_support::spawn_relay(state.clone()).await;

        Self {
            base_url,
            client: Client::new(),
            state,
            raw,
            _dir: dir,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let resp = self
            .client
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body = resp.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    /// Register a v1 account with a password and log it in: (user_id, token).
    async fn register_and_auth(&self, public_key: &str) -> (Uuid, String) {
        let (status, body) = self
            .post(
                "/register",
                json!({ "public_key": public_key, "password": PASSWORD }),
            )
            .await;
        assert_eq!(status, 200, "register failed: {body}");
        let user_id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();
        let (status, body) = self
            .post(
                "/auth",
                json!({ "public_key": public_key, "password": PASSWORD }),
            )
            .await;
        assert_eq!(status, 200, "auth failed: {body}");
        (user_id, body["token"].as_str().unwrap().to_string())
    }

    /// Insert an account with a raw stored hash. `username` makes it reachable
    /// on the v2 path as well.
    async fn insert_raw_account(&self, pkh: &str, username: Option<&str>, hash: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, public_key_hash, public_key, password_hash, username, created_at) VALUES (?, ?, ?, ?, ?, 0)",
        )
        .bind(id.to_string())
        .bind(pkh)
        .bind(pkh)
        .bind(hash)
        .bind(username.unwrap_or(""))
        .execute(&self.raw)
        .await
        .unwrap();
        id
    }

    async fn persisted_token_count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM auth_tokens")
            .fetch_one(&self.raw)
            .await
            .unwrap()
    }

    async fn stored_hash(&self, user_id: Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .fetch_optional(&self.raw)
            .await
            .unwrap()
    }
}

/// The exact refusal of a wrong password (SPEC-01 REQ-1).
fn invalid_password() -> Value {
    json!({ "error": "Invalid password", "code": 401 })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Put a live, unexpired token of the sentinel into the relay's token map.
async fn plant_sentinel_token(state: &AppState, token: &str) {
    state.auth_tokens.write().await.insert(
        token.to_string(),
        AuthToken {
            token: token.to_string(),
            user_id: DM_SYSTEM_USER_ID,
            expires_at: now() + 3600,
        },
    );
}

/// T-1 (REQ-1): unusable stored hashes are refused exactly like a wrong
/// password, on v1 and v2, and no token is created.
#[tokio::test]
async fn t1_unusable_hashes_are_refused_like_a_wrong_password() {
    let server = Spec01Server::new().await;

    // A real account: its login creates the token table, and its wrong
    // password gives the reference refusal.
    server.register_and_auth("t1_real").await;
    let (status, body) = server
        .post("/auth", json!({ "public_key": "t1_real", "password": "x" }))
        .await;
    assert_eq!((status, body), (401, invalid_password()));

    for (pkh, hash) in [
        ("t1_empty", ""),
        ("t1_locked", LOCK_MARKER),
        ("t1_system", "SYSTEM"),
    ] {
        server.insert_raw_account(pkh, None, hash).await;
    }
    server
        .insert_raw_account("t1_v2_empty", Some("t1_v2user"), "")
        .await;

    let tokens_before = server.persisted_token_count().await;
    let in_memory_before = server.state.auth_tokens.read().await.len();

    for pkh in ["t1_empty", "t1_locked", "t1_system"] {
        for password in ["", "x"] {
            let (status, body) = server
                .post(
                    "/auth",
                    json!({ "public_key_hash": pkh, "password": password }),
                )
                .await;
            assert_eq!(status, 401, "{pkh} / {password:?}");
            assert_eq!(body, invalid_password(), "{pkh} / {password:?}");
        }
    }
    let (status, body) = server
        .post("/auth", json!({ "username": "t1_v2user", "password": "x" }))
        .await;
    assert_eq!((status, body), (401, invalid_password()));

    assert_eq!(server.persisted_token_count().await, tokens_before);
    assert_eq!(
        server.state.auth_tokens.read().await.len(),
        in_memory_before
    );
}

/// T-2 (REQ-2(a)): the sentinel is refused even with its real password.
#[tokio::test]
async fn t2_sentinel_is_refused_whatever_its_hash() {
    let server = Spec01Server::new().await;
    server.register_and_auth("t2_real").await;

    let hash = hash_new_password("pw").unwrap();
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&hash)
        .bind(DM_SYSTEM_USER_ID.to_string())
        .execute(&server.raw)
        .await
        .unwrap();

    let tokens_before = server.persisted_token_count().await;
    let in_memory_before = server.state.auth_tokens.read().await.len();

    for request in [
        json!({ "public_key_hash": "SYSTEM", "password": "pw" }),
        json!({ "public_key_hash": "SYSTEM", "password": "" }),
    ] {
        let (status, body) = server.post("/auth", request.clone()).await;
        assert_eq!(status, 401, "{request}");
        assert_eq!(body, invalid_password(), "{request}");
    }

    assert_eq!(server.persisted_token_count().await, tokens_before);
    assert_eq!(
        server.state.auth_tokens.read().await.len(),
        in_memory_before
    );
    let sentinel_tokens: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM auth_tokens WHERE user_id = ?")
            .bind(DM_SYSTEM_USER_ID.to_string())
            .fetch_one(&server.raw)
            .await
            .unwrap();
    assert_eq!(sentinel_tokens, 0);
}

/// T-3 (REQ-3): a sentinel token is refused by REST and by WebSocket auth.
#[tokio::test]
async fn t3_sentinel_token_is_refused_everywhere() {
    let server = Spec01Server::new().await;
    let token = "tok_sentinel_t3";

    plant_sentinel_token(&server.state, token).await;
    assert_eq!(server.state.validate_token(token).await, None);
    assert!(!server.state.auth_tokens.read().await.contains_key(token));

    plant_sentinel_token(&server.state, token).await;
    let resp = server
        .client
        .get(server.url("/nodes"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);

    plant_sentinel_token(&server.state, token).await;
    let ws_url = format!("{}/ws", server.base_url.replace("http://", "ws://"));
    let (ws, _) = connect_async(&ws_url).await.unwrap();
    let (mut sink, mut stream) = ws.split();
    sink.send(WsMessage::Text(
        json!({ "Authenticate": { "token": token } }).to_string(),
    ))
    .await
    .unwrap();
    let frame = loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
            Ok(Some(Ok(WsMessage::Text(text)))) => {
                break serde_json::from_str::<Value>(&text).unwrap()
            }
            Ok(Some(Ok(_))) => continue,
            other => panic!("no auth reply: {other:?}"),
        }
    };
    assert_eq!(frame["type"], "error");
    assert_eq!(frame["code"], "auth_failed");

    // A regular account's token still works.
    let (_, user_token) = server.register_and_auth("t3_real").await;
    let resp = server
        .client
        .get(server.url("/nodes"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

/// T-4 (REQ-4(a)): a v1 registration with an empty password is refused with
/// 400 `invalid_request` and creates no account.
#[tokio::test]
async fn t4_register_with_empty_password_is_refused() {
    let server = Spec01Server::new().await;
    let users_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&server.raw)
        .await
        .unwrap();

    for body in [
        json!({ "public_key": "pk", "password": "" }),
        json!({ "public_key": "pk" }),
    ] {
        let (status, resp) = server.post("/register", body).await;
        assert_eq!(status, 400);
        assert_eq!(resp["reason"], "invalid_request");
        assert_eq!(resp["code"], 400);
        assert!(resp["error"].is_string());
    }

    let users_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&server.raw)
        .await
        .unwrap();
    assert_eq!(users_after, users_before);

    // The sentinel is seeded locked.
    assert_eq!(
        server.stored_hash(DM_SYSTEM_USER_ID).await.as_deref(),
        Some(LOCK_MARKER)
    );

    // With a password the same key registers.
    let (status, _) = server
        .post(
            "/register",
            json!({ "public_key": "pk", "password": PASSWORD }),
        )
        .await;
    assert_eq!(status, 200);
}

/// T-9 (REQ-9): redeeming an invite of a node owned by the sentinel gives a
/// plain membership and never ownership.
#[tokio::test]
async fn t9_invite_redemption_never_transfers_ownership() {
    let server = Spec01Server::new().await;

    // N: a legacy node owned by the sentinel, inserted raw.
    let node_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO nodes (id, name, owner_id, description, created_at) VALUES (?, 'Management', ?, NULL, 0)",
    )
    .bind(node_id.to_string())
    .bind(DM_SYSTEM_USER_ID.to_string())
    .execute(&server.raw)
    .await
    .unwrap();
    assert_ne!(node_id, DM_SYSTEM_NODE_ID);

    // M is a member holding the Admin role.
    let (m, m_token) = server.register_and_auth("t9_m").await;
    server
        .state
        .db
        .seed_management_roles(node_id)
        .await
        .unwrap();
    server
        .state
        .db
        .seed_node_member(node_id, m, NodeRole::Admin)
        .await
        .unwrap();

    let resp = server
        .client
        .post(server.url(&format!("/nodes/{node_id}/invites")))
        .bearer_auth(&m_token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let invite: Value = resp.json().await.unwrap();
    let code = invite["invite_code"].as_str().unwrap().to_string();

    let (u, u_token) = server.register_and_auth("t9_u").await;
    let resp = server
        .client
        .post(server.url(&format!("/invites/{code}/join")))
        .bearer_auth(&u_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let member = server
        .state
        .db
        .get_node_member(node_id, u)
        .await
        .unwrap()
        .expect("U is a member");
    assert_eq!(member.role, NodeRole::Member);
    assert!(server
        .state
        .db
        .get_member_roles(node_id, u)
        .await
        .unwrap()
        .is_empty());
    let owner: String = sqlx::query_scalar("SELECT owner_id FROM nodes WHERE id = ?")
        .bind(node_id.to_string())
        .fetch_one(&server.raw)
        .await
        .unwrap();
    assert_eq!(owner, DM_SYSTEM_USER_ID.to_string());
}

/// The reply to `Authenticate` with `token` on a fresh socket.
async fn ws_auth_reply(server: &Spec01Server, token: &str) -> Value {
    let ws_url = format!("{}/ws", server.base_url.replace("http://", "ws://"));
    let (ws, _) = connect_async(&ws_url).await.unwrap();
    let (mut sink, mut stream) = ws.split();
    sink.send(WsMessage::Text(
        json!({ "Authenticate": { "token": token } }).to_string(),
    ))
    .await
    .unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
            Ok(Some(Ok(WsMessage::Text(text)))) => {
                return serde_json::from_str::<Value>(&text).unwrap()
            }
            Ok(Some(Ok(_))) => continue,
            other => panic!("no auth reply: {other:?}"),
        }
    }
}

/// RG-C001-1 (C001): `POST /auth {"public_key_hash":"SYSTEM","password":""}`
/// returned a 24 h sentinel token. Now: 401 "Invalid password", no token.
#[tokio::test]
async fn rg_c001_1_sentinel_login_with_empty_password_gets_no_token() {
    let server = Spec01Server::new().await;
    server.register_and_auth("rg1_real").await;
    let tokens_before = server.persisted_token_count().await;
    let in_memory_before = server.state.auth_tokens.read().await.len();

    let (status, body) = server
        .post(
            "/auth",
            json!({ "public_key_hash": "SYSTEM", "password": "" }),
        )
        .await;
    assert_eq!((status, body), (401, invalid_password()));

    assert_eq!(server.persisted_token_count().await, tokens_before);
    assert_eq!(
        server.state.auth_tokens.read().await.len(),
        in_memory_before
    );
    assert!(!server
        .state
        .auth_tokens
        .read()
        .await
        .values()
        .any(|t| t.user_id == DM_SYSTEM_USER_ID));
}

/// RG-C001-8 (C001, N001): with a sentinel token, an attacker created a node
/// and sent `TypingStart`, and the relay panicked on the `[..8]` slice of the
/// 6-byte `SYSTEM` hash. Now no sentinel token can be obtained (RG-C001-1),
/// and an injected one is refused by `validate_token` (T-3), by REST node
/// creation and by WS auth, so no code path acts as the sentinel.
#[tokio::test]
async fn rg_c001_8_no_code_path_acts_as_the_sentinel() {
    let server = Spec01Server::new().await;
    let (status, _) = server
        .post(
            "/auth",
            json!({ "public_key_hash": "SYSTEM", "password": "" }),
        )
        .await;
    assert_eq!(status, 401);

    let token = "tok_sentinel_rg_c001_8";
    plant_sentinel_token(&server.state, token).await;
    assert_eq!(server.state.validate_token(token).await, None);

    plant_sentinel_token(&server.state, token).await;
    let resp = server
        .client
        .post(server.url("/nodes"))
        .bearer_auth(token)
        .json(&json!({ "name": "rg8" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let owned: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE owner_id = ? AND id != ?")
            .bind(DM_SYSTEM_USER_ID.to_string())
            .bind(DM_SYSTEM_NODE_ID.to_string())
            .fetch_one(&server.raw)
            .await
            .unwrap();
    assert_eq!(owned, 0);

    plant_sentinel_token(&server.state, token).await;
    let reply = ws_auth_reply(&server, token).await;
    assert_eq!(reply["type"], "error", "{reply}");
    assert_eq!(reply["code"], "auth_failed", "{reply}");

    // The relay is still serving.
    let (_, user_token) = server.register_and_auth("rg8_real").await;
    let resp = server
        .client
        .get(server.url("/nodes"))
        .bearer_auth(&user_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}
