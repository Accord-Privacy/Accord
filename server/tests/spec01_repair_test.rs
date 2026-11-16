//! SPEC-01 schema, boot repair, triggers and ledger (section 6.5 and 6.6):
//! T-5, T-10, T-11, T-11b, T-11c, T-12, T-13, T-14, T-15, T-40, T-46, T-47 and
//! T-48 of section 10.2, with the regressions RG-C001-6, RG-C055-1,
//! RG-C055-2, RG-C048-1 and RG-N008-2 of section 10.3. T-42 (REQ-42, the
//! capability registry and `admission_since`) lives here too, because
//! `admission_since` is T0 of the REQ-46 ledger step.
//!
//! Restart tests use a file-backed database in a temporary directory. A
//! database from before the upgrade is simulated as section 10.1 describes:
//! the fixture drops the triggers, writes the hijacked rows with raw SQL,
//! closes the database and reopens it. Deleting the `relay_migrations` rows
//! simulates a database whose one-time migrations have not run yet, which is
//! what restoring a pre-upgrade backup looks like (section 7.4).

use accord_server::attachments::AttachmentConfig;
use accord_server::{
    admission::LOCK_MARKER,
    db::{
        repair::{
            LEDGER_AUDIT_INVITE_CODES, LEDGER_EVERYONE_CREATE_INVITE, LEDGER_LEGACY_INVITE_EXPIRY,
            LEDGER_LEGACY_ROLES, LOG_TARGET, TRIGGER_NAMES,
        },
        DbOptions, DM_SYSTEM_NODE_ID, DM_SYSTEM_USER_ID,
    },
    faults::{FaultKind, FaultPlan},
    files::FileConfig,
    models::permission_bits::{
        ADMINISTRATOR, CREATE_INVITE, DEFAULT_EVERYONE, MANAGE_NODE, MENTION_EVERYONE,
    },
    node::NodeRole,
    state::{AppState, AppStateOptions},
    test_support::{admit_with_owner_invite, LogCapture, TestRelay, WsClient, TEST_PASSWORD},
};
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const D: &str = "00000000-0000-0000-0000-000000000001";
const S: &str = "00000000-0000-0000-0000-000000000000";
const GRACE: i64 = 604_800;

// ─────────────────────────────────────────────────────────────────────────
//  Harness
// ─────────────────────────────────────────────────────────────────────────

/// A relay database and blob store in a temporary directory, opened and
/// closed like a relay process restarting.
struct Store {
    _dir: tempfile::TempDir,
    db_path: String,
    files_dir: PathBuf,
}

impl Store {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relay.db").to_str().unwrap().to_string();
        let files_dir = dir.path().join("files");
        std::fs::create_dir_all(&files_dir).unwrap();
        Self {
            _dir: dir,
            db_path,
            files_dir,
        }
    }

    fn options(&self, db: DbOptions) -> AppStateOptions {
        AppStateOptions {
            database_encryption: false,
            db,
            file_config: Some(FileConfig {
                storage_dir: self.files_dir.clone(),
                max_file_size: 1024 * 1024,
            }),
            attachments: Some(AttachmentConfig::with_dir(
                self.files_dir.with_file_name("attachments"),
            )),
        }
    }

    async fn try_boot(&self, db: DbOptions) -> anyhow::Result<AppState> {
        AppState::new_with_options(&self.db_path, self.options(db)).await
    }

    async fn boot_with(&self, db: DbOptions) -> AppState {
        self.try_boot(db).await.expect("relay boots")
    }

    async fn boot(&self) -> AppState {
        self.boot_with(DbOptions::default()).await
    }

    /// A separate connection for inspecting the database without booting.
    async fn raw(&self) -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&self.db_path)
                    .busy_timeout(Duration::from_secs(5)),
            )
            .await
            .unwrap()
    }

    /// Write a blob into the store and return its storage path.
    fn blob(&self, name: &str) -> String {
        let path = self.files_dir.join(name);
        std::fs::write(&path, b"ciphertext").unwrap();
        path.to_str().unwrap().to_string()
    }
}

/// Close the relay's database, as a process exit would.
async fn close(state: AppState) {
    state.db.raw_pool().close().await;
}

fn pool(state: &AppState) -> &SqlitePool {
    state.db.raw_pool()
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

async fn text(pool: &SqlitePool, sql: &str) -> Option<String> {
    sqlx::query_scalar(sql)
        .fetch_optional(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// Forget the one-time migrations, as in a database from before the upgrade.
async fn forget_ledger(state: &AppState) {
    exec(pool(state), "DELETE FROM relay_migrations").await;
}

/// A user with a non-empty stored hash (not a locked account), without
/// paying for Argon2.
async fn user(state: &AppState, pk: &str) -> Uuid {
    state.db.create_user(pk, "fixture-hash").await.unwrap().id
}

/// A user who can log in with [`TEST_PASSWORD`].
async fn account(state: &AppState, pk: &str) -> Uuid {
    state
        .register_user(pk.to_string(), TEST_PASSWORD.to_string())
        .await
        .unwrap()
}

async fn login(relay: &TestRelay, pk: &str) -> String {
    let response = relay
        .client
        .post(relay.url("/auth"))
        .json(&json!({ "public_key": pk, "password": TEST_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

/// Every table's rows and the schema, as comparable text.
async fn dump(pool: &SqlitePool) -> Vec<String> {
    let mut out: Vec<String> = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|(kind, name, sql)| format!("{kind} {name} {sql:?}"))
    .collect();
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    for table in tables {
        let columns: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info(?)")
            .bind(&table)
            .fetch_all(pool)
            .await
            .unwrap();
        let row = columns
            .iter()
            .map(|c| format!("quote(\"{c}\")"))
            .collect::<Vec<_>>()
            .join(" || '|' || ");
        let rows: Vec<String> =
            sqlx::query_scalar(&format!("SELECT {row} FROM \"{table}\" ORDER BY 1"))
                .fetch_all(pool)
                .await
                .unwrap();
        out.push(format!("{table}: {rows:?}"));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
//  Hijack fixture (T-11, T-12, T-15)
// ─────────────────────────────────────────────────────────────────────────

/// The state an attacker who exploited C001 before the upgrade leaves behind.
struct Hijack {
    attacker: Uuid,
    u: Uuid,
    v: Uuid,
    w: Uuid,
    /// Ordinary node owned by U.
    n: Uuid,
    /// Legitimate DM between U and V, with two messages.
    dm_uv: Uuid,
    /// DM between the sentinel and V.
    dm_sv: Uuid,
    /// Non-DM channel the attacker created in the DM system node.
    d_channel: Uuid,
    /// Message in the U–V DM that the attacker reacted to.
    dm_message: Uuid,
    blob_d_channel: String,
    blob_dm_sv: String,
    blob_non_participant: String,
    blob_participant: String,
    secrets: Vec<String>,
}

async fn plant_hijack(store: &Store, state: &AppState) -> Hijack {
    let db = &state.db;
    let p = pool(state);
    let attacker = user(state, "pk-attacker").await;
    let u = user(state, "pk-u").await;
    let v = user(state, "pk-v").await;
    let w = user(state, "pk-w").await;
    let n = db.create_node("Ordinary", u, None).await.unwrap().id;
    let n_general = db.get_node_channels(n).await.unwrap()[0].id;
    let dm_uv = db.create_or_get_dm_channel(u, v).await.unwrap().id;
    let mut dm_message = Uuid::nil();
    for payload in [b"one".as_slice(), b"two".as_slice()] {
        dm_message = db
            .store_message(dm_uv, u, payload, None, None)
            .await
            .unwrap()
            .0;
    }
    let v_pkh = db.get_user_public_key_hash(v).await.unwrap().unwrap();

    db.drop_admission_triggers().await.unwrap();

    // D owned by the attacker, renamed, switched to requests, with metadata.
    exec(
        p,
        &format!(
            "UPDATE nodes SET owner_id = '{attacker}', name = 'hijacked-dm-node', join_policy = 'request', \
             description = 'pwned', icon_hash = 'icon', encrypted_name = x'01' WHERE id = '{D}'"
        ),
    )
    .await;
    // Memberships: the attacker and the sentinel in D, the sentinel in N.
    exec(p, &format!("INSERT INTO node_members (node_id, user_id, role, joined_at) VALUES ('{D}', '{attacker}', 'admin', 0), ('{D}', '{S}', 'member', 0), ('{n}', '{S}', 'member', 0)")).await;
    // The attacker subscribed to every DM.
    exec(p, &format!("INSERT INTO channel_members (channel_id, user_id, joined_at) VALUES ('{dm_uv}', '{attacker}', 0)")).await;
    // A D invite, and an invite the sentinel created in N.
    exec(p, &format!("INSERT INTO node_invites (id, node_id, created_by, invite_code, current_uses, created_at) VALUES ('{}', '{D}', '{attacker}', 'HIJACKCODE1', 0, 0), ('{}', '{n}', '{S}', 'SENTINELCODE', 0, 0)", Uuid::new_v4(), Uuid::new_v4())).await;
    // Roles in D and role assignments of the sentinel.
    let d_role = Uuid::new_v4();
    exec(p, &format!("INSERT INTO roles (id, node_id, name, permissions, position, created_at) VALUES ('{d_role}', '{D}', 'Hijack', {ADMINISTRATOR}, 1, 0)")).await;
    let n_admin = db.get_role_by_name(n, "Admin").await.unwrap().unwrap().id;
    exec(p, &format!("INSERT INTO member_roles (member_id, role_id, node_id, assigned_at) VALUES ('{attacker}', '{d_role}', '{D}', 0), ('{S}', '{n_admin}', '{n}', 0)")).await;
    // A legacy "Management" node owned by the sentinel, with its membership
    // and invite (section 7.1): it loses both and stays without an owner.
    let management = Uuid::new_v4();
    exec(p, &format!("INSERT INTO nodes (id, name, owner_id, created_at) VALUES ('{management}', 'Management', '{S}', 0)")).await;
    exec(p, &format!("INSERT INTO node_members (node_id, user_id, role, joined_at) VALUES ('{management}', '{S}', 'admin', 0)")).await;
    exec(p, &format!("INSERT INTO node_invites (id, node_id, created_by, invite_code, max_uses, current_uses, created_at) VALUES ('{}', '{management}', '{S}', 'MGMTCODE', 1, 0, 0)", Uuid::new_v4())).await;
    // A join request for D.
    exec(p, &format!("INSERT INTO node_join_requests (node_id, user_id, created_at, expires_at) VALUES ('{D}', '{w}', 0, 9999999999)")).await;
    // A non-DM channel in D with an upload.
    let d_channel = Uuid::new_v4();
    exec(p, &format!("INSERT INTO channels (id, name, node_id, created_by, created_at) VALUES ('{d_channel}', 'loot', '{D}', '{attacker}', 0)")).await;
    let blob_d_channel = store.blob("d-channel-blob");
    exec(p, &format!("INSERT INTO files (id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at) VALUES ('{}', '{d_channel}', '{attacker}', x'00', 10, 'h', '{blob_d_channel}', 0)", Uuid::new_v4())).await;
    // Sender-key distributions in a DM channel, and from the sentinel in N.
    exec(p, &format!("INSERT INTO sender_key_distributions (id, channel_id, from_user_id, to_user_id, encrypted_payload, created_at) VALUES ('{}', '{dm_uv}', '{u}', '{v}', x'00', 0), ('{}', '{dm_uv}', '{attacker}', '{u}', x'00', 0), ('{}', '{n_general}', '{S}', '{u}', x'00', 0)", Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())).await;
    // A DM between the sentinel and V, with a message and an upload.
    let dm_sv = Uuid::new_v4();
    exec(p, &format!("INSERT INTO dm_channels (id, user1_id, user2_id, created_at) VALUES ('{dm_sv}', '{S}', '{v}', 0)")).await;
    exec(p, &format!("INSERT INTO channels (id, name, node_id, created_by, created_at) VALUES ('{dm_sv}', 'DM-{dm_sv}', '{D}', '{S}', 0)")).await;
    exec(p, &format!("INSERT INTO channel_members (channel_id, user_id, joined_at) VALUES ('{dm_sv}', '{S}', 0), ('{dm_sv}', '{v}', 0)")).await;
    db.store_message(dm_sv, DM_SYSTEM_USER_ID, b"spoof", None, None)
        .await
        .unwrap();
    let blob_dm_sv = store.blob("dm-sv-blob");
    exec(p, &format!("INSERT INTO files (id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at) VALUES ('{}', '{dm_sv}', '{S}', x'00', 10, 'h', '{blob_dm_sv}', 0)", Uuid::new_v4())).await;
    // Keys published under the sentinel.
    exec(p, &format!("INSERT INTO key_bundles (user_id, identity_key, signed_prekey, updated_at) VALUES ('{S}', x'00', x'00', 0)")).await;
    exec(
        p,
        &format!("INSERT INTO one_time_prekeys (user_id, prekey) VALUES ('{S}', x'00')"),
    )
    .await;
    exec(p, &format!("INSERT INTO prekey_messages (id, recipient_id, sender_id, message_data, created_at) VALUES ('{}', '{S}', '{v}', x'00', 0)", Uuid::new_v4())).await;
    // Friendships and friend requests with the sentinel, and one tied to D.
    exec(p, &format!("INSERT INTO friendships (user_a_hash, user_b_hash, established_at) VALUES ('SYSTEM', '{v_pkh}', 0)")).await;
    exec(p, &format!("INSERT INTO friend_requests (id, from_user_id, to_user_id, node_id, created_at) VALUES ('{}', '{S}', '{v}', '{n}', 0), ('{}', '{v}', '{u}', '{D}', 0)", Uuid::new_v4(), Uuid::new_v4())).await;
    // A bot, its command, an invocation and a webhook in D, and an invocation
    // in N that targets a DM.
    exec(p, &format!("INSERT INTO installed_bots (bot_id, node_id, name, webhook_url, bot_token_hash, installed_at) VALUES ('evilbot', '{D}', 'Evil', 'https://example.invalid', 'h', 0)")).await;
    exec(p, &format!("INSERT INTO bot_commands (bot_id, node_id, command_name) VALUES ('evilbot', '{D}', 'spam')")).await;
    exec(p, &format!("INSERT INTO bot_invocations (invocation_id, bot_id, node_id, channel_id, invoker_user_id, command_name, created_at) VALUES ('inv-d', 'evilbot', '{D}', '{dm_uv}', '{attacker}', 'spam', 0), ('inv-n', 'goodbot', '{n}', '{dm_uv}', '{u}', 'spam', 0), ('inv-ok', 'goodbot', '{n}', '{n_general}', '{u}', 'spam', 0)")).await;
    exec(p, &format!("INSERT INTO webhooks (id, node_id, url, secret, events, created_by, created_at) VALUES ('{}', '{D}', 'https://example.invalid', 's', '[]', '{attacker}', 0)", Uuid::new_v4())).await;
    // Tables of SPEC-05 and SPEC-06, as those specs create them (B22).
    exec(p, "CREATE TABLE identity_registrations (user_id TEXT PRIMARY KEY NOT NULL, identity_signing_key BLOB NOT NULL, identity_key BLOB NOT NULL, identity_key_signature BLOB NOT NULL, generation INTEGER NOT NULL, registered_at INTEGER NOT NULL, last_published_at INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)").await;
    exec(p, "CREATE TABLE identity_resets (user_id TEXT NOT NULL, reset_at INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)").await;
    exec(p, "CREATE TABLE node_key_distributions (id TEXT PRIMARY KEY NOT NULL, node_id TEXT NOT NULL, from_user_id TEXT NOT NULL, to_user_id TEXT NOT NULL, encrypted_payload BLOB NOT NULL, created_at INTEGER NOT NULL, claimed INTEGER NOT NULL DEFAULT 0)").await;
    exec(p, "CREATE TABLE governance_log (node_id TEXT NOT NULL, seq INTEGER NOT NULL, kind INTEGER NOT NULL, entry_hash BLOB NOT NULL, entry BLOB NOT NULL, receipt BLOB NOT NULL, PRIMARY KEY (node_id, seq))").await;
    exec(p, &format!("INSERT INTO identity_registrations VALUES ('{S}', x'00', x'00', x'00', 1, 0, 0), ('{u}', x'01', x'01', x'01', 1, 0, 0)")).await;
    exec(p, &format!("INSERT INTO identity_resets VALUES ('{S}', 0)")).await;
    exec(p, &format!("INSERT INTO node_key_distributions (id, node_id, from_user_id, to_user_id, encrypted_payload, created_at) VALUES ('nk1', '{D}', '{u}', '{v}', x'00', 0), ('nk2', '{n}', '{S}', '{u}', x'00', 0), ('nk3', '{n}', '{u}', '{v}', x'00', 0)")).await;
    exec(p, &format!("INSERT INTO governance_log VALUES ('{D}', 1, 1, x'00', x'00', x'00'), ('{n}', 1, 1, x'00', x'00', x'00')")).await;

    // ── T-12 hygiene rows ──
    // D bans, allowlist, profile, emoji, category and audit row.
    exec(p, &format!("INSERT INTO node_bans (node_id, public_key_hash, banned_by, banned_at) VALUES ('{D}', '{v_pkh}', '{attacker}', 0)")).await;
    exec(p, &format!("INSERT INTO node_build_hash_allowlist (node_id, build_hash, added_by, added_at) VALUES ('{D}', 'h', '{attacker}', 0)")).await;
    exec(p, &format!("INSERT INTO node_user_profiles (node_id, user_id, joined_at) VALUES ('{D}', '{attacker}', 0), ('{n}', '{S}', 0)")).await;
    exec(p, &format!("INSERT INTO custom_emojis (id, node_id, name, uploaded_by, content_hash, created_at) VALUES ('{}', '{D}', 'pwn', '{attacker}', 'h', '0')", Uuid::new_v4())).await;
    let category = Uuid::new_v4();
    exec(p, &format!("INSERT INTO channel_categories (id, node_id, name, created_at) VALUES ('{category}', '{D}', 'stash', 0)")).await;
    exec(p, &format!("INSERT INTO audit_log (id, node_id, actor_id, action, target_type, created_at) VALUES ('{}', '{D}', '{attacker}', 'node_update', 'node', 0)", Uuid::new_v4())).await;
    // Overwrites on a DM channel and altered DM channel attributes.
    exec(p, &format!("INSERT INTO channel_permission_overwrites (channel_id, role_id, allow_bits, deny_bits) VALUES ('{dm_uv}', '{n}', 1, 0)")).await;
    exec(p, &format!("UPDATE channels SET name = 'renamed', topic = 'topic', slow_mode_seconds = 5, encrypted_name = x'01', category_id = '{category}' WHERE id = '{dm_uv}'")).await;
    // The sentinel's devices, tokens, registrations and blocks.
    exec(p, &format!("INSERT INTO device_keys (id, user_id, device_fingerprint_hash, public_key, created_at, last_seen_at) VALUES ('dk1', '{S}', 'fp', 'pk', 0, 0)")).await;
    exec(p, &format!("INSERT INTO device_tokens (id, user_id, platform, token, created_at) VALUES ('dt1', '{S}', 'ios', 't', 0)")).await;
    exec(p, &format!("INSERT INTO device_registrations (device_fingerprint_hash, user_id, created_at) VALUES ('fp', '{S}', 0)")).await;
    exec(p, &format!("INSERT INTO user_blocks (blocker_id, blocked_id, created_at) VALUES ('{S}', '{v}', 0), ('{v}', '{S}', 0)")).await;
    // Reactions and read receipts in a DM, by a non-participant and a participant.
    exec(p, &format!("INSERT INTO message_reactions (message_id, user_id, emoji, created_at) VALUES ('{dm_message}', '{attacker}', 'x', 0), ('{dm_message}', '{u}', 'y', 0)")).await;
    exec(p, &format!("INSERT INTO read_receipts (user_id, channel_id, last_read_message_id, updated_at) VALUES ('{attacker}', '{dm_uv}', '{dm_message}', 0), ('{u}', '{dm_uv}', '{dm_message}', 0)")).await;
    // Uploads in a DM by a non-participant and by a participant.
    let blob_non_participant = store.blob("non-participant-blob");
    let blob_participant = store.blob("participant-blob");
    exec(p, &format!("INSERT INTO files (id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at) VALUES ('{}', '{dm_uv}', '{attacker}', x'00', 10, 'h', '{blob_non_participant}', 0), ('{}', '{dm_uv}', '{u}', x'00', 10, 'h', '{blob_participant}', 0)", Uuid::new_v4(), Uuid::new_v4())).await;

    Hijack {
        attacker,
        u,
        v,
        w,
        n,
        dm_uv,
        dm_sv,
        d_channel,
        dm_message,
        blob_d_channel,
        blob_dm_sv,
        blob_non_participant,
        blob_participant,
        secrets: vec![
            "HIJACKCODE1".into(),
            "SENTINELCODE".into(),
            "hijacked-dm-node".into(),
            "Ordinary".into(),
            "Management".into(),
            "MGMTCODE".into(),
            "loot".into(),
            v_pkh,
        ],
    }
}

/// Boot, plant the hijack, close: the database as an attacker left it.
async fn hijacked_store() -> (Store, Hijack) {
    let store = Store::new();
    let state = store.boot().await;
    let hijack = plant_hijack(&store, &state).await;
    close(state).await;
    (store, hijack)
}

// ─────────────────────────────────────────────────────────────────────────
//  T-11, T-15, RG-C001-6: the MUST steps
// ─────────────────────────────────────────────────────────────────────────

/// T-11 (REQ-11, REQ-13, REQ-15) and RG-C001-6: a hijack persisted across a
/// restart is reverted at boot, legitimate DMs survive, blobs are removed
/// and the log carries counts only.
#[tokio::test]
async fn t11_boot_repair_reverts_a_hijacked_dm_node() {
    let (store, h) = hijacked_store().await;

    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::WARN);
    let state = store.boot().await;
    drop(guard);
    let p = pool(&state);
    let report = state.db.repair_report().clone();

    // B1, B4: the reserved node is the sentinel's, under its name and policy.
    let node: (String, String, String) = sqlx::query_as(&format!(
        "SELECT owner_id, name, join_policy FROM nodes WHERE id = '{D}'"
    ))
    .fetch_one(p)
    .await
    .unwrap();
    assert_eq!(
        node,
        (S.to_string(), "__dm_system__".into(), "invite".into())
    );
    // B5 to B8.
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM node_members WHERE node_id = '{D}' OR user_id = '{S}'")
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM roles WHERE node_id = '{D}'")
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM member_roles WHERE node_id = '{D}' OR member_id = '{S}'"
            )
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM node_invites WHERE node_id = '{D}' OR created_by = '{S}'"
            )
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM node_join_requests WHERE node_id = '{D}'")
        )
        .await,
        0
    );
    // B9: the sentinel's DM is gone with its channel, messages and files.
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM dm_channels WHERE id = '{}'", h.dm_sv)
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM channels WHERE id = '{}'", h.dm_sv)
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM messages WHERE channel_id = '{}'",
                h.dm_sv
            )
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM files WHERE channel_id = '{}'",
                h.dm_sv
            )
        )
        .await,
        0
    );
    // B10: no non-DM channel remains in D.
    assert_eq!(count(p, &format!("SELECT COUNT(*) FROM channels WHERE node_id = '{D}' AND id NOT IN (SELECT id FROM dm_channels)")).await, 0);
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM files WHERE channel_id = '{}'",
                h.d_channel
            )
        )
        .await,
        0
    );
    // B11: DM subscriptions are the participants only.
    let mut members: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT user_id FROM channel_members WHERE channel_id = '{}'",
        h.dm_uv
    ))
    .fetch_all(p)
    .await
    .unwrap();
    members.sort();
    let mut expected = vec![h.u.to_string(), h.v.to_string()];
    expected.sort();
    assert_eq!(members, expected);
    // B12: no distributions in D's channels or involving the sentinel.
    assert_eq!(count(p, &format!("SELECT COUNT(*) FROM sender_key_distributions WHERE channel_id IN (SELECT id FROM channels WHERE node_id = '{D}') OR from_user_id = '{S}' OR to_user_id = '{S}'")).await, 0);
    // B16: bots, commands, invocations and webhooks of D, and invocations
    // that target a DM; an ordinary invocation stays.
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM installed_bots WHERE node_id = '{D}'")
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM bot_commands WHERE node_id = '{D}'")
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM webhooks WHERE node_id = '{D}'")
        )
        .await,
        0
    );
    let invocations: Vec<String> = sqlx::query_scalar("SELECT invocation_id FROM bot_invocations")
        .fetch_all(p)
        .await
        .unwrap();
    assert_eq!(invocations, vec!["inv-ok".to_string()]);
    // B22: the SPEC-05 and SPEC-06 tables exist here, so they are cleaned.
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM identity_registrations WHERE user_id = '{S}'")
        )
        .await,
        0
    );
    assert_eq!(
        count(p, "SELECT COUNT(*) FROM identity_registrations").await,
        1
    );
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM identity_resets WHERE user_id = '{S}'")
        )
        .await,
        0
    );
    let nk: Vec<String> = sqlx::query_scalar("SELECT id FROM node_key_distributions")
        .fetch_all(p)
        .await
        .unwrap();
    assert_eq!(nk, vec!["nk3".to_string()]);
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM governance_log WHERE node_id = '{D}'")
        )
        .await,
        0
    );
    assert_eq!(count(p, "SELECT COUNT(*) FROM governance_log").await, 1);

    // The legitimate DM and its messages are intact; the attacker has no rows
    // left in D (RG-C001-6).
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM dm_channels WHERE id = '{}'", h.dm_uv)
        )
        .await,
        1
    );
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM messages WHERE channel_id = '{}'",
                h.dm_uv
            )
        )
        .await,
        2
    );
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM node_members WHERE user_id = '{}'",
                h.attacker
            )
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM channel_members WHERE user_id = '{}'",
                h.attacker
            )
        )
        .await,
        0
    );
    assert!(state.db.get_user_by_id(h.w).await.unwrap().is_some());
    assert!(state.db.is_node_member(h.n, h.u).await.unwrap());

    // Both blobs of deleted files rows are gone after start; an unrelated
    // participant upload is kept.
    assert!(!Path::new(&h.blob_d_channel).exists());
    assert!(!Path::new(&h.blob_dm_sv).exists());
    assert!(Path::new(&h.blob_participant).exists());

    // Every MUST step that had work to do changed rows.
    for step in [
        "B4", "B5", "B6", "B7", "B8", "B9", "B10", "B11", "B12", "B13", "B14", "B16", "B22",
    ] {
        assert!(
            report.step(step).unwrap_or(0) > 0,
            "{step}: {:?}",
            report.steps
        );
    }
    assert!(report.skipped.is_empty());

    // One WARN line per step that changed rows, with counts only.
    let lines = capture.lines_with_target(LOG_TARGET);
    for (step, changed) in &report.steps {
        let needle = format!("admission repair: step {step} changed {changed} rows");
        let matching = lines.iter().filter(|l| l.ends_with(&needle)).count();
        assert_eq!(matching, usize::from(*changed > 0), "{needle} in {lines:?}");
        assert!(lines
            .iter()
            .all(|l| l.contains(" WARN ") || l.contains(" ERROR ")));
    }
    // The orphaned legacy node is counted, not named (section 6.6).
    assert!(lines.iter().any(|l| l.contains("WARN")
        && l.contains("1 legacy nodes are still owned by the DM system user")));
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM nodes WHERE owner_id = '{S}' AND id != '{D}'")
        )
        .await,
        1
    );

    let mut forbidden: Vec<String> = h.secrets.clone();
    forbidden.extend(
        [
            h.attacker,
            h.u,
            h.v,
            h.w,
            h.n,
            h.dm_uv,
            h.dm_sv,
            h.d_channel,
            DM_SYSTEM_NODE_ID,
            DM_SYSTEM_USER_ID,
        ]
        .iter()
        .map(Uuid::to_string),
    );
    for line in capture.lines() {
        for secret in &forbidden {
            assert!(
                !line.contains(secret.as_str()),
                "log leaks {secret}: {line}"
            );
        }
    }
}

/// T-15 (REQ-15): after the repair no row references the sentinel.
#[tokio::test]
async fn t15_no_rows_reference_the_sentinel() {
    let (store, _h) = hijacked_store().await;
    let state = store.boot().await;
    let p = pool(&state);
    for (table, column) in [
        ("node_members", "user_id"),
        ("channel_members", "user_id"),
        ("member_roles", "member_id"),
        ("node_invites", "created_by"),
        ("key_bundles", "user_id"),
        ("one_time_prekeys", "user_id"),
        ("prekey_messages", "recipient_id"),
        ("prekey_messages", "sender_id"),
        ("sender_key_distributions", "from_user_id"),
        ("sender_key_distributions", "to_user_id"),
        ("friend_requests", "from_user_id"),
        ("friend_requests", "to_user_id"),
        ("dm_channels", "user1_id"),
        ("dm_channels", "user2_id"),
    ] {
        assert_eq!(
            count(
                p,
                &format!("SELECT COUNT(*) FROM {table} WHERE {column} = '{S}'")
            )
            .await,
            0,
            "{table}.{column}"
        );
    }
    assert_eq!(
        count(p, "SELECT COUNT(*) FROM friendships WHERE user_a_hash = 'SYSTEM' OR user_b_hash = 'SYSTEM'").await,
        0
    );
    assert_eq!(
        text(
            p,
            &format!("SELECT password_hash FROM users WHERE id = '{S}'")
        )
        .await
        .as_deref(),
        Some(LOCK_MARKER)
    );
}

/// T-12 (REQ-12): the SHOULD steps B15, B17 to B21 and B23.
#[tokio::test]
async fn t12_hygiene_steps_clean_the_reserved_node() {
    let (store, h) = hijacked_store().await;
    let state = store.boot().await;
    let p = pool(&state);
    assert!(state.db.repair_report().skipped.is_empty());

    // B15: the reserved node's metadata is reset.
    let row: (Option<String>, Option<String>, i64) = sqlx::query_as(&format!(
        "SELECT description, icon_hash, encrypted_name IS NULL FROM nodes WHERE id = '{D}'"
    ))
    .fetch_one(p)
    .await
    .unwrap();
    assert_eq!(row, (Some("System node for DM channels".into()), None, 1));
    // B17: DM channel attributes and overwrites.
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM channel_permission_overwrites WHERE channel_id = '{}'",
                h.dm_uv
            )
        )
        .await,
        0
    );
    let row: (String, Option<String>, Option<String>, i64, i64) = sqlx::query_as(&format!(
        "SELECT name, topic, category_id, slow_mode_seconds, encrypted_name IS NULL FROM channels WHERE id = '{}'",
        h.dm_uv
    ))
    .fetch_one(p)
    .await
    .unwrap();
    assert_eq!(row, (format!("DM-{}", h.dm_uv), None, None, 0, 1));
    // B18: the sentinel's device rows and blocks.
    for (table, column) in [
        ("device_keys", "user_id"),
        ("device_tokens", "user_id"),
        ("device_registrations", "user_id"),
        ("node_user_profiles", "user_id"),
        ("user_blocks", "blocker_id"),
        ("user_blocks", "blocked_id"),
    ] {
        assert_eq!(
            count(
                p,
                &format!("SELECT COUNT(*) FROM {table} WHERE {column} = '{S}'")
            )
            .await,
            0,
            "{table}.{column}"
        );
    }
    // B19, B20: non-participant reactions and receipts go, participants' stay.
    let reactors: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT user_id FROM message_reactions WHERE message_id = '{}'",
        h.dm_message
    ))
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(reactors, vec![h.u.to_string()]);
    let readers: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT user_id FROM read_receipts WHERE channel_id = '{}'",
        h.dm_uv
    ))
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(readers, vec![h.u.to_string()]);
    // B21: the non-participant's upload and its blob are gone.
    let uploaders: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT uploader_id FROM files WHERE channel_id = '{}'",
        h.dm_uv
    ))
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(uploaders, vec![h.u.to_string()]);
    assert!(!Path::new(&h.blob_non_participant).exists());
    assert!(Path::new(&h.blob_participant).exists());
    // B23: D's bans, allowlist, profiles, emojis, categories and audit rows.
    for table in [
        "node_bans",
        "node_build_hash_allowlist",
        "node_user_profiles",
        "custom_emojis",
        "channel_categories",
        "audit_log",
    ] {
        assert_eq!(
            count(
                p,
                &format!("SELECT COUNT(*) FROM {table} WHERE node_id = '{D}'")
            )
            .await,
            0,
            "{table}"
        );
    }
}

/// T-11b (REQ-13): the repair is idempotent; a second boot changes nothing.
#[tokio::test]
async fn t11b_second_boot_changes_nothing() {
    let (store, _h) = hijacked_store().await;
    let state = store.boot().await;
    assert!(state.db.repair_report().rows_changed() > 0);
    let before = dump(pool(&state)).await;
    close(state).await;

    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::WARN);
    let state = store.boot().await;
    drop(guard);
    let report = state.db.repair_report();
    assert_eq!(report.rows_changed(), 0, "{:?}", report.steps);
    assert!(report.skipped.is_empty());
    assert!(report.ledger_applied.is_empty());
    // No step or migration reports a change; only the orphaned legacy node
    // count is logged again, as at every boot.
    let lines = capture.lines_with_target(LOG_TARGET);
    assert!(
        lines
            .iter()
            .all(|l| l.contains("legacy nodes are still owned")),
        "{lines:?}"
    );
    assert_eq!(dump(pool(&state)).await, before);
}

/// T-11c (REQ-13): a SHOULD step failing with an ordinary error is logged and
/// skipped; one failing with `SQLITE_BUSY` fails closed with nothing
/// committed.
#[tokio::test]
async fn t11c_should_step_failures() {
    // B17 with a constraint-class error: the relay starts.
    let (store, h) = hijacked_store().await;
    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::WARN);
    let state = store
        .boot_with(DbOptions {
            faults: FaultPlan::new().armed("repair:B17", FaultKind::Constraint),
            ..DbOptions::default()
        })
        .await;
    drop(guard);
    assert_eq!(state.db.repair_report().skipped, vec!["B17"]);
    let b17: Vec<String> = capture
        .lines_with_target(LOG_TARGET)
        .into_iter()
        .filter(|l| l.contains("B17"))
        .collect();
    assert_eq!(b17.len(), 1, "{b17:?}");
    assert!(b17[0].contains("WARN") && b17[0].contains("SQLITE_CONSTRAINT"));
    // The fault fires before B17's first statement, so B17 wrote nothing; the
    // other steps committed. (A failure after B17 has written is covered by
    // `t11c_failed_should_step_is_undone_as_a_whole`.)
    let p = pool(&state);
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM channel_permission_overwrites WHERE channel_id = '{}'",
                h.dm_uv
            )
        )
        .await,
        1
    );
    assert_eq!(
        text(p, &format!("SELECT owner_id FROM nodes WHERE id = '{D}'"))
            .await
            .as_deref(),
        Some(S)
    );
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM message_reactions WHERE user_id = '{}'",
                h.attacker
            )
        )
        .await,
        0
    );

    // B19 with SQLITE_BUSY: initialization fails and nothing is committed.
    let (store, h) = hijacked_store().await;
    let err = store
        .try_boot(DbOptions {
            faults: FaultPlan::new().armed("repair:B19", FaultKind::Busy),
            ..DbOptions::default()
        })
        .await
        .expect_err("boot must fail");
    assert!(
        format!("{err:#}").contains("admission repair failed"),
        "{err:#}"
    );
    let raw = store.raw().await;
    assert_eq!(
        text(
            &raw,
            &format!("SELECT owner_id FROM nodes WHERE id = '{D}'")
        )
        .await,
        Some(h.attacker.to_string())
    );
    assert_eq!(
        count(
            &raw,
            &format!("SELECT COUNT(*) FROM node_members WHERE node_id = '{D}'")
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &raw,
            &format!("SELECT COUNT(*) FROM dm_channels WHERE id = '{}'", h.dm_sv)
        )
        .await,
        1
    );
    assert!(Path::new(&h.blob_dm_sv).exists());
}

/// T-11c (REQ-13, section 11.3): a SHOULD step that fails after it has
/// written is undone as a whole, not left half-applied. B17's second
/// statement (the DM channel rename) is made to fail for real with a
/// trigger raising a constraint-class error; the overwrite row that B17's
/// first statement deleted must be back after boot.
#[tokio::test]
async fn t11c_failed_should_step_is_undone_as_a_whole() {
    let (store, h) = hijacked_store().await;
    let raw = store.raw().await;
    // Fires only on a rename of a channel in D, which only B17 does; the
    // category deletion of B23 (`ON DELETE SET NULL`) keeps the name.
    exec(
        &raw,
        &format!(
            "CREATE TRIGGER test_fail_b17_rename BEFORE UPDATE ON channels \
             WHEN OLD.node_id = '{D}' AND NEW.name IS NOT OLD.name \
             BEGIN SELECT RAISE(ABORT, 'test: B17 rename refused'); END"
        ),
    )
    .await;
    raw.close().await;

    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::WARN);
    let state = store.boot().await;
    drop(guard);
    assert_eq!(state.db.repair_report().skipped, vec!["B17"]);
    assert!(!state
        .db
        .repair_report()
        .steps
        .iter()
        .any(|(step, _)| *step == "B17"));
    let b17: Vec<String> = capture
        .lines_with_target(LOG_TARGET)
        .into_iter()
        .filter(|l| l.contains("B17"))
        .collect();
    assert_eq!(b17.len(), 1, "{b17:?}");
    assert!(b17[0].contains("WARN") && b17[0].contains("SQLITE_CONSTRAINT"));

    let p = pool(&state);
    // B17's first statement ran and deleted the overwrite; the savepoint
    // rollback restored it.
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM channel_permission_overwrites WHERE channel_id = '{}'",
                h.dm_uv
            )
        )
        .await,
        1
    );
    // The failed rename did not apply either.
    assert_eq!(
        text(
            p,
            &format!("SELECT name FROM channels WHERE id = '{}'", h.dm_uv)
        )
        .await
        .as_deref(),
        Some("renamed")
    );
    // The steps before and after B17 committed.
    assert_eq!(
        text(p, &format!("SELECT owner_id FROM nodes WHERE id = '{D}'"))
            .await
            .as_deref(),
        Some(S)
    );
    assert_eq!(
        count(
            p,
            &format!(
                "SELECT COUNT(*) FROM message_reactions WHERE user_id = '{}'",
                h.attacker
            )
        )
        .await,
        0
    );
}

/// T-13 (REQ-13): a failing MUST step, trigger creation or ledger step stops
/// initialization.
#[tokio::test]
async fn t13_must_failures_fail_closed() {
    // B6 on a fresh database: nothing committed, no triggers.
    let store = Store::new();
    let err = store
        .try_boot(DbOptions {
            faults: FaultPlan::new().armed("repair:B6", FaultKind::Constraint),
            ..DbOptions::default()
        })
        .await
        .expect_err("boot must fail");
    assert!(
        format!("{err:#}").contains("admission repair failed"),
        "{err:#}"
    );
    let raw = store.raw().await;
    assert_eq!(
        count(
            &raw,
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &raw,
            &format!("SELECT COUNT(*) FROM users WHERE id = '{S}'")
        )
        .await,
        0
    );
    assert_eq!(
        count(&raw, "SELECT COUNT(*) FROM relay_migrations").await,
        0
    );
    raw.close().await;

    // Trigger creation.
    let store = Store::new();
    let err = store
        .try_boot(DbOptions {
            faults: FaultPlan::new().armed("repair:triggers", FaultKind::Busy),
            ..DbOptions::default()
        })
        .await
        .expect_err("boot must fail");
    assert!(
        format!("{err:#}").contains("admission repair failed"),
        "{err:#}"
    );
    let raw = store.raw().await;
    assert_eq!(
        count(
            &raw,
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'"
        )
        .await,
        0
    );
    assert_eq!(
        count(&raw, "SELECT COUNT(*) FROM relay_migrations").await,
        0
    );
    raw.close().await;

    // A ledger step: its row is absent, the earlier one committed.
    let store = Store::new();
    let err = store
        .try_boot(DbOptions {
            faults: FaultPlan::new().armed(
                &format!("ledger:{LEDGER_EVERYONE_CREATE_INVITE}"),
                FaultKind::Constraint,
            ),
            ..DbOptions::default()
        })
        .await
        .expect_err("boot must fail");
    assert!(
        format!("{err:#}").contains("admission repair failed"),
        "{err:#}"
    );
    let raw = store.raw().await;
    let ledger: Vec<String> = sqlx::query_scalar("SELECT name FROM relay_migrations")
        .fetch_all(&raw)
        .await
        .unwrap();
    assert_eq!(ledger, vec![LEDGER_LEGACY_ROLES.to_string()]);
    assert_eq!(
        count(
            &raw,
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'"
        )
        .await,
        TRIGGER_NAMES.len() as i64
    );
    raw.close().await;

    // The next boot without the fault completes the ledger.
    let state = store.boot().await;
    assert_eq!(
        state.db.repair_report().ledger_applied,
        vec![
            LEDGER_EVERYONE_CREATE_INVITE,
            LEDGER_LEGACY_INVITE_EXPIRY,
            LEDGER_AUDIT_INVITE_CODES
        ]
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  T-5: credential repair
// ─────────────────────────────────────────────────────────────────────────

/// T-5 (REQ-5): password-less accounts and the sentinel are locked at boot,
/// and their persisted tokens are deleted before tokens load.
#[tokio::test]
async fn t5_boot_locks_passwordless_accounts_and_drops_their_tokens() {
    let store = Store::new();
    let state = store.boot().await;
    let p = pool(&state);
    let real = account(&state, "pk-real").await;
    let empty_a = Uuid::new_v4();
    let empty_b = Uuid::new_v4();
    exec(p, &format!("INSERT INTO users (id, public_key_hash, public_key, password_hash, created_at) VALUES ('{empty_a}', 'pkh-a', 'pk-a', '', 0), ('{empty_b}', 'pkh-b', 'pk-b', '', 0)")).await;
    exec(
        p,
        &format!("UPDATE users SET password_hash = '' WHERE id = '{S}'"),
    )
    .await;
    let far = 4_000_000_000u64;
    for (token, owner) in [
        ("tok-real", real),
        ("tok-a", empty_a),
        ("tok-b", empty_b),
        ("tok-sentinel", DM_SYSTEM_USER_ID),
    ] {
        state.db.save_auth_token(token, owner, far).await.unwrap();
    }
    close(state).await;

    let state = store.boot().await;
    let p = pool(&state);
    for id in [empty_a, empty_b, DM_SYSTEM_USER_ID] {
        assert_eq!(
            text(
                p,
                &format!("SELECT password_hash FROM users WHERE id = '{id}'")
            )
            .await
            .as_deref(),
            Some(LOCK_MARKER)
        );
    }
    let tokens: Vec<String> = sqlx::query_scalar("SELECT token FROM auth_tokens")
        .fetch_all(p)
        .await
        .unwrap();
    assert_eq!(tokens, vec!["tok-real".to_string()]);
    assert_eq!(state.load_persisted_tokens().await, 1);
    assert_eq!(state.validate_token("tok-real").await, Some(real));
    assert_eq!(state.validate_token("tok-a").await, None);
    assert_eq!(state.validate_token("tok-sentinel").await, None);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-10: triggers
// ─────────────────────────────────────────────────────────────────────────

async fn expect_raise(p: &SqlitePool, sql: &str, raise: &str) {
    let err = sqlx::query(sql)
        .execute(p)
        .await
        .err()
        .unwrap_or_else(|| panic!("not refused: {sql}"));
    assert!(err.to_string().contains(raise), "{sql}: {err}");
}

/// T-10 (REQ-10): SQLite itself refuses every reserved-node violation, on
/// insert, update and delete, while legitimate writes pass.
#[tokio::test]
async fn t10_triggers_enforce_the_reserved_node_invariants() {
    let state = AppState::new_in_memory().await.unwrap();
    let db = &state.db;
    let p = pool(&state);
    let u = user(&state, "pk-u").await;
    let v = user(&state, "pk-v").await;
    let w = user(&state, "pk-w").await;
    let dm = db.create_or_get_dm_channel(u, v).await.unwrap().id;
    let n = db.create_node("N", u, None).await.unwrap().id;
    let n_channel = db.get_node_channels(n).await.unwrap()[0].id;
    db.seed_node_member(n, w, NodeRole::Member).await.unwrap();
    db.add_user_to_channel(n_channel, w).await.unwrap();
    let invite = Uuid::new_v4();
    exec(p, &format!("INSERT INTO node_invites (id, node_id, created_by, invite_code, current_uses, created_at) VALUES ('{invite}', '{n}', '{u}', 'ABCDEFGH', 0, 0)")).await;
    let before = dump(p).await;

    // (a)
    expect_raise(p, &format!("INSERT INTO node_members (node_id, user_id, role, joined_at) VALUES ('{D}', '{w}', 'member', 0)"), "reserved_node").await;
    expect_raise(
        p,
        &format!(
            "UPDATE node_members SET node_id = '{D}' WHERE node_id = '{n}' AND user_id = '{w}'"
        ),
        "reserved_node",
    )
    .await;
    // (b)
    expect_raise(p, &format!("INSERT INTO node_invites (id, node_id, created_by, invite_code, current_uses, created_at) VALUES ('{}', '{D}', '{u}', 'DCODE123', 0, 0)", Uuid::new_v4()), "reserved_node").await;
    expect_raise(
        p,
        &format!("UPDATE node_invites SET node_id = '{D}' WHERE id = '{invite}'"),
        "reserved_node",
    )
    .await;
    // (c)
    expect_raise(
        p,
        &format!("UPDATE nodes SET owner_id = '{u}' WHERE id = '{D}'"),
        "reserved_node",
    )
    .await;
    // (d)
    expect_raise(p, &format!("INSERT INTO channels (id, name, node_id, created_by, created_at) VALUES ('{}', 'x', '{D}', '{u}', 0)", Uuid::new_v4()), "reserved_node").await;
    expect_raise(
        p,
        &format!("UPDATE channels SET node_id = '{D}' WHERE id = '{n_channel}'"),
        "reserved_node",
    )
    .await;
    // (e)
    expect_raise(p, &format!("INSERT INTO channel_members (channel_id, user_id, joined_at) VALUES ('{dm}', '{w}', 0)"), "dm_participants_only").await;
    expect_raise(p, &format!("UPDATE channel_members SET user_id = '{w}' WHERE channel_id = '{dm}' AND user_id = '{v}'"), "dm_participants_only").await;
    expect_raise(p, &format!("UPDATE channel_members SET channel_id = '{dm}' WHERE channel_id = '{n_channel}' AND user_id = '{w}'"), "dm_participants_only").await;
    // (f)
    expect_raise(p, &format!("INSERT INTO dm_channels (id, user1_id, user2_id, created_at) VALUES ('{}', '{S}', '{w}', 0)", Uuid::new_v4()), "reserved_user").await;
    // (g)
    expect_raise(
        p,
        &format!("UPDATE dm_channels SET user2_id = '{w}' WHERE id = '{dm}'"),
        "dm_participants_fixed",
    )
    .await;
    expect_raise(
        p,
        &format!(
            "UPDATE dm_channels SET id = '{}' WHERE id = '{dm}'",
            Uuid::new_v4()
        ),
        "dm_participants_fixed",
    )
    .await;
    // (h)
    expect_raise(
        p,
        &format!("DELETE FROM nodes WHERE id = '{D}'"),
        "reserved_node",
    )
    .await;
    // The membership helpers cannot add anyone to the reserved node either.
    // (The private raw insert of `db::admission` is refused by the same
    // trigger; its unit test covers that, since it is not reachable here.)
    assert!(db
        .seed_node_member(DM_SYSTEM_NODE_ID, w, NodeRole::Admin)
        .await
        .is_err());
    // No violation changed a row.
    assert_eq!(dump(p).await, before);

    // Legitimate writes pass: a DM creation, a fingerprint update and an
    // invite consume.
    let dm_uw = db.create_or_get_dm_channel(u, w).await.unwrap().id;
    assert_eq!(db.get_channel_members(dm_uw).await.unwrap().len(), 2);
    exec(p, &format!("UPDATE node_members SET device_fingerprint_hash = 'fp' WHERE node_id = '{n}' AND user_id = '{w}'")).await;
    exec(
        p,
        &format!("UPDATE node_invites SET current_uses = current_uses + 1 WHERE id = '{invite}'"),
    )
    .await;
    assert_eq!(
        count(
            p,
            &format!("SELECT current_uses FROM node_invites WHERE id = '{invite}'")
        )
        .await,
        1
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  T-14, T-48, RG-C048-1: the legacy role conversion
// ─────────────────────────────────────────────────────────────────────────

/// T-14 (REQ-14): role seeding excludes the reserved node by id, even when
/// it is renamed and has a member with the `admin` marker, and seeds
/// ordinary nodes, a decoy named like the reserved node included.
#[tokio::test]
async fn t14_role_seeding_excludes_the_reserved_node_by_id() {
    let store = Store::new();
    let state = store.boot().await;
    let p = pool(&state);
    let owner = user(&state, "pk-owner").await;
    let m = user(&state, "pk-m").await;
    let m2 = user(&state, "pk-m2").await;
    // A node from before the custom-role model: no Admin or Moderator role,
    // a member carrying the legacy `moderator` marker.
    let legacy = state
        .db
        .create_node("Legacy", owner, None)
        .await
        .unwrap()
        .id;
    exec(
        p,
        &format!("DELETE FROM roles WHERE node_id = '{legacy}' AND id != node_id"),
    )
    .await;
    exec(p, &format!("INSERT INTO node_members (node_id, user_id, role, joined_at) VALUES ('{legacy}', '{m}', 'moderator', 0)")).await;
    // A decoy that carries the reserved node's old display name.
    let decoy = Uuid::new_v4();
    exec(p, &format!("INSERT INTO nodes (id, name, owner_id, created_at) VALUES ('{decoy}', '__dm_system__', '{owner}', 0)")).await;
    // The reserved node, renamed, with an `admin`-marked member.
    state.db.drop_admission_triggers().await.unwrap();
    exec(
        p,
        &format!("UPDATE nodes SET name = 'general' WHERE id = '{D}'"),
    )
    .await;
    exec(p, &format!("INSERT INTO node_members (node_id, user_id, role, joined_at) VALUES ('{D}', '{m2}', 'admin', 0)")).await;
    forget_ledger(&state).await;
    close(state).await;

    let state = store.boot().await;
    let p = pool(&state);
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM roles WHERE node_id = '{D}'")
        )
        .await,
        0
    );
    assert_eq!(
        count(
            p,
            &format!("SELECT COUNT(*) FROM node_members WHERE node_id = '{D}'")
        )
        .await,
        0
    );
    for node in [legacy, decoy] {
        for name in ["Admin", "Moderator"] {
            assert!(
                state
                    .db
                    .get_role_by_name(node, name)
                    .await
                    .unwrap()
                    .is_some(),
                "{name}"
            );
        }
    }
    let roles = state.db.get_member_roles(legacy, m).await.unwrap();
    assert!(roles.iter().any(|r| r.name == "Moderator"));
}

/// A node in the shape of a relay from before `4c122a2`: member M carries the
/// `moderator` marker and the Moderator role, the owner the `admin` marker,
/// and M has created an invite. The ledger is cleared, as on a database from
/// before the upgrade. Returns the store, the node, the owner, M and M's
/// invite code.
async fn legacy_moderator_store() -> (Store, Uuid, Uuid, Uuid, String) {
    let store = Store::new();
    let state = store.boot().await;
    let owner = user(&state, "pk-owner").await;
    let m = user(&state, "pk-m").await;
    let node = state.db.create_node("N", owner, None).await.unwrap().id;
    state
        .db
        .seed_node_member(node, m, NodeRole::Moderator)
        .await
        .unwrap();
    assert!(state
        .db
        .get_member_roles(node, m)
        .await
        .unwrap()
        .iter()
        .any(|r| r.name == "Moderator"));
    let (_, m_invite) = state.create_invite(node, m, None, None).await.unwrap();
    forget_ledger(&state).await;
    close(state).await;
    (store, node, owner, m, m_invite)
}

/// M's earlier invite no longer admits anyone (REQ-22 V6), and M can no
/// longer approve a join request (REQ-31, REQ-45): M lost admission
/// authority.
async fn assert_m_lost_admission_authority(state: &AppState, node: Uuid, m: Uuid, code: &str) {
    let joiner = Uuid::new_v4();
    let joiner = state
        .register_user(format!("pk-joiner-{joiner}"), "pw".into())
        .await
        .unwrap();
    assert_eq!(
        state.use_invite(code, joiner).await,
        Err("Invalid invite code".to_string())
    );
    assert!(!state.db.is_node_member(node, joiner).await.unwrap());
    sqlx::query("INSERT INTO node_join_requests (node_id, user_id, created_at, expires_at) VALUES (?, ?, 0, ?)")
        .bind(node.to_string())
        .bind(joiner.to_string())
        .bind(i64::MAX)
        .execute(pool(state))
        .await
        .unwrap();
    // Through the approval service behind
    // `POST /nodes/:id/join-requests/:user_id/approve`.
    assert_eq!(
        accord_server::admission::approve_join_request(state, m, node, joiner).await,
        Err(accord_server::admission::AdmissionError::Forbidden)
    );
    assert!(!state.db.is_node_member(node, joiner).await.unwrap());
}

async fn marker(state: &AppState, node: Uuid, user: Uuid) -> String {
    state
        .db
        .get_node_member(node, user)
        .await
        .unwrap()
        .unwrap()
        .role
        .as_str()
        .to_string()
}

/// T-48 (REQ-48, REQ-14) and RG-C048-1: the conversion runs once, resets
/// non-owner markers, and later unassignments and deletions survive restarts.
#[tokio::test]
async fn t48_legacy_role_conversion_runs_once() {
    // Run 1: the owner unassigns Moderator from M.
    let (store, node, owner, m, m_invite) = legacy_moderator_store().await;
    let state = store.boot().await;
    assert!(state
        .db
        .repair_report()
        .ledger_applied
        .contains(&LEDGER_LEGACY_ROLES));
    assert!(state
        .db
        .ledger_applied_at(LEDGER_LEGACY_ROLES)
        .await
        .unwrap()
        .is_some());
    assert_eq!(marker(&state, node, m).await, "member");
    assert_eq!(marker(&state, node, owner).await, "admin");
    let moderator = state
        .db
        .get_role_by_name(node, "Moderator")
        .await
        .unwrap()
        .unwrap();
    assert!(state.db.remove_member_role(m, moderator.id).await.unwrap());
    close(state).await;
    for _ in 0..2 {
        let state = store.boot().await;
        assert!(state.db.get_member_roles(node, m).await.unwrap().is_empty());
        let perms = state.db.compute_node_permissions(node, m).await.unwrap();
        assert_eq!(perms & CREATE_INVITE, 0);
        assert_eq!(marker(&state, node, m).await, "member");
        assert_m_lost_admission_authority(&state, node, m, &m_invite).await;
        close(state).await;
    }

    // Run 2: the owner deletes the Moderator role.
    let (store, node, _owner, m, m_invite) = legacy_moderator_store().await;
    let state = store.boot().await;
    let moderator = state
        .db
        .get_role_by_name(node, "Moderator")
        .await
        .unwrap()
        .unwrap();
    state.db.delete_role(moderator.id).await.unwrap();
    close(state).await;
    for _ in 0..2 {
        let state = store.boot().await;
        assert!(state
            .db
            .get_role_by_name(node, "Moderator")
            .await
            .unwrap()
            .is_none());
        assert!(state.db.get_member_roles(node, m).await.unwrap().is_empty());
        let perms = state.db.compute_node_permissions(node, m).await.unwrap();
        assert_eq!(perms & CREATE_INVITE, 0);
        assert_m_lost_admission_authority(&state, node, m, &m_invite).await;
        close(state).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  T-40, RG-C055-1: CREATE_INVITE off @everyone
// ─────────────────────────────────────────────────────────────────────────

/// T-40 (REQ-40) and RG-C055-1: the stale CREATE_INVITE grant is cleared from
/// every @everyone role once; an owner's later grant survives reboots.
#[tokio::test]
async fn t40_everyone_loses_create_invite_once() {
    let store = Store::new();
    let state = store.boot().await;
    let p = pool(&state);
    let owner = account(&state, "pk-owner").await;
    let plain = account(&state, "pk-plain").await;
    let node = |name: &'static str| {
        let db = state.db.clone();
        async move { db.create_node(name, owner, None).await.unwrap().id }
    };
    let (a, b, c, e) = (
        node("A").await,
        node("B").await,
        node("C").await,
        node("E").await,
    );
    let stale = DEFAULT_EVERYONE | CREATE_INVITE;
    assert_eq!(stale, 3_263_553);
    exec(
        p,
        &format!("UPDATE roles SET permissions = {stale} WHERE id = '{a}'"),
    )
    .await;
    exec(
        p,
        &format!(
            "UPDATE roles SET permissions = {} WHERE id = '{b}'",
            stale | MENTION_EVERYONE
        ),
    )
    .await;
    exec(
        p,
        &format!("UPDATE roles SET permissions = 'x3263553' WHERE id = '{e}'"),
    )
    .await;
    admit_with_owner_invite(&state, b, plain).await.unwrap();
    let (_, owner_invite) = state.create_invite(b, owner, None, Some(24)).await.unwrap();
    let owner_invite_id = state
        .db
        .get_node_invite_by_code(&owner_invite)
        .await
        .unwrap()
        .unwrap()
        .id;
    forget_ledger(&state).await;
    close(state).await;

    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::WARN);
    let state = store.boot().await;
    drop(guard);
    let p = pool(&state);
    let perms = |id: Uuid| format!("SELECT permissions FROM roles WHERE id = '{id}'");
    assert_eq!(count(p, &perms(a)).await as u64, DEFAULT_EVERYONE);
    assert_eq!(
        count(p, &perms(b)).await as u64,
        DEFAULT_EVERYONE | MENTION_EVERYONE
    );
    assert_eq!(count(p, &perms(c)).await as u64, DEFAULT_EVERYONE);
    assert_eq!(
        text(
            p,
            &format!(
                "SELECT typeof(permissions) || ':' || permissions FROM roles WHERE id = '{e}'"
            )
        )
        .await
        .as_deref(),
        Some("text:x3263553")
    );
    assert!(state
        .db
        .ledger_applied_at(LEDGER_EVERYONE_CREATE_INVITE)
        .await
        .unwrap()
        .is_some());
    assert!(capture
        .lines_with_target(LOG_TARGET)
        .iter()
        .any(|l| l.contains("WARN") && l.contains("CREATE_INVITE removed from 2 @everyone roles")));

    // The owner of A grants CREATE_INVITE to @everyone again.
    state
        .db
        .update_role(a, None, None, Some(stale), None, None, None)
        .await
        .unwrap();
    close(state).await;
    let state = store.boot().await;
    assert_eq!(count(pool(&state), &perms(a)).await as u64, stale);

    // RG-C055-1: a plain member of B can no longer mint, list or revoke.
    let relay = TestRelay::with_state(Arc::new(state)).await;
    let token = login(&relay, "pk-plain").await;
    let mint = relay
        .client
        .post(relay.url(&format!("/nodes/{b}/invites")))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(mint.status(), 403);
    let list = relay
        .client
        .get(relay.url(&format!("/nodes/{b}/invites")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 403);
    let revoke = relay
        .client
        .delete(relay.url(&format!("/invites/{owner_invite_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), 403);
}

// ─────────────────────────────────────────────────────────────────────────
//  T-46, RG-N008-2: pre-upgrade permanent invites
// ─────────────────────────────────────────────────────────────────────────

struct LegacyInvites {
    store: Store,
    node: Uuid,
    owner: Uuid,
    /// A member admitted before the upgrade through `permanent[0]`.
    member: Uuid,
    /// Invites without expiry, as the desktop made them (N008).
    permanent: Vec<String>,
    /// A used single-use invite without expiry.
    used_single: String,
    /// An invite with an explicit expiry.
    explicit: (String, u64),
}

async fn legacy_invites() -> LegacyInvites {
    let store = Store::new();
    let state = store.boot().await;
    let owner = account(&state, "pk-owner").await;
    let member = account(&state, "pk-member").await;
    let early = account(&state, "pk-early").await;
    let node = state.db.create_node("N", owner, None).await.unwrap().id;
    let mut permanent = Vec::new();
    for _ in 0..2 {
        permanent.push(
            state
                .create_invite(node, owner, None, None)
                .await
                .unwrap()
                .1,
        );
    }
    state.use_invite(&permanent[0], member).await.unwrap();
    let used_single = state
        .create_invite(node, owner, Some(1), None)
        .await
        .unwrap()
        .1;
    state.use_invite(&used_single, early).await.unwrap();
    let explicit = state
        .create_invite(node, owner, None, Some(48))
        .await
        .unwrap()
        .1;
    let explicit_at = state
        .db
        .get_node_invite_by_code(&explicit)
        .await
        .unwrap()
        .unwrap()
        .expires_at
        .unwrap();
    forget_ledger(&state).await;
    close(state).await;
    LegacyInvites {
        store,
        node,
        owner,
        member,
        permanent,
        used_single,
        explicit: (explicit, explicit_at),
    }
}

async fn expires_at(state: &AppState, code: &str) -> Option<u64> {
    state
        .db
        .get_node_invite_by_code(code)
        .await
        .unwrap()
        .unwrap()
        .expires_at
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// T-46 (REQ-46): invites without expiry lapse at T0 + G; explicit expiries
/// and invites created after the upgrade are left alone.
#[tokio::test]
async fn t46_legacy_permanent_invites_get_a_grace_expiry() {
    let fixture = legacy_invites().await;
    let before = now();
    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::WARN);
    let state = fixture.store.boot().await;
    drop(guard);
    let after = now();
    let t0 = state
        .db
        .ledger_applied_at(LEDGER_LEGACY_INVITE_EXPIRY)
        .await
        .unwrap()
        .expect("ledger row");
    assert!(before <= t0 && t0 <= after, "{before} <= {t0} <= {after}");
    let expected = (t0 + GRACE) as u64;
    for code in fixture.permanent.iter().chain([&fixture.used_single]) {
        assert_eq!(expires_at(&state, code).await, Some(expected), "{code}");
    }
    assert_eq!(
        expires_at(&state, &fixture.explicit.0).await,
        Some(fixture.explicit.1)
    );
    assert!(capture
        .lines_with_target(LOG_TARGET)
        .iter()
        .any(|l| l.contains("WARN")
            && l.contains("3 invites without expiry now expire after a grace period of 604800 s")));
    // No code reaches the log.
    for code in fixture
        .permanent
        .iter()
        .chain([&fixture.used_single, &fixture.explicit.0])
    {
        assert!(!capture.text().contains(code.as_str()));
    }

    // An invite created after the upgrade without expiry stays permanent.
    let (_, fresh) = state
        .create_invite(fixture.node, fixture.owner, None, None)
        .await
        .unwrap();
    close(state).await;
    let state = fixture.store.boot().await;
    assert_eq!(expires_at(&state, &fresh).await, None);
    assert_eq!(
        expires_at(&state, &fixture.permanent[1]).await,
        Some(expected)
    );
    assert_eq!(
        state
            .db
            .ledger_applied_at(LEDGER_LEGACY_INVITE_EXPIRY)
            .await
            .unwrap(),
        Some(t0)
    );
}

/// T-46 with `--legacy-invite-grace-hours 0`, and RG-N008-2: a kicked
/// member's pre-upgrade link stops working.
#[tokio::test]
async fn t46_grace_zero_expires_old_links_at_once() {
    let fixture = legacy_invites().await;
    let state = fixture
        .store
        .boot_with(DbOptions {
            legacy_invite_grace_secs: 0,
            ..DbOptions::default()
        })
        .await;
    let t0 = state
        .db
        .ledger_applied_at(LEDGER_LEGACY_INVITE_EXPIRY)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        expires_at(&state, &fixture.permanent[0]).await,
        Some(t0 as u64)
    );

    // RG-N008-2: the kicked member holds the desktop link they first used.
    state
        .kick_from_node(fixture.owner, fixture.member, fixture.node)
        .await
        .unwrap();
    // V3 of REQ-22: valid only while t < expires_at, so an invite that
    // expires at T0 is already expired.
    let relay = TestRelay::with_state(Arc::new(state)).await;
    let token = login(&relay, "pk-member").await;
    let (status, body) = accord_server::test_support::redeem_invite(
        &relay.client,
        &relay.base_url,
        &token,
        &fixture.permanent[0],
    )
    .await;
    assert_eq!(status, 410, "{body}");
    assert_eq!(body["reason"], "invite_expired", "{body}");
    assert_eq!(body["error"], "Invite has expired", "{body}");
    assert!(!relay
        .state
        .db
        .is_node_member(fixture.node, fixture.member)
        .await
        .unwrap());
}

/// T-46 with `--keep-legacy-permanent-invites`: nothing changes, the count
/// kept is logged, and the choice is final.
#[tokio::test]
async fn t46_opt_out_keeps_legacy_invites_permanent_for_good() {
    let fixture = legacy_invites().await;
    let capture = LogCapture::new();
    let guard = capture.start(tracing::Level::WARN);
    let state = fixture
        .store
        .boot_with(DbOptions {
            keep_legacy_permanent_invites: true,
            ..DbOptions::default()
        })
        .await;
    drop(guard);
    for code in fixture.permanent.iter().chain([&fixture.used_single]) {
        assert_eq!(expires_at(&state, code).await, None);
    }
    assert!(state
        .db
        .ledger_applied_at(LEDGER_LEGACY_INVITE_EXPIRY)
        .await
        .unwrap()
        .is_some());
    assert!(capture
        .lines_with_target(LOG_TARGET)
        .iter()
        .any(|l| l.contains("WARN") && l.contains("3 invites without expiry kept permanent")));
    close(state).await;

    // A later boot without the flag still changes nothing.
    let state = fixture.store.boot().await;
    for code in fixture.permanent.iter().chain([&fixture.used_single]) {
        assert_eq!(expires_at(&state, code).await, None);
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  T-42: the capability registry and `admission_since`
// ─────────────────────────────────────────────────────────────────────────

async fn health(relay: &TestRelay) -> Value {
    let response = relay.client.get(relay.url("/health")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}

fn lists_admission_only(features: &Value) {
    let features = features.as_array().expect("features is an array");
    assert!(features.iter().any(|t| t == "admission/1"), "{features:?}");
    // Only tokens of the batch registry are advertised (SPEC-01 §6.8);
    // tokens of specs whose relay part has not landed are not.
    for token in features {
        let token = token.as_str().expect("tokens are strings");
        assert!(
            accord_server::capabilities::REGISTERED_TOKENS.contains(&token),
            "{token} is not registered"
        );
        assert!(
            accord_server::capabilities::RELAY_FEATURES.contains(&token),
            "{token} is not implemented"
        );
    }
    assert!(
        !features.iter().any(|t| t == "governance/1"),
        "{features:?}"
    );
}

/// T-42 (REQ-42): `admission/1` is in the `features` of WS `hello` and of
/// `GET /health`, and `admission_since` is the `applied_at` of the
/// `spec01_legacy_invite_expiry` ledger row, which is T0 of REQ-46. The value
/// survives a reboot unchanged.
#[tokio::test]
async fn t42_features_and_admission_since() {
    let fixture = legacy_invites().await;
    let state = fixture.store.boot().await;
    let t0 = state
        .db
        .ledger_applied_at(LEDGER_LEGACY_INVITE_EXPIRY)
        .await
        .unwrap()
        .expect("ledger row");
    // T0 of REQ-46: the pre-upgrade permanent invites expire at T0 + G.
    assert_eq!(
        expires_at(&state, &fixture.permanent[1]).await,
        Some((t0 + GRACE) as u64)
    );

    let relay = TestRelay::with_state(Arc::new(state)).await;
    let body = health(&relay).await;
    lists_admission_only(&body["features"]);
    assert_eq!(body["admission_since"], json!(t0), "{body}");

    let token = login(&relay, "pk-member").await;
    let ws = WsClient::connect(&relay, &token).await;
    assert_eq!(ws.hello["type"], "hello");
    lists_admission_only(&ws.hello["features"]);
    drop(ws);
    relay.state.db.raw_pool().close().await;

    // Reboot: the ledger row is not rewritten, so the value is unchanged.
    let state = fixture.store.boot().await;
    let relay = TestRelay::with_state(Arc::new(state)).await;
    let body = health(&relay).await;
    lists_admission_only(&body["features"]);
    assert_eq!(body["admission_since"], json!(t0), "{body}");
}

/// T-42 with `--keep-legacy-permanent-invites`: the ledger row is still
/// written at T0, so `admission_since` is reported all the same.
#[tokio::test]
async fn t42_admission_since_with_the_invite_opt_out() {
    let fixture = legacy_invites().await;
    let before = now();
    let state = fixture
        .store
        .boot_with(DbOptions {
            keep_legacy_permanent_invites: true,
            ..DbOptions::default()
        })
        .await;
    let after = now();
    let t0 = state
        .db
        .ledger_applied_at(LEDGER_LEGACY_INVITE_EXPIRY)
        .await
        .unwrap()
        .expect("ledger row");
    assert!(before <= t0 && t0 <= after, "{before} <= {t0} <= {after}");
    assert_eq!(expires_at(&state, &fixture.permanent[1]).await, None);
    let relay = TestRelay::with_state(Arc::new(state)).await;
    let body = health(&relay).await;
    assert_eq!(body["admission_since"], json!(t0), "{body}");
    lists_admission_only(&body["features"]);
    relay.state.db.raw_pool().close().await;

    let state = fixture.store.boot().await;
    let relay = TestRelay::with_state(Arc::new(state)).await;
    assert_eq!(health(&relay).await["admission_since"], json!(t0));
}

// ─────────────────────────────────────────────────────────────────────────
//  T-47, RG-C055-2: invite codes in audit entries
// ─────────────────────────────────────────────────────────────────────────

/// Every `details` value in a JSON document.
fn all_details(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                if key == "details" {
                    if let Some(s) = inner.as_str() {
                        out.push(s.to_string());
                    }
                }
                all_details(inner, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| all_details(i, out)),
        _ => {}
    }
}

/// T-47 (REQ-47) and RG-C055-2: stored invite audit entries lose their codes
/// once, and the audit log never returns an `invite_code` key.
#[tokio::test]
async fn t47_audit_entries_never_expose_invite_codes() {
    let store = Store::new();
    let state = store.boot().await;
    let p = pool(&state);
    let owner = account(&state, "pk-owner").await;
    let manager = account(&state, "pk-manager").await;
    let node = state.db.create_node("N", owner, None).await.unwrap().id;
    admit_with_owner_invite(&state, node, manager)
        .await
        .unwrap();
    let role = state
        .db
        .create_role(node, "Settings", 0, MANAGE_NODE, 3, false, false, None)
        .await
        .unwrap();
    state
        .db
        .assign_member_role(node, manager, role.id)
        .await
        .unwrap();

    let invite_id = Uuid::new_v4();
    let rows = [
        (
            "invite_create",
            json!({"invite_code": "SECRET01", "invite_id": invite_id, "max_uses": null})
                .to_string(),
        ),
        (
            "invite_revoke",
            json!({"invite_code": "SECRET02", "invite_id": invite_id}).to_string(),
        ),
        ("invite_create", "plain text, not JSON".to_string()),
        (
            "member_kick",
            json!({"invite_code": "SECRET04", "reason": "x"}).to_string(),
        ),
    ];
    let mut ids = Vec::new();
    for (i, (action, details)) in rows.iter().enumerate() {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO audit_log (id, node_id, actor_id, action, target_type, details, created_at) VALUES (?, ?, ?, ?, 'invite', ?, ?)")
            .bind(id.to_string())
            .bind(node.to_string())
            .bind(owner.to_string())
            .bind(action)
            .bind(details)
            .bind(i as i64)
            .execute(p)
            .await
            .unwrap();
        ids.push(id);
    }
    forget_ledger(&state).await;
    close(state).await;

    let state = store.boot().await;
    let p = pool(&state);
    let details = |id: Uuid| format!("SELECT details FROM audit_log WHERE id = '{id}'");
    for id in &ids[..2] {
        let stored: Value = serde_json::from_str(&text(p, &details(*id)).await.unwrap()).unwrap();
        assert!(stored.get("invite_code").is_none(), "{stored}");
        assert_eq!(stored["invite_id"], invite_id.to_string());
    }
    assert_eq!(
        text(p, &details(ids[2])).await.as_deref(),
        Some("plain text, not JSON")
    );
    assert_eq!(text(p, &details(ids[3])).await, Some(rows[3].1.clone()));
    assert!(state
        .db
        .ledger_applied_at(LEDGER_AUDIT_INVITE_CODES)
        .await
        .unwrap()
        .is_some());

    // A member holding only MANAGE_NODE reads the log: no code anywhere.
    let relay = TestRelay::with_state(Arc::new(state)).await;
    let token = login(&relay, "pk-manager").await;
    let response = relay
        .client
        .get(relay.url(&format!("/nodes/{node}/audit-log")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    for secret in ["SECRET01", "SECRET02", "SECRET04"] {
        assert!(!body.contains(secret), "{secret} in {body}");
    }
    let mut seen = Vec::new();
    all_details(&serde_json::from_str(&body).unwrap(), &mut seen);
    // The four seeded rows, plus the `invite_create` entry of the setup
    // invite, which stores the invite id only (REQ-41).
    assert_eq!(seen.len(), 5, "{body}");
    for d in seen {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&d) {
            assert!(!map.contains_key("invite_code"), "{d}");
        }
    }
}
