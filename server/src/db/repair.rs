//! Admission boot repair, database triggers and the one-time migration ledger
//! (SPEC-01 sections 6.5 and 6.6; REQ-5, REQ-10 to REQ-15, REQ-40, REQ-46 to
//! REQ-48).
//!
//! [`run`] is the last step of `Database::run_migrations`, after every
//! `CREATE TABLE` and `ALTER TABLE`, and before the relay loads persisted
//! tokens. In order, it:
//!
//! 1. runs the repair steps B1 to B23 in one `BEGIN IMMEDIATE` transaction,
//!    reverting any state that past exploitation of the DM system node left
//!    behind. The steps are plain statements that are idempotent, read no row
//!    content except TEXT columns they return unchanged, and use no `unwrap`;
//! 2. creates the triggers that keep the reserved-node invariants in SQLite
//!    itself, on insert, update and delete;
//! 3. runs each ledger-gated migration that has no `relay_migrations` row, each
//!    in its own `BEGIN IMMEDIATE` transaction that ends by writing that row,
//!    so it never runs again;
//! 4. logs the number of legacy nodes still owned by the reserved user.
//!
//! Any failure of a MUST step, the triggers or a ledger migration is returned
//! as an error ("admission repair failed"), and the relay does not start. A
//! SHOULD step that fails with an ordinary error is logged and skipped.
//!
//! Every log event here uses the target `accord::admission` and carries only
//! step ids, error classes and counts, never ids, codes or names (REQ-41).

use super::Pool;
use crate::admission::LOCK_MARKER;
use crate::faults::FaultPlan;
use anyhow::{anyhow, Context, Result};
use sqlx::{Sqlite, SqliteConnection, Transaction};
use uuid::Uuid;

/// Tracing target of every admission log event (SPEC-01 REQ-41).
pub const LOG_TARGET: &str = "accord::admission";

/// Ledger row of the one-time legacy role conversion (REQ-48).
pub const LEDGER_LEGACY_ROLES: &str = "spec01_legacy_roles";
/// Ledger row of the one-time CREATE_INVITE strip from @everyone (REQ-40).
pub const LEDGER_EVERYONE_CREATE_INVITE: &str = "spec01_everyone_create_invite";
/// Ledger row of the one-time expiry of pre-upgrade permanent invites
/// (REQ-46). Its `applied_at` is T0, the time admission enforcement began.
pub const LEDGER_LEGACY_INVITE_EXPIRY: &str = "spec01_legacy_invite_expiry";
/// Ledger row of the one-time removal of invite codes from audit entries
/// (REQ-47).
pub const LEDGER_AUDIT_INVITE_CODES: &str = "spec01_audit_invite_codes";

/// Default grace period for invites that had no expiry before the upgrade:
/// 604 800 s, 7 days (REQ-46, OD-27).
pub const DEFAULT_LEGACY_INVITE_GRACE_SECS: u64 = 604_800;

/// Length of the invite codes this spec mints; shorter codes are legacy.
const NEW_INVITE_CODE_LEN: i64 = 22;

/// Names of the admission triggers of section 6.5, in creation order. Test
/// fixtures that simulate a database from before the upgrade drop these.
pub const TRIGGER_NAMES: &[&str] = &[
    "accord_reserved_no_members_ins",
    "accord_reserved_no_members_upd",
    "accord_reserved_no_invites",
    "accord_reserved_no_invites_upd",
    "accord_reserved_owner_fixed",
    "accord_reserved_dm_channels_ins",
    "accord_reserved_dm_channels_upd",
    "accord_dm_participants_only",
    "accord_dm_participants_only_upd",
    "accord_no_reserved_dm_participant",
    "accord_dm_participants_fixed",
    "accord_reserved_node_undeletable",
];

/// The reserved node, the reserved user and the lock marker as they appear in
/// SQL: UUIDs in their bound TEXT form (`Uuid::to_string()`, lowercase and
/// hyphenated), which is what the triggers and every bind compare.
const D: &str = "00000000-0000-0000-0000-000000000001";
const S: &str = "00000000-0000-0000-0000-000000000000";

/// Options of the boot repair and the ledger migrations.
#[derive(Debug, Clone)]
pub struct DbOptions {
    /// Grace period G of REQ-46, in seconds (`--legacy-invite-grace-hours`).
    pub legacy_invite_grace_secs: u64,
    /// `--keep-legacy-permanent-invites`: skip the REQ-46 update; the ledger
    /// row is still written, so the choice is final.
    pub keep_legacy_permanent_invites: bool,
    /// Fault points for tests (inert without the `fault-injection` feature).
    pub faults: FaultPlan,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self {
            legacy_invite_grace_secs: DEFAULT_LEGACY_INVITE_GRACE_SECS,
            keep_legacy_permanent_invites: false,
            faults: FaultPlan::default(),
        }
    }
}

/// What the boot repair did, for the caller and for tests.
#[derive(Debug, Clone, Default)]
pub struct RepairReport {
    /// Every repair step that ran successfully, in order, with the number of
    /// rows it changed. B22 lists the guarded tables it found.
    pub steps: Vec<(&'static str, u64)>,
    /// SHOULD steps that failed with an ordinary error and were skipped.
    pub skipped: Vec<&'static str>,
    /// Ledger-gated migrations that ran at this boot, in order.
    pub ledger_applied: Vec<&'static str>,
    /// `applied_at` of the `spec01_legacy_invite_expiry` ledger row: T0 of
    /// REQ-46, the time this relay began enforcing admission. `GET /health`
    /// reports it as `admission_since` (REQ-42). It is the same at every
    /// later boot, because the ledger row is written once.
    pub admission_since: Option<i64>,
    /// Storage paths of the blobs whose `files` rows the repair deleted. The
    /// caller removes them once the file handler exists.
    pub blob_paths: Vec<String>,
}

impl RepairReport {
    /// Total number of rows the repair steps changed.
    pub fn rows_changed(&self) -> u64 {
        self.steps.iter().map(|(_, n)| n).sum()
    }

    /// Rows changed by one step, if it ran.
    pub fn step(&self, id: &str) -> Option<u64> {
        self.steps
            .iter()
            .find(|(step, _)| *step == id)
            .map(|(_, n)| *n)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Must,
    Should,
}

/// One repair step: its statements run in order. A statement containing
/// `RETURNING` deletes `files` rows and yields their storage paths.
struct Step {
    id: &'static str,
    level: Level,
    sql: &'static [&'static str],
}

/// The repair steps of section 6.6 except B22, which is guarded per table.
/// `{D}`, `{S}` and `{L}` stand for the reserved node, the reserved user and
/// the lock marker.
const STEPS: &[Step] = &[
    Step {
        id: "B1",
        level: Level::Must,
        sql: &[
            "INSERT OR IGNORE INTO users (id, public_key_hash, public_key, password_hash, created_at) \
             VALUES ('{S}', 'SYSTEM', 'SYSTEM', '{L}', CAST(strftime('%s', 'now') AS INTEGER))",
            "INSERT OR IGNORE INTO nodes (id, name, owner_id, description, created_at) \
             VALUES ('{D}', '__dm_system__', '{S}', 'System node for DM channels', CAST(strftime('%s', 'now') AS INTEGER))",
        ],
    },
    Step {
        id: "B2",
        level: Level::Must,
        sql: &["UPDATE users SET password_hash = '{L}' \
                WHERE (id = '{S}' AND password_hash IS NOT '{L}') OR password_hash = ''"],
    },
    Step {
        id: "B3",
        level: Level::Must,
        sql: &["DELETE FROM auth_tokens WHERE user_id IN (SELECT id FROM users WHERE password_hash = '{L}')"],
    },
    Step {
        id: "B4",
        level: Level::Must,
        sql: &["UPDATE nodes SET owner_id = '{S}', name = '__dm_system__', join_policy = 'invite' \
                WHERE id = '{D}' AND (owner_id IS NOT '{S}' OR name IS NOT '__dm_system__' OR join_policy IS NOT 'invite')"],
    },
    Step {
        id: "B5",
        level: Level::Must,
        sql: &["DELETE FROM node_members WHERE node_id = '{D}' OR user_id = '{S}'"],
    },
    Step {
        id: "B6",
        level: Level::Must,
        sql: &[
            "DELETE FROM member_roles WHERE node_id = '{D}' OR member_id = '{S}'",
            "DELETE FROM roles WHERE node_id = '{D}'",
        ],
    },
    Step {
        id: "B7",
        level: Level::Must,
        sql: &["DELETE FROM node_invites WHERE node_id = '{D}' OR created_by = '{S}'"],
    },
    Step {
        id: "B8",
        level: Level::Must,
        sql: &["DELETE FROM node_join_requests WHERE node_id = '{D}' OR user_id = '{S}'"],
    },
    Step {
        id: "B9",
        level: Level::Must,
        sql: &[
            "DELETE FROM files WHERE channel_id IN \
             (SELECT id FROM dm_channels WHERE user1_id = '{S}' OR user2_id = '{S}') \
             RETURNING CAST(storage_path AS TEXT)",
            "DELETE FROM channels WHERE id IN \
             (SELECT id FROM dm_channels WHERE user1_id = '{S}' OR user2_id = '{S}')",
            "DELETE FROM dm_channels WHERE user1_id = '{S}' OR user2_id = '{S}'",
        ],
    },
    Step {
        id: "B10",
        level: Level::Must,
        sql: &[
            "DELETE FROM files WHERE channel_id IN \
             (SELECT id FROM channels WHERE node_id = '{D}' AND id NOT IN (SELECT id FROM dm_channels)) \
             RETURNING CAST(storage_path AS TEXT)",
            "DELETE FROM channels WHERE node_id = '{D}' AND id NOT IN (SELECT id FROM dm_channels)",
        ],
    },
    Step {
        id: "B11",
        level: Level::Must,
        sql: &["DELETE FROM channel_members WHERE user_id = '{S}' OR \
                (channel_id IN (SELECT id FROM channels WHERE node_id = '{D}') \
                 AND NOT EXISTS (SELECT 1 FROM dm_channels d WHERE d.id = channel_members.channel_id \
                                 AND channel_members.user_id IN (d.user1_id, d.user2_id)))"],
    },
    Step {
        id: "B12",
        level: Level::Must,
        sql: &["DELETE FROM sender_key_distributions WHERE from_user_id = '{S}' OR to_user_id = '{S}' \
                OR channel_id IN (SELECT id FROM channels WHERE node_id = '{D}')"],
    },
    Step {
        id: "B13",
        level: Level::Must,
        sql: &[
            "DELETE FROM key_bundles WHERE user_id = '{S}'",
            "DELETE FROM one_time_prekeys WHERE user_id = '{S}'",
            "DELETE FROM prekey_messages WHERE recipient_id = '{S}' OR sender_id = '{S}'",
        ],
    },
    Step {
        id: "B14",
        level: Level::Must,
        sql: &[
            "DELETE FROM friend_requests WHERE from_user_id = '{S}' OR to_user_id = '{S}' OR node_id = '{D}'",
            "DELETE FROM friendships WHERE user_a_hash = 'SYSTEM' OR user_b_hash = 'SYSTEM'",
        ],
    },
    Step {
        id: "B15",
        level: Level::Should,
        sql: &["UPDATE nodes SET encrypted_name = NULL, encrypted_description = NULL, \
                encrypted_settings = NULL, icon_hash = NULL, description = 'System node for DM channels' \
                WHERE id = '{D}' AND (encrypted_name IS NOT NULL OR encrypted_description IS NOT NULL \
                OR encrypted_settings IS NOT NULL OR icon_hash IS NOT NULL \
                OR description IS NOT 'System node for DM channels')"],
    },
    Step {
        id: "B16",
        level: Level::Must,
        sql: &[
            "DELETE FROM installed_bots WHERE node_id = '{D}'",
            "DELETE FROM bot_commands WHERE node_id = '{D}'",
            "DELETE FROM bot_invocations WHERE node_id = '{D}' OR channel_id IN (SELECT id FROM dm_channels)",
            "DELETE FROM webhooks WHERE node_id = '{D}'",
        ],
    },
    Step {
        id: "B17",
        level: Level::Should,
        sql: &[
            "DELETE FROM channel_permission_overwrites WHERE channel_id IN \
             (SELECT id FROM channels WHERE node_id = '{D}')",
            "UPDATE channels SET name = 'DM-' || id, encrypted_name = NULL, topic = NULL, \
             category_id = NULL, slow_mode_seconds = 0 \
             WHERE node_id = '{D}' AND (name IS NOT ('DM-' || id) OR encrypted_name IS NOT NULL \
             OR topic IS NOT NULL OR category_id IS NOT NULL OR slow_mode_seconds IS NOT 0)",
        ],
    },
    Step {
        id: "B18",
        level: Level::Should,
        sql: &[
            "DELETE FROM device_keys WHERE user_id = '{S}'",
            "DELETE FROM device_key_bundles WHERE user_id = '{S}'",
            "DELETE FROM device_tokens WHERE user_id = '{S}'",
            "DELETE FROM device_registrations WHERE user_id = '{S}'",
            "DELETE FROM node_user_profiles WHERE user_id = '{S}'",
            "DELETE FROM user_blocks WHERE blocker_id = '{S}' OR blocked_id = '{S}'",
        ],
    },
    Step {
        id: "B19",
        level: Level::Should,
        sql: &["DELETE FROM message_reactions WHERE EXISTS \
                (SELECT 1 FROM messages m JOIN dm_channels d ON d.id = m.channel_id \
                 WHERE m.id = message_reactions.message_id \
                 AND message_reactions.user_id NOT IN (d.user1_id, d.user2_id))"],
    },
    Step {
        id: "B20",
        level: Level::Should,
        sql: &["DELETE FROM read_receipts WHERE EXISTS \
                (SELECT 1 FROM dm_channels d WHERE d.id = read_receipts.channel_id \
                 AND read_receipts.user_id NOT IN (d.user1_id, d.user2_id))"],
    },
    Step {
        id: "B21",
        level: Level::Should,
        sql: &["DELETE FROM files WHERE EXISTS \
                (SELECT 1 FROM dm_channels d WHERE d.id = files.channel_id \
                 AND files.uploader_id NOT IN (d.user1_id, d.user2_id)) \
                RETURNING CAST(storage_path AS TEXT)"],
    },
    // B22 runs here; see `GUARDED`.
    Step {
        id: "B23",
        level: Level::Should,
        sql: &[
            "DELETE FROM node_bans WHERE node_id = '{D}'",
            "DELETE FROM node_build_hash_allowlist WHERE node_id = '{D}'",
            "DELETE FROM node_user_profiles WHERE node_id = '{D}'",
            "DELETE FROM custom_emojis WHERE node_id = '{D}'",
            "DELETE FROM channel_categories WHERE node_id = '{D}'",
            "DELETE FROM audit_log WHERE node_id = '{D}'",
        ],
    },
];

/// B22 (MUST): rows of the reserved node and user in tables that other batch
/// specs add (SPEC-05 section 6.13, SPEC-06 section 6.10). Each statement runs
/// only when its table exists.
const GUARDED: &[(&str, &str)] = &[
    (
        "identity_registrations",
        "DELETE FROM identity_registrations WHERE user_id = '{S}'",
    ),
    (
        "identity_resets",
        "DELETE FROM identity_resets WHERE user_id = '{S}'",
    ),
    (
        "node_key_distributions",
        "DELETE FROM node_key_distributions WHERE node_id = '{D}' OR from_user_id = '{S}' OR to_user_id = '{S}'",
    ),
    (
        "governance_log",
        "DELETE FROM governance_log WHERE node_id = '{D}'",
    ),
];

/// The triggers of section 6.5 (REQ-10 (a) to (h)), with the reserved ids
/// written out in full.
const TRIGGERS: &[&str] = &[
    // (a)
    "CREATE TRIGGER IF NOT EXISTS accord_reserved_no_members_ins BEFORE INSERT ON node_members \
     WHEN NEW.node_id = '{D}' BEGIN SELECT RAISE(ABORT, 'reserved_node'); END",
    "CREATE TRIGGER IF NOT EXISTS accord_reserved_no_members_upd BEFORE UPDATE OF node_id ON node_members \
     WHEN NEW.node_id = '{D}' BEGIN SELECT RAISE(ABORT, 'reserved_node'); END",
    // (b)
    "CREATE TRIGGER IF NOT EXISTS accord_reserved_no_invites BEFORE INSERT ON node_invites \
     WHEN NEW.node_id = '{D}' BEGIN SELECT RAISE(ABORT, 'reserved_node'); END",
    "CREATE TRIGGER IF NOT EXISTS accord_reserved_no_invites_upd BEFORE UPDATE OF node_id ON node_invites \
     WHEN NEW.node_id = '{D}' BEGIN SELECT RAISE(ABORT, 'reserved_node'); END",
    // (c)
    "CREATE TRIGGER IF NOT EXISTS accord_reserved_owner_fixed BEFORE UPDATE OF owner_id ON nodes \
     WHEN OLD.id = '{D}' AND NEW.owner_id IS NOT '{S}' BEGIN SELECT RAISE(ABORT, 'reserved_node'); END",
    // (d)
    "CREATE TRIGGER IF NOT EXISTS accord_reserved_dm_channels_ins BEFORE INSERT ON channels \
     WHEN NEW.node_id = '{D}' AND NOT EXISTS (SELECT 1 FROM dm_channels WHERE id = NEW.id) \
     BEGIN SELECT RAISE(ABORT, 'reserved_node'); END",
    "CREATE TRIGGER IF NOT EXISTS accord_reserved_dm_channels_upd BEFORE UPDATE OF node_id ON channels \
     WHEN NEW.node_id = '{D}' AND NOT EXISTS (SELECT 1 FROM dm_channels WHERE id = NEW.id) \
     BEGIN SELECT RAISE(ABORT, 'reserved_node'); END",
    // (e)
    "CREATE TRIGGER IF NOT EXISTS accord_dm_participants_only BEFORE INSERT ON channel_members \
     WHEN EXISTS (SELECT 1 FROM channels c WHERE c.id = NEW.channel_id AND c.node_id = '{D}') \
      AND NOT EXISTS (SELECT 1 FROM dm_channels d WHERE d.id = NEW.channel_id \
                      AND (d.user1_id = NEW.user_id OR d.user2_id = NEW.user_id)) \
     BEGIN SELECT RAISE(ABORT, 'dm_participants_only'); END",
    "CREATE TRIGGER IF NOT EXISTS accord_dm_participants_only_upd BEFORE UPDATE OF channel_id, user_id ON channel_members \
     WHEN EXISTS (SELECT 1 FROM channels c WHERE c.id = NEW.channel_id AND c.node_id = '{D}') \
      AND NOT EXISTS (SELECT 1 FROM dm_channels d WHERE d.id = NEW.channel_id \
                      AND (d.user1_id = NEW.user_id OR d.user2_id = NEW.user_id)) \
     BEGIN SELECT RAISE(ABORT, 'dm_participants_only'); END",
    // (f)
    "CREATE TRIGGER IF NOT EXISTS accord_no_reserved_dm_participant BEFORE INSERT ON dm_channels \
     WHEN NEW.user1_id = '{S}' OR NEW.user2_id = '{S}' BEGIN SELECT RAISE(ABORT, 'reserved_user'); END",
    // (g)
    "CREATE TRIGGER IF NOT EXISTS accord_dm_participants_fixed BEFORE UPDATE OF id, user1_id, user2_id ON dm_channels \
     WHEN NEW.id IS NOT OLD.id OR NEW.user1_id IS NOT OLD.user1_id OR NEW.user2_id IS NOT OLD.user2_id \
     BEGIN SELECT RAISE(ABORT, 'dm_participants_fixed'); END",
    // (h)
    "CREATE TRIGGER IF NOT EXISTS accord_reserved_node_undeletable BEFORE DELETE ON nodes \
     WHEN OLD.id = '{D}' BEGIN SELECT RAISE(ABORT, 'reserved_node'); END",
];

/// Substitute the reserved ids and the lock marker into a statement template.
fn sql(template: &str) -> String {
    template
        .replace("{D}", D)
        .replace("{S}", S)
        .replace("{L}", LOCK_MARKER)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Schema additions of section 6.5. Idempotent; run by `run_migrations`
/// before [`run`], with the other `CREATE TABLE` and `ALTER TABLE` statements.
pub(super) async fn create_schema(pool: &Pool) -> Result<()> {
    // Ignore only "duplicate column name" (C232); any other error is fatal.
    if let Err(e) =
        sqlx::query("ALTER TABLE nodes ADD COLUMN join_policy TEXT NOT NULL DEFAULT 'invite'")
            .execute(pool)
            .await
    {
        if !is_duplicate_column(&e) {
            return Err(e).context("Failed to add nodes.join_policy");
        }
    }

    let ddl: &[&str] = &[
        r#"CREATE TABLE IF NOT EXISTS node_join_requests (
            node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            device_fingerprint_hash TEXT,
            build_hash TEXT,
            PRIMARY KEY (node_id, user_id)
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_join_requests_node ON node_join_requests (node_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_join_requests_expiry ON node_join_requests (expires_at)",
        // The batch's shared migration ledger (identical in SPEC-02).
        r#"CREATE TABLE IF NOT EXISTS relay_migrations (
            name TEXT PRIMARY KEY NOT NULL,
            applied_at INTEGER NOT NULL
        )"#,
        // Persisted tokens, with their existing DDL, so the repair can purge
        // tokens of locked accounts (B3) before they are loaded.
        r#"CREATE TABLE IF NOT EXISTS auth_tokens (
            token TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )"#,
    ];
    for statement in ddl {
        sqlx::query(statement)
            .execute(pool)
            .await
            .context("Failed to create admission schema")?;
    }
    Ok(())
}

fn is_duplicate_column(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db) => db.message().contains("duplicate column name"),
        _ => false,
    }
}

/// The primary SQLite result code of a database error, if it has one.
fn primary_code(e: &sqlx::Error) -> Option<i32> {
    match e {
        sqlx::Error::Database(db) => db
            .code()
            .and_then(|code| code.parse::<i32>().ok())
            .map(|code| code & 0xff),
        _ => None,
    }
}

/// True when SQLite may have rolled back the whole transaction after this
/// error (`SQLITE_FULL`, `SQLITE_IOERR`, `SQLITE_BUSY`, `SQLITE_NOMEM`), or
/// when it is not a plain database error at all. The repair then fails
/// closed instead of skipping a SHOULD step.
fn may_have_ended_transaction(e: &sqlx::Error) -> bool {
    match primary_code(e) {
        Some(code) => matches!(code, 13 | 10 | 5 | 7),
        None => true,
    }
}

/// A short, data-free name for the class of an error, for logs.
pub(crate) fn error_class(e: &sqlx::Error) -> String {
    match primary_code(e) {
        Some(1) => "SQLITE_ERROR".into(),
        Some(5) => "SQLITE_BUSY".into(),
        Some(6) => "SQLITE_LOCKED".into(),
        Some(7) => "SQLITE_NOMEM".into(),
        Some(8) => "SQLITE_READONLY".into(),
        Some(10) => "SQLITE_IOERR".into(),
        Some(11) => "SQLITE_CORRUPT".into(),
        Some(13) => "SQLITE_FULL".into(),
        Some(19) => "SQLITE_CONSTRAINT".into(),
        Some(code) => format!("SQLITE code {code}"),
        None => match e {
            sqlx::Error::Database(_) => "database error".into(),
            sqlx::Error::PoolTimedOut => "pool timeout".into(),
            sqlx::Error::Io(_) => "I/O error".into(),
            sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "decode error".into(),
            _ => "other error".into(),
        },
    }
}

/// Run the repair, the triggers and the ledger migrations. See the module
/// documentation.
pub(super) async fn run(pool: &Pool, options: &DbOptions) -> Result<RepairReport> {
    let t0 = now_secs();
    let mut report = repair(pool, &options.faults).await?;

    for (step, changed) in &report.steps {
        if *changed > 0 {
            tracing::warn!(
                target: LOG_TARGET,
                "admission repair: step {} changed {} rows",
                step,
                changed
            );
        }
    }

    create_triggers(pool, &options.faults)
        .await
        .context("admission repair failed: could not create the admission triggers")?;

    report.ledger_applied = run_ledger(pool, options, t0).await?;
    report.admission_since = ledger_applied_at(pool, LEDGER_LEGACY_INVITE_EXPIRY)
        .await
        .context("admission repair failed: could not read the migration ledger")?;

    // Orphaned legacy nodes (section 12, Q12 / OD-22): left as they are.
    let orphaned: i64 = sqlx::query_scalar(&sql(
        "SELECT COUNT(*) FROM nodes WHERE owner_id = '{S}' AND id != '{D}'",
    ))
    .fetch_one(pool)
    .await
    .context("admission repair failed: could not count orphaned legacy nodes")?;
    if orphaned > 0 {
        tracing::warn!(
            target: LOG_TARGET,
            "admission repair: {} legacy nodes are still owned by the DM system user and stay without an owner",
            orphaned
        );
    }

    Ok(report)
}

/// The repair transaction: steps B1 to B23.
async fn repair(pool: &Pool, faults: &FaultPlan) -> Result<RepairReport> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(|e| {
        anyhow!(
            "admission repair failed: cannot begin ({})",
            error_class(&e)
        )
    })?;
    let mut report = RepairReport::default();

    for step in STEPS {
        if step.id == "B23" {
            // B22 sits between B21 and B23.
            run_guarded(&mut tx, faults, &mut report).await?;
        }
        let point = format!("repair:{}", step.id);
        let mut paths = Vec::new();
        let outcome = match step.level {
            Level::Must => run_statements(&mut tx, faults, &point, step.sql, &mut paths)
                .await
                .map_err(StepFailure::Fatal),
            Level::Should => run_in_savepoint(&mut tx, faults, &point, step.sql, &mut paths).await,
        };
        match outcome {
            Ok(changed) => {
                report.blob_paths.append(&mut paths);
                report.steps.push((step.id, changed));
            }
            Err(StepFailure::Skipped(e)) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "admission repair: step {} failed ({}); skipped",
                    step.id,
                    error_class(&e)
                );
                report.skipped.push(step.id);
            }
            Err(StepFailure::Fatal(e)) => {
                tracing::error!(
                    target: LOG_TARGET,
                    "admission repair: step {} failed ({})",
                    step.id,
                    error_class(&e)
                );
                return Err(anyhow!(
                    "admission repair failed: step {} ({})",
                    step.id,
                    error_class(&e)
                ));
            }
        }
    }

    tx.commit()
        .await
        .map_err(|e| anyhow!("admission repair failed: commit ({})", error_class(&e)))?;
    Ok(report)
}

/// Run a step's statements on the transaction. Returns the number of rows
/// changed; storage paths from `RETURNING` statements go to `paths`.
async fn run_statements(
    conn: &mut SqliteConnection,
    faults: &FaultPlan,
    point: &str,
    statements: &[&str],
    paths: &mut Vec<String>,
) -> std::result::Result<u64, sqlx::Error> {
    faults.check(point)?;
    let mut changed = 0u64;
    for template in statements {
        let statement = sql(template);
        if statement.contains("RETURNING") {
            let returned: Vec<Option<String>> =
                sqlx::query_scalar(&statement).fetch_all(&mut *conn).await?;
            changed += returned.len() as u64;
            paths.extend(returned.into_iter().flatten());
        } else {
            changed += sqlx::query(&statement)
                .execute(&mut *conn)
                .await?
                .rows_affected();
        }
    }
    Ok(changed)
}

/// How a repair step failed.
enum StepFailure {
    /// A SHOULD step failed with an ordinary error; its savepoint was rolled
    /// back and the repair continues.
    Skipped(sqlx::Error),
    /// A MUST step failed, or the transaction may be gone: fail closed.
    Fatal(sqlx::Error),
}

/// Run a SHOULD step inside a savepoint, so that a failure undoes the whole
/// step and nothing else. An error after which SQLite may have rolled back
/// the transaction, or a savepoint that cannot be rolled back, is fatal.
async fn run_in_savepoint(
    conn: &mut SqliteConnection,
    faults: &FaultPlan,
    point: &str,
    statements: &[&str],
    paths: &mut Vec<String>,
) -> std::result::Result<u64, StepFailure> {
    sqlx::query("SAVEPOINT admission_repair_step")
        .execute(&mut *conn)
        .await
        .map_err(StepFailure::Fatal)?;
    match run_statements(conn, faults, point, statements, paths).await {
        Ok(changed) => {
            sqlx::query("RELEASE admission_repair_step")
                .execute(&mut *conn)
                .await
                .map_err(StepFailure::Fatal)?;
            Ok(changed)
        }
        Err(e) => {
            paths.clear();
            if may_have_ended_transaction(&e) {
                return Err(StepFailure::Fatal(e));
            }
            sqlx::query("ROLLBACK TO admission_repair_step")
                .execute(&mut *conn)
                .await
                .map_err(StepFailure::Fatal)?;
            sqlx::query("RELEASE admission_repair_step")
                .execute(&mut *conn)
                .await
                .map_err(StepFailure::Fatal)?;
            Err(StepFailure::Skipped(e))
        }
    }
}

/// B22: guarded deletes in tables other specs add.
async fn run_guarded(
    tx: &mut Transaction<'static, Sqlite>,
    faults: &FaultPlan,
    report: &mut RepairReport,
) -> Result<()> {
    let outcome: std::result::Result<u64, sqlx::Error> = async {
        faults.check("repair:B22")?;
        let mut changed = 0u64;
        for (table, template) in GUARDED {
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
                    .bind(*table)
                    .fetch_optional(&mut **tx)
                    .await?;
            if exists.is_some() {
                changed += sqlx::query(&sql(template))
                    .execute(&mut **tx)
                    .await?
                    .rows_affected();
            }
        }
        Ok(changed)
    }
    .await;
    match outcome {
        Ok(changed) => {
            report.steps.push(("B22", changed));
            Ok(())
        }
        Err(e) => {
            tracing::error!(
                target: LOG_TARGET,
                "admission repair: step B22 failed ({})",
                error_class(&e)
            );
            Err(anyhow!(
                "admission repair failed: step B22 ({})",
                error_class(&e)
            ))
        }
    }
}

/// Create the triggers of section 6.5 in one transaction.
async fn create_triggers(pool: &Pool, faults: &FaultPlan) -> Result<()> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|e| anyhow!("cannot begin ({})", error_class(&e)))?;
    faults
        .check("repair:triggers")
        .map_err(|e| anyhow!("{}", error_class(&e)))?;
    for template in TRIGGERS {
        sqlx::query(&sql(template))
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow!("{}", error_class(&e)))?;
    }
    tx.commit()
        .await
        .map_err(|e| anyhow!("commit ({})", error_class(&e)))?;
    Ok(())
}

/// The ledger-gated migrations, in the order of section 6.6.
async fn run_ledger(pool: &Pool, options: &DbOptions, t0: i64) -> Result<Vec<&'static str>> {
    let mut applied = Vec::new();
    for name in [
        LEDGER_LEGACY_ROLES,
        LEDGER_EVERYONE_CREATE_INVITE,
        LEDGER_LEGACY_INVITE_EXPIRY,
        LEDGER_AUDIT_INVITE_CODES,
    ] {
        let ran = run_ledger_step(pool, options, name, t0)
            .await
            .map_err(|e| anyhow!("admission repair failed: ledger step {name} ({e})"))?;
        if ran {
            applied.push(name);
        }
    }
    Ok(applied)
}

/// Run one ledger-gated migration unless its ledger row exists. Returns
/// whether it ran. Errors carry only a class, never data.
async fn run_ledger_step(
    pool: &Pool,
    options: &DbOptions,
    name: &'static str,
    t0: i64,
) -> std::result::Result<bool, String> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|e| error_class(&e))?;
    let done: Option<i64> = sqlx::query_scalar("SELECT 1 FROM relay_migrations WHERE name = ?")
        .bind(name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| error_class(&e))?;
    if done.is_some() {
        return Ok(false);
    }

    let outcome: std::result::Result<(), sqlx::Error> = async {
        options.faults.check(&format!("ledger:{name}"))?;
        match name {
            LEDGER_LEGACY_ROLES => legacy_roles(&mut tx, t0).await?,
            LEDGER_EVERYONE_CREATE_INVITE => everyone_create_invite(&mut tx).await?,
            LEDGER_LEGACY_INVITE_EXPIRY => legacy_invite_expiry(&mut tx, options, t0).await?,
            LEDGER_AUDIT_INVITE_CODES => audit_invite_codes(&mut tx).await?,
            _ => {}
        }
        sqlx::query("INSERT INTO relay_migrations (name, applied_at) VALUES (?, ?)")
            .bind(name)
            .bind(t0)
            .execute(&mut *tx)
            .await?;
        Ok(())
    }
    .await;
    if let Err(e) = outcome {
        tracing::error!(
            target: LOG_TARGET,
            "admission ledger step {} failed ({})",
            name,
            error_class(&e)
        );
        return Err(error_class(&e));
    }
    tx.commit().await.map_err(|e| error_class(&e))?;
    Ok(true)
}

/// `spec01_legacy_roles` (REQ-48, REQ-14): the legacy role conversion, run
/// once and never on the reserved node, then the marker reset.
async fn legacy_roles(
    conn: &mut SqliteConnection,
    now: i64,
) -> std::result::Result<(), sqlx::Error> {
    use crate::models::permission_bits::{
        ALL_PERMISSIONS, BAN_MEMBERS, CREATE_INVITE, KICK_MEMBERS, MANAGE_CHANNELS, MANAGE_MESSAGES,
    };
    let moderator_perms =
        KICK_MEMBERS | BAN_MEMBERS | CREATE_INVITE | MANAGE_MESSAGES | MANAGE_CHANNELS;
    // (name, color, permissions, position), as `seed_management_roles` seeds them.
    let seeded: [(&str, i64, u64, i64); 2] = [
        ("Admin", 0x00E7_4C3C, ALL_PERMISSIONS, 2),
        ("Moderator", 0x0034_98DB, moderator_perms, 1),
    ];

    // The reserved node is excluded by id, never by name. Rows whose ids are
    // not TEXT UUIDs are skipped instead of failing.
    let node_ids: Vec<String> = sqlx::query_scalar(&sql(
        "SELECT id FROM nodes WHERE id != '{D}' AND typeof(id) = 'text'",
    ))
    .fetch_all(&mut *conn)
    .await?;

    let mut roles_created = 0u64;
    let mut roles_assigned = 0u64;
    for node_id in node_ids {
        if Uuid::parse_str(&node_id).is_err() {
            continue;
        }
        // 1a. Seed any missing Admin or Moderator role.
        for (name, color, permissions, position) in seeded {
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT id FROM roles WHERE node_id = ? AND name = ? AND typeof(id) = 'text' LIMIT 1",
            )
            .bind(&node_id)
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;
            if existing.is_none() {
                sqlx::query(
                    "INSERT INTO roles (id, node_id, name, color, permissions, position, hoist, mentionable, icon_emoji, created_at) \
                     VALUES (?, ?, ?, ?, ?, ?, 1, 1, NULL, ?)",
                )
                .bind(Uuid::new_v4().to_string())
                .bind(&node_id)
                .bind(name)
                .bind(color)
                .bind(permissions as i64)
                .bind(position)
                .bind(now)
                .execute(&mut *conn)
                .await?;
                roles_created += 1;
            }
        }

        // 1b. Assign them by the legacy marker.
        let legacy: Vec<(String, String)> = sqlx::query_as(
            "SELECT user_id, role FROM node_members \
             WHERE node_id = ? AND role IN ('admin', 'moderator') AND typeof(user_id) = 'text'",
        )
        .bind(&node_id)
        .fetch_all(&mut *conn)
        .await?;
        for (user_id, marker) in legacy {
            if Uuid::parse_str(&user_id).is_err() {
                continue;
            }
            let name = if marker == "admin" {
                "Admin"
            } else {
                "Moderator"
            };
            let role_id: Option<String> = sqlx::query_scalar(
                "SELECT id FROM roles WHERE node_id = ? AND name = ? AND typeof(id) = 'text' LIMIT 1",
            )
            .bind(&node_id)
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;
            if let Some(role_id) = role_id {
                roles_assigned += sqlx::query(
                    "INSERT OR IGNORE INTO member_roles (member_id, role_id, node_id, assigned_at) VALUES (?, ?, ?, ?)",
                )
                .bind(&user_id)
                .bind(&role_id)
                .bind(&node_id)
                .bind(now)
                .execute(&mut *conn)
                .await?
                .rows_affected();
            }
        }
    }

    // 2. Every member who is not the owner becomes a plain member.
    let demoted = sqlx::query(&sql(
        "UPDATE node_members SET role = 'member' WHERE node_id != '{D}' AND role IS NOT 'member' \
         AND user_id IS NOT (SELECT owner_id FROM nodes n WHERE n.id = node_members.node_id)",
    ))
    .execute(&mut *conn)
    .await?
    .rows_affected();
    // 3. The owner's row, where one exists, carries the admin marker.
    let owners = sqlx::query(&sql(
        "UPDATE node_members SET role = 'admin' WHERE node_id != '{D}' AND role IS NOT 'admin' \
         AND user_id = (SELECT owner_id FROM nodes n WHERE n.id = node_members.node_id)",
    ))
    .execute(&mut *conn)
    .await?
    .rows_affected();

    tracing::warn!(
        target: LOG_TARGET,
        "admission migration {}: {} roles seeded, {} role assignments made, {} legacy markers reset to member, {} owner markers set",
        LEDGER_LEGACY_ROLES,
        roles_created,
        roles_assigned,
        demoted,
        owners
    );
    Ok(())
}

/// `spec01_everyone_create_invite` (REQ-40): clear CREATE_INVITE (bit 0) from
/// every @everyone role whose permissions are stored as an integer.
async fn everyone_create_invite(
    conn: &mut SqliteConnection,
) -> std::result::Result<(), sqlx::Error> {
    let changed = sqlx::query(
        "UPDATE roles SET permissions = permissions & ~1 \
         WHERE id = node_id AND typeof(permissions) = 'integer' AND (permissions & 1) = 1",
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    tracing::warn!(
        target: LOG_TARGET,
        "admission migration {}: CREATE_INVITE removed from {} @everyone roles",
        LEDGER_EVERYONE_CREATE_INVITE,
        changed
    );
    Ok(())
}

/// `spec01_legacy_invite_expiry` (REQ-46): invites with no expiry lapse at
/// T0 + G, unless the operator opted out.
async fn legacy_invite_expiry(
    conn: &mut SqliteConnection,
    options: &DbOptions,
    t0: i64,
) -> std::result::Result<(), sqlx::Error> {
    if options.keep_legacy_permanent_invites {
        let kept: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM node_invites WHERE expires_at IS NULL")
                .fetch_one(&mut *conn)
                .await?;
        tracing::warn!(
            target: LOG_TARGET,
            "admission migration {}: skipped by --keep-legacy-permanent-invites; {} invites without expiry kept permanent",
            LEDGER_LEGACY_INVITE_EXPIRY,
            kept
        );
    } else {
        let grace = i64::try_from(options.legacy_invite_grace_secs).unwrap_or(i64::MAX);
        let changed =
            sqlx::query("UPDATE node_invites SET expires_at = ? WHERE expires_at IS NULL")
                .bind(t0.saturating_add(grace))
                .execute(&mut *conn)
                .await?
                .rows_affected();
        tracing::warn!(
            target: LOG_TARGET,
            "admission migration {}: {} invites without expiry now expire after a grace period of {} s",
            LEDGER_LEGACY_INVITE_EXPIRY,
            changed,
            grace
        );
    }
    // Legacy short codes that stay live keep their own expiry (Q5 / OD-15).
    let live_legacy: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM node_invites WHERE length(invite_code) < ? \
         AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(NEW_INVITE_CODE_LEN)
    .bind(t0)
    .fetch_one(&mut *conn)
    .await?;
    if live_legacy > 0 {
        tracing::warn!(
            target: LOG_TARGET,
            "admission migration {}: {} live invites use legacy short codes; owners should replace them",
            LEDGER_LEGACY_INVITE_EXPIRY,
            live_legacy
        );
    }
    Ok(())
}

/// `spec01_audit_invite_codes` (REQ-47): remove `invite_code` from stored
/// invite audit entries.
async fn audit_invite_codes(conn: &mut SqliteConnection) -> std::result::Result<(), sqlx::Error> {
    let changed = sqlx::query(
        "UPDATE audit_log SET details = json_remove(details, '$.invite_code') \
         WHERE action IN ('invite_create', 'invite_revoke') AND json_valid(details) \
         AND json_extract(details, '$.invite_code') IS NOT NULL",
    )
    .execute(&mut *conn)
    .await?
    .rows_affected();
    tracing::warn!(
        target: LOG_TARGET,
        "admission migration {}: invite codes removed from {} audit entries",
        LEDGER_AUDIT_INVITE_CODES,
        changed
    );
    Ok(())
}

/// `applied_at` of a ledger row, if the migration has run.
pub(super) async fn ledger_applied_at(pool: &Pool, name: &str) -> Result<Option<i64>> {
    sqlx::query_scalar("SELECT applied_at FROM relay_migrations WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await
        .context("Failed to read the migration ledger")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{DM_SYSTEM_NODE_ID, DM_SYSTEM_USER_ID};

    #[test]
    fn literals_match_the_reserved_ids() {
        assert_eq!(D, DM_SYSTEM_NODE_ID.to_string());
        assert_eq!(S, DM_SYSTEM_USER_ID.to_string());
        assert!(!sql("'{D}' '{S}' '{L}'").contains('{'));
        assert!(sql("{L}") == LOCK_MARKER);
    }

    #[test]
    fn every_trigger_is_named() {
        assert_eq!(TRIGGERS.len(), TRIGGER_NAMES.len());
        for (ddl, name) in TRIGGERS.iter().zip(TRIGGER_NAMES) {
            assert!(
                ddl.contains(&format!("IF NOT EXISTS {name} ")),
                "{name} out of order"
            );
        }
    }

    #[test]
    fn step_order_follows_the_spec() {
        let ids: Vec<&str> = STEPS.iter().map(|s| s.id).collect();
        let expected: Vec<String> = (1..=23)
            .filter(|n| *n != 22)
            .map(|n| format!("B{n}"))
            .collect();
        assert_eq!(ids, expected);
        for step in STEPS {
            let must = matches!(
                step.id,
                "B1" | "B2"
                    | "B3"
                    | "B4"
                    | "B5"
                    | "B6"
                    | "B7"
                    | "B8"
                    | "B9"
                    | "B10"
                    | "B11"
                    | "B12"
                    | "B13"
                    | "B14"
                    | "B16"
            );
            assert_eq!(step.level == Level::Must, must, "{}", step.id);
        }
    }

    #[test]
    fn statements_read_no_row_content() {
        // The repair reads only the TEXT storage paths it returns unchanged.
        for step in STEPS {
            for statement in step.sql {
                assert!(!statement.trim_start().starts_with("SELECT"), "{}", step.id);
                if statement.contains("RETURNING") {
                    assert!(statement.ends_with("RETURNING CAST(storage_path AS TEXT)"));
                }
            }
        }
    }
}
