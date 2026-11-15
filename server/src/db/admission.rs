//! The database side of relay admission (SPEC-01 section 11.1).
//!
//! SPEC-01 REQ-18 makes this module the only place that inserts
//! `node_members` rows. The raw insert, [`insert_member_row`], is private to
//! this module; everything else reaches it through:
//!
//! - [`Database::admit`], the admission transaction of the three entry points
//!   (section 6.6.1), and [`Database::approve_join_request`], the approval
//!   transaction. Both resolve the request to exactly one
//!   [`AdmissionGrant`] and admit through the single function
//!   `admit_with_grant`;
//! - [`Database::insert_owner_row`], the owner row written by node creation.
//!
//! It is also the only place that deletes them outside the boot repair: the
//! single removal routine of leave, kick and ban, [`Database::remove_member`]
//! (REQ-50), whose private `remove_node_member` returns the number of rows
//! deleted.
//!
//! Every read an admission needs (admission authority through the node
//! permissions, key and device bans, the device count and cap, the build
//! allowlist, membership) exists here in a form that runs on a given
//! connection. The pool-based `Database` methods delegate to these forms, so
//! each check has one implementation, and the admission transaction runs all
//! of its reads on its own connection (section 11.3, pool starvation).
//!
//! Integration tests create memberships through the real admission path (an
//! owner-created invite that the test user redeems, see `test_support`);
//! database-level tests that need raw rows use the seeding function at the
//! end of this module, which only the `test-helpers` feature compiles.

use super::{Database, DM_SYSTEM_NODE_ID};
use crate::admission::{
    is_reserved_node, is_reserved_user, unavailable, AdmissionContext, AdmissionEntry,
    AdmissionError, AdmissionGrant, AdmissionOutcome, JOIN_REQUEST_LIFETIME_SECS,
    MAX_BUILD_HASH_LEN, MAX_PENDING_JOIN_REQUESTS,
};
use crate::models::permission_bits::{ADMINISTRATOR, ALL_PERMISSIONS, CREATE_INVITE, MANAGE_NODE};
use crate::models::NodeInvite;
use crate::rate_limit::{ActionType, RateLimiter};
use sqlx::{Row, SqliteConnection};
use uuid::Uuid;

/// The legacy role marker written for owners (REQ-26) and node creation.
const MARKER_OWNER: &str = "admin";
/// The role marker of every invite or approval admission (REQ-9).
const MARKER_MEMBER: &str = "member";

/// Decode a stored UUID, as a decode error rather than a panic.
fn parse_uuid(text: &str) -> Result<Uuid, sqlx::Error> {
    Uuid::parse_str(text).map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

/// The node row as admission reads it.
#[derive(Debug, Clone)]
pub(crate) struct NodeRow {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub join_policy: String,
}

/// The invite row as admission reads it. Ids stay TEXT until they are
/// needed, so a corrupt row is simply invalid instead of an error.
#[derive(Debug, Clone)]
struct InviteRow {
    node_id: String,
    created_by: String,
    max_uses: Option<i64>,
    current_uses: i64,
    expires_at: Option<i64>,
}

// ── Connection-generic reads (REQ-18) ──

pub(super) async fn node_row_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
) -> Result<Option<NodeRow>, sqlx::Error> {
    let row = sqlx::query("SELECT id, name, owner_id, join_policy FROM nodes WHERE id = ?")
        .bind(node_id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    match row {
        None => Ok(None),
        Some(row) => Ok(Some(NodeRow {
            id: parse_uuid(&row.try_get::<String, _>("id")?)?,
            name: row.try_get("name")?,
            owner_id: parse_uuid(&row.try_get::<String, _>("owner_id")?)?,
            join_policy: row.try_get("join_policy")?,
        })),
    }
}

/// Is `user_id` a member of `node_id`?
pub(super) async fn is_member_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row =
        sqlx::query("SELECT COUNT(*) AS count FROM node_members WHERE node_id = ? AND user_id = ?")
            .bind(node_id.to_string())
            .bind(user_id.to_string())
            .fetch_one(&mut *conn)
            .await?;
    Ok(row.try_get::<i64, _>("count")? > 0)
}

/// Node-level permissions of `user_id` in `node_id`: 0 for the reserved node
/// and the reserved user (REQ-8), every bit for the owner, otherwise the
/// @everyone role OR the member's roles, with ADMINISTRATOR expanding to
/// every bit. `None` when the node does not exist.
pub(super) async fn node_permissions_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    user_id: Uuid,
) -> Result<Option<u64>, sqlx::Error> {
    if is_reserved_node(node_id) || is_reserved_user(user_id) {
        return Ok(Some(0));
    }
    let Some(node) = node_row_on(conn, node_id).await? else {
        return Ok(None);
    };
    if node.owner_id == user_id {
        return Ok(Some(ALL_PERMISSIONS));
    }
    let everyone = sqlx::query("SELECT permissions FROM roles WHERE node_id = ? AND position = 0")
        .bind(node_id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    let mut perms = match everyone {
        Some(row) => row.try_get::<i64, _>("permissions")? as u64,
        None => 0,
    };
    let roles = sqlx::query(
        "SELECT r.permissions FROM roles r JOIN member_roles mr ON r.id = mr.role_id \
         WHERE mr.member_id = ? AND mr.node_id = ?",
    )
    .bind(user_id.to_string())
    .bind(node_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    for row in roles {
        perms |= row.try_get::<i64, _>("permissions")? as u64;
    }
    if perms & ADMINISTRATOR != 0 {
        return Ok(Some(ALL_PERMISSIONS));
    }
    Ok(Some(perms))
}

/// Admission authority of `user_id` in `node_id` (SPEC-01 section 5
/// definitions): never in the reserved node or for the reserved user; always
/// for the owner; otherwise only for a member whose node permissions include
/// CREATE_INVITE. A non-member's @everyone bits never count.
pub(super) async fn admission_authority_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    if is_reserved_node(node_id) || is_reserved_user(user_id) {
        return Ok(false);
    }
    let Some(node) = node_row_on(conn, node_id).await? else {
        return Ok(false);
    };
    if node.owner_id == user_id {
        return Ok(true);
    }
    if !is_member_on(conn, node_id, user_id).await? {
        return Ok(false);
    }
    let perms = node_permissions_on(conn, node_id, user_id)
        .await?
        .unwrap_or(0);
    Ok(perms & CREATE_INVITE != 0)
}

/// Is there an unexpired public-key-hash ban of `public_key_hash` in the node?
pub(super) async fn is_banned_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    public_key_hash: &str,
    now: u64,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS count FROM node_bans WHERE node_id = ? AND public_key_hash = ? \
         AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(node_id.to_string())
    .bind(public_key_hash)
    .bind(now as i64)
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.try_get::<i64, _>("count")? > 0)
}

/// Does the node have at least one unexpired ban that names a device
/// fingerprint (REQ-24(d))?
pub(super) async fn has_device_bans_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    now: u64,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS count FROM node_bans WHERE node_id = ? \
         AND device_fingerprint_hash IS NOT NULL AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(node_id.to_string())
    .bind(now as i64)
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.try_get::<i64, _>("count")? > 0)
}

/// Is there an unexpired ban of this device fingerprint in the node?
pub(super) async fn is_device_banned_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    device_fingerprint_hash: &str,
    now: u64,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS count FROM node_bans WHERE node_id = ? AND device_fingerprint_hash = ? \
         AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(node_id.to_string())
    .bind(device_fingerprint_hash)
    .bind(now as i64)
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.try_get::<i64, _>("count")? > 0)
}

/// How many members of the node joined with this device fingerprint?
pub(super) async fn count_members_with_fingerprint_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    device_fingerprint_hash: &str,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS count FROM node_members WHERE node_id = ? AND device_fingerprint_hash = ?",
    )
    .bind(node_id.to_string())
    .bind(device_fingerprint_hash)
    .fetch_one(&mut *conn)
    .await?;
    row.try_get::<i64, _>("count")
}

/// The node's per-device account cap (0 = unlimited).
pub(super) async fn max_accounts_per_device_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query("SELECT max_accounts_per_device FROM nodes WHERE id = ?")
        .bind(node_id.to_string())
        .fetch_one(&mut *conn)
        .await?;
    row.try_get::<i64, _>("max_accounts_per_device")
}

/// Does the node's build allowlist accept `build_hash`? An empty allowlist
/// accepts everything; an absent hash is the empty string (REQ-24(e)).
pub(super) async fn is_build_hash_allowed_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    build_hash: &str,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS total, COALESCE(SUM(build_hash = ?), 0) AS matching \
         FROM node_build_hash_allowlist WHERE node_id = ?",
    )
    .bind(build_hash)
    .bind(node_id.to_string())
    .fetch_one(&mut *conn)
    .await?;
    let total: i64 = row.try_get("total")?;
    let matching: i64 = row.try_get("matching")?;
    Ok(total == 0 || matching > 0)
}

/// The public-key hash of a user.
pub(super) async fn public_key_hash_on(
    conn: &mut SqliteConnection,
    user_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query("SELECT public_key_hash FROM users WHERE id = ?")
        .bind(user_id.to_string())
        .fetch_optional(&mut *conn)
        .await?;
    row.map(|r| r.try_get::<String, _>("public_key_hash"))
        .transpose()
}

async fn invite_row_on(
    conn: &mut SqliteConnection,
    code: &str,
) -> Result<Option<InviteRow>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT node_id, created_by, max_uses, current_uses, expires_at FROM node_invites \
         WHERE invite_code = ?",
    )
    .bind(code)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        None => Ok(None),
        Some(row) => Ok(Some(InviteRow {
            node_id: row.try_get("node_id")?,
            created_by: row.try_get("created_by")?,
            max_uses: row.try_get("max_uses")?,
            current_uses: row.try_get("current_uses")?,
            expires_at: row.try_get("expires_at")?,
        })),
    }
}

// ── Writes ──

/// The raw `node_members` insert. Private to this module (REQ-18): every
/// membership is written here, by the admission function, by the owner row
/// of node creation, or by the test-only seeding function.
async fn insert_member_row(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    user_id: Uuid,
    marker: &str,
    device_fingerprint_hash: Option<&str>,
    joined_at: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO node_members (node_id, user_id, role, joined_at, device_fingerprint_hash) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(node_id.to_string())
    .bind(user_id.to_string())
    .bind(marker)
    .bind(joined_at as i64)
    .bind(device_fingerprint_hash)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Assign the node's seeded "Admin" role to `user_id`, if it still exists.
async fn assign_admin_role_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    user_id: Uuid,
    now: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR IGNORE INTO member_roles (member_id, role_id, node_id, assigned_at) \
         SELECT ?, id, node_id, ? FROM roles WHERE node_id = ? AND name = 'Admin' LIMIT 1",
    )
    .bind(user_id.to_string())
    .bind(now as i64)
    .bind(node_id.to_string())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Clean slate, membership and channel subscriptions of one admission
/// (REQ-25). Deletes the user's stale roles, channel subscriptions and
/// pending sender-key distributions addressed to them in the node, inserts
/// the membership, restores the Admin role for an owner, and subscribes the
/// user to every channel of the node.
async fn write_admission(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    user_id: Uuid,
    marker: &str,
    device_fingerprint_hash: Option<&str>,
    now: u64,
) -> Result<(), sqlx::Error> {
    let node = node_id.to_string();
    let user = user_id.to_string();
    sqlx::query("DELETE FROM member_roles WHERE node_id = ? AND member_id = ?")
        .bind(&node)
        .bind(&user)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "DELETE FROM channel_members WHERE user_id = ? \
         AND channel_id IN (SELECT id FROM channels WHERE node_id = ?)",
    )
    .bind(&user)
    .bind(&node)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "DELETE FROM sender_key_distributions WHERE to_user_id = ? \
         AND channel_id IN (SELECT id FROM channels WHERE node_id = ?)",
    )
    .bind(&user)
    .bind(&node)
    .execute(&mut *conn)
    .await?;
    insert_member_row(conn, node_id, user_id, marker, device_fingerprint_hash, now).await?;
    if marker == MARKER_OWNER {
        assign_admin_role_on(conn, node_id, user_id, now).await?;
    }
    sqlx::query(
        "INSERT OR IGNORE INTO channel_members (channel_id, user_id, joined_at) \
         SELECT id, ?, ? FROM channels WHERE node_id = ?",
    )
    .bind(&user)
    .bind(now as i64)
    .bind(&node)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Why inserting an invite failed.
#[derive(Debug)]
pub enum InsertInviteError {
    /// The code collided with an existing invite's unique code; retry with
    /// a fresh one (REQ-36).
    Collision,
    /// Any other failure.
    Refused(AdmissionError),
}

impl Database {
    // ── Pool-level entry points ──

    /// Admission authority of `user_id` in `node_id`, on one pooled
    /// connection. Database errors fail closed with `unavailable`.
    pub async fn admission_authority(
        &self,
        node_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, AdmissionError> {
        self.faults
            .check("admission:authority")
            .map_err(|e| unavailable(&e))?;
        let mut conn = self.pool.acquire().await.map_err(|e| unavailable(&e))?;
        admission_authority_on(&mut conn, node_id, user_id)
            .await
            .map_err(|e| unavailable(&e))
    }

    /// The owner row written by node creation: marker `admin` and the seeded
    /// Admin role, if it exists (REQ-18).
    pub(super) async fn insert_owner_row(
        &self,
        node_id: Uuid,
        owner_id: Uuid,
    ) -> anyhow::Result<()> {
        let now = super::now();
        let mut conn = self.pool.acquire().await?;
        insert_member_row(&mut conn, node_id, owner_id, MARKER_OWNER, None, now).await?;
        assign_admin_role_on(&mut conn, node_id, owner_id, now).await?;
        Ok(())
    }

    /// Insert a new invite row with the given code (REQ-36). A collision on
    /// the unique code is reported as [`InsertInviteError::Collision`]; the
    /// trigger that keeps invites out of the reserved node, and any other
    /// error, as a refusal.
    pub async fn insert_invite(
        &self,
        node_id: Uuid,
        created_by: Uuid,
        code: &str,
        max_uses: Option<u32>,
        expires_at: Option<u64>,
        created_at: u64,
    ) -> Result<NodeInvite, InsertInviteError> {
        let id = Uuid::new_v4();
        let result = sqlx::query(
            "INSERT INTO node_invites (id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
        )
        .bind(id.to_string())
        .bind(node_id.to_string())
        .bind(created_by.to_string())
        .bind(code)
        .bind(max_uses.map(i64::from))
        .bind(expires_at.map(|t| t as i64))
        .bind(created_at as i64)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(NodeInvite {
                id,
                node_id,
                created_by,
                invite_code: code.to_string(),
                max_uses,
                current_uses: 0,
                expires_at,
                created_at,
            }),
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
                Err(InsertInviteError::Collision)
            }
            Err(e) => Err(InsertInviteError::Refused(unavailable(&e))),
        }
    }

    /// REQ-22 without consuming, for the preview (REQ-39): the invite with
    /// `code` if it is valid for redemption at `now`, else the refusal of
    /// the first failing condition in the order V1 to V6.
    pub async fn check_invite(&self, code: &str, now: u64) -> Result<NodeInvite, AdmissionError> {
        let mut conn = self.pool.acquire().await.map_err(|e| unavailable(&e))?;
        let row = invite_row_on(&mut conn, code)
            .await
            .map_err(|e| unavailable(&e))?
            .ok_or(AdmissionError::InviteInvalid)?;
        let node_id = Uuid::parse_str(&row.node_id).map_err(|_| AdmissionError::InviteInvalid)?;
        classify_v1_to_v4(&mut conn, &row, node_id, now).await?;
        self.check_invite_creator_on(&mut conn, &row, node_id)
            .await?;
        let invite = sqlx::query(
            "SELECT id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at \
             FROM node_invites WHERE invite_code = ?",
        )
        .bind(code)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| unavailable(&e))?
        .ok_or(AdmissionError::InviteInvalid)?;
        super::parse_node_invite(&invite).map_err(|_| AdmissionError::InviteInvalid)
    }

    /// V5 and V6 of REQ-22 on a connection: the creator is not the reserved
    /// user and holds admission authority in the invite's node now.
    async fn check_invite_creator_on(
        &self,
        conn: &mut SqliteConnection,
        row: &InviteRow,
        node_id: Uuid,
    ) -> Result<(), AdmissionError> {
        let creator =
            Uuid::parse_str(&row.created_by).map_err(|_| AdmissionError::InviteInvalid)?;
        if is_reserved_user(creator) {
            return Err(AdmissionError::InviteInvalid);
        }
        self.faults
            .check("admission:authority")
            .map_err(|e| unavailable(&e))?;
        if !admission_authority_on(conn, node_id, creator)
            .await
            .map_err(|e| unavailable(&e))?
        {
            return Err(AdmissionError::InviteInvalid);
        }
        Ok(())
    }

    // ── The admission transaction (section 6.6.1) ──

    /// Run one admission for an entry point (REQ-45 steps 4 to 8) in a single
    /// `BEGIN IMMEDIATE` transaction. The caller has authenticated, validated
    /// the request syntax and charged `MembershipChange`; it broadcasts the
    /// join after this returns `Joined`. Every failure rolls the transaction
    /// back, including an invite consume made earlier in it.
    pub async fn admit(
        &self,
        ctx: &AdmissionContext,
        entry: &AdmissionEntry,
        limiter: &RateLimiter,
    ) -> Result<AdmissionOutcome, AdmissionError> {
        // SQLite serializes writers anyway; serializing admissions in-process
        // keeps them from holding several pooled connections while they wait
        // for the write lock (section 11.3).
        let _serial = self.admission_lock.lock().await;
        let now = super::now();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| unavailable(&e))?;
        match self.admit_in_tx(&mut tx, ctx, entry, limiter, now).await {
            Ok(outcome) => {
                tx.commit().await.map_err(|e| unavailable(&e))?;
                Ok(outcome)
            }
            Err(e) => {
                let _ = tx.rollback().await;
                Err(e)
            }
        }
    }

    async fn admit_in_tx(
        &self,
        conn: &mut SqliteConnection,
        ctx: &AdmissionContext,
        entry: &AdmissionEntry,
        limiter: &RateLimiter,
        now: u64,
    ) -> Result<AdmissionOutcome, AdmissionError> {
        // Step 4: identify the node.
        let (node, invite_code, names_node) = match entry {
            AdmissionEntry::Node {
                node_id,
                invite_code,
            } => {
                if is_reserved_node(*node_id) {
                    return Err(AdmissionError::NodeNotFound);
                }
                let node = node_row_on(conn, *node_id)
                    .await
                    .map_err(|e| unavailable(&e))?
                    .ok_or(AdmissionError::NodeNotFound)?;
                (node, invite_code.as_deref(), true)
            }
            AdmissionEntry::InviteCode { code } => {
                let row = invite_row_on(conn, code)
                    .await
                    .map_err(|e| unavailable(&e))?
                    .ok_or(AdmissionError::InviteInvalid)?;
                let node_id =
                    Uuid::parse_str(&row.node_id).map_err(|_| AdmissionError::InviteInvalid)?;
                if is_reserved_node(node_id) {
                    return Err(AdmissionError::InviteInvalid);
                }
                let node = node_row_on(conn, node_id)
                    .await
                    .map_err(|e| unavailable(&e))?
                    .ok_or(AdmissionError::InviteInvalid)?;
                (node, Some(code.as_str()), false)
            }
        };
        if is_reserved_user(ctx.user_id) {
            return Err(AdmissionError::Forbidden);
        }

        // Step 5: an existing member consumes nothing.
        if is_member_on(conn, node.id, ctx.user_id)
            .await
            .map_err(|e| unavailable(&e))?
        {
            return Err(AdmissionError::AlreadyMember);
        }

        // Steps 6 and 7: resolve the request to exactly one grant.
        let grant = if node.owner_id == ctx.user_id {
            AdmissionGrant::OwnerSelf { node: node.id }
        } else if let Some(code) = invite_code {
            AdmissionGrant::Invite {
                code: code.to_string(),
                expected_node: Some(node.id),
            }
        } else if names_node && node.join_policy == "request" {
            return self
                .create_join_request_on(conn, ctx, &node, limiter, now)
                .await;
        } else {
            return Err(AdmissionError::InviteRequired);
        };

        self.admit_with_grant(conn, ctx, &node, &grant, now).await?;
        Ok(AdmissionOutcome::Joined {
            node_id: node.id,
            node_name: node.name,
            grant,
        })
    }

    /// The single admission function (REQ-18): admit `ctx.user_id` to `node`
    /// under exactly one grant, on the admission transaction's connection.
    ///
    /// - `Invite`: consume the invite (V2 to V4, bound to the node), classify
    ///   a failed consume per REQ-22, then check V5 and V6;
    /// - `ApprovedRequest`: the caller has already consumed the request row;
    /// - `OwnerSelf`: nothing is consumed and REQ-24(c) to (e) are skipped
    ///   (REQ-26).
    ///
    /// Then REQ-24(c) to (e), the clean slate and the membership (REQ-25).
    async fn admit_with_grant(
        &self,
        conn: &mut SqliteConnection,
        ctx: &AdmissionContext,
        node: &NodeRow,
        grant: &AdmissionGrant,
        now: u64,
    ) -> Result<(), AdmissionError> {
        let marker = match grant {
            AdmissionGrant::OwnerSelf { .. } => MARKER_OWNER,
            AdmissionGrant::Invite {
                code,
                expected_node,
            } => {
                self.consume_invite_on(conn, code, expected_node.unwrap_or(node.id), now)
                    .await?;
                self.check_admission_rules_on(conn, node.id, ctx, now)
                    .await?;
                MARKER_MEMBER
            }
            AdmissionGrant::ApprovedRequest { .. } => {
                self.check_admission_rules_on(conn, node.id, ctx, now)
                    .await?;
                MARKER_MEMBER
            }
        };
        write_admission(
            conn,
            node.id,
            ctx.user_id,
            marker,
            ctx.device_fingerprint_hash.as_deref(),
            now,
        )
        .await
        .map_err(|e| unavailable(&e))
    }

    /// The atomic invite consume (REQ-23): the only statement that increments
    /// `current_uses`, conditional on V2 to V4. When it changes no row, the
    /// invite is classified per REQ-22; after it, V5 and V6 are checked.
    async fn consume_invite_on(
        &self,
        conn: &mut SqliteConnection,
        code: &str,
        node_id: Uuid,
        now: u64,
    ) -> Result<(), AdmissionError> {
        self.faults
            .check("admission:invite_consume")
            .map_err(|e| unavailable(&e))?;
        let changed = sqlx::query(
            "UPDATE node_invites SET current_uses = current_uses + 1 \
             WHERE invite_code = ? AND node_id = ? AND node_id != ? \
             AND (max_uses IS NULL OR current_uses < max_uses) \
             AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(code)
        .bind(node_id.to_string())
        .bind(DM_SYSTEM_NODE_ID.to_string())
        .bind(now as i64)
        .execute(&mut *conn)
        .await
        .map_err(|e| unavailable(&e))?
        .rows_affected();
        let row = invite_row_on(conn, code)
            .await
            .map_err(|e| unavailable(&e))?
            .ok_or(AdmissionError::InviteInvalid)?;
        if changed != 1 {
            // Classify V1 to V4 in order; a consume that failed although they
            // hold cannot happen inside the transaction, but is refused too.
            classify_v1_to_v4(conn, &row, node_id, now).await?;
            return Err(AdmissionError::InviteInvalid);
        }
        self.check_invite_creator_on(conn, &row, node_id).await
    }

    /// REQ-24 (c) to (e) on the admission connection.
    async fn check_admission_rules_on(
        &self,
        conn: &mut SqliteConnection,
        node_id: Uuid,
        ctx: &AdmissionContext,
        now: u64,
    ) -> Result<(), AdmissionError> {
        // (c) public-key-hash ban.
        self.faults
            .check("admission:ban_check")
            .map_err(|e| unavailable(&e))?;
        let public_key_hash = public_key_hash_on(conn, ctx.user_id)
            .await
            .map_err(|e| unavailable(&e))?
            .ok_or(AdmissionError::Forbidden)?;
        if is_banned_on(conn, node_id, &public_key_hash, now)
            .await
            .map_err(|e| unavailable(&e))?
        {
            return Err(AdmissionError::Banned);
        }

        // (d) device checks.
        self.faults
            .check("admission:device_check")
            .map_err(|e| unavailable(&e))?;
        match ctx.device_fingerprint_hash.as_deref() {
            None => {
                if has_device_bans_on(conn, node_id, now)
                    .await
                    .map_err(|e| unavailable(&e))?
                {
                    return Err(AdmissionError::FingerprintRequired);
                }
            }
            Some(fingerprint) => {
                if is_device_banned_on(conn, node_id, fingerprint, now)
                    .await
                    .map_err(|e| unavailable(&e))?
                {
                    return Err(AdmissionError::DeviceBanned);
                }
                let cap = max_accounts_per_device_on(conn, node_id)
                    .await
                    .map_err(|e| unavailable(&e))?;
                if cap > 0
                    && count_members_with_fingerprint_on(conn, node_id, fingerprint)
                        .await
                        .map_err(|e| unavailable(&e))?
                        >= cap
                {
                    return Err(AdmissionError::DeviceLimit);
                }
            }
        }

        // (e) per-node build allowlist.
        self.faults
            .check("admission:allowlist")
            .map_err(|e| unavailable(&e))?;
        if !is_build_hash_allowed_on(conn, node_id, &ctx.build_hash)
            .await
            .map_err(|e| unavailable(&e))?
        {
            return Err(AdmissionError::BuildNotAllowed);
        }
        Ok(())
    }

    /// The request path of REQ-45 step 7 (REQ-30): create or refresh the
    /// caller's join request, inside the admission transaction.
    async fn create_join_request_on(
        &self,
        conn: &mut SqliteConnection,
        ctx: &AdmissionContext,
        node: &NodeRow,
        limiter: &RateLimiter,
        now: u64,
    ) -> Result<AdmissionOutcome, AdmissionError> {
        if ctx.build_hash.len() > MAX_BUILD_HASH_LEN {
            return Err(AdmissionError::InvalidRequest(
                "Build hash must not exceed 128 characters".into(),
            ));
        }
        limiter
            .check(ctx.user_id, ActionType::JoinRequestCreate)
            .await
            .map_err(|e| AdmissionError::RateLimited {
                retry_after: e.retry_after_secs,
            })?;
        self.check_admission_rules_on(conn, node.id, ctx, now)
            .await?;

        let node_text = node.id.to_string();
        let user_text = ctx.user_id.to_string();
        let own = sqlx::query(
            "SELECT COUNT(*) AS count FROM node_join_requests \
             WHERE node_id = ? AND user_id = ? AND expires_at > ?",
        )
        .bind(&node_text)
        .bind(&user_text)
        .bind(now as i64)
        .fetch_one(&mut *conn)
        .await
        .and_then(|row| row.try_get::<i64, _>("count"))
        .map_err(|e| unavailable(&e))?;
        if own == 0 {
            let others = sqlx::query(
                "SELECT COUNT(*) AS count FROM node_join_requests \
                 WHERE node_id = ? AND user_id != ? AND expires_at > ?",
            )
            .bind(&node_text)
            .bind(&user_text)
            .bind(now as i64)
            .fetch_one(&mut *conn)
            .await
            .and_then(|row| row.try_get::<i64, _>("count"))
            .map_err(|e| unavailable(&e))?;
            if others >= MAX_PENDING_JOIN_REQUESTS {
                return Err(AdmissionError::JoinRequestsFull);
            }
        }

        let expires_at = now + JOIN_REQUEST_LIFETIME_SECS;
        sqlx::query(
            "INSERT INTO node_join_requests \
             (node_id, user_id, created_at, expires_at, device_fingerprint_hash, build_hash) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(node_id, user_id) DO UPDATE SET created_at = excluded.created_at, \
             expires_at = excluded.expires_at, \
             device_fingerprint_hash = excluded.device_fingerprint_hash, \
             build_hash = excluded.build_hash",
        )
        .bind(&node_text)
        .bind(&user_text)
        .bind(now as i64)
        .bind(expires_at as i64)
        .bind(ctx.device_fingerprint_hash.as_deref())
        .bind(&ctx.build_hash)
        .execute(&mut *conn)
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(AdmissionOutcome::Pending {
            node_id: node.id,
            expires_at,
        })
    }

    /// The approval transaction of section 6.6.1 (REQ-32, REQ-45 approvals):
    /// `approver` admits `requester` to `node_id` under an
    /// `ApprovedRequest` grant. The consume step deletes the unexpired
    /// pending request and must delete exactly one row; a failure after it
    /// keeps the request deleted. The request's stored fingerprint and build
    /// hash are the request context. The caller broadcasts the join and sends
    /// `node_joined` to the requester after a `Joined` outcome.
    pub async fn approve_join_request(
        &self,
        approver: Uuid,
        node_id: Uuid,
        requester: Uuid,
    ) -> Result<AdmissionOutcome, AdmissionError> {
        if is_reserved_node(node_id) {
            return Err(AdmissionError::NodeNotFound);
        }
        let _serial = self.admission_lock.lock().await;
        let now = super::now();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| unavailable(&e))?;
        let node = match node_row_on(&mut tx, node_id).await {
            Ok(Some(node)) => node,
            Ok(None) => {
                let _ = tx.rollback().await;
                return Err(AdmissionError::NodeNotFound);
            }
            Err(e) => {
                let _ = tx.rollback().await;
                return Err(unavailable(&e));
            }
        };
        // Refusals before the consume change nothing.
        let before_consume = async {
            self.faults
                .check("admission:authority")
                .map_err(|e| unavailable(&e))?;
            if !admission_authority_on(&mut tx, node_id, approver)
                .await
                .map_err(|e| unavailable(&e))?
            {
                return Err(AdmissionError::Forbidden);
            }
            if is_reserved_user(requester) {
                return Err(AdmissionError::Forbidden);
            }
            let row = sqlx::query(
                "DELETE FROM node_join_requests WHERE node_id = ? AND user_id = ? AND expires_at > ? \
                 RETURNING device_fingerprint_hash, build_hash",
            )
            .bind(node_id.to_string())
            .bind(requester.to_string())
            .bind(now as i64)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| unavailable(&e))?
            .ok_or(AdmissionError::RequestNotFound)?;
            let device_fingerprint_hash: Option<String> = row
                .try_get("device_fingerprint_hash")
                .map_err(|e| unavailable(&e))?;
            let build_hash: Option<String> =
                row.try_get("build_hash").map_err(|e| unavailable(&e))?;
            Ok(AdmissionContext {
                user_id: requester,
                device_fingerprint_hash,
                build_hash: build_hash.unwrap_or_default(),
            })
        }
        .await;
        let ctx = match before_consume {
            Ok(ctx) => ctx,
            Err(e) => {
                let _ = tx.rollback().await;
                return Err(e);
            }
        };
        // After the consume, a refusal commits: only the request's deletion
        // is kept, nothing else was written.
        let grant = AdmissionGrant::ApprovedRequest {
            node: node_id,
            requester,
            approver,
        };
        let admitted = async {
            if is_member_on(&mut tx, node_id, requester)
                .await
                .map_err(|e| unavailable(&e))?
            {
                return Err(AdmissionError::AlreadyMember);
            }
            self.admit_with_grant(&mut tx, &ctx, &node, &grant, now)
                .await
        }
        .await;
        match admitted {
            Ok(()) => {
                tx.commit().await.map_err(|e| unavailable(&e))?;
                Ok(AdmissionOutcome::Joined {
                    node_id,
                    node_name: node.name,
                    grant,
                })
            }
            Err(AdmissionError::Unavailable) => {
                let _ = tx.rollback().await;
                Err(AdmissionError::Unavailable)
            }
            Err(refusal) => {
                tx.commit().await.map_err(|e| unavailable(&e))?;
                Err(refusal)
            }
        }
    }
}

// ── Membership removal (REQ-34, REQ-35, REQ-50) ──

/// A ban row written by `POST /nodes/:id/bans`, in the same transaction as
/// the member removal it causes (REQ-50).
#[derive(Debug, Clone, Copy)]
pub struct NewBan<'a> {
    pub public_key_hash: &'a str,
    pub banned_by: Uuid,
    pub reason_encrypted: Option<&'a [u8]>,
    pub expires_at: Option<u64>,
    pub device_fingerprint_hash: Option<&'a str>,
}

/// One `PATCH /nodes/:id` as the database applies it (REQ-29). Every field
/// is optional; `name` and `description` are already stripped for the
/// relay's metadata mode and `max_accounts_per_device` is already clamped
/// (0 means unlimited).
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeSettingsUpdate<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub max_accounts_per_device: Option<i64>,
    pub join_policy: Option<crate::node::JoinPolicy>,
    /// The request named a field besides `join_policy` (an empty request
    /// counts as one, as before), so today's settings rule applies to it
    /// even when metadata stripping dropped the field's value.
    pub other_fields: bool,
}

impl NodeSettingsUpdate<'_> {
    /// The request changes the join policy and nothing else.
    pub fn policy_only(&self) -> bool {
        self.join_policy.is_some() && !self.other_fields
    }
}

/// The membership removal the single removal routine runs (REQ-50).
#[derive(Debug, Clone, Copy)]
pub enum Removal<'a> {
    /// The member leaves (REQ-34). Besides the membership and the queued
    /// distributions, the leaver's channel subscriptions and role
    /// assignments in the node are deleted.
    Leave { user_id: Uuid },
    /// A moderator kicks the member (REQ-35). The rest of kick removal
    /// (subscriptions, roles, sockets, tokens) belongs to roadmap item 4.
    Kick { user_id: Uuid },
    /// A ban: the ban row is written, then the account with the banned
    /// public-key hash, if any, is removed as by a kick.
    Ban(NewBan<'a>),
}

/// What the removal transaction did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemberRemoval {
    /// The user whose membership row was deleted; `None` when the delete
    /// removed no row, in which case nothing else changed (except a ban's
    /// own row).
    pub removed_user: Option<Uuid>,
    /// The node's channels at removal time, for the rotation hook. Empty
    /// when nothing was removed.
    pub channel_ids: Vec<Uuid>,
}

/// Write a ban row (insert or replace) on a connection.
pub(super) async fn insert_ban_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
    ban: &NewBan<'_>,
    banned_at: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR REPLACE INTO node_bans (node_id, public_key_hash, banned_by, banned_at, reason_encrypted, expires_at, device_fingerprint_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(node_id.to_string())
    .bind(ban.public_key_hash)
    .bind(ban.banned_by.to_string())
    .bind(banned_at as i64)
    .bind(ban.reason_encrypted)
    .bind(ban.expires_at.map(|t| t as i64))
    .bind(ban.device_fingerprint_hash)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The id of the account with this public-key hash, if one exists and its
/// id parses.
async fn user_id_by_public_key_hash_on(
    conn: &mut SqliteConnection,
    public_key_hash: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    let id: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE public_key_hash = ?")
        .bind(public_key_hash)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(id.and_then(|id| Uuid::parse_str(&id).ok()))
}

/// The ids of the node's channels, in display order. Rows whose id does not
/// parse are skipped rather than failing the removal.
async fn node_channel_ids_on(
    conn: &mut SqliteConnection,
    node_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE node_id = ? ORDER BY position ASC")
            .bind(node_id.to_string())
            .fetch_all(&mut *conn)
            .await?;
    Ok(ids
        .iter()
        .filter_map(|id| Uuid::parse_str(id).ok())
        .collect())
}

impl Database {
    /// Delete the membership row of `user_id` in `node_id` on the removal
    /// transaction's connection and return the number of rows deleted
    /// (REQ-50). Private to this module: its only caller is the removal
    /// routine, [`Database::remove_member`]. Fault point `removal:delete`.
    async fn remove_node_member(
        faults: &crate::faults::FaultPlan,
        conn: &mut SqliteConnection,
        node_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        faults.check("removal:delete")?;
        let result = sqlx::query("DELETE FROM node_members WHERE node_id = ? AND user_id = ?")
            .bind(node_id.to_string())
            .bind(user_id.to_string())
            .execute(&mut *conn)
            .await?;
        Ok(result.rows_affected())
    }

    /// The single removal routine of leave, kick and ban, database side
    /// (REQ-34 steps 4 and 5, REQ-35, REQ-50). In one `BEGIN IMMEDIATE`
    /// transaction it writes a ban's row, deletes the membership row and,
    /// only when exactly one row was deleted, the queued sender-key
    /// distributions to and from the removed user in the node's channels
    /// and, for a leave, the leaver's channel subscriptions and role
    /// assignments in the node.
    ///
    /// When no membership row was deleted nothing else changes (a ban keeps
    /// its row). Any database error rolls everything back and gives
    /// `unavailable`. The caller runs the removal hooks after this returns a
    /// removed user (`admission::remove_member`), never while the
    /// transaction is held.
    pub async fn remove_member(
        &self,
        node_id: Uuid,
        removal: Removal<'_>,
    ) -> Result<MemberRemoval, AdmissionError> {
        // Membership changes are serialized in-process like admissions
        // (section 11.3).
        let _serial = self.admission_lock.lock().await;
        let now = super::now();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| unavailable(&e))?;
        match self
            .remove_member_in_tx(&mut tx, node_id, removal, now)
            .await
        {
            Ok(outcome) => {
                tx.commit().await.map_err(|e| unavailable(&e))?;
                Ok(outcome)
            }
            Err(e) => {
                let _ = tx.rollback().await;
                Err(unavailable(&e))
            }
        }
    }

    async fn remove_member_in_tx(
        &self,
        conn: &mut SqliteConnection,
        node_id: Uuid,
        removal: Removal<'_>,
        now: u64,
    ) -> Result<MemberRemoval, sqlx::Error> {
        let (user_id, leave) = match removal {
            Removal::Leave { user_id } => (Some(user_id), true),
            Removal::Kick { user_id } => (Some(user_id), false),
            Removal::Ban(ban) => {
                insert_ban_on(conn, node_id, &ban, now).await?;
                (
                    user_id_by_public_key_hash_on(conn, ban.public_key_hash).await?,
                    false,
                )
            }
        };
        let Some(user_id) = user_id else {
            return Ok(MemberRemoval::default());
        };
        if Self::remove_node_member(&self.faults, conn, node_id, user_id).await? != 1 {
            return Ok(MemberRemoval::default());
        }
        let node = node_id.to_string();
        let user = user_id.to_string();
        sqlx::query(
            "DELETE FROM sender_key_distributions WHERE (from_user_id = ? OR to_user_id = ?) \
             AND channel_id IN (SELECT id FROM channels WHERE node_id = ?)",
        )
        .bind(&user)
        .bind(&user)
        .bind(&node)
        .execute(&mut *conn)
        .await?;
        if leave {
            sqlx::query(
                "DELETE FROM channel_members WHERE user_id = ? \
                 AND channel_id IN (SELECT id FROM channels WHERE node_id = ?)",
            )
            .bind(&user)
            .bind(&node)
            .execute(&mut *conn)
            .await?;
            sqlx::query("DELETE FROM member_roles WHERE node_id = ? AND member_id = ?")
                .bind(&node)
                .bind(&user)
                .execute(&mut *conn)
                .await?;
        }
        Ok(MemberRemoval {
            removed_user: Some(user_id),
            channel_ids: node_channel_ids_on(conn, node_id).await?,
        })
    }

    // ── Join requests (REQ-29 to REQ-33) ──

    /// Apply one `PATCH /nodes/:id` as `actor` (REQ-29) in a single
    /// `BEGIN IMMEDIATE` transaction: every field is authorized before
    /// anything is written, and either every field changes or none does.
    ///
    /// - A request that changes only the join policy may come from the owner
    ///   or a member holding MANAGE_NODE; a non-member's @everyone bits never
    ///   count.
    /// - Any other request keeps today's rule for the node settings: the
    ///   actor must be a member holding MANAGE_NODE (an owner without a
    ///   membership row included).
    ///
    /// Switching to `invite` deletes the node's pending join requests in the
    /// same transaction. Fault point `admission:node_settings`, after the
    /// writes and before the commit.
    pub async fn update_node_settings(
        &self,
        actor: Uuid,
        node_id: Uuid,
        update: NodeSettingsUpdate<'_>,
    ) -> Result<(), AdmissionError> {
        if is_reserved_node(node_id) {
            return Err(AdmissionError::NodeNotFound);
        }
        let _serial = self.admission_lock.lock().await;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| unavailable(&e))?;
        let result = async {
            let node = node_row_on(&mut tx, node_id)
                .await
                .map_err(|e| unavailable(&e))?
                .ok_or(AdmissionError::NodeNotFound)?;
            let allowed = if update.policy_only() && node.owner_id == actor {
                true
            } else if is_reserved_user(actor)
                || !is_member_on(&mut tx, node_id, actor)
                    .await
                    .map_err(|e| unavailable(&e))?
            {
                false
            } else {
                let perms = node_permissions_on(&mut tx, node_id, actor)
                    .await
                    .map_err(|e| unavailable(&e))?
                    .unwrap_or(0);
                perms & MANAGE_NODE != 0
            };
            if !allowed {
                return Err(AdmissionError::Forbidden);
            }
            let node = node_id.to_string();
            if let Some(name) = update.name {
                sqlx::query("UPDATE nodes SET name = ? WHERE id = ?")
                    .bind(name)
                    .bind(&node)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| unavailable(&e))?;
            }
            if let Some(description) = update.description {
                sqlx::query("UPDATE nodes SET description = ? WHERE id = ?")
                    .bind(description)
                    .bind(&node)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| unavailable(&e))?;
            }
            if let Some(limit) = update.max_accounts_per_device {
                sqlx::query("UPDATE nodes SET max_accounts_per_device = ? WHERE id = ?")
                    .bind(limit)
                    .bind(&node)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| unavailable(&e))?;
            }
            if let Some(policy) = update.join_policy {
                sqlx::query("UPDATE nodes SET join_policy = ? WHERE id = ?")
                    .bind(policy.as_str())
                    .bind(&node)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| unavailable(&e))?;
                if policy == crate::node::JoinPolicy::Invite {
                    sqlx::query("DELETE FROM node_join_requests WHERE node_id = ?")
                        .bind(&node)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| unavailable(&e))?;
                }
            }
            self.faults
                .check("admission:node_settings")
                .map_err(|e| unavailable(&e))?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => tx.commit().await.map_err(|e| unavailable(&e)),
            Err(e) => {
                let _ = tx.rollback().await;
                Err(e)
            }
        }
    }

    /// The node's unexpired join requests, oldest first, at most
    /// [`MAX_PENDING_JOIN_REQUESTS`] (REQ-31, REQ-33). Only a user with
    /// admission authority may list them.
    pub async fn list_join_requests(
        &self,
        approver: Uuid,
        node_id: Uuid,
    ) -> Result<Vec<crate::models::JoinRequestInfo>, AdmissionError> {
        let now = super::now();
        self.faults
            .check("admission:authority")
            .map_err(|e| unavailable(&e))?;
        let mut conn = self.pool.acquire().await.map_err(|e| unavailable(&e))?;
        if !admission_authority_on(&mut conn, node_id, approver)
            .await
            .map_err(|e| unavailable(&e))?
        {
            return Err(AdmissionError::Forbidden);
        }
        let rows = sqlx::query(
            "SELECT r.user_id, u.public_key_hash, p.display_name, r.created_at, r.expires_at \
             FROM node_join_requests r JOIN users u ON u.id = r.user_id \
             LEFT JOIN user_profiles p ON p.user_id = r.user_id \
             WHERE r.node_id = ? AND r.expires_at > ? \
             ORDER BY r.created_at ASC, r.user_id ASC LIMIT ?",
        )
        .bind(node_id.to_string())
        .bind(now as i64)
        .bind(MAX_PENDING_JOIN_REQUESTS)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| unavailable(&e))?;
        let mut requests = Vec::with_capacity(rows.len());
        for row in rows {
            let user_id: String = row.try_get("user_id").map_err(|e| unavailable(&e))?;
            let Ok(user_id) = Uuid::parse_str(&user_id) else {
                continue;
            };
            requests.push(crate::models::JoinRequestInfo {
                user_id,
                public_key_hash: row
                    .try_get("public_key_hash")
                    .map_err(|e| unavailable(&e))?,
                display_name: row.try_get("display_name").map_err(|e| unavailable(&e))?,
                created_at: row
                    .try_get::<i64, _>("created_at")
                    .map_err(|e| unavailable(&e))?
                    .max(0) as u64,
                expires_at: row
                    .try_get::<i64, _>("expires_at")
                    .map_err(|e| unavailable(&e))?
                    .max(0) as u64,
            });
        }
        Ok(requests)
    }

    /// Deny `requester`'s unexpired join request as `approver` (REQ-31): one
    /// transaction that checks admission authority, then deletes the row.
    /// No such row gives `request_not_found`.
    pub async fn deny_join_request(
        &self,
        approver: Uuid,
        node_id: Uuid,
        requester: Uuid,
    ) -> Result<(), AdmissionError> {
        if is_reserved_node(node_id) {
            return Err(AdmissionError::NodeNotFound);
        }
        let _serial = self.admission_lock.lock().await;
        let now = super::now();
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|e| unavailable(&e))?;
        let result = async {
            if node_row_on(&mut tx, node_id)
                .await
                .map_err(|e| unavailable(&e))?
                .is_none()
            {
                return Err(AdmissionError::NodeNotFound);
            }
            self.faults
                .check("admission:authority")
                .map_err(|e| unavailable(&e))?;
            if !admission_authority_on(&mut tx, node_id, approver)
                .await
                .map_err(|e| unavailable(&e))?
            {
                return Err(AdmissionError::Forbidden);
            }
            let deleted = sqlx::query(
                "DELETE FROM node_join_requests WHERE node_id = ? AND user_id = ? AND expires_at > ?",
            )
            .bind(node_id.to_string())
            .bind(requester.to_string())
            .bind(now as i64)
            .execute(&mut *tx)
            .await
            .map_err(|e| unavailable(&e))?
            .rows_affected();
            if deleted != 1 {
                return Err(AdmissionError::RequestNotFound);
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => tx.commit().await.map_err(|e| unavailable(&e)),
            Err(e) => {
                let _ = tx.rollback().await;
                Err(e)
            }
        }
    }

    /// Withdraw `user_id`'s own unexpired join request to `node_id`
    /// (REQ-31). No such row gives `request_not_found`.
    pub async fn withdraw_join_request(
        &self,
        node_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AdmissionError> {
        let deleted = sqlx::query(
            "DELETE FROM node_join_requests WHERE node_id = ? AND user_id = ? AND expires_at > ?",
        )
        .bind(node_id.to_string())
        .bind(user_id.to_string())
        .bind(super::now() as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?
        .rows_affected();
        if deleted == 1 {
            Ok(())
        } else {
            Err(AdmissionError::RequestNotFound)
        }
    }

    /// Delete every join request that has expired at `now` (REQ-33); the
    /// relay's 5-minute maintenance task calls this. Returns the number of
    /// rows deleted.
    pub async fn purge_expired_join_requests(&self, now: u64) -> anyhow::Result<u64> {
        let result = sqlx::query("DELETE FROM node_join_requests WHERE expires_at <= ?")
            .bind(now as i64)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

/// V1 to V4 of REQ-22 for an existing invite row (V1), in order: its node
/// exists, is not reserved and is the expected node (V2), it has not expired
/// at `now` (V3), and it has uses left (V4).
async fn classify_v1_to_v4(
    conn: &mut SqliteConnection,
    row: &InviteRow,
    expected_node: Uuid,
    now: u64,
) -> Result<(), AdmissionError> {
    let node_id = Uuid::parse_str(&row.node_id).map_err(|_| AdmissionError::InviteInvalid)?;
    if node_id != expected_node || is_reserved_node(node_id) {
        return Err(AdmissionError::InviteInvalid);
    }
    if node_row_on(conn, node_id)
        .await
        .map_err(|e| unavailable(&e))?
        .is_none()
    {
        return Err(AdmissionError::InviteInvalid);
    }
    if let Some(expires_at) = row.expires_at {
        if now as i64 >= expires_at {
            return Err(AdmissionError::InviteExpired);
        }
    }
    if let Some(max_uses) = row.max_uses {
        if row.current_uses >= max_uses {
            return Err(AdmissionError::InviteExhausted);
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "test-helpers"))]
impl Database {
    /// Test-only raw seeding of a membership, bypassing admission. Inserts a
    /// `node_members` row with the given legacy marker and, for `Admin` and
    /// `Moderator`, assigns the seeded role of that name if it exists, as
    /// legacy callers did. The admission triggers still apply, so the
    /// reserved node cannot be seeded.
    pub async fn seed_node_member(
        &self,
        node_id: Uuid,
        user_id: Uuid,
        role: crate::node::NodeRole,
    ) -> anyhow::Result<()> {
        use crate::node::NodeRole;
        use anyhow::Context;
        let mut conn = self.pool.acquire().await?;
        insert_member_row(
            &mut conn,
            node_id,
            user_id,
            role.as_str(),
            None,
            super::now(),
        )
        .await
        .context("Failed to seed node member")?;
        drop(conn);
        match role {
            NodeRole::Admin => self.assign_named_role(node_id, user_id, "Admin").await?,
            NodeRole::Moderator => {
                self.assign_named_role(node_id, user_id, "Moderator")
                    .await?
            }
            NodeRole::Member => {}
        }
        Ok(())
    }

    /// Test-only: drop the admission triggers, the first step of a fixture
    /// that simulates a database hijacked before the upgrade (SPEC-01 §10.1).
    /// The next open of the database creates them again.
    pub async fn drop_admission_triggers(&self) -> anyhow::Result<()> {
        use anyhow::Context;
        for name in super::repair::TRIGGER_NAMES {
            sqlx::query(&format!("DROP TRIGGER IF EXISTS {name}"))
                .execute(&self.pool)
                .await
                .context("Failed to drop an admission trigger")?;
        }
        Ok(())
    }

    /// Test-only access to the connection pool, for raw fixtures.
    pub fn raw_pool(&self) -> &super::Pool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-10 (REQ-10, REQ-18): the private raw insert cannot put a member into
    /// the reserved node; the trigger refuses it.
    #[tokio::test]
    async fn raw_member_insert_refused_on_reserved_node() {
        let db = Database::new(":memory:").await.unwrap();
        let user = db.create_user("t10-helper", "").await.unwrap();
        let mut conn = db.pool.acquire().await.unwrap();
        let err = insert_member_row(
            &mut conn,
            DM_SYSTEM_NODE_ID,
            user.id,
            MARKER_MEMBER,
            None,
            1,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("reserved_node"), "{err}");
    }
}
