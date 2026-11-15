//! The database side of version-2 attachments (SPEC-02 section 6.6.1).
//!
//! The `attachments` table holds one row per version-2 blob: an upload
//! reservation (state 2, "uploading"), a blob waiting for its message
//! (state 0, "pending") or a blob bound to a message (state 1, "claimed").
//! Rows carry no name, MIME type or path (REQ-34, REQ-43): the blob's path is
//! derived from the attachments directory and the row id.
//!
//! There are deliberately no foreign keys. The garbage collection of section
//! 6.6.3 treats a missing message or channel as the deletion signal, so no
//! deletion path has to know about attachments (section 9.6, D9).
//!
//! The reservation of REQ-33 is one `BEGIN IMMEDIATE` transaction that counts
//! and sums the user's and the node's rows, reads the free space, and inserts
//! the uploading row only if every limit holds. The claim of REQ-35 is one
//! `BEGIN IMMEDIATE` transaction that claims every listed pending row,
//! computes `seq` and inserts the message with its read gate, or changes
//! nothing. Reservations and claims are also serialized in-process, so
//! concurrent requests wait for the lock without holding pooled connections
//! (section 11.3).
//!
//! The legacy `files` table keeps its schema; this module adds its paginated
//! list (section 6.4.5) and the batched deletion of retirement (section 7.7).
//!
//! Every error returned here carries a class only, never an attachment id
//! (REQ-43).

use super::{Database, Pool};
use anyhow::{Context, Result};
use sqlx::Row;
use std::collections::HashSet;
use uuid::Uuid;

/// Ledger row written at the first start of a relay that implements SPEC-02.
/// Its `applied_at` is T0 of the legacy window (section 7.7).
pub const LEDGER_ATTACHMENTS_V2: &str = "spec02_attachments_v2";

/// Ledger row written when legacy retirement completes (section 7.7).
pub const LEDGER_LEGACY_RETIRED: &str = "spec02_legacy_retired";

/// Lifetime of an upload reservation (state 2): `created_at + 3600`
/// (section 6.6.1, REQ-41).
pub const RESERVATION_LIFETIME_SECS: i64 = 3600;

/// The section 6.6.1 DDL, run in `run_migrations` before SPEC-01's boot
/// repair. `relay_migrations` is SPEC-01's ledger, created here with the
/// identical definition in case this schema is applied first.
const DDL: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS attachments (
        id                 TEXT PRIMARY KEY NOT NULL,
        channel_id         TEXT NOT NULL,
        node_id            TEXT NULL,
        uploader_id        TEXT NOT NULL,
        message_id         TEXT NULL,
        state              INTEGER NOT NULL CHECK (state IN (0, 1, 2)),
        blob_size          INTEGER NOT NULL CHECK (blob_size >= 16),
        blob_sha256        BLOB NULL CHECK (blob_sha256 IS NULL OR length(blob_sha256) = 32),
        created_at         INTEGER NOT NULL,
        pending_expires_at INTEGER NULL,
        CHECK ((state = 2 AND message_id IS NULL AND blob_sha256 IS NULL AND pending_expires_at IS NOT NULL)
            OR (state = 0 AND message_id IS NULL AND blob_sha256 IS NOT NULL AND pending_expires_at IS NOT NULL)
            OR (state = 1 AND message_id IS NOT NULL AND blob_sha256 IS NOT NULL AND pending_expires_at IS NULL))
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_attachments_message  ON attachments (message_id)",
    "CREATE INDEX IF NOT EXISTS idx_attachments_channel  ON attachments (channel_id)",
    "CREATE INDEX IF NOT EXISTS idx_attachments_pending  ON attachments (state, pending_expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_attachments_uploader ON attachments (uploader_id)",
    "CREATE INDEX IF NOT EXISTS idx_attachments_node     ON attachments (node_id)",
    r#"CREATE TABLE IF NOT EXISTS relay_migrations (
        name TEXT PRIMARY KEY NOT NULL,
        applied_at INTEGER NOT NULL
    )"#,
];

/// Create the attachment schema (section 6.6.1).
pub(super) async fn create_schema(pool: &Pool) -> Result<()> {
    for statement in DDL {
        sqlx::query(statement)
            .execute(pool)
            .await
            .context("Failed to create attachment schema")?;
    }
    Ok(())
}

/// Write the `spec02_attachments_v2` ledger row unless it exists. Its
/// `applied_at` is the first start of this relay version, T0 of the legacy
/// window, and never changes afterwards.
pub(super) async fn record_first_start(pool: &Pool) -> Result<()> {
    sqlx::query("INSERT OR IGNORE INTO relay_migrations (name, applied_at) VALUES (?, ?)")
        .bind(LEDGER_ATTACHMENTS_V2)
        .bind(super::now() as i64)
        .execute(pool)
        .await
        .context("Failed to record the attachment ledger row")?;
    Ok(())
}

/// The lifecycle state of an attachment row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentState {
    /// State 0: uploaded, waiting for its message until `pending_expires_at`.
    Pending,
    /// State 1: bound to `message_id`; lives as long as that message.
    Claimed,
    /// State 2: an upload reservation; the body is still streaming.
    Uploading,
}

impl AttachmentState {
    /// The stored integer of the state.
    pub fn code(self) -> i64 {
        match self {
            AttachmentState::Pending => 0,
            AttachmentState::Claimed => 1,
            AttachmentState::Uploading => 2,
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(AttachmentState::Pending),
            1 => Some(AttachmentState::Claimed),
            2 => Some(AttachmentState::Uploading),
            _ => None,
        }
    }
}

/// One `attachments` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRecord {
    pub id: Uuid,
    pub channel_id: Uuid,
    /// The channel's node at upload; `None` for DM channels.
    pub node_id: Option<Uuid>,
    pub uploader_id: Uuid,
    pub message_id: Option<Uuid>,
    pub state: AttachmentState,
    /// The blob length; for an uploading row, the declared `Content-Length`.
    pub blob_size: u64,
    pub blob_sha256: Option<Vec<u8>>,
    pub created_at: i64,
    pub pending_expires_at: Option<i64>,
}

/// An upload reservation to insert (REQ-33).
#[derive(Debug, Clone)]
pub struct AttachmentReservation {
    pub id: Uuid,
    pub channel_id: Uuid,
    /// `None` for DM channels, which no node quota covers.
    pub node_id: Option<Uuid>,
    pub uploader_id: Uuid,
    /// The request's `Content-Length`.
    pub blob_size: u64,
    /// The relay clock at reservation time, in Unix seconds.
    pub now: i64,
}

/// The limits a reservation is checked against (section 6.6.4).
#[derive(Debug, Clone, Copy)]
pub struct ReservationLimits {
    /// `attachment_max_pending_per_user`: pending plus uploading rows.
    pub max_pending_per_user: u64,
    /// `attachment_quota_user_bytes`; 0 means unlimited.
    pub quota_user_bytes: u64,
    /// `attachment_quota_node_bytes`; 0 means unlimited.
    pub quota_node_bytes: u64,
    /// `attachments_min_free_bytes`.
    pub min_free_bytes: u64,
}

/// The outcome of a reservation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationOutcome {
    /// The uploading row was inserted; its deadline is `created_at + 3600`.
    Reserved { deadline: i64 },
    /// The user already has the maximum number of pending or uploading rows.
    /// `retry_after` is the time until the oldest of them expires, at least 1.
    TooManyPending { retry_after: u64 },
    /// The user's or the node's byte quota would be exceeded.
    QuotaExceeded,
    /// The free-space floor would be crossed.
    StorageFull,
}

/// The outcome of `DELETE /attachments/{id}` at the database (REQ-39).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingDeletion {
    /// The requester's pending row was deleted.
    Deleted,
    /// The requester uploaded the attachment and it is claimed.
    Claimed,
    /// Any other case: unknown id, another user's attachment, or an upload
    /// reservation.
    NotFound,
}

fn parse_uuid_column(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<Uuid> {
    let text: String = row.try_get(column)?;
    Uuid::parse_str(&text).context("Invalid UUID in attachments row")
}

fn parse_optional_uuid_column(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<Option<Uuid>> {
    let text: Option<String> = row.try_get(column)?;
    text.map(|t| Uuid::parse_str(&t).context("Invalid UUID in attachments row"))
        .transpose()
}

fn parse_record(row: &sqlx::sqlite::SqliteRow) -> Result<AttachmentRecord> {
    let state: i64 = row.try_get("state")?;
    let blob_size: i64 = row.try_get("blob_size")?;
    Ok(AttachmentRecord {
        id: parse_uuid_column(row, "id")?,
        channel_id: parse_uuid_column(row, "channel_id")?,
        node_id: parse_optional_uuid_column(row, "node_id")?,
        uploader_id: parse_uuid_column(row, "uploader_id")?,
        message_id: parse_optional_uuid_column(row, "message_id")?,
        state: AttachmentState::from_code(state).context("Invalid attachment state")?,
        blob_size: u64::try_from(blob_size).context("Invalid attachment size")?,
        blob_sha256: row.try_get("blob_sha256")?,
        created_at: row.try_get("created_at")?,
        pending_expires_at: row.try_get("pending_expires_at")?,
    })
}

/// Parse the ids a `RETURNING id` clause produced. Ids that are not UUIDs
/// cannot name a blob file and are skipped.
fn parse_returned_ids(ids: Vec<String>) -> Vec<Uuid> {
    ids.iter()
        .filter_map(|id| Uuid::parse_str(id).ok())
        .collect()
}

impl Database {
    /// The REQ-33 reservation: in one `BEGIN IMMEDIATE` transaction, count
    /// the user's pending and uploading rows, sum `blob_size` over the user's
    /// rows and the node's rows (DM channels have no node), read the free
    /// space and subtract every uploading row's `blob_size`, add the
    /// request's size to each figure, and insert the uploading row only if
    /// every limit holds.
    ///
    /// `free_bytes` reports the free space of the attachments directory. An
    /// error from it, like any database error, is returned and nothing is
    /// inserted.
    pub async fn reserve_attachment(
        &self,
        request: &AttachmentReservation,
        limits: &ReservationLimits,
        free_bytes: &(dyn Fn() -> std::io::Result<u64> + Send + Sync),
    ) -> Result<ReservationOutcome> {
        let size = i64::try_from(request.blob_size).context("Attachment size out of range")?;
        let _serial = self.attachment_lock.lock().await;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("Failed to begin the attachment reservation")?;
        self.faults.check("attachments:reserve")?;
        let uploader = request.uploader_id.to_string();

        let (pending, oldest_expiry): (i64, Option<i64>) = sqlx::query_as(
            "SELECT COUNT(*), MIN(pending_expires_at) FROM attachments \
             WHERE uploader_id = ? AND state IN (0, 2)",
        )
        .bind(&uploader)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to count pending attachments")?;
        if u64::try_from(pending).unwrap_or(u64::MAX) >= limits.max_pending_per_user {
            let retry_after = oldest_expiry
                .map(|expiry| expiry.saturating_sub(request.now))
                .unwrap_or(1)
                .max(1);
            tx.rollback().await.ok();
            return Ok(ReservationOutcome::TooManyPending {
                retry_after: u64::try_from(retry_after).unwrap_or(1),
            });
        }

        let user_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(blob_size), 0) FROM attachments WHERE uploader_id = ?",
        )
        .bind(&uploader)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to sum the user's attachments")?;
        if exceeds(limits.quota_user_bytes, user_bytes, size) {
            tx.rollback().await.ok();
            return Ok(ReservationOutcome::QuotaExceeded);
        }

        if let Some(node_id) = request.node_id {
            let node_bytes: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(blob_size), 0) FROM attachments WHERE node_id = ?",
            )
            .bind(node_id.to_string())
            .fetch_one(&mut *tx)
            .await
            .context("Failed to sum the node's attachments")?;
            if exceeds(limits.quota_node_bytes, node_bytes, size) {
                tx.rollback().await.ok();
                return Ok(ReservationOutcome::QuotaExceeded);
            }
        }

        let reserved: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(blob_size), 0) FROM attachments WHERE state = 2",
        )
        .fetch_one(&mut *tx)
        .await
        .context("Failed to sum the upload reservations")?;
        let free = free_bytes().context("Failed to read the free space")?;
        // In-flight bytes are counted twice, once on disk and once as
        // reserved, which errs on the safe side (section 6.6.1).
        let needed =
            i128::from(reserved.max(0)) + i128::from(size) + i128::from(limits.min_free_bytes);
        if i128::from(free) < needed {
            tx.rollback().await.ok();
            return Ok(ReservationOutcome::StorageFull);
        }

        let deadline = request.now.saturating_add(RESERVATION_LIFETIME_SECS);
        sqlx::query(
            "INSERT INTO attachments (id, channel_id, node_id, uploader_id, message_id, state, \
             blob_size, blob_sha256, created_at, pending_expires_at) \
             VALUES (?, ?, ?, ?, NULL, 2, ?, NULL, ?, ?)",
        )
        .bind(request.id.to_string())
        .bind(request.channel_id.to_string())
        .bind(request.node_id.map(|id| id.to_string()))
        .bind(&uploader)
        .bind(size)
        .bind(request.now)
        .bind(deadline)
        .execute(&mut *tx)
        .await
        .context("Failed to insert the upload reservation")?;
        tx.commit()
            .await
            .context("Failed to commit the upload reservation")?;
        Ok(ReservationOutcome::Reserved { deadline })
    }

    /// Turn an uploading row into a pending one once its blob is in place
    /// (REQ-34). Returns false if the reservation no longer exists, for
    /// example because the garbage collection removed it.
    pub async fn complete_attachment_upload(
        &self,
        id: Uuid,
        blob_sha256: &[u8; 32],
        pending_expires_at: i64,
    ) -> Result<bool> {
        self.faults.check("attachments:complete")?;
        let result = sqlx::query(
            "UPDATE attachments SET state = 0, blob_sha256 = ?, pending_expires_at = ? \
             WHERE id = ? AND state = 2",
        )
        .bind(&blob_sha256[..])
        .bind(pending_expires_at)
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .context("Failed to complete the attachment upload")?;
        Ok(result.rows_affected() == 1)
    }

    /// Delete the row of a failed or aborted upload, which releases its
    /// reservation (REQ-34). Claimed rows are never touched.
    pub async fn discard_attachment_upload(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM attachments WHERE id = ? AND state IN (0, 2)")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to discard the attachment upload")?;
        Ok(())
    }

    /// One attachment row, if it exists.
    pub async fn get_attachment(&self, id: Uuid) -> Result<Option<AttachmentRecord>> {
        let row = sqlx::query(
            "SELECT id, channel_id, node_id, uploader_id, message_id, state, blob_size, \
             blob_sha256, created_at, pending_expires_at FROM attachments WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to read the attachment")?;
        row.as_ref().map(parse_record).transpose()
    }

    /// Whether the message of a claimed attachment still exists in that
    /// channel and has not expired at `now` (`expires_at` null or in the
    /// future, REQ-38). An expired message that the sweep has not removed
    /// yet counts as gone.
    pub async fn attachment_message_is_live(
        &self,
        message_id: Uuid,
        channel_id: Uuid,
        now: i64,
    ) -> Result<bool> {
        let row: Option<(Option<i64>,)> =
            sqlx::query_as("SELECT expires_at FROM messages WHERE id = ? AND channel_id = ?")
                .bind(message_id.to_string())
                .bind(channel_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .context("Failed to read the attachment's message")?;
        Ok(match row {
            None => false,
            Some((None,)) => true,
            Some((Some(expires_at),)) => expires_at > now,
        })
    }

    /// `DELETE /attachments/{id}` (REQ-39): delete the row when it is pending
    /// and the requester uploaded it; report a claimed row only to its
    /// uploader; everything else is "not found".
    pub async fn delete_pending_attachment(
        &self,
        id: Uuid,
        requester: Uuid,
    ) -> Result<PendingDeletion> {
        let deleted: Option<String> = sqlx::query_scalar(
            "DELETE FROM attachments WHERE id = ? AND uploader_id = ? AND state = 0 RETURNING id",
        )
        .bind(id.to_string())
        .bind(requester.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to delete the pending attachment")?;
        if deleted.is_some() {
            return Ok(PendingDeletion::Deleted);
        }
        let state: Option<i64> =
            sqlx::query_scalar("SELECT state FROM attachments WHERE id = ? AND uploader_id = ?")
                .bind(id.to_string())
                .bind(requester.to_string())
                .fetch_optional(&self.pool)
                .await
                .context("Failed to read the attachment")?;
        Ok(match state {
            Some(1) => PendingDeletion::Claimed,
            _ => PendingDeletion::NotFound,
        })
    }

    // ── Garbage collection (section 6.6.3) ──

    /// GC statement 1: pending rows and upload reservations whose deadline
    /// has passed. Returns the deleted ids.
    pub async fn gc_expired_attachments(&self, now: i64) -> Result<Vec<Uuid>> {
        self.faults.check("attachments:gc")?;
        let ids: Vec<String> = sqlx::query_scalar(
            "DELETE FROM attachments WHERE state IN (0, 2) AND pending_expires_at <= ? RETURNING id",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .context("Failed to collect expired attachments")?;
        Ok(parse_returned_ids(ids))
    }

    /// GC statement 2: claimed rows whose message no longer exists.
    pub async fn gc_attachments_without_message(&self) -> Result<Vec<Uuid>> {
        let ids: Vec<String> = sqlx::query_scalar(
            "DELETE FROM attachments WHERE state = 1 \
             AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.id = attachments.message_id) \
             RETURNING id",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to collect attachments of deleted messages")?;
        Ok(parse_returned_ids(ids))
    }

    /// GC statement 3: rows of any state whose channel no longer exists.
    pub async fn gc_attachments_without_channel(&self) -> Result<Vec<Uuid>> {
        let ids: Vec<String> = sqlx::query_scalar(
            "DELETE FROM attachments \
             WHERE NOT EXISTS (SELECT 1 FROM channels c WHERE c.id = attachments.channel_id) \
             RETURNING id",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to collect attachments of deleted channels")?;
        Ok(parse_returned_ids(ids))
    }

    // ── Reconciliation (REQ-42) ──

    /// Whether any attachment row, of any state, has this id.
    pub async fn attachment_row_exists(&self, id: Uuid) -> Result<bool> {
        let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM attachments WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to look up an attachment row")?;
        Ok(found.is_some())
    }

    /// Whether an upload reservation (state 2) has this id.
    pub async fn uploading_attachment_exists(&self, id: Uuid) -> Result<bool> {
        let found: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM attachments WHERE id = ? AND state = 2")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .context("Failed to look up an upload reservation")?;
        Ok(found.is_some())
    }

    /// Ids of pending and claimed rows created at or before `cutoff`.
    pub async fn stored_attachments_created_before(&self, cutoff: i64) -> Result<Vec<Uuid>> {
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM attachments WHERE state IN (0, 1) AND created_at <= ?",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list stored attachments")?;
        Ok(parse_returned_ids(ids))
    }

    /// Delete a pending or claimed row whose blob is missing. Returns whether
    /// a row was deleted.
    pub async fn delete_stored_attachment_row(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM attachments WHERE id = ? AND state IN (0, 1)")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to delete an attachment row")?;
        Ok(result.rows_affected() > 0)
    }

    /// Every `files.id`, for the legacy part of the reconciliation. An error
    /// means the `files` table could not be read.
    pub async fn legacy_file_ids(&self) -> Result<HashSet<String>> {
        self.faults.check("attachments:legacy_files")?;
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM files")
            .fetch_all(&self.pool)
            .await
            .context("Failed to read the legacy files table")?;
        Ok(ids.into_iter().collect())
    }
}

// ── The claim in `ChannelMessage` and the edit guard (REQ-35, REQ-37) ──

/// The read gate of a message: it does not expire until every listed user
/// and every member of every listed role has read it, then `ttl_secs` runs.
#[derive(Debug, Clone, Copy)]
pub struct MessageGate<'a> {
    pub users: &'a [Uuid],
    pub roles: &'a [Uuid],
    pub ttl_secs: u64,
}

/// A message to store together with the attachments it claims (REQ-35).
#[derive(Debug, Clone, Copy)]
pub struct MessageWithAttachments<'a> {
    pub channel_id: Uuid,
    pub sender_id: Uuid,
    pub encrypted_payload: &'a [u8],
    pub reply_to: Option<Uuid>,
    pub expires_at: Option<u64>,
    pub gate: Option<MessageGate<'a>>,
    /// Validated, pairwise distinct ids (at most 10).
    pub attachment_ids: &'a [Uuid],
    /// The relay clock in Unix seconds: a pending row whose deadline is not
    /// after it has expired and does not qualify.
    pub now: i64,
}

/// The outcome of [`Database::store_message_claiming_attachments`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The message is stored and every listed attachment is claimed for it.
    Stored { message_id: Uuid, seq: i64 },
    /// These attachments did not qualify; nothing was stored or claimed.
    Unavailable(Vec<Uuid>),
}

// ── Legacy files (REQ-30, REQ-31) ──

/// Stored legacy names longer than this are returned as `""` (section
/// 6.4.5).
pub const LEGACY_NAME_MAX_BYTES: i64 = 4096;

/// One legacy `files` row as the legacy list returns it (section 6.4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFileRow {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub uploader_id: Uuid,
    /// The stored name bytes, or `None` when they exceed
    /// [`LEGACY_NAME_MAX_BYTES`] (never read whole in that case).
    pub name: Option<Vec<u8>>,
    pub file_size_bytes: i64,
    pub created_at: i64,
}

/// A legacy row to retire: its id and stored blob path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyBlob {
    pub id: String,
    pub storage_path: String,
}

impl Database {
    /// REQ-35 step 3: in one `BEGIN IMMEDIATE` transaction, move every
    /// listed attachment from pending to claimed with `message_id` set,
    /// compute `seq`, insert the message and set its read gate. Only rows
    /// that are pending, unexpired at `now`, uploaded by the sender and in
    /// the message's channel qualify. If any listed attachment does not
    /// qualify, everything is rolled back and the ids that did not qualify
    /// are returned. Any database error rolls back as well.
    ///
    /// Claims share the in-process lock of the reservations, so concurrent
    /// claims of one blob wait here and exactly one of them wins.
    pub async fn store_message_claiming_attachments(
        &self,
        message: &MessageWithAttachments<'_>,
    ) -> Result<ClaimOutcome> {
        let _serial = self.attachment_lock.lock().await;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("Failed to begin the attachment claim")?;
        let message_id = Uuid::new_v4();
        let channel = message.channel_id.to_string();
        let sender = message.sender_id.to_string();

        let mut unavailable = Vec::new();
        for id in message.attachment_ids {
            let claimed = sqlx::query(
                "UPDATE attachments SET state = 1, message_id = ?, pending_expires_at = NULL \
                 WHERE id = ? AND state = 0 AND uploader_id = ? AND channel_id = ? \
                 AND pending_expires_at > ?",
            )
            .bind(message_id.to_string())
            .bind(id.to_string())
            .bind(&sender)
            .bind(&channel)
            .bind(message.now)
            .execute(&mut *tx)
            .await
            .context("Failed to claim an attachment")?;
            if claimed.rows_affected() != 1 {
                unavailable.push(*id);
            }
        }
        if !unavailable.is_empty() {
            tx.rollback().await.ok();
            return Ok(ClaimOutcome::Unavailable(unavailable));
        }

        // The sequence number is computed under the write lock, so claimed
        // messages never share one (C139).
        let seq: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE channel_id = ?",
        )
        .bind(&channel)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to compute next sequence number")?;
        sqlx::query(
            "INSERT INTO messages (id, channel_id, sender_id, encrypted_payload, created_at, \
             reply_to, seq, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(message_id.to_string())
        .bind(&channel)
        .bind(&sender)
        .bind(message.encrypted_payload)
        .bind(super::now() as i64)
        .bind(message.reply_to.map(|id| id.to_string()))
        .bind(seq)
        .bind(
            message
                .expires_at
                .map(|t| i64::try_from(t).unwrap_or(i64::MAX)),
        )
        .execute(&mut *tx)
        .await
        .context("Failed to store message")?;
        if let Some(gate) = message.gate {
            let users = serde_json::to_string(gate.users).unwrap_or_else(|_| "[]".into());
            let roles = serde_json::to_string(gate.roles).unwrap_or_else(|_| "[]".into());
            sqlx::query(
                "UPDATE messages SET gate_users = ?, gate_roles = ?, gate_ttl_secs = ? WHERE id = ?",
            )
            .bind(users)
            .bind(roles)
            .bind(i64::try_from(gate.ttl_secs).unwrap_or(i64::MAX))
            .bind(message_id.to_string())
            .execute(&mut *tx)
            .await
            .context("Failed to set message read-gate")?;
        }

        self.faults.check("attachments:claim")?;
        tx.commit()
            .await
            .context("Failed to commit the attachment claim")?;
        Ok(ClaimOutcome::Stored { message_id, seq })
    }

    /// Whether `message_id` is a message of `sender_id` with claimed
    /// attachments, which cannot be edited (REQ-37). [`Database::edit_message`]
    /// refuses such edits; this tells the refusal apart from "not found".
    pub async fn authored_message_has_attachments(
        &self,
        message_id: Uuid,
        sender_id: Uuid,
    ) -> Result<bool> {
        let found: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM messages m JOIN attachments a ON a.message_id = m.id \
             WHERE m.id = ? AND m.sender_id = ? AND a.state = 1 LIMIT 1",
        )
        .bind(message_id.to_string())
        .bind(sender_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to look up the message's attachments")?;
        Ok(found.is_some())
    }

    /// The ids of the attachments claimed for a message.
    pub async fn claimed_attachment_ids(&self, message_id: Uuid) -> Result<Vec<Uuid>> {
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM attachments WHERE message_id = ? AND state = 1 ORDER BY id",
        )
        .bind(message_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to list the message's attachments")?;
        Ok(parse_returned_ids(ids))
    }

    // ── Legacy files (REQ-30, REQ-31) ──

    /// One page of a channel's legacy files (section 6.4.5): newest first
    /// (`created_at`, then `id`, both descending), only rows strictly before
    /// the `(created_at, id)` cursor when one is given. Names longer than
    /// [`LEGACY_NAME_MAX_BYTES`] are not read.
    pub async fn list_legacy_files(
        &self,
        channel_id: Uuid,
        before: Option<(i64, Uuid)>,
        limit: u32,
    ) -> Result<Vec<LegacyFileRow>> {
        const COLUMNS: &str = "SELECT id, channel_id, uploader_id, \
             CASE WHEN length(CAST(encrypted_filename AS BLOB)) <= 4096 \
                  THEN CAST(encrypted_filename AS BLOB) END AS name, \
             file_size_bytes, created_at FROM files WHERE channel_id = ?";
        let rows = match before {
            Some((created_at, id)) => {
                sqlx::query(&format!(
                    "{COLUMNS} AND (created_at < ? OR (created_at = ? AND id < ?)) \
                     ORDER BY created_at DESC, id DESC LIMIT ?"
                ))
                .bind(channel_id.to_string())
                .bind(created_at)
                .bind(created_at)
                .bind(id.to_string())
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query(&format!(
                    "{COLUMNS} ORDER BY created_at DESC, id DESC LIMIT ?"
                ))
                .bind(channel_id.to_string())
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
            }
        }
        .context("Failed to list legacy files")?;
        rows.iter()
            .map(|row| {
                Ok(LegacyFileRow {
                    id: parse_uuid_column(row, "id")?,
                    channel_id: parse_uuid_column(row, "channel_id")?,
                    uploader_id: parse_uuid_column(row, "uploader_id")?,
                    name: row.try_get("name")?,
                    file_size_bytes: row.try_get("file_size_bytes")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    /// Up to `limit` legacy rows to retire (section 7.7).
    pub async fn legacy_blobs_batch(&self, limit: u32) -> Result<Vec<LegacyBlob>> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT id, storage_path FROM files ORDER BY id LIMIT ?")
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
                .context("Failed to read legacy files to retire")?;
        Ok(rows
            .into_iter()
            .map(|(id, storage_path)| LegacyBlob { id, storage_path })
            .collect())
    }

    /// Delete the legacy rows with these ids. Returns how many were deleted.
    pub async fn delete_legacy_file_rows(&self, ids: &[String]) -> Result<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin deleting legacy files")?;
        let mut deleted = 0;
        for id in ids {
            deleted += sqlx::query("DELETE FROM files WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .context("Failed to delete a legacy file row")?
                .rows_affected();
        }
        tx.commit()
            .await
            .context("Failed to commit deleting legacy files")?;
        Ok(deleted)
    }

    /// Write the `spec02_legacy_retired` ledger row unless it exists.
    pub async fn record_legacy_retired(&self, now: i64) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO relay_migrations (name, applied_at) VALUES (?, ?)")
            .bind(LEDGER_LEGACY_RETIRED)
            .bind(now)
            .execute(&self.pool)
            .await
            .context("Failed to record legacy retirement")?;
        Ok(())
    }
}

/// True when `quota` is set (non-zero) and `used + size` exceeds it.
fn exceeds(quota: u64, used: i64, size: i64) -> bool {
    quota != 0 && i128::from(used.max(0)) + i128::from(size) > i128::from(quota)
}

#[cfg(any(test, feature = "test-helpers"))]
impl Database {
    /// Test-only: claim a pending attachment for an existing message, as the
    /// claim in `ChannelMessage` (REQ-35) does, without the message path.
    /// Returns whether the row was pending and is now claimed.
    pub async fn seed_claim_attachment(&self, id: Uuid, message_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE attachments SET state = 1, message_id = ?, pending_expires_at = NULL \
             WHERE id = ? AND state = 0",
        )
        .bind(message_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .context("Failed to claim the attachment")?;
        Ok(result.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ReservationLimits {
        ReservationLimits {
            max_pending_per_user: 2,
            quota_user_bytes: 100,
            quota_node_bytes: 150,
            min_free_bytes: 10,
        }
    }

    async fn fixture() -> (Database, Uuid, Uuid, Uuid) {
        let db = Database::new(":memory:").await.unwrap();
        let user = db.create_user("att-db-user", "").await.unwrap();
        let node = db
            .create_node("n", user.id, None)
            .await
            .expect("create node");
        let channel = db.create_channel("c", node.id, user.id).await.unwrap();
        (db, user.id, node.id, channel.id)
    }

    fn reservation(user: Uuid, node: Uuid, channel: Uuid, size: u64) -> AttachmentReservation {
        AttachmentReservation {
            id: Uuid::new_v4(),
            channel_id: channel,
            node_id: Some(node),
            uploader_id: user,
            blob_size: size,
            now: 1_000,
        }
    }

    #[tokio::test]
    async fn schema_and_ledger_row_exist() {
        let (db, ..) = fixture().await;
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('attachments')")
                .fetch_all(&db.pool)
                .await
                .unwrap();
        assert_eq!(
            columns,
            vec![
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
        assert!(db
            .ledger_applied_at(LEDGER_ATTACHMENTS_V2)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn check_constraints_reject_inconsistent_rows() {
        let (db, user, node, channel) = fixture().await;
        // A pending row without a hash violates the state CHECK.
        let err =
            sqlx::query("INSERT INTO attachments VALUES (?, ?, ?, ?, NULL, 0, 16, NULL, 1, 2)")
                .bind(Uuid::new_v4().to_string())
                .bind(channel.to_string())
                .bind(node.to_string())
                .bind(user.to_string())
                .execute(&db.pool)
                .await;
        assert!(err.is_err());
        // A blob below 16 bytes violates the size CHECK.
        let err =
            sqlx::query("INSERT INTO attachments VALUES (?, ?, ?, ?, NULL, 2, 15, NULL, 1, 2)")
                .bind(Uuid::new_v4().to_string())
                .bind(channel.to_string())
                .bind(node.to_string())
                .bind(user.to_string())
                .execute(&db.pool)
                .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn reservation_limits_apply_in_order() {
        let (db, user, node, channel) = fixture().await;
        let plenty = || Ok(1_000_000);
        let first = reservation(user, node, channel, 60);
        assert_eq!(
            db.reserve_attachment(&first, &limits(), &plenty)
                .await
                .unwrap(),
            ReservationOutcome::Reserved { deadline: 4_600 }
        );
        // 60 + 50 > the user quota of 100.
        let second = reservation(user, node, channel, 50);
        assert_eq!(
            db.reserve_attachment(&second, &limits(), &plenty)
                .await
                .unwrap(),
            ReservationOutcome::QuotaExceeded
        );
        // The free-space floor: 100 free, 60 reserved, 10 floor, 40 more fails.
        let third = reservation(user, node, channel, 40);
        let tight = || Ok(100);
        assert_eq!(
            db.reserve_attachment(&third, &limits(), &tight)
                .await
                .unwrap(),
            ReservationOutcome::StorageFull
        );
        // The second reservation fills the pending cap of 2.
        let fourth = reservation(user, node, channel, 20);
        assert!(matches!(
            db.reserve_attachment(&fourth, &limits(), &plenty)
                .await
                .unwrap(),
            ReservationOutcome::Reserved { .. }
        ));
        let fifth = reservation(user, node, channel, 16);
        assert_eq!(
            db.reserve_attachment(&fifth, &limits(), &plenty)
                .await
                .unwrap(),
            ReservationOutcome::TooManyPending { retry_after: 3_600 }
        );
    }

    #[tokio::test]
    async fn free_space_errors_insert_nothing() {
        let (db, user, node, channel) = fixture().await;
        let failing = || Err(std::io::Error::other("statvfs failed"));
        let request = reservation(user, node, channel, 16);
        assert!(db
            .reserve_attachment(&request, &limits(), &failing)
            .await
            .is_err());
        assert!(db.get_attachment(request.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn completion_deletion_and_gc() {
        let (db, user, node, channel) = fixture().await;
        let plenty = || Ok(1_000_000);
        let request = reservation(user, node, channel, 16);
        db.reserve_attachment(&request, &limits(), &plenty)
            .await
            .unwrap();
        // An uploading row is not deletable through the API.
        assert_eq!(
            db.delete_pending_attachment(request.id, user)
                .await
                .unwrap(),
            PendingDeletion::NotFound
        );
        assert!(db
            .complete_attachment_upload(request.id, &[7u8; 32], 2_000)
            .await
            .unwrap());
        let row = db.get_attachment(request.id).await.unwrap().unwrap();
        assert_eq!(row.state, AttachmentState::Pending);
        assert_eq!(row.blob_sha256.as_deref(), Some(&[7u8; 32][..]));
        // Not expired yet at 1_999; expired at 2_000.
        assert!(db.gc_expired_attachments(1_999).await.unwrap().is_empty());
        assert_eq!(
            db.gc_expired_attachments(2_000).await.unwrap(),
            vec![request.id]
        );
        assert!(!db.attachment_row_exists(request.id).await.unwrap());
    }
}
