//! Legacy files: the read-only legacy routes and their retirement (SPEC-02
//! sections 6.4.4, 6.4.5 and 7.7; REQ-30, REQ-31; owner decisions OD-33 and
//! OD-34).
//!
//! Legacy files are the rows of the `files` table and their blobs, uploaded
//! before version 2 under a key the relay can compute. From R1:
//!
//! - `POST /channels/{id}/files` answers 410 `legacy_uploads_removed` and
//!   stores nothing;
//! - `GET /channels/{id}/files` lists a channel's legacy rows, paginated,
//!   with string names and without `storage_path` or `content_hash`;
//! - `GET /files/{id}` serves a legacy blob unchanged, with
//!   `Cache-Control: no-store`;
//! - `DELETE /files/{id}` deletes a legacy file for its uploader, or in a node
//!   channel for a holder of MANAGE_MESSAGES under role bitflags.
//!
//! The three read and delete routes authorize with `user_can_access_channel`
//! (participation for a DM channel) and answer 404 otherwise; an error while
//! authorizing denies. Legacy routes keep accepting `?token=`, as clients
//! older than SPEC-02 send it.
//!
//! **Retirement (section 7.7).** T0 is the `applied_at` of the
//! `spec02_attachments_v2` ledger row. Retirement is reached at T0 +
//! `legacy_attachments_retire_after_days` (90 days by default, OD-33), when
//! the operator sets `legacy_attachments = "retired"`, or when the operator
//! runs `accord-server purge-legacy-attachments`. From then on every legacy
//! route answers 410; the relay deletes the `files` rows and their blobs in
//! batches (OD-34: delete, not archive) and records `spec02_legacy_retired`.
//! The check runs at boot and before every reconciliation, so rows that
//! reappear later (an older relay binary run against the database) are
//! deleted too. The check and the legacy routes read the ledger until
//! retirement is known, so a running relay applies a retirement that the
//! purge subcommand recorded from another process.
//!
//! No log event here carries a file id at INFO or above.

use super::http::{error_response, internal, unauthorized};
use super::{is_canonical_uuid, AttachmentStore, LOG_TARGET};
use crate::db::attachments::{
    LegacyBlob, LegacyFileRow, LEDGER_ATTACHMENTS_V2, LEDGER_LEGACY_RETIRED, LEGACY_NAME_MAX_BYTES,
};
use crate::db::Database;
use crate::files::FileHandler;
use crate::models::{permission_bits, LegacyFileEntry};
use crate::state::{AppState, SharedState};
use anyhow::{bail, Result};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

/// Rows deleted per retirement batch.
pub const RETIREMENT_BATCH: u32 = 500;

/// Default page size of the legacy list (section 6.4.5).
pub const LEGACY_LIST_DEFAULT_LIMIT: u32 = 50;

/// Largest page of the legacy list; larger requests are clamped to it.
pub const LEGACY_LIST_MAX_LIMIT: u32 = 100;

/// Seconds in a day, for the retirement delay.
const DAY_SECS: i64 = 86_400;

/// What one retirement run removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetirementReport {
    /// `files` rows deleted.
    pub rows: u64,
    /// Blob files deleted.
    pub blobs: u64,
    /// Blob files that exist but could not be deleted; the reconciliation
    /// removes them later.
    pub blob_failures: u64,
}

impl AttachmentStore {
    /// Read the legacy window from the ledger: T0 sets the automatic
    /// retirement deadline, and a `spec02_legacy_retired` row means
    /// retirement has completed before.
    pub async fn load_legacy_window(&self, db: &Database) -> Result<()> {
        if db.ledger_applied_at(LEDGER_LEGACY_RETIRED).await?.is_some() {
            self.mark_legacy_retired();
        }
        if let Some(t0) = db.ledger_applied_at(LEDGER_ATTACHMENTS_V2).await? {
            let days = i64::try_from(self.config().legacy_retire_after_days).unwrap_or(i64::MAX);
            self.set_legacy_deadline(t0.saturating_add(days.saturating_mul(DAY_SECS)));
        }
        Ok(())
    }

    /// True when legacy retirement is reached, including a retirement that
    /// another process recorded in the ledger after this relay started:
    /// `accord-server purge-legacy-attachments` run beside a live relay
    /// writes `spec02_legacy_retired`, and this relay applies it from the
    /// next call on. Until retirement is known, every call reads the ledger.
    pub async fn refresh_legacy_retired(&self, db: &Database) -> Result<bool> {
        if self.legacy_retired() {
            return Ok(true);
        }
        if db.ledger_applied_at(LEDGER_LEGACY_RETIRED).await?.is_some() {
            self.mark_legacy_retired();
            return Ok(true);
        }
        Ok(false)
    }

    /// Retire legacy files if retirement is reached; otherwise do nothing.
    /// Runs at boot and before every reconciliation. It reads the ledger
    /// first, so a retirement recorded by another process deletes any rows
    /// and blobs left behind.
    pub async fn enforce_legacy_retirement(
        &self,
        db: &Database,
        files: &FileHandler,
    ) -> Result<Option<RetirementReport>> {
        if !self.refresh_legacy_retired(db).await? {
            return Ok(None);
        }
        self.retire_legacy_now(db, files).await.map(Some)
    }

    /// Retire legacy files now (section 7.7, REQ-31): every legacy route
    /// answers 410 from the start of the call; every `files` row and its
    /// blob are deleted in batches; then the `spec02_legacy_retired` ledger
    /// row is written. A blob that cannot be deleted is left to the
    /// reconciliation, which removes legacy blobs without a row.
    pub async fn retire_legacy_now(
        &self,
        db: &Database,
        files: &FileHandler,
    ) -> Result<RetirementReport> {
        self.mark_legacy_retired();
        let mut report = RetirementReport::default();
        loop {
            let batch = db.legacy_blobs_batch(RETIREMENT_BATCH).await?;
            if batch.is_empty() {
                break;
            }
            for blob in &batch {
                match self.remove_legacy_blob(files, blob).await {
                    Some(true) => report.blobs += 1,
                    Some(false) => report.blob_failures += 1,
                    None => {}
                }
            }
            let ids: Vec<String> = batch.into_iter().map(|blob| blob.id).collect();
            let deleted = db.delete_legacy_file_rows(&ids).await?;
            if deleted == 0 {
                bail!("legacy retirement: a batch of rows could not be deleted");
            }
            report.rows += deleted;
        }
        db.record_legacy_retired(self.now()).await?;
        if report.rows > 0 {
            info!(
                target: LOG_TARGET,
                "legacy attachments retired: {} files and {} blobs deleted",
                report.rows,
                report.blobs
            );
        }
        if report.blob_failures > 0 {
            warn!(
                target: LOG_TARGET,
                "legacy retirement: {} blobs could not be deleted; the reconciliation will retry",
                report.blob_failures
            );
        }
        Ok(report)
    }

    /// Delete the blob of a legacy row: the file the relay derives from the
    /// id in the legacy directory, and the stored path when it lies inside
    /// that directory. Returns `Some(true)` if a blob was deleted,
    /// `Some(false)` if one exists but could not be deleted, and `None` if
    /// there was none.
    async fn remove_legacy_blob(&self, files: &FileHandler, blob: &LegacyBlob) -> Option<bool> {
        let mut outcome = None;
        if is_canonical_uuid(&blob.id) {
            let derived = self.legacy_dir().join(&blob.id);
            if let Ok(meta) = tokio::fs::symlink_metadata(&derived).await {
                if meta.file_type().is_file() {
                    outcome = Some(tokio::fs::remove_file(&derived).await.is_ok());
                }
            }
        }
        // A stored path that differs from the derived one: `delete_file`
        // refuses any path outside the legacy directory.
        if files.file_exists(&blob.storage_path).await {
            let removed = files.delete_file(&blob.storage_path).await.is_ok()
                && !files.file_exists(&blob.storage_path).await;
            outcome = Some(outcome.unwrap_or(true) && removed);
        }
        outcome
    }
}

// ── Routes ──

fn gone(reason: &str, text: &str) -> Response {
    error_response(StatusCode::GONE, reason, text)
}

/// The 410 of every legacy route once retirement is reached.
fn retired() -> Response {
    gone(
        "legacy_retired",
        "Legacy uploads are no longer available on this relay",
    )
}

/// The answer of a legacy read or delete route before anything else: 410
/// once retirement is reached, also when another process recorded it
/// (REQ-31). A ledger read error answers 500, not 410, since clients hide
/// the legacy section for good on the first 410 (REQ-29).
async fn retirement_gate(state: &AppState) -> Option<Response> {
    match state.attachments.refresh_legacy_retired(&state.db).await {
        Ok(true) => Some(retired()),
        Ok(false) => None,
        Err(_) => {
            warn!(target: LOG_TARGET, "legacy route: the retirement ledger could not be read");
            Some(internal())
        }
    }
}

fn not_found(text: &str) -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found", text)
}

fn bad_request(text: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, "bad_request", text)
}

/// The user of a legacy request: `Authorization: Bearer`, or the `?token=`
/// query parameter that clients older than SPEC-02 send.
async fn legacy_user(
    state: &AppState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Option<Uuid> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let token = bearer.or_else(|| params.get("token").map(String::as_str))?;
    if token.is_empty() {
        return None;
    }
    state.validate_token(token).await
}

/// Whether `user_id` passes `user_can_access_channel`; an error denies.
async fn can_access(state: &AppState, user_id: Uuid, channel_id: Uuid) -> bool {
    matches!(
        state.user_can_access_channel(user_id, channel_id).await,
        Ok(true)
    )
}

/// `POST /channels/{id}/files`: legacy uploads are gone (REQ-30). The body is
/// never read and nothing is stored.
pub async fn legacy_upload_handler() -> Response {
    gone(
        "legacy_uploads_removed",
        "This relay no longer accepts legacy uploads; update Accord to send end-to-end \
         encrypted attachments",
    )
}

/// Parse the `limit` query parameter: 1 to 100, default 50, larger values
/// (however many digits) clamped to 100. The error is the answer's text.
fn parse_limit(value: Option<&String>) -> Result<u32, &'static str> {
    const INVALID: &str = "limit must be a positive integer";
    let Some(value) = value else {
        return Ok(LEGACY_LIST_DEFAULT_LIMIT);
    };
    let digits = value.trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(INVALID);
    }
    match digits.parse::<u64>() {
        Ok(0) => Err(INVALID),
        Ok(n) => {
            Ok(u32::try_from(n.min(u64::from(LEGACY_LIST_MAX_LIMIT)))
                .unwrap_or(LEGACY_LIST_MAX_LIMIT))
        }
        // Only digits, too many for u64: larger than the maximum.
        Err(_) => Ok(LEGACY_LIST_MAX_LIMIT),
    }
}

/// Parse the `before=<created_at>:<id>` cursor. The error is the answer's
/// text.
fn parse_cursor(value: Option<&String>) -> Result<Option<(i64, Uuid)>, &'static str> {
    const INVALID: &str = "before must be <created_at>:<id>";
    let Some(value) = value else {
        return Ok(None);
    };
    let (created_at, id) = value.split_once(':').ok_or(INVALID)?;
    let created_at = created_at
        .parse::<u64>()
        .ok()
        .and_then(|t| i64::try_from(t).ok())
        .ok_or(INVALID)?;
    let id = Uuid::parse_str(id).map_err(|_| INVALID)?;
    Ok(Some((created_at, id)))
}

/// The list entry of a legacy row: the stored name as a UTF-8 string, or
/// `""` when it is not valid UTF-8 or exceeds 4 096 bytes.
fn list_entry(row: LegacyFileRow) -> LegacyFileEntry {
    let encrypted_filename = row
        .name
        .filter(|bytes| bytes.len() as i64 <= LEGACY_NAME_MAX_BYTES)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default();
    LegacyFileEntry {
        id: row.id,
        channel_id: row.channel_id,
        uploader_id: row.uploader_id,
        encrypted_filename,
        file_size_bytes: row.file_size_bytes,
        created_at: u64::try_from(row.created_at).unwrap_or(0),
    }
}

/// `GET /channels/{id}/files` (section 6.4.5): a page of the channel's legacy
/// files, newest first. Query: `limit` (1 to 100, default 50) and an
/// optional `before=<created_at>:<id>` cursor. The answer stays a JSON array.
pub async fn legacy_list_handler(
    State(state): State<SharedState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(answer) = retirement_gate(&state).await {
        return answer;
    }
    let Some(user_id) = legacy_user(&state, &headers, &params).await else {
        return unauthorized();
    };
    let Ok(channel_id) = Uuid::parse_str(&channel_id) else {
        return not_found("Channel not found");
    };
    if !can_access(&state, user_id, channel_id).await {
        return not_found("Channel not found");
    }
    let limit = match parse_limit(params.get("limit")) {
        Ok(limit) => limit,
        Err(text) => return bad_request(text),
    };
    let before = match parse_cursor(params.get("before")) {
        Ok(before) => before,
        Err(text) => return bad_request(text),
    };
    match state.db.list_legacy_files(channel_id, before, limit).await {
        Ok(rows) => Json(rows.into_iter().map(list_entry).collect::<Vec<_>>()).into_response(),
        Err(_) => {
            warn!(target: LOG_TARGET, "legacy file list failed");
            internal()
        }
    }
}

/// `GET /files/{id}` (section 6.4.4): the legacy blob unchanged (IV ‖
/// ciphertext ‖ tag), with `Cache-Control: no-store`, for whoever passes
/// `user_can_access_channel` for its channel; 404 otherwise.
pub async fn legacy_download_handler(
    State(state): State<SharedState>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(answer) = retirement_gate(&state).await {
        return answer;
    }
    let Some(user_id) = legacy_user(&state, &headers, &params).await else {
        return unauthorized();
    };
    let Ok(file_id) = Uuid::parse_str(&file_id) else {
        return not_found("File not found");
    };
    let file = match state.db.get_file_metadata(file_id).await {
        Ok(Some(file)) => file,
        Ok(None) => return not_found("File not found"),
        Err(_) => {
            warn!(target: LOG_TARGET, "legacy download: the file lookup failed");
            return internal();
        }
    };
    if !can_access(&state, user_id, file.channel_id).await {
        return not_found("File not found");
    }
    let bytes = match state.file_handler.read_file(&file.storage_path).await {
        Ok(bytes) => bytes,
        Err(e) => {
            let missing = e.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            });
            if missing {
                return not_found("File not found");
            }
            warn!(target: LOG_TARGET, "legacy download: reading the blob failed");
            return internal();
        }
    };
    let length = bytes.len();
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{file_id}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Why a legacy deletion was refused.
enum DeleteRefusal {
    NotFound,
    Forbidden,
    Internal,
}

/// Whether `user_id` may delete a legacy file of `uploader_id` in
/// `channel_id` (REQ-30): it passes `user_can_access_channel`, and is the
/// uploader, or, in a node channel, holds MANAGE_MESSAGES under role
/// bitflags. The legacy role marker is never consulted. Any error denies.
async fn authorize_delete(
    state: &AppState,
    user_id: Uuid,
    uploader_id: Uuid,
    channel_id: Uuid,
) -> Result<(), DeleteRefusal> {
    if !can_access(state, user_id, channel_id).await {
        return Err(DeleteRefusal::NotFound);
    }
    if uploader_id == user_id {
        return Ok(());
    }
    // In a DM only the uploader may delete.
    match state.db.dm_participants(channel_id).await {
        Ok(Some(_)) => return Err(DeleteRefusal::Forbidden),
        Ok(None) => {}
        Err(_) => return Err(DeleteRefusal::Internal),
    }
    let channel = state
        .db
        .get_channel(channel_id)
        .await
        .map_err(|_| DeleteRefusal::Internal)?
        .ok_or(DeleteRefusal::NotFound)?;
    let perms = state
        .db
        .compute_channel_permissions(channel.node_id, user_id, channel_id)
        .await
        .map_err(|_| DeleteRefusal::Internal)?;
    if perms & permission_bits::MANAGE_MESSAGES == 0 {
        return Err(DeleteRefusal::Forbidden);
    }
    Ok(())
}

/// `DELETE /files/{id}` (section 6.4.4, REQ-30): deletes the legacy file and
/// its blob for its uploader, or in a node channel for a holder of
/// MANAGE_MESSAGES under role bitflags.
pub async fn legacy_delete_handler(
    State(state): State<SharedState>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(answer) = retirement_gate(&state).await {
        return answer;
    }
    let Some(user_id) = legacy_user(&state, &headers, &params).await else {
        return unauthorized();
    };
    let Ok(file_id) = Uuid::parse_str(&file_id) else {
        return not_found("File not found");
    };
    let file = match state.db.get_file_metadata(file_id).await {
        Ok(Some(file)) => file,
        Ok(None) => return not_found("File not found"),
        Err(_) => {
            warn!(target: LOG_TARGET, "legacy delete: the file lookup failed");
            return internal();
        }
    };
    match authorize_delete(&state, user_id, file.uploader_id, file.channel_id).await {
        Ok(()) => {}
        Err(DeleteRefusal::NotFound) => return not_found("File not found"),
        Err(DeleteRefusal::Forbidden) => {
            return error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "Only the uploader, or a member with Manage Messages, can delete this file",
            )
        }
        Err(DeleteRefusal::Internal) => {
            warn!(target: LOG_TARGET, "legacy delete: authorization failed");
            return internal();
        }
    }

    let blob = LegacyBlob {
        id: file.id.to_string(),
        storage_path: file.storage_path,
    };
    if state
        .attachments
        .remove_legacy_blob(&state.file_handler, &blob)
        .await
        == Some(false)
    {
        warn!(
            target: LOG_TARGET,
            "legacy delete: the blob could not be removed; the reconciliation will retry"
        );
    }
    match state.db.delete_file_metadata(file_id).await {
        Ok(()) => {
            Json(serde_json::json!({ "message": "File deleted successfully" })).into_response()
        }
        Err(_) => {
            warn!(target: LOG_TARGET, "legacy delete: deleting the row failed");
            internal()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn limit_defaults_clamps_and_rejects() {
        assert_eq!(parse_limit(None).ok(), Some(50));
        assert_eq!(parse_limit(Some(&s("1"))).ok(), Some(1));
        assert_eq!(parse_limit(Some(&s("100"))).ok(), Some(100));
        assert_eq!(parse_limit(Some(&s("500"))).ok(), Some(100));
        assert_eq!(
            parse_limit(Some(&s("99999999999999999999999"))).ok(),
            Some(100)
        );
        for bad in ["0", "000", "-1", "+5", "x", "", "1.5"] {
            assert!(parse_limit(Some(&s(bad))).is_err(), "{bad}");
        }
    }

    #[test]
    fn cursor_is_created_at_and_id() {
        let id = Uuid::new_v4();
        assert_eq!(
            parse_cursor(Some(&format!("1700000000:{id}"))).ok(),
            Some(Some((1_700_000_000, id)))
        );
        assert_eq!(parse_cursor(None).ok(), Some(None));
        for bad in [
            s("1700000000"),
            format!("-1:{id}"),
            s("1:not-a-uuid"),
            s(":"),
        ] {
            assert!(parse_cursor(Some(&bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn list_entries_have_string_names() {
        let row = |name: Option<Vec<u8>>| LegacyFileRow {
            id: Uuid::new_v4(),
            channel_id: Uuid::new_v4(),
            uploader_id: Uuid::new_v4(),
            name,
            file_size_bytes: 10,
            created_at: 5,
        };
        assert_eq!(
            list_entry(row(Some(b"abc=".to_vec()))).encrypted_filename,
            "abc="
        );
        assert_eq!(
            list_entry(row(Some(vec![0xff, 0xfe]))).encrypted_filename,
            ""
        );
        assert_eq!(list_entry(row(None)).encrypted_filename, "");
        assert_eq!(
            list_entry(row(Some(vec![b'a'; 4097]))).encrypted_filename,
            ""
        );
        assert_eq!(
            list_entry(row(Some(vec![b'a'; 4096])))
                .encrypted_filename
                .len(),
            4096
        );
    }
}
