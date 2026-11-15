//! Garbage collection (section 6.6.3; REQ-40, REQ-41) and storage
//! reconciliation (REQ-42) of version-2 attachments, and the background
//! tasks that run them.
//!
//! The GC deletes rows whose message or channel is gone, pending rows and
//! upload reservations past their deadline, and then unlinks their files.
//! The reconciliation removes what the GC cannot see: blob files without a
//! row, stale temporary files, rows whose blob is missing, and legacy blobs
//! whose `files` row is gone. It never recurses, deletes only regular files
//! with the exact names the relay derives, and leaves everything else alone.
//!
//! Log events carry counts and error classes, never attachment ids, at INFO
//! and above (REQ-43).

use super::{
    is_canonical_uuid, AttachmentStore, LOG_TARGET, MARKER_FILE, ORPHAN_MIN_AGE_SECS,
    PART_MIN_AGE_SECS, TMP_DIR,
};
use crate::db::Database;
use crate::state::SharedState;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// What one GC run removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Pending rows and upload reservations past their deadline.
    pub expired: usize,
    /// Claimed rows whose message no longer exists.
    pub without_message: usize,
    /// Rows whose channel no longer exists.
    pub without_channel: usize,
    /// Files that exist but could not be unlinked; the reconciliation
    /// removes them later.
    pub unlink_failures: usize,
}

impl GcReport {
    /// Rows removed by this run.
    pub fn rows(&self) -> usize {
        self.expired + self.without_message + self.without_channel
    }
}

/// What one reconciliation run removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// `<attachments_dir>/<uuid>` files without a row.
    pub orphan_blobs: usize,
    /// `.tmp/<uuid>.part` files without an uploading row.
    pub orphan_parts: usize,
    /// Pending or claimed rows whose blob file is missing.
    pub rows_without_blob: usize,
    /// Legacy blobs without a `files` row.
    pub legacy_orphans: usize,
    /// True when the `files` table could not be read and the legacy part was
    /// skipped.
    pub legacy_skipped: bool,
    /// Entries left alone (not a regular file, an unexpected name, too
    /// young, or still referenced).
    pub left_alone: usize,
}

impl AttachmentStore {
    /// Run the garbage collection of section 6.6.3 once. Each statement
    /// commits before its files are unlinked; "not found" is ignored, and a
    /// file that cannot be unlinked is left to the reconciliation. If a
    /// statement fails, the others still run and the first error is
    /// returned.
    pub async fn run_gc_now(&self, db: &Database) -> Result<GcReport> {
        let now = self.now();
        let mut report = GcReport::default();
        let mut first_error = None;

        match db.gc_expired_attachments(now).await {
            Ok(ids) => {
                report.expired = ids.len();
                report.unlink_failures += self.unlink_all(&ids).await;
            }
            Err(e) => first_error = first_error.or(Some(e)),
        }
        match db.gc_attachments_without_message().await {
            Ok(ids) => {
                report.without_message = ids.len();
                report.unlink_failures += self.unlink_all(&ids).await;
            }
            Err(e) => first_error = first_error.or(Some(e)),
        }
        match db.gc_attachments_without_channel().await {
            Ok(ids) => {
                report.without_channel = ids.len();
                report.unlink_failures += self.unlink_all(&ids).await;
            }
            Err(e) => first_error = first_error.or(Some(e)),
        }

        if report.unlink_failures > 0 {
            warn!(
                target: LOG_TARGET,
                "attachment GC: {} files could not be removed; the reconciliation will retry",
                report.unlink_failures
            );
        }
        if report.rows() > 0 {
            debug!(
                target: LOG_TARGET,
                "attachment GC removed {} expired, {} without message, {} without channel",
                report.expired,
                report.without_message,
                report.without_channel
            );
        }
        match first_error {
            Some(e) => {
                warn!(target: LOG_TARGET, "attachment GC: a statement failed");
                Err(e)
            }
            None => Ok(report),
        }
    }

    async fn unlink_all(&self, ids: &[Uuid]) -> usize {
        let mut failures = 0;
        for id in ids {
            if !self.unlink(*id).await {
                failures += 1;
            }
        }
        failures
    }

    /// Run the reconciliation of REQ-42 once.
    pub async fn run_reconciliation_now(&self, db: &Database) -> Result<ReconcileReport> {
        let now = self.now();
        let mut report = ReconcileReport::default();

        // 1. <attachments_dir>/<uuid> with no row, older than 10 minutes.
        for entry in list_dir(&self.dir).await? {
            if entry.name == MARKER_FILE || entry.name == TMP_DIR {
                continue;
            }
            let Some(id) = deletable_candidate(&entry, None, now, ORPHAN_MIN_AGE_SECS) else {
                report.left_alone += 1;
                continue;
            };
            if db.attachment_row_exists(id).await? {
                continue;
            }
            if remove_regular_file(&entry.path).await {
                report.orphan_blobs += 1;
            }
        }

        // 2. <attachments_dir>/.tmp/<uuid>.part with no uploading row, older
        // than 1 hour.
        for entry in list_dir(&self.tmp_dir).await? {
            let Some(id) = deletable_candidate(&entry, Some(".part"), now, PART_MIN_AGE_SECS)
            else {
                report.left_alone += 1;
                continue;
            };
            if db.uploading_attachment_exists(id).await? {
                continue;
            }
            if remove_regular_file(&entry.path).await {
                report.orphan_parts += 1;
            }
        }

        // 3. Pending or claimed rows older than 10 minutes whose blob is
        // missing.
        for id in db
            .stored_attachments_created_before(now - ORPHAN_MIN_AGE_SECS)
            .await?
        {
            let missing = matches!(
                tokio::fs::symlink_metadata(self.blob_path(id)).await,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound
            );
            if missing && db.delete_stored_attachment_row(id).await? {
                report.rows_without_blob += 1;
            }
        }

        // 4. <legacy dir>/<uuid> whose uuid matches no files.id, older than
        // 10 minutes. If the files table cannot be read, skip this part.
        match db.legacy_file_ids().await {
            Ok(file_ids) => {
                for entry in list_dir(&self.legacy_dir).await.unwrap_or_default() {
                    let Some(id) = deletable_candidate(&entry, None, now, ORPHAN_MIN_AGE_SECS)
                    else {
                        report.left_alone += 1;
                        continue;
                    };
                    if file_ids.contains(&id.to_string()) {
                        continue;
                    }
                    if remove_regular_file(&entry.path).await {
                        report.legacy_orphans += 1;
                    }
                }
            }
            Err(_) => {
                report.legacy_skipped = true;
                error!(
                    target: LOG_TARGET,
                    "attachment reconciliation: the legacy files table cannot be read; \
                     skipping the legacy directory"
                );
            }
        }

        let removed = report.orphan_blobs
            + report.orphan_parts
            + report.rows_without_blob
            + report.legacy_orphans;
        if removed > 0 {
            debug!(
                target: LOG_TARGET,
                "attachment reconciliation removed {} blobs, {} temporary files, {} rows, {} legacy blobs",
                report.orphan_blobs,
                report.orphan_parts,
                report.rows_without_blob,
                report.legacy_orphans
            );
        }
        Ok(report)
    }
}

/// One directory entry, with the metadata of the entry itself (never of a
/// symbolic link's target).
struct DirEntryInfo {
    name: String,
    path: std::path::PathBuf,
    metadata: Option<std::fs::Metadata>,
}

/// List a directory without recursing. A missing directory is empty.
async fn list_dir(dir: &Path) -> Result<Vec<DirEntryInfo>> {
    let mut out = Vec::new();
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = tokio::fs::symlink_metadata(&path).await.ok();
        out.push(DirEntryInfo {
            name: entry.file_name().to_string_lossy().into_owned(),
            path,
            metadata,
        });
    }
    Ok(out)
}

/// The id of an entry that may be deleted if no row references it: a
/// regular file (not a symbolic link) whose name is exactly a lowercase
/// canonical UUID followed by `suffix`, last modified more than `min_age`
/// seconds before `now`. Every other entry is left alone and logged at
/// DEBUG.
fn deletable_candidate(
    entry: &DirEntryInfo,
    suffix: Option<&str>,
    now: i64,
    min_age: i64,
) -> Option<Uuid> {
    let Some(metadata) = entry.metadata.as_ref() else {
        debug!(target: LOG_TARGET, "reconciliation: left {:?} alone (unreadable)", entry.name);
        return None;
    };
    if !metadata.file_type().is_file() {
        debug!(target: LOG_TARGET, "reconciliation: left {:?} alone (not a regular file)", entry.name);
        return None;
    }
    let stem = match suffix {
        Some(suffix) => entry.name.strip_suffix(suffix)?,
        None => entry.name.as_str(),
    };
    if !is_canonical_uuid(stem) {
        debug!(target: LOG_TARGET, "reconciliation: left {:?} alone (unexpected name)", entry.name);
        return None;
    }
    let modified = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)?;
    if now.saturating_sub(modified) <= min_age {
        debug!(target: LOG_TARGET, "reconciliation: left {:?} alone (too recent)", entry.name);
        return None;
    }
    Uuid::parse_str(stem).ok()
}

/// Remove a file that was checked to be a regular file. Returns whether it
/// was removed.
async fn remove_regular_file(path: &Path) -> bool {
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.file_type().is_file() => tokio::fs::remove_file(path).await.is_ok(),
        _ => false,
    }
}

/// Start the GC and reconciliation tasks of a relay (REQ-40 to REQ-42).
///
/// The GC runs every `attachment_gc_interval_secs` and whenever
/// [`AttachmentStore::request_gc`] is called (after each expiry sweep and
/// after message deletions and purges). The reconciliation runs at start
/// and then every `attachment_reconcile_interval_secs`, each time after the
/// legacy retirement check (section 7.7). Both tasks hold only a weak
/// reference and stop when the relay state is dropped.
pub fn spawn_background_tasks(state: &SharedState) {
    let config = state.attachments.config().clone();

    let weak = Arc::downgrade(state);
    let notify = state.attachments.gc_notifier();
    let gc_period = Duration::from_secs(config.gc_interval_secs);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(gc_period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = notify.notified() => {}
            }
            let Some(state) = weak.upgrade() else { break };
            // Errors are logged inside, without ids.
            let _ = state.attachments.run_gc_now(&state.db).await;
        }
    });

    let weak = Arc::downgrade(state);
    let reconcile_period = Duration::from_secs(config.reconcile_interval_secs);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(reconcile_period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let Some(state) = weak.upgrade() else { break };
            // Legacy retirement first (section 7.7), so the reconciliation
            // then removes any legacy blob it could not delete.
            if state
                .attachments
                .enforce_legacy_retirement(&state.db, &state.file_handler)
                .await
                .is_err()
            {
                warn!(target: LOG_TARGET, "legacy retirement failed; it is retried with the next reconciliation");
            }
            if state
                .attachments
                .run_reconciliation_now(&state.db)
                .await
                .is_err()
            {
                warn!(target: LOG_TARGET, "attachment reconciliation failed");
            }
        }
    });
}
