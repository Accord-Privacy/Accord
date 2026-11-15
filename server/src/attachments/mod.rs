//! Version-2 attachment storage (SPEC-02 sections 6.4, 6.6; REQ-32 to
//! REQ-34, REQ-38 to REQ-43).
//!
//! The relay stores nameless, client-encrypted blobs. Each blob belongs to
//! one `attachments` row (`db::attachments`); its path is derived from the
//! configured directory and the row id, and no path is stored (REQ-43):
//!
//! ```text
//! <attachments_dir>/                          mode 0700
//! <attachments_dir>/.accord-attachments       marker file
//! <attachments_dir>/<attachment_id>           one blob per pending or claimed row, mode 0600
//! <attachments_dir>/.tmp/<attachment_id>.part upload in progress, mode 0600
//! ```
//!
//! [`AttachmentStore`] holds the configuration (section 6.6.4), the
//! directory and its startup checks (REQ-42), the relay clock, the free-space
//! probe, the GC trigger and the legacy retirement flag. [`lifecycle`] holds
//! the garbage collection (section 6.6.3) and the reconciliation (REQ-42)
//! with their background tasks, [`http`] the upload, download and delete
//! routes (section 6.4), [`claim`] the attachment list and error frames of
//! the claim in `ChannelMessage` (sections 6.5.1 to 6.5.3, REQ-35 to REQ-37),
//! and [`legacy`] the read-only legacy routes and their retirement (sections
//! 6.4.4, 6.4.5 and 7.7; REQ-30, REQ-31).
//!
//! No log event of this module carries an attachment id at INFO or above
//! (REQ-43); its target is [`LOG_TARGET`].

pub mod claim;
pub mod http;
pub mod legacy;
pub mod lifecycle;

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Tracing target of every attachment log event.
pub const LOG_TARGET: &str = "accord::attachments";

/// Name of the marker file that identifies an attachments directory
/// (section 6.6.2).
pub const MARKER_FILE: &str = ".accord-attachments";

/// Name of the directory of uploads in progress.
pub const TMP_DIR: &str = ".tmp";

/// The smallest possible blob: one empty record's 16-byte tag (REQ-33).
pub const MIN_BLOB_BYTES: u64 = 16;

/// The most attachments one message may claim (REQ-6, REQ-35).
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 10;

/// An upload that is not complete within 30 minutes is aborted (REQ-34).
pub const UPLOAD_DEADLINE_SECS: u64 = 1800;

/// Orphan blobs and rows with a missing blob are removed once older than
/// 10 minutes (REQ-42).
pub const ORPHAN_MIN_AGE_SECS: i64 = 600;

/// Orphan temporary files are removed once older than 1 hour (REQ-42).
pub const PART_MIN_AGE_SECS: i64 = 3600;

const MARKER_CONTENT: &str = "Accord version-2 attachment store. The relay deletes files here \
that no attachment row references; do not put other files in this directory.\n";

/// The `legacy_attachments` setting (section 6.6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LegacyAttachmentsMode {
    /// Legacy files stay readable until the retirement date.
    #[default]
    ReadOnly,
    /// Legacy files are retired (section 7.7).
    Retired,
}

impl std::str::FromStr for LegacyAttachmentsMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "read-only" => Ok(Self::ReadOnly),
            "retired" => Ok(Self::Retired),
            other => Err(format!(
                "legacy_attachments must be \"read-only\" or \"retired\", not {other:?}"
            )),
        }
    }
}

impl std::fmt::Display for LegacyAttachmentsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReadOnly => "read-only",
            Self::Retired => "retired",
        })
    }
}

/// The attachment settings of section 6.6.4. Each is a CLI flag and a TOML
/// key of the same name; the defaults are the owner's decision OD-35.
#[derive(Debug, Clone)]
pub struct AttachmentConfig {
    /// `attachments_dir`: the blob directory.
    pub dir: PathBuf,
    /// `attachment_max_blob_bytes`: the largest accepted blob.
    pub max_blob_bytes: u64,
    /// `attachment_pending_ttl_secs`: pending lifetime, 300 to 86 400.
    pub pending_ttl_secs: u64,
    /// `attachment_max_pending_per_user`: pending and uploading rows per user.
    pub max_pending_per_user: u64,
    /// `attachment_quota_user_bytes`: uploading, pending and claimed bytes per
    /// uploader; 0 means unlimited.
    pub quota_user_bytes: u64,
    /// `attachment_quota_node_bytes`: bytes per node, DM channels excluded;
    /// 0 means unlimited.
    pub quota_node_bytes: u64,
    /// `attachments_min_free_bytes`: uploads are refused below this much
    /// free space.
    pub min_free_bytes: u64,
    /// `attachment_gc_interval_secs`: GC interval, 1 to 3 600.
    pub gc_interval_secs: u64,
    /// `attachment_reconcile_interval_secs`: reconciliation interval, 60 to
    /// 86 400.
    pub reconcile_interval_secs: u64,
    /// `legacy_attachments`: `read-only` or `retired`.
    pub legacy_mode: LegacyAttachmentsMode,
    /// `legacy_attachments_retire_after_days`: automatic retirement after T0.
    pub legacy_retire_after_days: u64,
    /// The upload deadline of REQ-34. Not an operator setting.
    pub upload_deadline_secs: u64,
}

impl Default for AttachmentConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("./data/attachments"),
            max_blob_bytes: 104_857_600,
            pending_ttl_secs: 3600,
            max_pending_per_user: 32,
            quota_user_bytes: 1_073_741_824,
            quota_node_bytes: 10_737_418_240,
            min_free_bytes: 1_073_741_824,
            gc_interval_secs: 60,
            reconcile_interval_secs: 3600,
            legacy_mode: LegacyAttachmentsMode::ReadOnly,
            legacy_retire_after_days: 90,
            upload_deadline_secs: UPLOAD_DEADLINE_SECS,
        }
    }
}

impl AttachmentConfig {
    /// The default settings with another blob directory.
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            ..Self::default()
        }
    }

    /// Check the allowed ranges. The error names the setting.
    pub fn validate(&self) -> Result<()> {
        fn range(name: &str, value: u64, min: u64, max: u64) -> Result<()> {
            if value < min || value > max {
                bail!("{name} must be between {min} and {max}, not {value}");
            }
            Ok(())
        }
        if self.dir.as_os_str().is_empty() {
            bail!("attachments_dir must not be empty");
        }
        range(
            "attachment_max_blob_bytes",
            self.max_blob_bytes,
            MIN_BLOB_BYTES,
            i64::MAX as u64,
        )?;
        range(
            "attachment_pending_ttl_secs",
            self.pending_ttl_secs,
            300,
            86_400,
        )?;
        range(
            "attachment_max_pending_per_user",
            self.max_pending_per_user,
            1,
            u32::MAX as u64,
        )?;
        range(
            "attachment_gc_interval_secs",
            self.gc_interval_secs,
            1,
            3600,
        )?;
        range(
            "attachment_reconcile_interval_secs",
            self.reconcile_interval_secs,
            60,
            86_400,
        )?;
        if self.upload_deadline_secs == 0 {
            bail!("the upload deadline must be positive");
        }
        Ok(())
    }

    /// The reservation limits of this configuration.
    pub fn limits(&self) -> crate::db::attachments::ReservationLimits {
        crate::db::attachments::ReservationLimits {
            max_pending_per_user: self.max_pending_per_user,
            quota_user_bytes: self.quota_user_bytes,
            quota_node_bytes: self.quota_node_bytes,
            min_free_bytes: self.min_free_bytes,
        }
    }
}

/// Reports the free space, in bytes, of the filesystem holding a directory.
pub type FreeSpaceProbe = Arc<dyn Fn(&Path) -> std::io::Result<u64> + Send + Sync>;

/// The free space available to an unprivileged process, from `statvfs`.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // the field types differ between platforms
pub fn filesystem_free_bytes(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `statvfs` writes only into the zeroed struct we pass, and the
    // path is a valid NUL-terminated string that outlives the call.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

/// Without `statvfs` the free space is unknown and the floor is not
/// enforced; the quotas still are.
#[cfg(not(unix))]
pub fn filesystem_free_bytes(_path: &Path) -> std::io::Result<u64> {
    Ok(u64::MAX)
}

/// True when `name` is a lowercase canonical UUID of 36 characters, the only
/// file names the relay derives (REQ-42).
pub fn is_canonical_uuid(name: &str) -> bool {
    name.len() == 36
        && Uuid::parse_str(name)
            .map(|id| id.to_string() == name)
            .unwrap_or(false)
}

/// The version-2 attachment store of one relay.
pub struct AttachmentStore {
    config: AttachmentConfig,
    /// The canonical attachments directory.
    dir: PathBuf,
    /// `<dir>/.tmp`.
    tmp_dir: PathBuf,
    /// The legacy blob directory (`FileConfig::storage_dir`).
    legacy_dir: PathBuf,
    /// Seconds added to the system clock; only tests change it.
    clock_offset: AtomicI64,
    free_space: std::sync::RwLock<FreeSpaceProbe>,
    gc_notify: Arc<tokio::sync::Notify>,
    /// The largest body chunk an upload held in memory.
    peak_chunk: AtomicU64,
    /// Set once legacy retirement has started or completed (section 7.7).
    legacy_retired: AtomicBool,
    /// T0 + `legacy_attachments_retire_after_days`, in Unix seconds on the
    /// relay clock; `i64::MAX` until the ledger has been read.
    legacy_deadline: AtomicI64,
}

impl std::fmt::Debug for AttachmentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentStore")
            .field("dir", &self.dir)
            .field("legacy_dir", &self.legacy_dir)
            .field("config", &self.config)
            .finish()
    }
}

impl AttachmentStore {
    /// Open the store: validate the settings, run the startup checks of
    /// REQ-42 and prepare the directory. Nothing is created when a check
    /// fails, and the database is not opened before this succeeds.
    ///
    /// `db_path` is the database file, or `None` for an in-memory database,
    /// for which the database-directory check is skipped.
    pub fn open(
        config: AttachmentConfig,
        db_path: Option<&Path>,
        legacy_dir: &Path,
    ) -> Result<Self> {
        config.validate()?;
        let dir = lenient_canonical(&config.dir)
            .with_context(|| "attachments_dir: cannot resolve the directory".to_string())?;
        let legacy = lenient_canonical(legacy_dir)
            .context("attachments_dir: cannot resolve the legacy file directory")?;

        if let Some(db_path) = db_path {
            let parent = match db_path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            let db_dir = lenient_canonical(&parent)
                .context("attachments_dir: cannot resolve the database directory")?;
            if db_dir.starts_with(&dir) {
                bail!(
                    "attachments_dir ({}) must not be the database's directory or one of its \
                     ancestors",
                    dir.display()
                );
            }
        }
        if dir == legacy || legacy.starts_with(&dir) || dir.starts_with(&legacy) {
            bail!(
                "attachments_dir ({}) must not be the legacy file directory ({}), contain it or \
                 lie inside it",
                dir.display(),
                legacy.display()
            );
        }

        prepare_directory(&dir)?;
        let tmp_dir = dir.join(TMP_DIR);
        prepare_tmp_directory(&tmp_dir)?;

        Ok(Self {
            config,
            dir,
            tmp_dir,
            legacy_dir: legacy_dir.to_path_buf(),
            clock_offset: AtomicI64::new(0),
            free_space: std::sync::RwLock::new(Arc::new(filesystem_free_bytes)),
            gc_notify: Arc::new(tokio::sync::Notify::new()),
            peak_chunk: AtomicU64::new(0),
            legacy_retired: AtomicBool::new(false),
            legacy_deadline: AtomicI64::new(i64::MAX),
        })
    }

    /// The settings of this store.
    pub fn config(&self) -> &AttachmentConfig {
        &self.config
    }

    /// The canonical attachments directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The directory of uploads in progress.
    pub fn tmp_dir(&self) -> &Path {
        &self.tmp_dir
    }

    /// The legacy blob directory.
    pub fn legacy_dir(&self) -> &Path {
        &self.legacy_dir
    }

    /// The path of a stored blob, derived from the id (REQ-43).
    pub fn blob_path(&self, id: Uuid) -> PathBuf {
        self.dir.join(id.to_string())
    }

    /// The path of an upload in progress.
    pub fn part_path(&self, id: Uuid) -> PathBuf {
        self.tmp_dir.join(format!("{id}.part"))
    }

    /// The relay clock in Unix seconds.
    pub fn now(&self) -> i64 {
        let system = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        system.saturating_add(self.clock_offset.load(Ordering::Relaxed))
    }

    /// The free space of the attachments directory.
    pub fn free_bytes(&self) -> std::io::Result<u64> {
        let probe = match self.free_space.read() {
            Ok(probe) => probe.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        probe(&self.dir)
    }

    /// Ask the GC task to run now, for example after a message deletion
    /// (REQ-40). Requests made while it runs are coalesced into one more run.
    pub fn request_gc(&self) {
        self.gc_notify.notify_one();
    }

    /// The notifier [`AttachmentStore::request_gc`] signals.
    pub fn gc_notifier(&self) -> Arc<tokio::sync::Notify> {
        self.gc_notify.clone()
    }

    /// Record the size of a body chunk an upload holds in memory.
    pub(crate) fn note_chunk(&self, len: usize) {
        self.peak_chunk.fetch_max(len as u64, Ordering::Relaxed);
    }

    /// The largest body chunk any upload has held in memory at once. Uploads
    /// stream to disk, so this stays far below the blob size (T-34).
    pub fn peak_upload_chunk_bytes(&self) -> u64 {
        self.peak_chunk.load(Ordering::Relaxed)
    }

    /// True once legacy retirement is reached (section 7.7, REQ-31): the
    /// operator set `legacy_attachments = "retired"`, retirement was started
    /// or completed (also by `purge-legacy-attachments`), or the relay clock
    /// passed T0 + `legacy_attachments_retire_after_days`. Every legacy route
    /// answers 410 from then on.
    pub fn legacy_retired(&self) -> bool {
        self.config.legacy_mode == LegacyAttachmentsMode::Retired
            || self.legacy_retired.load(Ordering::SeqCst)
            || self.now() >= self.legacy_deadline.load(Ordering::SeqCst)
    }

    /// Record that legacy retirement has been reached. It is never undone.
    pub(crate) fn mark_legacy_retired(&self) {
        self.legacy_retired.store(true, Ordering::SeqCst);
    }

    /// Set the end of the legacy window, T0 + the retirement delay.
    pub(crate) fn set_legacy_deadline(&self, deadline: i64) {
        self.legacy_deadline.store(deadline, Ordering::SeqCst);
    }

    /// The end of the legacy window in Unix seconds, once known.
    pub fn legacy_deadline(&self) -> Option<i64> {
        match self.legacy_deadline.load(Ordering::SeqCst) {
            i64::MAX => None,
            deadline => Some(deadline),
        }
    }

    /// Remove a blob and the temporary file of an id, ignoring files that do
    /// not exist. Returns false if a file exists but could not be removed.
    pub async fn unlink(&self, id: Uuid) -> bool {
        let mut ok = true;
        for path in [self.blob_path(id), self.part_path(id)] {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => ok = false,
            }
        }
        ok
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl AttachmentStore {
    /// Test-only: move the relay clock forward (or back) by `secs`.
    pub fn advance_clock(&self, secs: i64) {
        self.clock_offset.fetch_add(secs, Ordering::Relaxed);
    }

    /// Test-only: replace the free-space probe.
    pub fn set_free_space_probe(&self, probe: FreeSpaceProbe) {
        match self.free_space.write() {
            Ok(mut slot) => *slot = probe,
            Err(poisoned) => *poisoned.into_inner() = probe,
        }
    }
}

/// Create the attachments directory, or adopt an existing one (REQ-42).
fn prepare_directory(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                bail!("attachments_dir ({}) is not a directory", dir.display());
            }
            let has_marker = || {
                std::fs::symlink_metadata(dir.join(MARKER_FILE))
                    .map(|m| m.is_file())
                    .unwrap_or(false)
            };
            if !has_marker() {
                let mut entries = std::fs::read_dir(dir).with_context(|| {
                    format!("attachments_dir ({}) cannot be read", dir.display())
                })?;
                // A relay process that created the directory a moment ago
                // writes the marker before anything else, so look again
                // before refusing.
                if entries.next().is_some() && !has_marker() {
                    bail!(
                        "attachments_dir ({}) is not empty and has no {} marker file; refusing \
                         to use a directory the relay did not create",
                        dir.display(),
                        MARKER_FILE
                    );
                }
                write_marker(dir)?;
            }
            restrict_directory(dir);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "attachments_dir ({}): cannot create the parent directory",
                        dir.display()
                    )
                })?;
            }
            create_private_dir(dir).with_context(|| {
                format!("attachments_dir ({}) cannot be created", dir.display())
            })?;
            write_marker(dir)
        }
        Err(e) => Err(anyhow!(
            "attachments_dir ({}) cannot be inspected: {}",
            dir.display(),
            e.kind()
        )),
    }
}

/// Create `<dir>/.tmp` unless it exists as a directory.
fn prepare_tmp_directory(tmp: &Path) -> Result<()> {
    match std::fs::symlink_metadata(tmp) {
        Ok(meta) if meta.is_dir() => {
            restrict_directory(tmp);
            Ok(())
        }
        Ok(_) => bail!(
            "attachments_dir: {} exists and is not a directory",
            tmp.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_private_dir(tmp)
            .with_context(|| format!("attachments_dir: cannot create {}", tmp.display())),
        Err(e) => Err(anyhow!(
            "attachments_dir: {} cannot be inspected: {}",
            tmp.display(),
            e.kind()
        )),
    }
}

fn write_marker(dir: &Path) -> Result<()> {
    let marker = dir.join(MARKER_FILE);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&marker)
        .with_context(|| format!("attachments_dir: cannot write {}", marker.display()))?;
    std::io::Write::write_all(&mut file, MARKER_CONTENT.as_bytes())
        .with_context(|| format!("attachments_dir: cannot write {}", marker.display()))?;
    Ok(())
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Ok(()) => Ok(()),
        // Another relay process sharing the directory created it first.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        Err(e) => Err(e),
    }
}

/// Set an existing directory to mode 0700 (REQ-43). A failure is logged and
/// does not stop the relay: the operator may manage the permissions.
fn restrict_directory(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let wanted = std::fs::Permissions::from_mode(0o700);
        let current = std::fs::metadata(dir).map(|m| m.permissions().mode() & 0o777);
        if current.ok() != Some(0o700) && std::fs::set_permissions(dir, wanted).is_err() {
            tracing::warn!(
                target: LOG_TARGET,
                "attachments_dir: could not set a directory to mode 0700"
            );
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// The canonical form of a path that may not exist yet: the longest existing
/// ancestor is canonicalized and the rest is appended, with `.` and `..`
/// resolved lexically.
pub fn lenient_canonical(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let absolute = normalize_lexically(&absolute);
    let mut existing = absolute.clone();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match std::fs::canonicalize(&existing) {
            Ok(mut canonical) => {
                for part in rest.iter().rev() {
                    canonical.push(part);
                }
                return Ok(canonical);
            }
            Err(_) => match (existing.parent(), existing.file_name()) {
                (Some(parent), Some(name)) => {
                    rest.push(name.to_os_string());
                    existing = parent.to_path_buf();
                }
                _ => return Ok(absolute),
            },
        }
    }
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_od_35() {
        let config = AttachmentConfig::default();
        assert_eq!(config.dir, PathBuf::from("./data/attachments"));
        assert_eq!(config.max_blob_bytes, 100 * 1024 * 1024);
        assert_eq!(config.pending_ttl_secs, 3600);
        assert_eq!(config.max_pending_per_user, 32);
        assert_eq!(config.quota_user_bytes, 1 << 30);
        assert_eq!(config.quota_node_bytes, 10 << 30);
        assert_eq!(config.min_free_bytes, 1 << 30);
        assert_eq!(config.gc_interval_secs, 60);
        assert_eq!(config.reconcile_interval_secs, 3600);
        assert_eq!(config.legacy_mode, LegacyAttachmentsMode::ReadOnly);
        assert_eq!(config.legacy_retire_after_days, 90);
        config.validate().unwrap();
    }

    #[test]
    fn ranges_name_the_setting() {
        let check = |f: fn(&mut AttachmentConfig), name: &str| {
            let mut config = AttachmentConfig::default();
            f(&mut config);
            let err = config.validate().unwrap_err().to_string();
            assert!(err.contains(name), "{err}");
        };
        check(|c| c.pending_ttl_secs = 299, "attachment_pending_ttl_secs");
        check(
            |c| c.pending_ttl_secs = 86_401,
            "attachment_pending_ttl_secs",
        );
        check(|c| c.gc_interval_secs = 0, "attachment_gc_interval_secs");
        check(|c| c.gc_interval_secs = 3601, "attachment_gc_interval_secs");
        check(
            |c| c.reconcile_interval_secs = 59,
            "attachment_reconcile_interval_secs",
        );
        check(
            |c| c.reconcile_interval_secs = 86_401,
            "attachment_reconcile_interval_secs",
        );
        check(|c| c.max_blob_bytes = 15, "attachment_max_blob_bytes");
        check(
            |c| c.max_pending_per_user = 0,
            "attachment_max_pending_per_user",
        );
    }

    #[test]
    fn legacy_mode_parses_both_values_only() {
        assert_eq!(
            "read-only".parse::<LegacyAttachmentsMode>().unwrap(),
            LegacyAttachmentsMode::ReadOnly
        );
        assert_eq!(
            "retired".parse::<LegacyAttachmentsMode>().unwrap(),
            LegacyAttachmentsMode::Retired
        );
        assert!("readonly".parse::<LegacyAttachmentsMode>().is_err());
    }

    #[test]
    fn canonical_uuid_names() {
        let id = Uuid::new_v4().to_string();
        assert!(is_canonical_uuid(&id));
        assert!(!is_canonical_uuid(&id.to_uppercase()));
        assert!(!is_canonical_uuid(&id.replace('-', "")));
        assert!(!is_canonical_uuid(&format!("{{{id}}}")));
        assert!(!is_canonical_uuid("not-a-uuid"));
    }

    #[test]
    fn lenient_canonical_resolves_missing_tails() {
        let temp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(temp.path()).unwrap();
        let missing = temp.path().join("a/./b/../c");
        assert_eq!(lenient_canonical(&missing).unwrap(), base.join("a/c"));
    }

    #[cfg(unix)]
    #[test]
    fn statvfs_reports_free_space() {
        let temp = tempfile::tempdir().unwrap();
        assert!(filesystem_free_bytes(temp.path()).unwrap() > 0);
    }

    #[test]
    fn new_directory_gets_marker_and_tmp() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("attachments");
        let legacy = temp.path().join("files");
        let store = AttachmentStore::open(AttachmentConfig::with_dir(&dir), None, &legacy).unwrap();
        assert!(dir.join(MARKER_FILE).is_file());
        assert!(dir.join(TMP_DIR).is_dir());
        let id = Uuid::new_v4();
        assert_eq!(store.blob_path(id), store.dir().join(id.to_string()));
        assert_eq!(
            store.part_path(id),
            store.dir().join(TMP_DIR).join(format!("{id}.part"))
        );
        // Reopening an adopted directory works.
        drop(store);
        AttachmentStore::open(AttachmentConfig::with_dir(&dir), None, &legacy).unwrap();
    }
}
