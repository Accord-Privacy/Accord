//! Database backup and restore for Accord server.
//!
//! Creates compressed `.tar.gz` archives containing the SQLite database file
//! and a JSON metadata file with timestamp, server version, and schema info.

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};

/// Metadata stored alongside the database in the backup archive.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub timestamp: String,
    pub server_version: String,
    pub schema_version: i64,
    pub encrypted: bool,
    pub database_filename: String,
}

/// Check if a server process has the database file open (Unix: via fuser/lsof heuristic).
fn check_db_locked(db_path: &Path) -> bool {
    // Try to open with exclusive lock as a quick check
    if let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(db_path) {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // Try POSIX advisory lock (non-blocking exclusive)
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            return true; // locked by another process
        }
        // Unlock immediately
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }
    false
}

/// Read the SQLite `user_version` pragma to get schema version.
fn read_schema_version(db_path: &Path, encryption_key: Option<&str>) -> Result<i64> {
    // Use a synchronous approach: run sqlite3/sqlcipher CLI or parse the file
    // For simplicity, we'll use sqlx in a blocking tokio runtime
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let db_url = format!("sqlite:{}?mode=ro", db_path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .context("Failed to open database for schema version check")?;

        if let Some(key) = encryption_key {
            crate::db::encryption::apply_pragma_key(&pool, key).await?;
        }

        let row: (i64,) = sqlx::query_as("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .context("Failed to read user_version")?;

        pool.close().await;
        Ok(row.0)
    })
}

/// Perform a hot backup using the SQLite backup API (via VACUUM INTO).
fn hot_backup_db(db_path: &Path, dest_path: &Path, encryption_key: Option<&str>) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let db_url = format!("sqlite:{}?mode=ro", db_path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .context("Failed to open database for backup")?;

        if let Some(key) = encryption_key {
            crate::db::encryption::apply_pragma_key(&pool, key).await?;
        }

        let vacuum_sql = format!("VACUUM INTO '{}'", dest_path.display());
        sqlx::query(&vacuum_sql)
            .execute(&pool)
            .await
            .context("VACUUM INTO failed — is the destination writable?")?;

        pool.close().await;
        Ok(())
    })
}

/// Create a backup archive of the database.
pub fn create_backup(
    db_path: &Path,
    output_path: Option<&Path>,
    encryption_key: Option<&str>,
    force_hot: bool,
) -> Result<PathBuf> {
    if !db_path.exists() {
        bail!("Database file not found: {}", db_path.display());
    }

    let db_locked = check_db_locked(db_path);
    if db_locked && !force_hot {
        eprintln!("⚠️  Database appears to be in use by another process.");
        eprintln!("   Using SQLite VACUUM INTO for a consistent hot backup.");
    }

    let schema_version = read_schema_version(db_path, encryption_key).unwrap_or_else(|e| {
        eprintln!("Warning: could not read schema version: {e}");
        0
    });

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let db_filename = db_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let archive_name = output_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        let parent = db_path.parent().unwrap_or(Path::new("."));
        parent.join(format!("accord-backup-{}.tar.gz", timestamp))
    });

    let metadata = BackupMetadata {
        timestamp: chrono::Utc::now().to_rfc3339(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        schema_version,
        encrypted: encryption_key.is_some(),
        database_filename: db_filename.clone(),
    };

    // Create a temp copy of the DB (either hot backup or file copy)
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let temp_db = temp_dir.path().join(&db_filename);

    if db_locked || force_hot {
        hot_backup_db(db_path, &temp_db, encryption_key)?;
    } else {
        fs::copy(db_path, &temp_db).context("Failed to copy database file")?;
        // Also copy WAL/SHM if present for consistency
        let wal = db_path.with_extension("db-wal");
        let shm = db_path.with_extension("db-shm");
        if wal.exists() {
            fs::copy(&wal, temp_dir.path().join(wal.file_name().unwrap()))?;
        }
        if shm.exists() {
            fs::copy(&shm, temp_dir.path().join(shm.file_name().unwrap()))?;
        }
    }

    // Build tar.gz
    let archive_file = fs::File::create(&archive_name)
        .with_context(|| format!("Failed to create archive: {}", archive_name.display()))?;
    let enc = GzEncoder::new(archive_file, Compression::default());
    let mut tar = Builder::new(enc);

    // Add metadata
    let meta_json = serde_json::to_string_pretty(&metadata)?;
    let meta_bytes = meta_json.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(meta_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "backup-metadata.json", meta_bytes)?;

    // Add database file
    tar.append_path_with_name(&temp_db, &db_filename)?;

    // Add WAL if we copied it
    let temp_wal = temp_dir.path().join(format!("{}-wal", db_filename));
    if temp_wal.exists() {
        tar.append_path_with_name(&temp_wal, format!("{}-wal", db_filename))?;
    }

    tar.finish()?;
    drop(tar); // ensure flush

    println!("✅ Backup created: {}", archive_name.display());
    println!("   Schema version: {}", schema_version);
    println!("   Server version: {}", env!("CARGO_PKG_VERSION"));
    println!("   Encrypted: {}", encryption_key.is_some());

    Ok(archive_name)
}

/// Read and validate backup metadata from an archive without extracting.
pub fn read_backup_metadata(archive_path: &Path) -> Result<BackupMetadata> {
    let file = fs::File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if path.to_string_lossy() == "backup-metadata.json" {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            let metadata: BackupMetadata =
                serde_json::from_str(&content).context("Failed to parse backup metadata")?;
            return Ok(metadata);
        }
    }

    bail!("Invalid backup archive: missing backup-metadata.json");
}

/// Restore a database from a backup archive.
pub fn restore_backup(
    archive_path: &Path,
    db_path: &Path,
    encryption_key: Option<&str>,
    skip_confirm: bool,
) -> Result<()> {
    if !archive_path.exists() {
        bail!("Archive not found: {}", archive_path.display());
    }

    // Read and display metadata
    let metadata = read_backup_metadata(archive_path)?;
    println!("📦 Backup info:");
    println!("   Created: {}", metadata.timestamp);
    println!("   Server version: {}", metadata.server_version);
    println!("   Schema version: {}", metadata.schema_version);
    println!("   Encrypted: {}", metadata.encrypted);

    // Check schema compatibility
    if db_path.exists() {
        let current_schema = read_schema_version(db_path, encryption_key).unwrap_or(0);
        if metadata.schema_version > current_schema {
            eprintln!(
                "⚠️  Backup schema version ({}) is newer than current ({}). \
                 You may need to upgrade the server first.",
                metadata.schema_version, current_schema
            );
        }
    }

    // Check encryption mismatch
    if metadata.encrypted && encryption_key.is_none() {
        bail!(
            "Backup was created from an encrypted database but no encryption key is configured. \
             Enable --database-encryption and ensure the key file is present."
        );
    }

    // Check if DB is in use
    if db_path.exists() && check_db_locked(db_path) {
        bail!(
            "Database is currently in use. Stop the Accord server before restoring.\n\
             Hint: accord-server should be stopped first."
        );
    }

    // Confirmation prompt
    if !skip_confirm && db_path.exists() {
        eprint!(
            "⚠️  This will OVERWRITE the existing database at {}. Continue? [y/N] ",
            db_path.display()
        );
        std::io::stderr().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Restore cancelled.");
            return Ok(());
        }
    }

    // Extract to temp dir first, then move into place
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let file = fs::File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    archive
        .unpack(temp_dir.path())
        .context("Failed to extract backup archive")?;

    // Find the database file in the extracted archive
    let extracted_db = temp_dir.path().join(&metadata.database_filename);
    if !extracted_db.exists() {
        bail!(
            "Backup archive does not contain expected database file: {}",
            metadata.database_filename
        );
    }

    // Create backup of current DB if it exists
    if db_path.exists() {
        let backup_existing = db_path.with_extension("db.pre-restore");
        fs::copy(db_path, &backup_existing).context("Failed to backup existing database")?;
        println!(
            "   Existing database backed up to: {}",
            backup_existing.display()
        );
    }

    // Move restored DB into place
    fs::copy(&extracted_db, db_path).context("Failed to restore database file")?;

    // Remove WAL/SHM from old DB (restored DB has its own state)
    let wal = db_path.with_extension("db-wal");
    let shm = db_path.with_extension("db-shm");
    let _ = fs::remove_file(&wal);
    let _ = fs::remove_file(&shm);

    // Check if archive contained WAL
    let extracted_wal = temp_dir
        .path()
        .join(format!("{}-wal", metadata.database_filename));
    if extracted_wal.exists() {
        fs::copy(&extracted_wal, &wal)?;
    }

    println!("✅ Database restored from backup successfully.");
    println!("   You can now start the Accord server.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_db(dir: &TempDir) -> PathBuf {
        let db_path = dir.path().join("test.db");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let url = format!("sqlite:{}?mode=rwc", db_path.display());
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .unwrap();
            sqlx::query("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO test_table (id, name) VALUES (1, 'hello')")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("PRAGMA user_version = 42")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        });
        db_path
    }

    #[test]
    fn test_backup_and_restore_roundtrip() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_db(&dir);
        let archive_path = dir.path().join("backup.tar.gz");

        // Create backup
        let result = create_backup(&db_path, Some(&archive_path), None, false);
        assert!(result.is_ok(), "Backup failed: {:?}", result.err());
        assert!(archive_path.exists());

        // Read metadata
        let meta = read_backup_metadata(&archive_path).unwrap();
        assert_eq!(meta.schema_version, 42);
        assert!(!meta.encrypted);
        assert_eq!(meta.server_version, env!("CARGO_PKG_VERSION"));

        // Restore to new location
        let restore_dir = TempDir::new().unwrap();
        let restore_db = restore_dir.path().join("restored.db");
        let result = restore_backup(&archive_path, &restore_db, None, true);
        assert!(result.is_ok(), "Restore failed: {:?}", result.err());
        assert!(restore_db.exists());

        // Verify data
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let url = format!("sqlite:{}?mode=ro", restore_db.display());
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .unwrap();
            let row: (i64, String) = sqlx::query_as("SELECT id, name FROM test_table WHERE id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(row.0, 1);
            assert_eq!(row.1, "hello");

            let ver: (i64,) = sqlx::query_as("PRAGMA user_version")
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(ver.0, 42);
            pool.close().await;
        });
    }

    #[test]
    fn test_read_metadata_invalid_archive() {
        let dir = TempDir::new().unwrap();
        let bad_file = dir.path().join("not-a-backup.tar.gz");
        fs::write(&bad_file, b"not a real archive").unwrap();
        assert!(read_backup_metadata(&bad_file).is_err());
    }

    #[test]
    fn test_backup_missing_db() {
        let result = create_backup(Path::new("/nonexistent/db.sqlite"), None, None, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_restore_missing_archive() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("db.sqlite");
        let result = restore_backup(Path::new("/nonexistent.tar.gz"), &db, None, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_restore_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_db(&dir);
        let archive_path = dir.path().join("backup.tar.gz");
        create_backup(&db_path, Some(&archive_path), None, false).unwrap();

        // Modify the original DB
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let url = format!("sqlite:{}?mode=rwc", db_path.display());
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .unwrap();
            sqlx::query("UPDATE test_table SET name = 'modified' WHERE id = 1")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        });

        // Restore should overwrite
        restore_backup(&archive_path, &db_path, None, true).unwrap();

        // Verify original data is back
        rt.block_on(async {
            let url = format!("sqlite:{}?mode=ro", db_path.display());
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .unwrap();
            let row: (String,) = sqlx::query_as("SELECT name FROM test_table WHERE id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(row.0, "hello");
            pool.close().await;
        });

        // Pre-restore backup should exist
        assert!(db_path.with_extension("db.pre-restore").exists());
    }

    #[test]
    fn test_hot_backup() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_db(&dir);
        let archive_path = dir.path().join("hot-backup.tar.gz");

        // Force hot backup path
        let result = create_backup(&db_path, Some(&archive_path), None, true);
        assert!(result.is_ok(), "Hot backup failed: {:?}", result.err());

        let meta = read_backup_metadata(&archive_path).unwrap();
        assert_eq!(meta.schema_version, 42);
    }
}
