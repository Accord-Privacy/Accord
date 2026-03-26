//! External integration tests for the backup/restore module.
//!
//! Covers BackupMetadata serde, backup creation, restore, error cases,
//! and a full round-trip with data-integrity verification.

#![allow(clippy::all)]

use accord_server::backup::{create_backup, read_backup_metadata, restore_backup, BackupMetadata};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Create a minimal SQLite database in `dir` with a test table and known data.
/// Sets user_version = 7 so we can verify schema_version in metadata.
fn create_test_db(dir: &TempDir) -> std::path::PathBuf {
    let db_path = dir.path().join("accord.db");
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
        sqlx::query("CREATE TABLE messages (id INTEGER PRIMARY KEY, content TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO messages (id, content) VALUES (1, 'hello accord')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO messages (id, content) VALUES (2, 'second row')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 7")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    });
    db_path
}

/// Read all rows from `messages` table in the given database.
fn read_messages(db_path: &Path) -> Vec<(i64, String)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let url = format!("sqlite:{}?mode=ro", db_path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let rows: Vec<(i64, String)> =
            sqlx::query_as("SELECT id, content FROM messages ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        pool.close().await;
        rows
    })
}

/// Read user_version pragma from a database.
fn read_user_version(db_path: &Path) -> i64 {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let url = format!("sqlite:{}?mode=ro", db_path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let row: (i64,) = sqlx::query_as("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        row.0
    })
}

// ============================================================================
// Group 1 — BackupMetadata serialization / deserialization (~6 tests)
// ============================================================================

#[test]
fn test_metadata_roundtrip_json() {
    let meta = BackupMetadata {
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        server_version: "1.0.0".to_string(),
        schema_version: 5,
        encrypted: false,
        database_filename: "accord.db".to_string(),
    };
    let json = serde_json::to_string(&meta).expect("serialize");
    let decoded: BackupMetadata = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.timestamp, meta.timestamp);
    assert_eq!(decoded.server_version, meta.server_version);
    assert_eq!(decoded.schema_version, meta.schema_version);
    assert_eq!(decoded.encrypted, meta.encrypted);
    assert_eq!(decoded.database_filename, meta.database_filename);
}

#[test]
fn test_metadata_encrypted_flag_true() {
    let meta = BackupMetadata {
        timestamp: "2026-03-01T12:00:00Z".to_string(),
        server_version: "2.3.1".to_string(),
        schema_version: 99,
        encrypted: true,
        database_filename: "accord.db".to_string(),
    };
    let json = serde_json::to_string(&meta).unwrap();
    let decoded: BackupMetadata = serde_json::from_str(&json).unwrap();
    assert!(decoded.encrypted);
    assert_eq!(decoded.schema_version, 99);
}

#[test]
fn test_metadata_schema_version_zero() {
    let meta = BackupMetadata {
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        server_version: "0.1.0".to_string(),
        schema_version: 0,
        encrypted: false,
        database_filename: "test.db".to_string(),
    };
    let json = serde_json::to_string(&meta).unwrap();
    let decoded: BackupMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.schema_version, 0);
}

#[test]
fn test_metadata_pretty_json_deserializes() {
    // The backup code uses serde_json::to_string_pretty — verify that also round-trips.
    let meta = BackupMetadata {
        timestamp: "2026-06-15T08:30:00Z".to_string(),
        server_version: "1.2.3".to_string(),
        schema_version: 12,
        encrypted: false,
        database_filename: "accord.db".to_string(),
    };
    let pretty = serde_json::to_string_pretty(&meta).unwrap();
    let decoded: BackupMetadata = serde_json::from_str(&pretty).unwrap();
    assert_eq!(decoded.schema_version, 12);
    assert_eq!(decoded.database_filename, "accord.db");
}

#[test]
fn test_metadata_missing_field_fails() {
    // Omit required field — should fail to deserialize.
    let bad_json = r#"{"timestamp":"2026-01-01T00:00:00Z","server_version":"1.0","schema_version":1,"encrypted":false}"#;
    let result: Result<BackupMetadata, _> = serde_json::from_str(bad_json);
    assert!(result.is_err(), "Should fail without database_filename");
}

#[test]
fn test_metadata_debug_impl() {
    let meta = BackupMetadata {
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        server_version: "1.0.0".to_string(),
        schema_version: 3,
        encrypted: false,
        database_filename: "accord.db".to_string(),
    };
    // Debug derive should produce non-empty output
    let dbg = format!("{:?}", meta);
    assert!(dbg.contains("BackupMetadata"));
    assert!(dbg.contains("schema_version"));
}

// ============================================================================
// Group 2 — Backup creation (~5 tests)
// ============================================================================

#[test]
fn test_create_backup_produces_archive() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("backup.tar.gz");

    let result = create_backup(&db_path, Some(&archive_path), None, false);
    assert!(result.is_ok(), "create_backup failed: {:?}", result.err());

    let returned_path = result.unwrap();
    assert_eq!(returned_path, archive_path);
    assert!(archive_path.exists(), "Archive file should exist on disk");
    // Should be non-empty (a valid gzip archive)
    let size = fs::metadata(&archive_path).unwrap().len();
    assert!(size > 0, "Archive should not be empty");
}

#[test]
fn test_create_backup_metadata_correct() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("backup.tar.gz");

    create_backup(&db_path, Some(&archive_path), None, false).unwrap();

    let meta = read_backup_metadata(&archive_path).unwrap();
    assert_eq!(
        meta.schema_version, 7,
        "Schema version should match PRAGMA user_version"
    );
    assert!(
        !meta.encrypted,
        "Unencrypted backup should report encrypted=false"
    );
    assert_eq!(meta.server_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(meta.database_filename, "accord.db");
    assert!(!meta.timestamp.is_empty());
}

#[test]
fn test_create_backup_default_output_path() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);

    // Pass None for output path — should auto-generate beside the DB
    let result = create_backup(&db_path, None, None, false);
    assert!(
        result.is_ok(),
        "create_backup with auto path failed: {:?}",
        result.err()
    );

    let archive_path = result.unwrap();
    assert!(
        archive_path.to_string_lossy().contains("accord-backup-"),
        "Auto-named archive should contain 'accord-backup-'"
    );
    assert!(archive_path.exists());
}

#[test]
fn test_create_backup_missing_database() {
    let dir = TempDir::new().unwrap();
    let nonexistent = dir.path().join("does_not_exist.db");
    let archive = dir.path().join("out.tar.gz");

    let result = create_backup(&nonexistent, Some(&archive), None, false);
    assert!(result.is_err(), "Should fail when DB does not exist");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("not found") || msg.contains("does_not_exist"),
        "Error should mention missing file, got: {msg}"
    );
}

#[test]
fn test_create_backup_hot_path() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("hot-backup.tar.gz");

    // force_hot = true exercises the VACUUM INTO path
    let result = create_backup(&db_path, Some(&archive_path), None, true);
    assert!(result.is_ok(), "Hot backup failed: {:?}", result.err());

    let meta = read_backup_metadata(&archive_path).unwrap();
    assert_eq!(meta.schema_version, 7);
}

// ============================================================================
// Group 3 — Restore (~5 tests)
// ============================================================================

#[test]
fn test_restore_to_fresh_path() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("backup.tar.gz");
    create_backup(&db_path, Some(&archive_path), None, false).unwrap();

    // Restore to a completely new path (no pre-existing DB)
    let restore_dir = TempDir::new().unwrap();
    let restore_db = restore_dir.path().join("restored.db");

    let result = restore_backup(&archive_path, &restore_db, None, true);
    assert!(result.is_ok(), "restore_backup failed: {:?}", result.err());
    assert!(restore_db.exists(), "Restored DB should exist");
}

#[test]
fn test_restore_missing_archive() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("db.sqlite");

    let result = restore_backup(
        Path::new("/absolutely/nonexistent/backup.tar.gz"),
        &db,
        None,
        true,
    );
    assert!(result.is_err(), "Should fail for missing archive");
}

#[test]
fn test_restore_corrupt_archive() {
    let dir = TempDir::new().unwrap();
    let corrupt = dir.path().join("corrupt.tar.gz");
    // Write garbage bytes — not a valid gzip stream
    fs::write(&corrupt, b"this is not a tar.gz file at all").unwrap();

    let db = dir.path().join("db.sqlite");
    let result = restore_backup(&corrupt, &db, None, true);
    assert!(result.is_err(), "Should fail for corrupt archive");
}

#[test]
fn test_restore_archive_missing_metadata() {
    // Build a tar.gz that contains a DB file but no backup-metadata.json
    let dir = TempDir::new().unwrap();
    let archive_path = dir.path().join("no-meta.tar.gz");

    let db_path = create_test_db(&dir);
    {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let file = fs::File::create(&archive_path).unwrap();
        let enc = GzEncoder::new(file, Compression::default());
        let mut tar = tar::Builder::new(enc);
        tar.append_path_with_name(&db_path, "accord.db").unwrap();
        tar.finish().unwrap();
    }

    let result = read_backup_metadata(&archive_path);
    assert!(result.is_err(), "Should fail when metadata JSON is absent");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("missing") || msg.contains("Invalid"),
        "Error should mention missing metadata, got: {msg}"
    );
}

#[test]
fn test_restore_overwrites_and_preserves_pre_restore() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("backup.tar.gz");
    create_backup(&db_path, Some(&archive_path), None, false).unwrap();

    // Mutate the DB after taking the backup
    {
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
            sqlx::query("DELETE FROM messages")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        });
    }

    // Restore (skip_confirm = true skips the stdin prompt)
    restore_backup(&archive_path, &db_path, None, true).unwrap();

    // The pre-restore backup file should exist
    let pre_restore = db_path.with_extension("db.pre-restore");
    assert!(
        pre_restore.exists(),
        ".pre-restore backup should be created"
    );
}

// ============================================================================
// Group 4 — Round-trip data integrity (~4 tests)
// ============================================================================

#[test]
fn test_roundtrip_data_integrity() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("backup.tar.gz");

    create_backup(&db_path, Some(&archive_path), None, false).unwrap();

    // Restore to a new location
    let restore_dir = TempDir::new().unwrap();
    let restore_db = restore_dir.path().join("restored.db");
    restore_backup(&archive_path, &restore_db, None, true).unwrap();

    // Verify data rows
    let rows = read_messages(&restore_db);
    assert_eq!(rows.len(), 2, "Should have 2 rows");
    assert_eq!(rows[0], (1, "hello accord".to_string()));
    assert_eq!(rows[1], (2, "second row".to_string()));
}

#[test]
fn test_roundtrip_schema_version_preserved() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("backup.tar.gz");

    create_backup(&db_path, Some(&archive_path), None, false).unwrap();

    let restore_dir = TempDir::new().unwrap();
    let restore_db = restore_dir.path().join("restored.db");
    restore_backup(&archive_path, &restore_db, None, true).unwrap();

    let version = read_user_version(&restore_db);
    assert_eq!(version, 7, "user_version pragma should be preserved");
}

#[test]
fn test_roundtrip_hot_backup_data_integrity() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("hot-backup.tar.gz");

    // Force hot backup path (VACUUM INTO)
    create_backup(&db_path, Some(&archive_path), None, true).unwrap();

    let restore_dir = TempDir::new().unwrap();
    let restore_db = restore_dir.path().join("restored.db");
    restore_backup(&archive_path, &restore_db, None, true).unwrap();

    let rows = read_messages(&restore_db);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1, "hello accord");
    assert_eq!(rows[1].1, "second row");
}

#[test]
fn test_roundtrip_metadata_matches_restored_db() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("backup.tar.gz");

    create_backup(&db_path, Some(&archive_path), None, false).unwrap();

    let meta = read_backup_metadata(&archive_path).unwrap();

    let restore_dir = TempDir::new().unwrap();
    let restore_db = restore_dir.path().join("restored.db");
    restore_backup(&archive_path, &restore_db, None, true).unwrap();

    // Schema version from metadata should match the restored DB's pragma
    let version = read_user_version(&restore_db);
    assert_eq!(
        meta.schema_version, version,
        "Metadata schema_version should match restored DB user_version"
    );
}

// ============================================================================
// Group 5 — read_backup_metadata edge cases (~4 tests)
// ============================================================================

#[test]
fn test_read_metadata_from_valid_backup() {
    let dir = TempDir::new().unwrap();
    let db_path = create_test_db(&dir);
    let archive_path = dir.path().join("backup.tar.gz");

    create_backup(&db_path, Some(&archive_path), None, false).unwrap();

    let meta = read_backup_metadata(&archive_path).unwrap();
    // Should have a valid RFC3339 timestamp
    assert!(!meta.timestamp.is_empty());
    assert!(
        meta.timestamp.contains('T'),
        "Timestamp should be RFC3339, got: {}",
        meta.timestamp
    );
    // database_filename should be the DB's filename only, not a full path
    assert_eq!(meta.database_filename, "accord.db");
    assert!(!meta.encrypted);
}

#[test]
fn test_read_metadata_nonexistent_archive() {
    let result = read_backup_metadata(Path::new("/no/such/file.tar.gz"));
    assert!(result.is_err());
}

#[test]
fn test_read_metadata_not_a_gzip() {
    let dir = TempDir::new().unwrap();
    let bad = dir.path().join("bad.tar.gz");
    fs::write(&bad, b"\x00\x01\x02\x03 totally not gzip").unwrap();

    let result = read_backup_metadata(&bad);
    assert!(result.is_err(), "Should fail on non-gzip content");
}

#[test]
fn test_read_metadata_valid_gzip_no_metadata_entry() {
    // Valid tar.gz but no backup-metadata.json entry
    let dir = TempDir::new().unwrap();
    let archive_path = dir.path().join("no-meta.tar.gz");
    let dummy = dir.path().join("dummy.txt");
    fs::write(&dummy, b"hello").unwrap();

    {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let file = fs::File::create(&archive_path).unwrap();
        let enc = GzEncoder::new(file, Compression::default());
        let mut tar = tar::Builder::new(enc);
        tar.append_path_with_name(&dummy, "dummy.txt").unwrap();
        tar.finish().unwrap();
    }

    let result = read_backup_metadata(&archive_path);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("missing") || msg.contains("Invalid"),
        "Got: {msg}"
    );
}
