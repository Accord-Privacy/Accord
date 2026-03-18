//! SQLCipher encryption-at-rest support for the Accord database.
//!
//! When the `sqlcipher` cargo feature is enabled and `database_encryption` is true:
//! 1. On first run, generates a random 256-bit key and writes it to `<db_path>.key`
//!    with restrictive file permissions (0600).
//! 2. On startup, reads the key file and issues `PRAGMA key = 'x"<hex>"'` to unlock.
//! 3. If an existing unencrypted database is detected with encryption enabled,
//!    migrates it in-place: exports via plaintext, re-imports with encryption key.
//!
//! When `database_encryption` is false (or the feature is not compiled in), regular
//! SQLite is used with no PRAGMA key issued.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Derive the key file path from the database path: `<db>.key`
pub fn key_file_path(db_path: &Path) -> PathBuf {
    let mut key_path = db_path.as_os_str().to_owned();
    key_path.push(".key");
    PathBuf::from(key_path)
}

/// Read or generate the 256-bit hex encryption key.
/// Creates the key file with mode 0600 if it doesn't exist.
pub fn read_or_create_key(db_path: &Path) -> Result<String> {
    let kf = key_file_path(db_path);

    if kf.exists() {
        let key = std::fs::read_to_string(&kf)
            .with_context(|| format!("Failed to read key file: {}", kf.display()))?;
        let key = key.trim().to_string();
        if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!(
                "Key file {} does not contain a valid 64-char hex key",
                kf.display()
            );
        }
        Ok(key)
    } else {
        // Generate 32 random bytes (256 bits)
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        let hex_key = hex::encode(buf);

        // Write with restrictive permissions
        std::fs::write(&kf, &hex_key)
            .with_context(|| format!("Failed to write key file: {}", kf.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o600)).with_context(
                || format!("Failed to set permissions on key file: {}", kf.display()),
            )?;
        }

        tracing::info!("Generated new database encryption key: {}", kf.display());
        Ok(hex_key)
    }
}

/// Issue `PRAGMA key` on the given sqlx pool to unlock a SQLCipher database.
pub async fn apply_pragma_key(pool: &sqlx::SqlitePool, hex_key: &str) -> Result<()> {
    // SQLCipher expects: PRAGMA key = "x'<hex>'"
    let pragma = format!("PRAGMA key = \"x'{hex_key}'\"");
    sqlx::query(&pragma)
        .execute(pool)
        .await
        .context("Failed to set SQLCipher PRAGMA key")?;
    Ok(())
}

/// Check if a database file is an unencrypted SQLite database by reading the header.
/// SQLite files start with "SQLite format 3\0". Encrypted files will have random bytes.
pub fn is_unencrypted_sqlite(db_path: &Path) -> Result<bool> {
    if !db_path.exists() {
        return Ok(false); // No file, nothing to check
    }
    let header = std::fs::read(db_path).context("Failed to read database file")?;
    // SQLite magic: first 16 bytes start with "SQLite format 3\0"
    Ok(header.len() >= 16 && &header[..16] == b"SQLite format 3\0")
}

/// Migrate an unencrypted database to an encrypted one in place.
///
/// Strategy: use the `sqlcipher_export` extension or plain ATTACH + copy approach:
///   1. Open the unencrypted DB
///   2. ATTACH a new encrypted DB
///   3. Copy all data via sqlcipher_export('encrypted')
///   4. Replace original with encrypted version
pub async fn migrate_to_encrypted(db_path: &Path, hex_key: &str) -> Result<()> {
    tracing::info!(
        "Migrating unencrypted database to encrypted: {}",
        db_path.display()
    );

    let tmp_path = db_path.with_extension("db.encrypted_tmp");

    // Open the existing unencrypted database
    let plain_url = format!("sqlite:{}", db_path.display());
    let plain_pool = sqlx::SqlitePool::connect(&plain_url)
        .await
        .context("Failed to open unencrypted database for migration")?;

    // ATTACH the new encrypted database and set its key
    let attach_sql = format!(
        "ATTACH DATABASE '{}' AS encrypted KEY \"x'{}'\"",
        tmp_path.display(),
        hex_key
    );
    sqlx::query(&attach_sql)
        .execute(&plain_pool)
        .await
        .context("Failed to attach encrypted database")?;

    // Export using sqlcipher_export
    sqlx::query("SELECT sqlcipher_export('encrypted')")
        .execute(&plain_pool)
        .await
        .context("Failed to export data to encrypted database (sqlcipher_export)")?;

    // Detach and close
    sqlx::query("DETACH DATABASE encrypted")
        .execute(&plain_pool)
        .await
        .context("Failed to detach encrypted database")?;

    plain_pool.close().await;

    // Replace original with encrypted version
    let backup_path = db_path.with_extension("db.unencrypted_backup");
    std::fs::rename(db_path, &backup_path).with_context(|| {
        format!(
            "Failed to backup unencrypted DB to {}",
            backup_path.display()
        )
    })?;
    std::fs::rename(&tmp_path, db_path).with_context(|| {
        format!(
            "Failed to replace DB with encrypted version: {}",
            tmp_path.display()
        )
    })?;

    tracing::info!(
        "Database encryption migration complete. Backup at: {}",
        backup_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::TempDir;

    // -------------------------------------------------------------------------
    // key_file_path
    // -------------------------------------------------------------------------

    #[test]
    fn test_key_file_path_appends_key_extension() {
        let db = Path::new("/var/db/accord.db");
        let kp = key_file_path(db);
        assert_eq!(kp, PathBuf::from("/var/db/accord.db.key"));
    }

    #[test]
    fn test_key_file_path_relative() {
        let db = Path::new("accord.db");
        let kp = key_file_path(db);
        assert_eq!(kp, PathBuf::from("accord.db.key"));
    }

    #[test]
    fn test_key_file_path_no_extension() {
        let db = Path::new("/tmp/database");
        let kp = key_file_path(db);
        assert_eq!(kp, PathBuf::from("/tmp/database.key"));
    }

    // -------------------------------------------------------------------------
    // read_or_create_key – key generation
    // -------------------------------------------------------------------------

    #[test]
    fn test_read_or_create_key_creates_key_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");

        let key = read_or_create_key(&db_path).unwrap();

        // Key must be exactly 64 hex chars (256-bit / 32 bytes)
        assert_eq!(key.len(), 64, "key should be 64 hex chars");
        assert!(
            key.chars().all(|c| c.is_ascii_hexdigit()),
            "key should be all hex digits"
        );

        // Key file should have been created
        let key_file = key_file_path(&db_path);
        assert!(key_file.exists(), "key file should be created on disk");
    }

    #[test]
    fn test_read_or_create_key_file_content_matches_returned_key() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");

        let key = read_or_create_key(&db_path).unwrap();
        let key_file = key_file_path(&db_path);
        let stored = std::fs::read_to_string(&key_file).unwrap();
        assert_eq!(
            key,
            stored.trim(),
            "returned key and file content must match"
        );
    }

    #[test]
    fn test_read_or_create_key_idempotent_reads_same_key() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");

        let key1 = read_or_create_key(&db_path).unwrap();
        let key2 = read_or_create_key(&db_path).unwrap();

        assert_eq!(key1, key2, "subsequent reads should return the same key");
    }

    #[test]
    fn test_read_or_create_key_generates_unique_keys() {
        // Each fresh DB path should get a distinct key (probabilistic but extremely reliable)
        let dir = TempDir::new().unwrap();
        let mut keys = HashSet::new();
        for i in 0..5 {
            let db_path = dir.path().join(format!("accord_{i}.db"));
            let key = read_or_create_key(&db_path).unwrap();
            keys.insert(key);
        }
        assert_eq!(keys.len(), 5, "all generated keys should be unique");
    }

    #[test]
    fn test_read_or_create_key_reads_valid_existing_key_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");
        let key_file = key_file_path(&db_path);

        // Write a known valid 64-char hex key
        let known_key = "a".repeat(64);
        std::fs::write(&key_file, &known_key).unwrap();

        let key = read_or_create_key(&db_path).unwrap();
        assert_eq!(key, known_key);
    }

    #[test]
    fn test_read_or_create_key_rejects_short_key_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");
        let key_file = key_file_path(&db_path);

        std::fs::write(&key_file, "tooshort").unwrap();
        let result = read_or_create_key(&db_path);
        assert!(result.is_err(), "should reject a key that is too short");
    }

    #[test]
    fn test_read_or_create_key_rejects_non_hex_key_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");
        let key_file = key_file_path(&db_path);

        // 64 chars but not hex
        let bad_key = "g".repeat(64);
        std::fs::write(&key_file, &bad_key).unwrap();
        let result = read_or_create_key(&db_path);
        assert!(result.is_err(), "should reject a key with non-hex chars");
    }

    #[test]
    fn test_read_or_create_key_rejects_key_with_trailing_whitespace_only_after_trim() {
        // A key stored with leading/trailing whitespace (e.g. newline) must still be accepted
        // because we call `.trim()` on read.
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");
        let key_file = key_file_path(&db_path);

        let valid_key = "deadbeef".repeat(8); // 64 hex chars
        std::fs::write(&key_file, format!("{valid_key}\n")).unwrap();

        let key = read_or_create_key(&db_path).unwrap();
        assert_eq!(key, valid_key, "trailing newline should be trimmed away");
    }

    #[test]
    fn test_read_or_create_key_exact_length_boundary_65_chars_rejected() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");
        let key_file = key_file_path(&db_path);

        // 65 hex chars – one too many
        let bad_key = "a".repeat(65);
        std::fs::write(&key_file, &bad_key).unwrap();
        assert!(
            read_or_create_key(&db_path).is_err(),
            "65-char key should be rejected"
        );
    }

    #[test]
    fn test_read_or_create_key_exact_length_boundary_63_chars_rejected() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");
        let key_file = key_file_path(&db_path);

        // 63 hex chars – one too few
        let bad_key = "a".repeat(63);
        std::fs::write(&key_file, &bad_key).unwrap();
        assert!(
            read_or_create_key(&db_path).is_err(),
            "63-char key should be rejected"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_read_or_create_key_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("accord.db");

        read_or_create_key(&db_path).unwrap();

        let key_file = key_file_path(&db_path);
        let meta = std::fs::metadata(&key_file).unwrap();
        let mode = meta.permissions().mode();
        // Mask to lower 9 permission bits; expect owner-only read+write (0600)
        assert_eq!(
            mode & 0o777,
            0o600,
            "key file must have 0600 permissions, got {:o}",
            mode & 0o777
        );
    }

    // -------------------------------------------------------------------------
    // is_unencrypted_sqlite
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_unencrypted_sqlite_true_for_sqlite_magic_header() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("plain.db");

        // Write a minimal file starting with the SQLite magic header
        let mut content = b"SQLite format 3\0".to_vec();
        content.extend_from_slice(&[0u8; 84]); // total 100 bytes
        std::fs::write(&db_path, &content).unwrap();

        assert!(is_unencrypted_sqlite(&db_path).unwrap());
    }

    #[test]
    fn test_is_unencrypted_sqlite_false_for_encrypted_header() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("encrypted.db");

        // Encrypted SQLCipher files start with random bytes, not the magic
        let random_header = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC, 0xAA, 0xBB,
            0xCC, 0xDD,
        ];
        std::fs::write(&db_path, &random_header).unwrap();

        assert!(!is_unencrypted_sqlite(&db_path).unwrap());
    }

    #[test]
    fn test_is_unencrypted_sqlite_false_for_nonexistent_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("does_not_exist.db");

        assert!(!is_unencrypted_sqlite(&db_path).unwrap());
    }

    #[test]
    fn test_is_unencrypted_sqlite_false_for_empty_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("empty.db");
        std::fs::write(&db_path, b"").unwrap();

        assert!(!is_unencrypted_sqlite(&db_path).unwrap());
    }

    #[test]
    fn test_is_unencrypted_sqlite_false_for_short_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("short.db");
        // Only 15 bytes – just under the 16-byte threshold
        std::fs::write(&db_path, b"SQLite format 3").unwrap();

        assert!(!is_unencrypted_sqlite(&db_path).unwrap());
    }

    #[test]
    fn test_is_unencrypted_sqlite_false_for_partial_magic_mismatch() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("partial.db");

        // Starts right but the final null byte is wrong
        let mut content = b"SQLite format 3X".to_vec();
        content.extend_from_slice(&[0u8; 64]);
        std::fs::write(&db_path, &content).unwrap();

        assert!(!is_unencrypted_sqlite(&db_path).unwrap());
    }

    #[test]
    fn test_is_unencrypted_sqlite_true_exact_16_bytes() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("exact.db");

        // Exactly 16 bytes — the minimum to pass the check
        std::fs::write(&db_path, b"SQLite format 3\0").unwrap();

        assert!(is_unencrypted_sqlite(&db_path).unwrap());
    }

    #[test]
    fn test_is_unencrypted_sqlite_large_file() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("large.db");

        // 1 MiB file starting with SQLite magic
        let mut content = b"SQLite format 3\0".to_vec();
        content.extend(vec![0u8; 1024 * 1024 - 16]);
        std::fs::write(&db_path, &content).unwrap();

        assert!(is_unencrypted_sqlite(&db_path).unwrap());
    }
}
