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
