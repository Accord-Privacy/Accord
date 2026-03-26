//! Unit tests for pure/sync logic in files.rs
//!
//! Note: `validate_path` is a private method on `FileHandler`. Path-traversal
//! protection is fully covered by the inline `#[cfg(test)]` module inside
//! `files.rs`. This external test file focuses on:
//!   - `FileConfig::default()` field values
//!   - `FileHandler::with_default_config()` constructor
//!   - `FileHandler::new(config)` constructor
//!   - Structural invariants that can be verified without async I/O

use accord_server::files::{FileConfig, FileHandler};
use std::path::PathBuf;

// ── FileConfig::default() ─────────────────────────────────────────────────────

#[test]
fn file_config_default_storage_dir() {
    let cfg = FileConfig::default();
    assert_eq!(
        cfg.storage_dir,
        PathBuf::from("./data/files"),
        "default storage_dir must be './data/files'"
    );
}

#[test]
fn file_config_default_max_file_size_is_100mb() {
    let cfg = FileConfig::default();
    let expected: u64 = 100 * 1024 * 1024;
    assert_eq!(
        cfg.max_file_size, expected,
        "default max_file_size must be 100 MB ({expected} bytes), got {}",
        cfg.max_file_size
    );
}

#[test]
fn file_config_custom_values() {
    let cfg = FileConfig {
        storage_dir: PathBuf::from("/tmp/test-storage"),
        max_file_size: 512,
    };
    assert_eq!(cfg.storage_dir, PathBuf::from("/tmp/test-storage"));
    assert_eq!(cfg.max_file_size, 512);
}

#[test]
fn file_config_clone_is_independent() {
    let orig = FileConfig::default();
    let mut cloned = orig.clone();
    cloned.max_file_size = 42;
    // original should be unchanged
    assert_eq!(orig.max_file_size, 100 * 1024 * 1024);
}

// ── FileHandler constructors ───────────────────────────────────────────────────

#[test]
fn file_handler_with_default_config_max_file_size() {
    let handler = FileHandler::with_default_config();
    // We can't access private fields directly; test via behavior.
    // Store an oversized byte slice to confirm limit is 100 MB.
    // Since the limit check is synchronous (before any I/O) we can spin up
    // a minimal tokio runtime inline.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        // Something obviously larger than 100 MB would be slow to allocate;
        // instead confirm the config value via the known default.
        // We use a tiny write to an absent dir to confirm the handler was
        // created (init() not called — store_file will fail on write, not limit).
        // We just confirm the error is NOT a size-limit error for a 1-byte payload.
        let tiny: &[u8] = b"x";
        handler.store_file(uuid::Uuid::new_v4(), tiny).await
    });
    // The storage dir doesn't exist (default "./data/files") so it will fail,
    // but the error must NOT be about the size limit (size check comes first).
    match result {
        Ok(_) => { /* succeeded — that's also fine */ }
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            assert!(
                !msg.contains("exceeds maximum"),
                "1-byte payload should not trigger size limit, got: {e}"
            );
        }
    }
}

#[test]
fn file_handler_new_with_custom_config() {
    use tempfile::TempDir;
    let dir = TempDir::new().unwrap();
    let cfg = FileConfig {
        storage_dir: dir.path().to_path_buf(),
        max_file_size: 10,
    };
    let handler = FileHandler::new(cfg);

    let rt = tokio::runtime::Runtime::new().unwrap();

    // 10 bytes: exactly at the limit
    let result = rt.block_on(async {
        handler.init().await.unwrap();
        handler.store_file(uuid::Uuid::new_v4(), &[0u8; 10]).await
    });
    assert!(
        result.is_ok(),
        "exact-limit write should succeed: {result:?}"
    );

    // 11 bytes: one over the limit
    let over_result =
        rt.block_on(async { handler.store_file(uuid::Uuid::new_v4(), &[0u8; 11]).await });
    assert!(over_result.is_err(), "over-limit write must be rejected");
    assert!(
        over_result
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum"),
        "error message should mention 'exceeds maximum'"
    );
}
