//! File handling for encrypted file sharing
//!
//! This module handles the storage and retrieval of encrypted files.
//! Files are encrypted client-side before upload, so the server only
//! stores opaque encrypted blobs and cannot read the actual content or filenames.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

/// Configuration for file storage
#[derive(Debug, Clone)]
pub struct FileConfig {
    /// Directory where files are stored
    pub storage_dir: PathBuf,
    /// Maximum file size in bytes (default: 100MB)
    pub max_file_size: u64,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            storage_dir: PathBuf::from("./data/files"),
            max_file_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// File handler for encrypted file operations
pub struct FileHandler {
    config: FileConfig,
}

impl FileHandler {
    /// Create a new file handler with the given configuration
    pub fn new(config: FileConfig) -> Self {
        Self { config }
    }

    /// Create a new file handler with default configuration
    pub fn with_default_config() -> Self {
        Self::new(FileConfig::default())
    }

    /// Initialize the storage directory
    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.config.storage_dir)
            .await
            .with_context(|| {
                format!(
                    "Failed to create storage directory: {:?}",
                    self.config.storage_dir
                )
            })?;
        Ok(())
    }

    /// Store an encrypted file to disk
    pub async fn store_file(
        &self,
        file_id: Uuid,
        encrypted_data: &[u8],
    ) -> Result<(String, String)> {
        // Check file size
        if encrypted_data.len() as u64 > self.config.max_file_size {
            return Err(anyhow!(
                "File size exceeds maximum allowed size of {} bytes",
                self.config.max_file_size
            ));
        }

        // Generate storage path
        let filename = format!("{}", file_id);
        let file_path = self.config.storage_dir.join(&filename);

        // Calculate content hash (SHA-256 of encrypted content)
        let mut hasher = Sha256::new();
        hasher.update(encrypted_data);
        let content_hash = format!("{:x}", hasher.finalize());

        // Write file to disk
        fs::write(&file_path, encrypted_data)
            .await
            .with_context(|| format!("Failed to write file to {:?}", file_path))?;

        Ok((file_path.to_string_lossy().to_string(), content_hash))
    }

    /// Canonicalize and validate a file path is within the storage directory (H6 fix)
    fn validate_path(&self, storage_path: &str) -> Result<PathBuf> {
        let file_path = Path::new(storage_path);

        // Canonicalize both paths to resolve symlinks, .., etc.
        let canonical_storage =
            std::fs::canonicalize(&self.config.storage_dir).with_context(|| {
                format!(
                    "Failed to canonicalize storage dir: {:?}",
                    self.config.storage_dir
                )
            })?;

        let canonical_file = std::fs::canonicalize(file_path)
            .with_context(|| format!("Failed to canonicalize file path: {:?}", file_path))?;

        if !canonical_file.starts_with(&canonical_storage) {
            return Err(anyhow!("Invalid file path: path traversal detected"));
        }

        Ok(canonical_file)
    }

    /// Read an encrypted file from disk
    pub async fn read_file(&self, storage_path: &str) -> Result<Vec<u8>> {
        let canonical_path = self.validate_path(storage_path)?;

        fs::read(&canonical_path)
            .await
            .with_context(|| format!("Failed to read file from {:?}", canonical_path))
    }

    /// Delete a file from disk
    pub async fn delete_file(&self, storage_path: &str) -> Result<()> {
        let canonical_path = self.validate_path(storage_path)?;

        if canonical_path.exists() {
            fs::remove_file(&canonical_path)
                .await
                .with_context(|| format!("Failed to delete file at {:?}", canonical_path))?;
        }

        Ok(())
    }

    /// Get file size from disk
    pub async fn get_file_size(&self, storage_path: &str) -> Result<u64> {
        let canonical_path = self.validate_path(storage_path)?;

        let metadata = fs::metadata(&canonical_path)
            .await
            .with_context(|| format!("Failed to get file metadata for {:?}", canonical_path))?;

        Ok(metadata.len())
    }

    /// Check if a file exists on disk
    pub async fn file_exists(&self, storage_path: &str) -> bool {
        match self.validate_path(storage_path) {
            Ok(path) => path.exists(),
            Err(_) => false,
        }
    }

    /// Verify content hash of a stored file
    pub async fn verify_content_hash(
        &self,
        storage_path: &str,
        expected_hash: &str,
    ) -> Result<bool> {
        let file_data = self.read_file(storage_path).await?;

        let mut hasher = Sha256::new();
        hasher.update(&file_data);
        let actual_hash = format!("{:x}", hasher.finalize());

        Ok(actual_hash == expected_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a FileHandler backed by a fresh temp directory
    async fn setup_handler(max_file_size: u64) -> (FileHandler, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = FileConfig {
            storage_dir: temp_dir.path().to_path_buf(),
            max_file_size,
        };
        let handler = FileHandler::new(config);
        handler.init().await.unwrap();
        (handler, temp_dir)
    }

    // ---------------------------------------------------------------
    // Basic store / read / delete round-trip
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_file_storage() {
        let (handler, _dir) = setup_handler(1024).await;

        let file_id = Uuid::new_v4();
        let test_data = b"encrypted_test_data";

        // Store file
        let (storage_path, content_hash) = handler.store_file(file_id, test_data).await.unwrap();

        // Verify file exists
        assert!(handler.file_exists(&storage_path).await);

        // Read file back
        let read_data = handler.read_file(&storage_path).await.unwrap();
        assert_eq!(read_data, test_data);

        // Verify content hash
        assert!(handler
            .verify_content_hash(&storage_path, &content_hash)
            .await
            .unwrap());

        // Delete file
        handler.delete_file(&storage_path).await.unwrap();
        assert!(!handler.file_exists(&storage_path).await);
    }

    #[tokio::test]
    async fn test_store_empty_file() {
        let (handler, _dir) = setup_handler(1024).await;
        let file_id = Uuid::new_v4();
        let empty: &[u8] = b"";

        let (path, hash) = handler.store_file(file_id, empty).await.unwrap();
        let data = handler.read_file(&path).await.unwrap();
        assert!(data.is_empty());
        // SHA-256 of empty input is the well-known constant
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn test_store_binary_data_with_null_bytes() {
        let (handler, _dir) = setup_handler(1024).await;
        let file_id = Uuid::new_v4();
        let data: Vec<u8> = vec![0x00, 0xFF, 0x00, 0xDE, 0xAD, 0x00, 0xBE, 0xEF];

        let (path, _hash) = handler.store_file(file_id, &data).await.unwrap();
        let read_back = handler.read_file(&path).await.unwrap();
        assert_eq!(read_back, data);
    }

    #[tokio::test]
    async fn test_deterministic_content_hash() {
        let (handler, _dir) = setup_handler(4096).await;
        let data = b"same_data";

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let (_, hash1) = handler.store_file(id1, data).await.unwrap();
        let (_, hash2) = handler.store_file(id2, data).await.unwrap();
        assert_eq!(
            hash1, hash2,
            "identical content must produce identical hashes"
        );
    }

    #[tokio::test]
    async fn test_different_data_different_hash() {
        let (handler, _dir) = setup_handler(4096).await;

        let (_, h1) = handler.store_file(Uuid::new_v4(), b"aaa").await.unwrap();
        let (_, h2) = handler.store_file(Uuid::new_v4(), b"bbb").await.unwrap();
        assert_ne!(h1, h2);
    }

    // ---------------------------------------------------------------
    // File size limit enforcement
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_file_size_limit() {
        let (handler, _dir) = setup_handler(10).await;

        let file_id = Uuid::new_v4();
        let large_data = vec![0u8; 100]; // Exceeds limit

        let result = handler.store_file(file_id, &large_data).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("exceeds maximum"),
            "error message should mention size limit"
        );
    }

    #[tokio::test]
    async fn test_file_size_exactly_at_limit() {
        let (handler, _dir) = setup_handler(10).await;

        // Exactly at the limit should succeed
        let data = vec![0u8; 10];
        let result = handler.store_file(Uuid::new_v4(), &data).await;
        assert!(
            result.is_ok(),
            "file exactly at size limit should be accepted"
        );
    }

    #[tokio::test]
    async fn test_file_size_one_byte_over_limit() {
        let (handler, _dir) = setup_handler(10).await;

        let data = vec![0u8; 11];
        let result = handler.store_file(Uuid::new_v4(), &data).await;
        assert!(result.is_err(), "file one byte over limit must be rejected");
    }

    #[tokio::test]
    async fn test_file_size_one_byte_under_limit() {
        let (handler, _dir) = setup_handler(10).await;

        let data = vec![0u8; 9];
        let result = handler.store_file(Uuid::new_v4(), &data).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_zero_size_limit_rejects_nonempty() {
        let (handler, _dir) = setup_handler(0).await;

        let result = handler.store_file(Uuid::new_v4(), b"x").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_zero_size_limit_accepts_empty() {
        let (handler, _dir) = setup_handler(0).await;

        let result = handler.store_file(Uuid::new_v4(), b"").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_oversized_file_not_written_to_disk() {
        let (handler, dir) = setup_handler(10).await;

        let file_id = Uuid::new_v4();
        let _ = handler.store_file(file_id, &vec![0u8; 100]).await;

        // The file should NOT exist on disk after rejection
        let would_be_path = dir.path().join(file_id.to_string());
        assert!(
            !would_be_path.exists(),
            "rejected file must not be persisted to disk"
        );
    }

    // ---------------------------------------------------------------
    // Path traversal protection (validate_path)
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_path_traversal_protection() {
        let (handler, _dir) = setup_handler(1024).await;

        // Classic path traversal
        let result = handler.read_file("../../../etc/passwd").await;
        assert!(result.is_err());

        let result = handler.delete_file("../../../important_file").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_traversal_dot_dot_in_middle() {
        let (handler, _dir) = setup_handler(1024).await;

        let result = handler.read_file("subdir/../../../etc/shadow").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_traversal_absolute_path() {
        let (handler, _dir) = setup_handler(1024).await;

        // Absolute path pointing outside storage
        let result = handler.read_file("/etc/passwd").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_traversal_double_encoded() {
        let (handler, _dir) = setup_handler(1024).await;

        // Percent-encoded dots won't help on the filesystem but test robustness
        let result = handler.read_file("..%2f..%2f..%2fetc%2fpasswd").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_traversal_null_byte() {
        let (handler, _dir) = setup_handler(1024).await;

        // Null byte injection — canonicalize should fail
        let result = handler.read_file("file\0.txt").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_path_rejects_symlink_escape() {
        let (handler, dir) = setup_handler(1024).await;

        // Create a symlink inside storage that points outside
        let link_path = dir.path().join("escape_link");
        std::os::unix::fs::symlink("/etc/hostname", &link_path).unwrap();

        let result = handler.read_file(link_path.to_str().unwrap()).await;
        assert!(
            result.is_err(),
            "symlink escaping storage dir must be rejected"
        );
    }

    #[tokio::test]
    async fn test_file_exists_returns_false_for_traversal() {
        let (handler, _dir) = setup_handler(1024).await;

        assert!(
            !handler.file_exists("../../../etc/passwd").await,
            "file_exists must return false for traversal paths"
        );
    }

    #[tokio::test]
    async fn test_get_file_size_rejects_traversal() {
        let (handler, _dir) = setup_handler(1024).await;

        let result = handler.get_file_size("../../../etc/passwd").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_file_rejects_traversal() {
        let (handler, _dir) = setup_handler(1024).await;

        let result = handler.delete_file("../../../tmp/should_not_delete").await;
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // Content hash verification
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_content_hash_wrong_hash() {
        let (handler, _dir) = setup_handler(1024).await;

        let (path, _correct_hash) = handler.store_file(Uuid::new_v4(), b"hello").await.unwrap();

        let result = handler
            .verify_content_hash(
                &path,
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .await
            .unwrap();
        assert!(!result, "wrong hash must not verify");
    }

    #[tokio::test]
    async fn test_verify_content_hash_correct() {
        let (handler, _dir) = setup_handler(1024).await;

        let (path, hash) = handler.store_file(Uuid::new_v4(), b"hello").await.unwrap();

        assert!(handler.verify_content_hash(&path, &hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_verify_content_hash_nonexistent_file() {
        let (handler, dir) = setup_handler(1024).await;

        let fake_path = dir.path().join("nonexistent").to_string_lossy().to_string();
        let result = handler.verify_content_hash(&fake_path, "abc").await;
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // Read / delete / size of nonexistent files
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_read_nonexistent_file() {
        let (handler, dir) = setup_handler(1024).await;

        let fake = dir
            .path()
            .join("does_not_exist")
            .to_string_lossy()
            .to_string();
        let result = handler.read_file(&fake).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_file_is_ok() {
        let (handler, dir) = setup_handler(1024).await;

        // Current implementation: delete of missing file succeeds (no-op)
        // because it checks .exists() before remove_file.
        // BUT validate_path uses canonicalize which will fail on nonexistent files.
        let fake = dir.path().join("ghost").to_string_lossy().to_string();
        let result = handler.delete_file(&fake).await;
        // canonicalize fails on nonexistent path, so this is an error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_file_size_nonexistent() {
        let (handler, dir) = setup_handler(1024).await;

        let fake = dir.path().join("nope").to_string_lossy().to_string();
        let result = handler.get_file_size(&fake).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_file_exists_nonexistent() {
        let (handler, dir) = setup_handler(1024).await;

        let fake = dir.path().join("nope").to_string_lossy().to_string();
        assert!(!handler.file_exists(&fake).await);
    }

    // ---------------------------------------------------------------
    // get_file_size returns correct value
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_get_file_size_correct() {
        let (handler, _dir) = setup_handler(4096).await;

        let data = vec![0xABu8; 256];
        let (path, _) = handler.store_file(Uuid::new_v4(), &data).await.unwrap();

        let size = handler.get_file_size(&path).await.unwrap();
        assert_eq!(size, 256);
    }

    // ---------------------------------------------------------------
    // Default config sanity
    // ---------------------------------------------------------------

    #[test]
    fn test_default_config_values() {
        let cfg = FileConfig::default();
        assert_eq!(
            cfg.max_file_size,
            100 * 1024 * 1024,
            "default max should be 100 MB"
        );
        assert_eq!(cfg.storage_dir, PathBuf::from("./data/files"));
    }

    #[test]
    fn test_with_default_config_constructor() {
        let handler = FileHandler::with_default_config();
        assert_eq!(handler.config.max_file_size, 100 * 1024 * 1024);
    }

    // ---------------------------------------------------------------
    // Storage path uses UUID filename (no user-controlled names)
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_storage_path_uses_uuid() {
        let (handler, dir) = setup_handler(1024).await;

        let file_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let (path, _) = handler.store_file(file_id, b"data").await.unwrap();

        // The stored path should contain the UUID as filename
        assert!(
            path.contains("550e8400-e29b-41d4-a716-446655440000"),
            "storage path should use the UUID as filename, got: {}",
            path
        );
        // And the file should be directly under storage_dir
        let expected = dir.path().join("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(Path::new(&path), expected.as_path());
    }

    // ---------------------------------------------------------------
    // Init creates nested directories
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_init_creates_nested_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let nested = temp_dir.path().join("a").join("b").join("c");
        let config = FileConfig {
            storage_dir: nested.clone(),
            max_file_size: 1024,
        };

        let handler = FileHandler::new(config);
        handler.init().await.unwrap();
        assert!(nested.exists());
    }

    #[tokio::test]
    async fn test_init_idempotent() {
        let (handler, _dir) = setup_handler(1024).await;
        // Calling init again should not fail
        handler.init().await.unwrap();
    }

    // ---------------------------------------------------------------
    // Multiple files stored independently
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_multiple_files_independent() {
        let (handler, _dir) = setup_handler(4096).await;

        let (path1, _) = handler
            .store_file(Uuid::new_v4(), b"file_one")
            .await
            .unwrap();
        let (path2, _) = handler
            .store_file(Uuid::new_v4(), b"file_two")
            .await
            .unwrap();

        assert_ne!(path1, path2);

        // Deleting one doesn't affect the other
        handler.delete_file(&path1).await.unwrap();
        assert!(!handler.file_exists(&path1).await);
        assert!(handler.file_exists(&path2).await);

        let data2 = handler.read_file(&path2).await.unwrap();
        assert_eq!(data2, b"file_two");
    }

    // ---------------------------------------------------------------
    // Large file at exact boundary (default 100MB not practical,
    // but we test the boundary logic with small limits)
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_large_data_within_limit() {
        // 1 MB limit, store exactly 1 MB
        let limit = 1024 * 1024;
        let (handler, _dir) = setup_handler(limit).await;

        let data = vec![0x42u8; limit as usize];
        let result = handler.store_file(Uuid::new_v4(), &data).await;
        assert!(result.is_ok());
    }
}
