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

    #[tokio::test]
    async fn test_file_storage() {
        let temp_dir = TempDir::new().unwrap();
        let config = FileConfig {
            storage_dir: temp_dir.path().to_path_buf(),
            max_file_size: 1024,
        };

        let handler = FileHandler::new(config);
        handler.init().await.unwrap();

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
    async fn test_file_size_limit() {
        let temp_dir = TempDir::new().unwrap();
        let config = FileConfig {
            storage_dir: temp_dir.path().to_path_buf(),
            max_file_size: 10, // Very small limit
        };

        let handler = FileHandler::new(config);
        handler.init().await.unwrap();

        let file_id = Uuid::new_v4();
        let large_data = vec![0u8; 100]; // Exceeds limit

        // Should fail due to size limit
        let result = handler.store_file(file_id, &large_data).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_path_traversal_protection() {
        let temp_dir = TempDir::new().unwrap();
        let config = FileConfig {
            storage_dir: temp_dir.path().to_path_buf(),
            max_file_size: 1024,
        };

        let handler = FileHandler::new(config);

        // Try to read a file outside the storage directory
        let result = handler.read_file("../../../etc/passwd").await;
        assert!(result.is_err());

        // Try to delete a file outside the storage directory
        let result = handler.delete_file("../../../important_file").await;
        assert!(result.is_err());
    }
}
