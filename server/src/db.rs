//! Database layer for Accord server using SQLite
//!
//! Provides persistent storage for users, channels, and messages while maintaining
//! zero-knowledge properties for encrypted content.

use crate::models::{AuthToken, Channel, User};
use anyhow::{Context, Result};
use sqlx::{sqlite::SqlitePool, Row, SqlitePool as Pool};
use std::path::Path;
use uuid::Uuid;

/// Database connection pool and operations
#[derive(Debug, Clone)]
pub struct Database {
    pool: Pool,
}

impl Database {
    /// Create a new database connection to the specified file path
    ///
    /// If the path is ":memory:", creates an in-memory database for testing
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let db_url = if db_path.as_ref().to_str() == Some(":memory:") {
            "sqlite::memory:".to_string()
        } else {
            format!("sqlite:{}", db_path.as_ref().display())
        };

        let pool = SqlitePool::connect(&db_url)
            .await
            .context("Failed to connect to SQLite database")?;

        let db = Self { pool };
        db.run_migrations().await?;
        Ok(db)
    }

    /// Run database migrations to create or update schema
    async fn run_migrations(&self) -> Result<()> {
        // Create users table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY NOT NULL,
                username TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create users table")?;

        // Create channels table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create channels table")?;

        // Create channel_members table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS channel_members (
                channel_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                joined_at INTEGER NOT NULL,
                PRIMARY KEY (channel_id, user_id),
                FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create channel_members table")?;

        // Create messages table for persistent message history
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY NOT NULL,
                channel_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                encrypted_payload BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create messages table")?;

        // Create indexes for better query performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_channel_members_channel ON channel_members (channel_id)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_channel_members_user ON channel_members (user_id)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages (channel_id, created_at)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Register a new user in the database
    pub async fn create_user(&self, username: &str, public_key: &str) -> Result<User> {
        let user_id = Uuid::new_v4();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        sqlx::query(
            "INSERT INTO users (id, username, public_key, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(user_id.to_string())
        .bind(username)
        .bind(public_key)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to insert user")?;

        Ok(User {
            id: user_id,
            username: username.to_string(),
            public_key: public_key.to_string(),
            created_at,
        })
    }

    /// Get a user by their ID
    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let row = sqlx::query("SELECT id, username, public_key, created_at FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query user by ID")?;

        if let Some(row) = row {
            Ok(Some(User {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                username: row.get("username"),
                public_key: row.get("public_key"),
                created_at: row.get::<i64, _>("created_at") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get a user by their username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query("SELECT id, username, public_key, created_at FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query user by username")?;

        if let Some(row) = row {
            Ok(Some(User {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                username: row.get("username"),
                public_key: row.get("public_key"),
                created_at: row.get::<i64, _>("created_at") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Create a new channel
    pub async fn create_channel(&self, name: &str, created_by: Uuid) -> Result<Channel> {
        let channel_id = Uuid::new_v4();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        sqlx::query(
            "INSERT INTO channels (id, name, created_by, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(channel_id.to_string())
        .bind(name)
        .bind(created_by.to_string())
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to insert channel")?;

        // Add the creator as the first member
        self.add_user_to_channel(channel_id, created_by).await?;

        // Get members to return in the Channel struct
        let members = self.get_channel_members(channel_id).await?;

        Ok(Channel {
            id: channel_id,
            name: name.to_string(),
            members,
            created_at,
        })
    }

    /// Get a channel by its ID
    pub async fn get_channel(&self, channel_id: Uuid) -> Result<Option<Channel>> {
        let row = sqlx::query("SELECT id, name, created_by, created_at FROM channels WHERE id = ?")
            .bind(channel_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query channel")?;

        if let Some(row) = row {
            let members = self.get_channel_members(channel_id).await?;

            Ok(Some(Channel {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                name: row.get("name"),
                members,
                created_at: row.get::<i64, _>("created_at") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Add a user to a channel
    pub async fn add_user_to_channel(&self, channel_id: Uuid, user_id: Uuid) -> Result<()> {
        let joined_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        sqlx::query(
            "INSERT OR IGNORE INTO channel_members (channel_id, user_id, joined_at) VALUES (?, ?, ?)",
        )
        .bind(channel_id.to_string())
        .bind(user_id.to_string())
        .bind(joined_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to add user to channel")?;

        Ok(())
    }

    /// Remove a user from a channel
    pub async fn remove_user_from_channel(&self, channel_id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM channel_members WHERE channel_id = ? AND user_id = ?")
            .bind(channel_id.to_string())
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to remove user from channel")?;

        Ok(())
    }

    /// Get all members of a channel
    pub async fn get_channel_members(&self, channel_id: Uuid) -> Result<Vec<Uuid>> {
        let rows = sqlx::query("SELECT user_id FROM channel_members WHERE channel_id = ?")
            .bind(channel_id.to_string())
            .fetch_all(&self.pool)
            .await
            .context("Failed to query channel members")?;

        let mut members = Vec::new();
        for row in rows {
            let user_id_str: String = row.get("user_id");
            members.push(Uuid::parse_str(&user_id_str)?);
        }

        Ok(members)
    }

    /// Store an encrypted message (for history/offline delivery)
    pub async fn store_message(
        &self,
        channel_id: Uuid,
        sender_id: Uuid,
        encrypted_payload: &[u8],
    ) -> Result<Uuid> {
        let message_id = Uuid::new_v4();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        sqlx::query(
            "INSERT INTO messages (id, channel_id, sender_id, encrypted_payload, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(message_id.to_string())
        .bind(channel_id.to_string())
        .bind(sender_id.to_string())
        .bind(encrypted_payload)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to store message")?;

        Ok(message_id)
    }

    /// Get recent messages from a channel (for history/catching up)
    pub async fn get_channel_messages(
        &self,
        channel_id: Uuid,
        limit: u32,
        before: Option<u64>,
    ) -> Result<Vec<(Uuid, Uuid, Vec<u8>, u64)>> {
        let query = if let Some(before_timestamp) = before {
            sqlx::query(
                "SELECT id, sender_id, encrypted_payload, created_at FROM messages 
                 WHERE channel_id = ? AND created_at < ?
                 ORDER BY created_at DESC LIMIT ?",
            )
            .bind(channel_id.to_string())
            .bind(before_timestamp as i64)
            .bind(limit as i64)
        } else {
            sqlx::query(
                "SELECT id, sender_id, encrypted_payload, created_at FROM messages 
                 WHERE channel_id = ?
                 ORDER BY created_at DESC LIMIT ?",
            )
            .bind(channel_id.to_string())
            .bind(limit as i64)
        };

        let rows = query
            .fetch_all(&self.pool)
            .await
            .context("Failed to query channel messages")?;

        let mut messages = Vec::new();
        for row in rows {
            let message_id = Uuid::parse_str(&row.get::<String, _>("id"))?;
            let sender_id = Uuid::parse_str(&row.get::<String, _>("sender_id"))?;
            let encrypted_payload: Vec<u8> = row.get("encrypted_payload");
            let created_at = row.get::<i64, _>("created_at") as u64;

            messages.push((message_id, sender_id, encrypted_payload, created_at));
        }

        // Reverse to get chronological order (oldest first)
        messages.reverse();
        Ok(messages)
    }

    /// Get all channels that a user is a member of
    pub async fn get_user_channels(&self, user_id: Uuid) -> Result<Vec<Channel>> {
        let rows = sqlx::query(
            "SELECT c.id, c.name, c.created_by, c.created_at 
             FROM channels c 
             JOIN channel_members cm ON c.id = cm.channel_id 
             WHERE cm.user_id = ?",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query user channels")?;

        let mut channels = Vec::new();
        for row in rows {
            let channel_id = Uuid::parse_str(&row.get::<String, _>("id"))?;
            let members = self.get_channel_members(channel_id).await?;

            channels.push(Channel {
                id: channel_id,
                name: row.get("name"),
                members,
                created_at: row.get::<i64, _>("created_at") as u64,
            });
        }

        Ok(channels)
    }

    /// Check if username already exists
    pub async fn username_exists(&self, username: &str) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(&self.pool)
            .await
            .context("Failed to check username existence")?;

        let count: i64 = row.get("count");
        Ok(count > 0)
    }

    /// Clean up expired auth tokens (this would be called periodically)
    pub async fn cleanup_expired_tokens(&self, current_time: u64) -> Result<u64> {
        // Note: Auth tokens are still kept in-memory for now
        // This is a placeholder for future token persistence
        // For now, just return 0 as no database tokens were cleaned
        let _ = current_time; // Suppress unused warning
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_initialization() {
        let db = Database::new(":memory:").await.expect("Failed to create in-memory database");
        // If we get here, the database was created and migrations ran successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_user_operations() {
        let db = Database::new(":memory:").await.unwrap();

        // Test user creation
        let user = db.create_user("test_user", "test_public_key").await.unwrap();
        assert_eq!(user.username, "test_user");
        assert_eq!(user.public_key, "test_public_key");

        // Test get user by ID
        let found_user = db.get_user_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(found_user.username, "test_user");

        // Test get user by username
        let found_user = db.get_user_by_username("test_user").await.unwrap().unwrap();
        assert_eq!(found_user.id, user.id);

        // Test username existence check
        assert!(db.username_exists("test_user").await.unwrap());
        assert!(!db.username_exists("nonexistent_user").await.unwrap());
    }

    #[tokio::test]
    async fn test_channel_operations() {
        let db = Database::new(":memory:").await.unwrap();

        // Create a user first
        let user = db.create_user("test_user", "test_key").await.unwrap();

        // Create a channel
        let channel = db.create_channel("test_channel", user.id).await.unwrap();
        assert_eq!(channel.name, "test_channel");
        assert_eq!(channel.members.len(), 1);
        assert!(channel.members.contains(&user.id));

        // Get channel
        let found_channel = db.get_channel(channel.id).await.unwrap().unwrap();
        assert_eq!(found_channel.name, "test_channel");

        // Test channel members
        let members = db.get_channel_members(channel.id).await.unwrap();
        assert_eq!(members.len(), 1);
        assert!(members.contains(&user.id));

        // Add another user
        let user2 = db.create_user("test_user2", "test_key2").await.unwrap();
        db.add_user_to_channel(channel.id, user2.id).await.unwrap();

        let members = db.get_channel_members(channel.id).await.unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&user.id));
        assert!(members.contains(&user2.id));

        // Remove a user
        db.remove_user_from_channel(channel.id, user2.id).await.unwrap();
        let members = db.get_channel_members(channel.id).await.unwrap();
        assert_eq!(members.len(), 1);
        assert!(members.contains(&user.id));
    }

    #[tokio::test]
    async fn test_message_operations() {
        let db = Database::new(":memory:").await.unwrap();

        let user = db.create_user("test_user", "test_key").await.unwrap();
        let channel = db.create_channel("test_channel", user.id).await.unwrap();

        // Store a message
        let encrypted_data = b"encrypted_message_data";
        let message_id = db.store_message(channel.id, user.id, encrypted_data).await.unwrap();

        // Get messages
        let messages = db.get_channel_messages(channel.id, 10, None).await.unwrap();
        assert_eq!(messages.len(), 1);
        
        let (stored_id, sender_id, payload, _timestamp) = &messages[0];
        assert_eq!(*stored_id, message_id);
        assert_eq!(*sender_id, user.id);
        assert_eq!(*payload, encrypted_data.to_vec());
    }
}