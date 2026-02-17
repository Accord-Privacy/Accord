//! Database layer for Accord server using SQLite
//!
//! Provides persistent storage for users, nodes, channels, and messages while maintaining
//! zero-knowledge properties for encrypted content.

use crate::models::{Channel, FileMetadata, NodeInvite, User};
use crate::node::{Node, NodeMember, NodeRole};
use anyhow::{Context, Result};
use base64::Engine;
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
                password_hash TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create users table")?;

        // Create nodes table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                description TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create nodes table")?;

        // Create node_members table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS node_members (
                node_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                joined_at INTEGER NOT NULL,
                PRIMARY KEY (node_id, user_id),
                FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create node_members table")?;

        // Create channel_categories table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS channel_categories (
                id TEXT PRIMARY KEY NOT NULL,
                node_id TEXT NOT NULL,
                name TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create channel_categories table")?;

        // Create channels table (with node_id)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                node_id TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                category_id TEXT,
                position INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users (id),
                FOREIGN KEY (category_id) REFERENCES channel_categories (id) ON DELETE SET NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create channels table")?;

        // Add password_hash column to existing users table if it doesn't exist
        sqlx::query("ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await
            .ok(); // Ignore error if column already exists

        // Add category_id and position columns to existing channels table if they don't exist
        sqlx::query("ALTER TABLE channels ADD COLUMN category_id TEXT")
            .execute(&self.pool)
            .await
            .ok(); // Ignore error if column already exists

        sqlx::query("ALTER TABLE channels ADD COLUMN position INTEGER NOT NULL DEFAULT 0")
            .execute(&self.pool)
            .await
            .ok(); // Ignore error if column already exists

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

        // Create messages table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY NOT NULL,
                channel_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                encrypted_payload BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                edited_at INTEGER,
                pinned_at INTEGER,
                pinned_by TEXT,
                FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (pinned_by) REFERENCES users (id) ON DELETE SET NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create messages table")?;

        // Add edited_at column to existing messages table if it doesn't exist
        sqlx::query("ALTER TABLE messages ADD COLUMN edited_at INTEGER")
            .execute(&self.pool)
            .await
            .ok(); // Ignore error if column already exists

        // Add pinning columns to existing messages table if they don't exist
        sqlx::query("ALTER TABLE messages ADD COLUMN pinned_at INTEGER")
            .execute(&self.pool)
            .await
            .ok(); // Ignore error if column already exists

        sqlx::query("ALTER TABLE messages ADD COLUMN pinned_by TEXT")
            .execute(&self.pool)
            .await
            .ok(); // Ignore error if column already exists

        // Add reply_to column to existing messages table if it doesn't exist
        sqlx::query("ALTER TABLE messages ADD COLUMN reply_to TEXT")
            .execute(&self.pool)
            .await
            .ok(); // Ignore error if column already exists

        // Create node_invites table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS node_invites (
                id TEXT PRIMARY KEY NOT NULL,
                node_id TEXT NOT NULL,
                created_by TEXT NOT NULL,
                invite_code TEXT NOT NULL UNIQUE,
                max_uses INTEGER,
                current_uses INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create node_invites table")?;

        // Create user_profiles table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id TEXT PRIMARY KEY NOT NULL,
                display_name TEXT NOT NULL,
                avatar_url TEXT,
                bio TEXT,
                status TEXT NOT NULL DEFAULT 'offline',
                custom_status TEXT,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create user_profiles table")?;

        // Create files table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY NOT NULL,
                channel_id TEXT NOT NULL,
                uploader_id TEXT NOT NULL,
                encrypted_filename BLOB NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                content_hash TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE,
                FOREIGN KEY (uploader_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create files table")?;

        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_nodes_owner ON nodes (owner_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_node_members_node ON node_members (node_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_node_members_user ON node_members (user_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_channels_node ON channels (node_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_channel_members_channel ON channel_members (channel_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_channel_members_user ON channel_members (user_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages (channel_id, created_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_node_invites_code ON node_invites (invite_code)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_node_invites_node ON node_invites (node_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_user_profiles_status ON user_profiles (status)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_files_channel ON files (channel_id, created_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_uploader ON files (uploader_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_content_hash ON files (content_hash)")
            .execute(&self.pool)
            .await?;

        // Additional indexes for message history and search functionality
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages (sender_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages (created_at DESC)",
        )
        .execute(&self.pool)
        .await?;

        // Create message_reactions table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS message_reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                emoji TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(message_id, user_id, emoji),
                FOREIGN KEY (message_id) REFERENCES messages (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create message_reactions table")?;

        // Create indexes for reactions
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_reactions_message ON message_reactions (message_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_reactions_user ON message_reactions (user_id)")
            .execute(&self.pool)
            .await?;

        // Create dm_channels table for direct messages
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS dm_channels (
                id TEXT PRIMARY KEY NOT NULL,
                user1_id TEXT NOT NULL,
                user2_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user1_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (user2_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(user1_id, user2_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create dm_channels table")?;

        // Create indexes for dm_channels
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_dm_channels_user1 ON dm_channels (user1_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_dm_channels_user2 ON dm_channels (user2_id)")
            .execute(&self.pool)
            .await?;

        // Create audit_log table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY NOT NULL,
                node_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                details TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
                FOREIGN KEY (actor_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create audit_log table")?;

        // Create indexes for audit_log
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_node ON audit_log (node_id, created_at DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // ── User operations ──

    pub async fn create_user(
        &self,
        username: &str,
        public_key: &str,
        password_hash: &str,
    ) -> Result<User> {
        let user_id = Uuid::new_v4();
        let created_at = now();

        sqlx::query(
            "INSERT INTO users (id, username, public_key, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id.to_string())
        .bind(username)
        .bind(public_key)
        .bind(password_hash)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to insert user")?;

        // Create default user profile
        self.create_user_profile(user_id, username).await?;

        Ok(User {
            id: user_id,
            username: username.to_string(),
            public_key: public_key.to_string(),
            created_at,
        })
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let row =
            sqlx::query("SELECT id, username, public_key, created_at FROM users WHERE id = ?")
                .bind(user_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .context("Failed to query user by ID")?;

        row.map(|r| parse_user(&r)).transpose()
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, username, public_key, created_at FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query user by username")?;

        row.map(|r| parse_user(&r)).transpose()
    }

    pub async fn get_user_password_hash(&self, username: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query user password hash")?;
        Ok(row.map(|r| r.get::<String, _>("password_hash")))
    }

    pub async fn username_exists(&self, username: &str) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("count") > 0)
    }

    // ── Node operations ──

    pub async fn create_node(
        &self,
        name: &str,
        owner_id: Uuid,
        description: Option<&str>,
    ) -> Result<Node> {
        let node_id = Uuid::new_v4();
        let created_at = now();

        sqlx::query("INSERT INTO nodes (id, name, owner_id, description, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(node_id.to_string())
            .bind(name)
            .bind(owner_id.to_string())
            .bind(description)
            .bind(created_at as i64)
            .execute(&self.pool)
            .await
            .context("Failed to insert node")?;

        // Add owner as admin member
        self.add_node_member(node_id, owner_id, NodeRole::Admin)
            .await?;

        // Create a default "general" channel
        self.create_channel("general", node_id, owner_id).await?;

        Ok(Node {
            id: node_id,
            name: name.to_string(),
            owner_id,
            description: description.map(|s| s.to_string()),
            created_at,
        })
    }

    pub async fn get_node(&self, node_id: Uuid) -> Result<Option<Node>> {
        let row = sqlx::query(
            "SELECT id, name, owner_id, description, created_at FROM nodes WHERE id = ?",
        )
        .bind(node_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query node")?;

        row.map(|r| parse_node(&r)).transpose()
    }

    pub async fn update_node(
        &self,
        node_id: Uuid,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<()> {
        let mut query_parts = Vec::new();
        let mut binds = Vec::new();

        if let Some(name) = name {
            query_parts.push("name = ?");
            binds.push(name.to_string());
        }

        if let Some(description) = description {
            query_parts.push("description = ?");
            binds.push(description.to_string());
        }

        if query_parts.is_empty() {
            return Ok(());
        }

        let query = format!(
            "UPDATE nodes SET {} WHERE id = ?",
            query_parts.join(", ")
        );

        let mut sqlx_query = sqlx::query(&query);
        for bind in binds {
            sqlx_query = sqlx_query.bind(bind);
        }
        sqlx_query = sqlx_query.bind(node_id.to_string());

        sqlx_query
            .execute(&self.pool)
            .await
            .context("Failed to update node")?;

        Ok(())
    }

    pub async fn delete_node(&self, node_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM nodes WHERE id = ?")
            .bind(node_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to delete node")?;
        Ok(())
    }

    pub async fn add_node_member(
        &self,
        node_id: Uuid,
        user_id: Uuid,
        role: NodeRole,
    ) -> Result<()> {
        let joined_at = now();
        sqlx::query("INSERT OR IGNORE INTO node_members (node_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)")
            .bind(node_id.to_string())
            .bind(user_id.to_string())
            .bind(role.as_str())
            .bind(joined_at as i64)
            .execute(&self.pool)
            .await
            .context("Failed to add node member")?;
        Ok(())
    }

    pub async fn remove_node_member(&self, node_id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM node_members WHERE node_id = ? AND user_id = ?")
            .bind(node_id.to_string())
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to remove node member")?;
        Ok(())
    }

    pub async fn get_node_members(&self, node_id: Uuid) -> Result<Vec<NodeMember>> {
        let rows = sqlx::query(
            "SELECT node_id, user_id, role, joined_at FROM node_members WHERE node_id = ?",
        )
        .bind(node_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query node members")?;

        rows.iter().map(|r| parse_node_member(r)).collect()
    }

    pub async fn get_node_member(
        &self,
        node_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<NodeMember>> {
        let row = sqlx::query("SELECT node_id, user_id, role, joined_at FROM node_members WHERE node_id = ? AND user_id = ?")
            .bind(node_id.to_string())
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query node member")?;

        row.map(|r| parse_node_member(&r)).transpose()
    }

    pub async fn is_node_member(&self, node_id: Uuid, user_id: Uuid) -> Result<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM node_members WHERE node_id = ? AND user_id = ?",
        )
        .bind(node_id.to_string())
        .bind(user_id.to_string())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("count") > 0)
    }

    pub async fn get_user_nodes(&self, user_id: Uuid) -> Result<Vec<Node>> {
        let rows = sqlx::query(
            "SELECT n.id, n.name, n.owner_id, n.description, n.created_at FROM nodes n JOIN node_members nm ON n.id = nm.node_id WHERE nm.user_id = ?"
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query user nodes")?;

        rows.iter().map(|r| parse_node(r)).collect()
    }

    pub async fn count_node_channels(&self, node_id: Uuid) -> Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM channels WHERE node_id = ?")
            .bind(node_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("count") as u64)
    }

    // ── Channel operations (now scoped to nodes) ──

    pub async fn create_channel(
        &self,
        name: &str,
        node_id: Uuid,
        created_by: Uuid,
    ) -> Result<Channel> {
        let channel_id = Uuid::new_v4();
        self.create_channel_with_id(channel_id, name, node_id, created_by)
            .await
    }

    pub async fn create_channel_with_id(
        &self,
        channel_id: Uuid,
        name: &str,
        node_id: Uuid,
        created_by: Uuid,
    ) -> Result<Channel> {
        let created_at = now();

        // Get the next position for this node (counting existing channels)
        let position_row = sqlx::query("SELECT COALESCE(MAX(position), -1) + 1 as next_position FROM channels WHERE node_id = ?")
            .bind(node_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        let position = position_row.get::<i64, _>("next_position");

        sqlx::query("INSERT INTO channels (id, name, node_id, created_by, created_at, position) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(channel_id.to_string())
            .bind(name)
            .bind(node_id.to_string())
            .bind(created_by.to_string())
            .bind(created_at as i64)
            .bind(position)
            .execute(&self.pool)
            .await
            .context("Failed to insert channel")?;

        // Add creator as first member
        self.add_user_to_channel(channel_id, created_by).await?;

        let members = self.get_channel_members(channel_id).await?;

        Ok(Channel {
            id: channel_id,
            name: name.to_string(),
            node_id,
            members,
            created_at,
        })
    }

    pub async fn get_channel(&self, channel_id: Uuid) -> Result<Option<Channel>> {
        let row = sqlx::query(
            "SELECT id, name, node_id, created_by, created_at FROM channels WHERE id = ?",
        )
        .bind(channel_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query channel")?;

        if let Some(row) = row {
            let members = self.get_channel_members(channel_id).await?;
            Ok(Some(Channel {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                name: row.get("name"),
                node_id: Uuid::parse_str(&row.get::<String, _>("node_id"))?,
                members,
                created_at: row.get::<i64, _>("created_at") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn get_node_channels(&self, node_id: Uuid) -> Result<Vec<Channel>> {
        let rows = sqlx::query(
            "SELECT id, name, node_id, created_by, created_at FROM channels WHERE node_id = ? ORDER BY position ASC",
        )
        .bind(node_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query node channels")?;

        let mut channels = Vec::new();
        for row in rows {
            let channel_id = Uuid::parse_str(&row.get::<String, _>("id"))?;
            let members = self.get_channel_members(channel_id).await?;
            channels.push(Channel {
                id: channel_id,
                name: row.get("name"),
                node_id: Uuid::parse_str(&row.get::<String, _>("node_id"))?,
                members,
                created_at: row.get::<i64, _>("created_at") as u64,
            });
        }
        Ok(channels)
    }

    pub async fn delete_channel(&self, channel_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM channels WHERE id = ?")
            .bind(channel_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to delete channel")?;
        Ok(())
    }

    pub async fn add_user_to_channel(&self, channel_id: Uuid, user_id: Uuid) -> Result<()> {
        let joined_at = now();
        sqlx::query("INSERT OR IGNORE INTO channel_members (channel_id, user_id, joined_at) VALUES (?, ?, ?)")
            .bind(channel_id.to_string())
            .bind(user_id.to_string())
            .bind(joined_at as i64)
            .execute(&self.pool)
            .await
            .context("Failed to add user to channel")?;
        Ok(())
    }

    pub async fn remove_user_from_channel(&self, channel_id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM channel_members WHERE channel_id = ? AND user_id = ?")
            .bind(channel_id.to_string())
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to remove user from channel")?;
        Ok(())
    }

    pub async fn get_channel_members(&self, channel_id: Uuid) -> Result<Vec<Uuid>> {
        let rows = sqlx::query("SELECT user_id FROM channel_members WHERE channel_id = ?")
            .bind(channel_id.to_string())
            .fetch_all(&self.pool)
            .await
            .context("Failed to query channel members")?;

        rows.iter()
            .map(|r| Uuid::parse_str(&r.get::<String, _>("user_id")).map_err(Into::into))
            .collect()
    }

    // ── Channel Category operations ──

    pub async fn create_channel_category(
        &self,
        node_id: Uuid,
        name: &str,
    ) -> Result<crate::models::ChannelCategory> {
        let category_id = Uuid::new_v4();
        let created_at = now();

        // Get the next position for this node
        let position_row = sqlx::query("SELECT COALESCE(MAX(position), -1) + 1 as next_position FROM channel_categories WHERE node_id = ?")
            .bind(node_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        let position = position_row.get::<i64, _>("next_position");

        sqlx::query("INSERT INTO channel_categories (id, node_id, name, position, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(category_id.to_string())
            .bind(node_id.to_string())
            .bind(name)
            .bind(position)
            .bind(created_at as i64)
            .execute(&self.pool)
            .await
            .context("Failed to insert channel category")?;

        Ok(crate::models::ChannelCategory {
            id: category_id,
            node_id,
            name: name.to_string(),
            position: position as u32,
            created_at,
        })
    }

    pub async fn get_category_by_id(
        &self,
        category_id: Uuid,
    ) -> Result<Option<crate::models::ChannelCategory>> {
        let row = sqlx::query(
            "SELECT id, node_id, name, position, created_at FROM channel_categories WHERE id = ?",
        )
        .bind(category_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query channel category by ID")?;

        row.map(|r| -> Result<crate::models::ChannelCategory> {
            Ok(crate::models::ChannelCategory {
                id: Uuid::parse_str(&r.get::<String, _>("id"))?,
                node_id: Uuid::parse_str(&r.get::<String, _>("node_id"))?,
                name: r.get("name"),
                position: r.get::<i64, _>("position") as u32,
                created_at: r.get::<i64, _>("created_at") as u64,
            })
        })
        .transpose()
    }

    pub async fn get_node_categories(
        &self,
        node_id: Uuid,
    ) -> Result<Vec<crate::models::ChannelCategory>> {
        let rows = sqlx::query(
            "SELECT id, node_id, name, position, created_at FROM channel_categories WHERE node_id = ? ORDER BY position ASC",
        )
        .bind(node_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query channel categories")?;

        rows.iter()
            .map(|row| -> Result<crate::models::ChannelCategory> {
                Ok(crate::models::ChannelCategory {
                    id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                    node_id: Uuid::parse_str(&row.get::<String, _>("node_id"))?,
                    name: row.get("name"),
                    position: row.get::<i64, _>("position") as u32,
                    created_at: row.get::<i64, _>("created_at") as u64,
                })
            })
            .collect()
    }

    pub async fn update_channel_category(
        &self,
        category_id: Uuid,
        name: Option<&str>,
        position: Option<u32>,
    ) -> Result<()> {
        let mut query_parts = Vec::new();
        let mut binds = Vec::new();

        if let Some(name) = name {
            query_parts.push("name = ?");
            binds.push(name.to_string());
        }

        if let Some(position) = position {
            query_parts.push("position = ?");
            binds.push(position.to_string());
        }

        if query_parts.is_empty() {
            return Ok(()); // Nothing to update
        }

        let query = format!(
            "UPDATE channel_categories SET {} WHERE id = ?",
            query_parts.join(", ")
        );

        let mut sqlx_query = sqlx::query(&query);
        for bind in binds {
            sqlx_query = sqlx_query.bind(bind);
        }
        sqlx_query = sqlx_query.bind(category_id.to_string());

        sqlx_query
            .execute(&self.pool)
            .await
            .context("Failed to update channel category")?;

        Ok(())
    }

    pub async fn delete_channel_category(&self, category_id: Uuid) -> Result<()> {
        // First, move all channels in this category to uncategorized (category_id = NULL)
        sqlx::query("UPDATE channels SET category_id = NULL WHERE category_id = ?")
            .bind(category_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to uncategorize channels")?;

        // Then delete the category
        sqlx::query("DELETE FROM channel_categories WHERE id = ?")
            .bind(category_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to delete channel category")?;

        Ok(())
    }

    pub async fn update_channel_category_and_position(
        &self,
        channel_id: Uuid,
        category_id: Option<Uuid>,
        position: Option<u32>,
    ) -> Result<()> {
        let mut query_parts = Vec::new();
        let mut binds: Vec<String> = Vec::new();

        if let Some(category_id) = category_id {
            query_parts.push("category_id = ?");
            binds.push(category_id.to_string());
        } else {
            query_parts.push("category_id = NULL");
        }

        if let Some(position) = position {
            query_parts.push("position = ?");
            binds.push(position.to_string());
        }

        let query = format!(
            "UPDATE channels SET {} WHERE id = ?",
            query_parts.join(", ")
        );

        let mut sqlx_query = sqlx::query(&query);
        for bind in binds {
            sqlx_query = sqlx_query.bind(bind);
        }
        sqlx_query = sqlx_query.bind(channel_id.to_string());

        sqlx_query
            .execute(&self.pool)
            .await
            .context("Failed to update channel category and position")?;

        Ok(())
    }

    pub async fn get_channels_with_categories(
        &self,
        node_id: Uuid,
    ) -> Result<Vec<crate::models::ChannelWithCategory>> {
        let rows = sqlx::query(
            r#"
            SELECT c.id, c.name, c.node_id, c.created_by, c.created_at, c.category_id, c.position,
                   cat.name as category_name
            FROM channels c
            LEFT JOIN channel_categories cat ON c.category_id = cat.id
            WHERE c.node_id = ?
            ORDER BY c.category_id ASC NULLS FIRST, c.position ASC
            "#,
        )
        .bind(node_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query channels with categories")?;

        let mut channels = Vec::new();
        for row in rows {
            let channel_id = Uuid::parse_str(&row.get::<String, _>("id"))?;
            let members = self.get_channel_members(channel_id).await?;

            let category_id = row
                .get::<Option<String>, _>("category_id")
                .and_then(|s| Uuid::parse_str(&s).ok());
            let category_name = row.get::<Option<String>, _>("category_name");

            channels.push(crate::models::ChannelWithCategory {
                id: channel_id,
                name: row.get("name"),
                node_id: Uuid::parse_str(&row.get::<String, _>("node_id"))?,
                members,
                created_at: row.get::<i64, _>("created_at") as u64,
                category_id,
                category_name,
                position: row.get::<i64, _>("position") as u32,
            });
        }
        Ok(channels)
    }

    // ── Message operations ──

    pub async fn store_message(
        &self,
        channel_id: Uuid,
        sender_id: Uuid,
        encrypted_payload: &[u8],
        reply_to: Option<Uuid>,
    ) -> Result<Uuid> {
        let message_id = Uuid::new_v4();
        let created_at = now();

        sqlx::query("INSERT INTO messages (id, channel_id, sender_id, encrypted_payload, created_at, reply_to) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(message_id.to_string())
            .bind(channel_id.to_string())
            .bind(sender_id.to_string())
            .bind(encrypted_payload)
            .bind(created_at as i64)
            .bind(reply_to.map(|id| id.to_string()))
            .execute(&self.pool)
            .await
            .context("Failed to store message")?;

        Ok(message_id)
    }

    pub async fn get_channel_messages(
        &self,
        channel_id: Uuid,
        limit: u32,
        before: Option<u64>,
    ) -> Result<Vec<(Uuid, Uuid, Vec<u8>, u64)>> {
        let query = if let Some(before_timestamp) = before {
            sqlx::query(
                "SELECT id, sender_id, encrypted_payload, created_at FROM messages WHERE channel_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?",
            )
            .bind(channel_id.to_string())
            .bind(before_timestamp as i64)
            .bind(limit as i64)
        } else {
            sqlx::query(
                "SELECT id, sender_id, encrypted_payload, created_at FROM messages WHERE channel_id = ? ORDER BY created_at DESC LIMIT ?",
            )
            .bind(channel_id.to_string())
            .bind(limit as i64)
        };

        let rows = query
            .fetch_all(&self.pool)
            .await
            .context("Failed to query channel messages")?;

        let mut messages: Vec<_> = rows
            .iter()
            .map(|row| -> Result<_> {
                let message_id = Uuid::parse_str(&row.get::<String, _>("id"))?;
                let sender_id = Uuid::parse_str(&row.get::<String, _>("sender_id"))?;
                let encrypted_payload: Vec<u8> = row.get("encrypted_payload");
                let created_at = row.get::<i64, _>("created_at") as u64;
                Ok((message_id, sender_id, encrypted_payload, created_at))
            })
            .collect::<Result<Vec<_>>>()?;

        messages.reverse(); // chronological order
        Ok(messages)
    }

    /// Get channel messages with cursor-based pagination for message history endpoint
    pub async fn get_channel_messages_paginated(
        &self,
        channel_id: Uuid,
        limit: u32,
        before_id: Option<Uuid>,
    ) -> Result<Vec<crate::models::MessageMetadata>> {
        let query = if let Some(before_message_id) = before_id {
            // Get the timestamp of the before_id message for cursor pagination
            let before_timestamp: i64 =
                sqlx::query_scalar("SELECT created_at FROM messages WHERE id = ?")
                    .bind(before_message_id.to_string())
                    .fetch_optional(&self.pool)
                    .await
                    .context("Failed to get before message timestamp")?
                    .unwrap_or(0);

            sqlx::query(
                r#"
                SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.edited_at, m.pinned_at, m.pinned_by, m.reply_to, u.username,
                       rm.id as replied_message_id, rm.sender_id as replied_sender_id, rm.encrypted_payload as replied_payload, rm.created_at as replied_created_at, ru.username as replied_username
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                LEFT JOIN messages rm ON m.reply_to = rm.id
                LEFT JOIN users ru ON rm.sender_id = ru.id
                WHERE m.channel_id = ? AND m.created_at < ?
                ORDER BY m.created_at DESC
                LIMIT ?
                "#,
            )
            .bind(channel_id.to_string())
            .bind(before_timestamp)
            .bind(limit as i64)
        } else {
            sqlx::query(
                r#"
                SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.edited_at, m.pinned_at, m.pinned_by, m.reply_to, u.username,
                       rm.id as replied_message_id, rm.sender_id as replied_sender_id, rm.encrypted_payload as replied_payload, rm.created_at as replied_created_at, ru.username as replied_username
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                LEFT JOIN messages rm ON m.reply_to = rm.id
                LEFT JOIN users ru ON rm.sender_id = ru.id
                WHERE m.channel_id = ?
                ORDER BY m.created_at DESC
                LIMIT ?
                "#,
            )
            .bind(channel_id.to_string())
            .bind(limit as i64)
        };

        let rows = query
            .fetch_all(&self.pool)
            .await
            .context("Failed to query channel messages")?;

        let messages: Vec<_> = rows
            .iter()
            .map(|row| parse_message_metadata(row))
            .collect::<Result<Vec<_>>>()?;

        Ok(messages)
    }

    /// Search messages within a Node by metadata (sender, channel, timestamp)
    /// Note: Content search is not possible due to E2E encryption
    pub async fn search_messages(
        &self,
        node_id: Uuid,
        query: &str,
        channel_id_filter: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<crate::models::SearchResult>> {
        // Since messages are E2E encrypted, we can only search by metadata:
        // - sender username
        // - channel name
        // - timestamp (not implemented in query param, but could be)

        let base_query = if let Some(channel_filter) = channel_id_filter {
            format!(
                r#"
                SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.pinned_at, m.pinned_by,
                       u.username as sender_username, c.name as channel_name
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                JOIN channels c ON m.channel_id = c.id
                WHERE c.node_id = ? AND c.id = ?
                  AND (LOWER(u.username) LIKE LOWER(?) OR LOWER(c.name) LIKE LOWER(?))
                ORDER BY m.created_at DESC
                LIMIT ?
                "#
            )
        } else {
            format!(
                r#"
                SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.pinned_at, m.pinned_by,
                       u.username as sender_username, c.name as channel_name
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                JOIN channels c ON m.channel_id = c.id
                WHERE c.node_id = ?
                  AND (LOWER(u.username) LIKE LOWER(?) OR LOWER(c.name) LIKE LOWER(?))
                ORDER BY m.created_at DESC
                LIMIT ?
                "#
            )
        };

        let search_pattern = format!("%{}%", query.to_lowercase());

        let query_builder = if channel_id_filter.is_some() {
            sqlx::query(&base_query)
                .bind(node_id.to_string())
                .bind(channel_id_filter.unwrap().to_string())
                .bind(&search_pattern)
                .bind(&search_pattern)
                .bind(limit as i64)
        } else {
            sqlx::query(&base_query)
                .bind(node_id.to_string())
                .bind(&search_pattern)
                .bind(&search_pattern)
                .bind(limit as i64)
        };

        let rows = query_builder
            .fetch_all(&self.pool)
            .await
            .context("Failed to search messages")?;

        let results: Vec<_> = rows
            .iter()
            .map(|row| -> Result<_> {
                let message_id = Uuid::parse_str(&row.get::<String, _>("id"))?;
                let channel_id = Uuid::parse_str(&row.get::<String, _>("channel_id"))?;
                let sender_id = Uuid::parse_str(&row.get::<String, _>("sender_id"))?;
                let sender_username: String = row.get("sender_username");
                let channel_name: String = row.get("channel_name");
                let encrypted_payload: Vec<u8> = row.get("encrypted_payload");
                let created_at = row.get::<i64, _>("created_at") as u64;

                Ok(crate::models::SearchResult {
                    message_id,
                    channel_id,
                    channel_name,
                    sender_id,
                    sender_username,
                    created_at,
                    encrypted_payload: base64::engine::general_purpose::STANDARD
                        .encode(&encrypted_payload),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(results)
    }

    pub async fn get_user_channels(&self, user_id: Uuid) -> Result<Vec<Channel>> {
        let rows = sqlx::query(
            "SELECT c.id, c.name, c.node_id, c.created_by, c.created_at FROM channels c JOIN channel_members cm ON c.id = cm.channel_id WHERE cm.user_id = ?",
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
                node_id: Uuid::parse_str(&row.get::<String, _>("node_id"))?,
                members,
                created_at: row.get::<i64, _>("created_at") as u64,
            });
        }
        Ok(channels)
    }

    pub async fn cleanup_expired_tokens(&self, _current_time: u64) -> Result<u64> {
        Ok(0)
    }

    /// Edit a message (author only)
    pub async fn edit_message(
        &self,
        message_id: Uuid,
        sender_id: Uuid,
        new_encrypted_payload: &[u8],
    ) -> Result<bool> {
        let edited_at = now();

        let result = sqlx::query(
            "UPDATE messages SET encrypted_payload = ?, edited_at = ? WHERE id = ? AND sender_id = ?"
        )
        .bind(new_encrypted_payload)
        .bind(edited_at as i64)
        .bind(message_id.to_string())
        .bind(sender_id.to_string())
        .execute(&self.pool)
        .await
        .context("Failed to edit message")?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a message (author or admin/mod)
    pub async fn delete_message(
        &self,
        message_id: Uuid,
        requester_id: Uuid,
    ) -> Result<Option<(Uuid, Uuid)>> {
        // Returns (channel_id, sender_id) if successful
        // First, get the message details to check permissions and return channel info
        let message_info: Option<(String, String)> =
            sqlx::query_as("SELECT channel_id, sender_id FROM messages WHERE id = ?")
                .bind(message_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .context("Failed to query message")?;

        if let Some((channel_id_str, sender_id_str)) = message_info {
            let channel_id =
                Uuid::parse_str(&channel_id_str).context("Invalid channel_id format")?;
            let sender_id = Uuid::parse_str(&sender_id_str).context("Invalid sender_id format")?;

            // Check if requester is the author
            let is_author = requester_id == sender_id;

            // Check if requester is admin/mod of the node containing this channel
            let is_admin_or_mod = sqlx::query_scalar::<_, bool>(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM node_members nm
                    JOIN channels c ON c.node_id = nm.node_id
                    WHERE c.id = ? AND nm.user_id = ? AND nm.role IN ('admin', 'moderator')
                )
                "#,
            )
            .bind(channel_id.to_string())
            .bind(requester_id.to_string())
            .fetch_one(&self.pool)
            .await
            .unwrap_or(false);

            if is_author || is_admin_or_mod {
                let result = sqlx::query("DELETE FROM messages WHERE id = ?")
                    .bind(message_id.to_string())
                    .execute(&self.pool)
                    .await
                    .context("Failed to delete message")?;

                if result.rows_affected() > 0 {
                    return Ok(Some((channel_id, sender_id)));
                }
            }
        }

        Ok(None)
    }

    /// Get message details for permission checking
    pub async fn get_message_details(
        &self,
        message_id: Uuid,
    ) -> Result<Option<(Uuid, Uuid, u64, Option<u64>)>> {
        // (channel_id, sender_id, created_at, edited_at)
        let result: Option<(String, String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT channel_id, sender_id, created_at, edited_at FROM messages WHERE id = ?",
        )
        .bind(message_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query message details")?;

        if let Some((channel_id_str, sender_id_str, created_at, edited_at)) = result {
            let channel_id =
                Uuid::parse_str(&channel_id_str).context("Invalid channel_id format")?;
            let sender_id = Uuid::parse_str(&sender_id_str).context("Invalid sender_id format")?;

            Ok(Some((
                channel_id,
                sender_id,
                created_at as u64,
                edited_at.map(|t| t as u64),
            )))
        } else {
            Ok(None)
        }
    }

    // ── Node invite operations ──

    pub async fn create_node_invite(
        &self,
        node_id: Uuid,
        created_by: Uuid,
        invite_code: &str,
        max_uses: Option<u32>,
        expires_at: Option<u64>,
    ) -> Result<Uuid> {
        let invite_id = Uuid::new_v4();
        let created_at = now();

        sqlx::query("INSERT INTO node_invites (id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)")
            .bind(invite_id.to_string())
            .bind(node_id.to_string())
            .bind(created_by.to_string())
            .bind(invite_code)
            .bind(max_uses.map(|u| u as i64))
            .bind(expires_at.map(|t| t as i64))
            .bind(created_at as i64)
            .execute(&self.pool)
            .await
            .context("Failed to create node invite")?;

        Ok(invite_id)
    }

    pub async fn get_node_invite_by_code(&self, invite_code: &str) -> Result<Option<NodeInvite>> {
        let row = sqlx::query("SELECT id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at FROM node_invites WHERE invite_code = ?")
            .bind(invite_code)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query node invite by code")?;

        row.map(|r| parse_node_invite(&r)).transpose()
    }

    pub async fn get_node_invites(&self, node_id: Uuid) -> Result<Vec<NodeInvite>> {
        let rows = sqlx::query("SELECT id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at FROM node_invites WHERE node_id = ? ORDER BY created_at DESC")
            .bind(node_id.to_string())
            .fetch_all(&self.pool)
            .await
            .context("Failed to query node invites")?;

        rows.iter().map(|r| parse_node_invite(r)).collect()
    }

    pub async fn increment_invite_usage(&self, invite_code: &str) -> Result<()> {
        sqlx::query(
            "UPDATE node_invites SET current_uses = current_uses + 1 WHERE invite_code = ?",
        )
        .bind(invite_code)
        .execute(&self.pool)
        .await
        .context("Failed to increment invite usage")?;
        Ok(())
    }

    pub async fn get_node_invite(&self, invite_id: Uuid) -> Result<Option<NodeInvite>> {
        let row = sqlx::query("SELECT id, node_id, created_by, invite_code, max_uses, current_uses, expires_at, created_at FROM node_invites WHERE id = ?")
            .bind(invite_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query node invite by ID")?;

        row.map(|r| parse_node_invite(&r)).transpose()
    }

    pub async fn delete_node_invite(&self, invite_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM node_invites WHERE id = ?")
            .bind(invite_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to delete node invite")?;
        Ok(())
    }

    // ── User profile operations ──

    pub async fn create_user_profile(&self, user_id: Uuid, display_name: &str) -> Result<()> {
        let updated_at = now();
        sqlx::query(
            "INSERT INTO user_profiles (user_id, display_name, updated_at) VALUES (?, ?, ?)",
        )
        .bind(user_id.to_string())
        .bind(display_name)
        .bind(updated_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to create user profile")?;
        Ok(())
    }

    pub async fn get_user_profile(
        &self,
        user_id: Uuid,
    ) -> Result<Option<crate::models::UserProfile>> {
        let row = sqlx::query("SELECT user_id, display_name, avatar_url, bio, status, custom_status, updated_at FROM user_profiles WHERE user_id = ?")
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query user profile")?;

        row.map(|r| parse_user_profile(&r)).transpose()
    }

    pub async fn update_user_profile(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        bio: Option<&str>,
        status: Option<&str>,
        custom_status: Option<&str>,
    ) -> Result<()> {
        let updated_at = now();

        let mut query_parts = Vec::new();
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(name) = display_name {
            query_parts.push("display_name = ?");
            bind_values.push(name.to_string());
        }
        if let Some(bio) = bio {
            query_parts.push("bio = ?");
            bind_values.push(bio.to_string());
        }
        if let Some(status) = status {
            query_parts.push("status = ?");
            bind_values.push(status.to_string());
        }
        if let Some(custom_status) = custom_status {
            query_parts.push("custom_status = ?");
            bind_values.push(custom_status.to_string());
        }

        if query_parts.is_empty() {
            return Ok(()); // Nothing to update
        }

        query_parts.push("updated_at = ?");
        bind_values.push(updated_at.to_string());

        let sql = format!(
            "UPDATE user_profiles SET {} WHERE user_id = ?",
            query_parts.join(", ")
        );

        let mut query = sqlx::query(&sql);
        for value in bind_values {
            query = query.bind(value);
        }
        query = query.bind(user_id.to_string());

        query
            .execute(&self.pool)
            .await
            .context("Failed to update user profile")?;
        Ok(())
    }

    pub async fn update_user_status(&self, user_id: Uuid, status: &str) -> Result<()> {
        let updated_at = now();
        sqlx::query("UPDATE user_profiles SET status = ?, updated_at = ? WHERE user_id = ?")
            .bind(status)
            .bind(updated_at as i64)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to update user status")?;
        Ok(())
    }

    pub async fn get_node_members_with_profiles(
        &self,
        node_id: Uuid,
    ) -> Result<Vec<crate::models::MemberWithProfile>> {
        let rows = sqlx::query(
            r#"
            SELECT
                nm.user_id, nm.role, nm.joined_at,
                u.username,
                up.display_name, up.avatar_url, up.bio, up.status, up.custom_status
            FROM node_members nm
            JOIN users u ON nm.user_id = u.id
            LEFT JOIN user_profiles up ON nm.user_id = up.user_id
            WHERE nm.node_id = ?
            "#,
        )
        .bind(node_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query node members with profiles")?;

        rows.iter().map(|r| parse_member_with_profile(r)).collect()
    }

    // ── File Operations ──

    /// Store file metadata in the database
    pub async fn store_file_metadata(
        &self,
        file_id: Uuid,
        channel_id: Uuid,
        uploader_id: Uuid,
        encrypted_filename: &[u8],
        file_size_bytes: i64,
        content_hash: &str,
        storage_path: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO files (id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(file_id.to_string())
        .bind(channel_id.to_string())
        .bind(uploader_id.to_string())
        .bind(encrypted_filename)
        .bind(file_size_bytes)
        .bind(content_hash)
        .bind(storage_path)
        .bind(now() as i64)
        .execute(&self.pool)
        .await
        .context("Failed to store file metadata")?;

        Ok(())
    }

    /// Get file metadata by ID
    pub async fn get_file_metadata(&self, file_id: Uuid) -> Result<Option<FileMetadata>> {
        let row = sqlx::query(
            r#"
            SELECT id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at
            FROM files
            WHERE id = ?
            "#
        )
        .bind(file_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query file metadata")?;

        match row {
            Some(row) => Ok(Some(parse_file_metadata(&row)?)),
            None => Ok(None),
        }
    }

    /// List files in a channel
    pub async fn list_channel_files(&self, channel_id: Uuid) -> Result<Vec<FileMetadata>> {
        let rows = sqlx::query(
            r#"
            SELECT id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at
            FROM files
            WHERE channel_id = ?
            ORDER BY created_at DESC
            "#
        )
        .bind(channel_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query channel files")?;

        rows.iter().map(|r| parse_file_metadata(r)).collect()
    }

    /// Delete file metadata from database
    pub async fn delete_file_metadata(&self, file_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM files WHERE id = ?")
            .bind(file_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to delete file metadata")?;

        Ok(())
    }

    // ── Message Reaction operations ──

    /// Add a reaction to a message
    pub async fn add_reaction(&self, message_id: Uuid, user_id: Uuid, emoji: &str) -> Result<()> {
        let created_at = now();
        sqlx::query(
            "INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)"
        )
        .bind(message_id.to_string())
        .bind(user_id.to_string())
        .bind(emoji)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to add reaction")?;

        Ok(())
    }

    /// Remove a reaction from a message
    pub async fn remove_reaction(
        &self,
        message_id: Uuid,
        user_id: Uuid,
        emoji: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
        )
        .bind(message_id.to_string())
        .bind(user_id.to_string())
        .bind(emoji)
        .execute(&self.pool)
        .await
        .context("Failed to remove reaction")?;

        Ok(result.rows_affected() > 0)
    }

    /// Get reactions for a message with counts and user lists
    pub async fn get_message_reactions(
        &self,
        message_id: Uuid,
    ) -> Result<Vec<crate::models::MessageReaction>> {
        let rows = sqlx::query(
            r#"
            SELECT emoji, user_id, created_at
            FROM message_reactions
            WHERE message_id = ?
            ORDER BY created_at ASC
            "#,
        )
        .bind(message_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query message reactions")?;

        // Group reactions by emoji
        let mut reaction_map: std::collections::HashMap<String, Vec<(Uuid, u64)>> =
            std::collections::HashMap::new();

        for row in rows {
            let emoji: String = row.get("emoji");
            let user_id = Uuid::parse_str(&row.get::<String, _>("user_id"))?;
            let created_at = row.get::<i64, _>("created_at") as u64;

            reaction_map
                .entry(emoji)
                .or_insert_with(Vec::new)
                .push((user_id, created_at));
        }

        let mut reactions = Vec::new();
        for (emoji, users) in reaction_map {
            let created_at = users.iter().map(|(_, time)| *time).min().unwrap_or(now());
            reactions.push(crate::models::MessageReaction {
                emoji,
                count: users.len() as u32,
                users: users.into_iter().map(|(user_id, _)| user_id).collect(),
                created_at,
            });
        }

        // Sort by creation time (earliest first)
        reactions.sort_by_key(|r| r.created_at);
        Ok(reactions)
    }

    // ── Message Pinning operations ──

    /// Pin a message (admin/mod only)
    pub async fn pin_message(&self, message_id: Uuid, pinned_by: Uuid) -> Result<bool> {
        let pinned_at = now();

        let result = sqlx::query(
            "UPDATE messages SET pinned_at = ?, pinned_by = ? WHERE id = ? AND pinned_at IS NULL",
        )
        .bind(pinned_at as i64)
        .bind(pinned_by.to_string())
        .bind(message_id.to_string())
        .execute(&self.pool)
        .await
        .context("Failed to pin message")?;

        Ok(result.rows_affected() > 0)
    }

    /// Unpin a message (admin/mod only)
    pub async fn unpin_message(&self, message_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE messages SET pinned_at = NULL, pinned_by = NULL WHERE id = ? AND pinned_at IS NOT NULL"
        )
        .bind(message_id.to_string())
        .execute(&self.pool)
        .await
        .context("Failed to unpin message")?;

        Ok(result.rows_affected() > 0)
    }

    /// Get pinned messages for a channel
    pub async fn get_pinned_messages(
        &self,
        channel_id: Uuid,
    ) -> Result<Vec<crate::models::MessageMetadata>> {
        let rows = sqlx::query(
            r#"
            SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.edited_at, m.pinned_at, m.pinned_by, m.reply_to, u.username,
                   rm.id as replied_message_id, rm.sender_id as replied_sender_id, rm.encrypted_payload as replied_payload, rm.created_at as replied_created_at, ru.username as replied_username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            LEFT JOIN messages rm ON m.reply_to = rm.id
            LEFT JOIN users ru ON rm.sender_id = ru.id
            WHERE m.channel_id = ? AND m.pinned_at IS NOT NULL
            ORDER BY m.pinned_at DESC
            "#,
        )
        .bind(channel_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query pinned messages")?;

        let messages: Vec<_> = rows
            .iter()
            .map(|row| parse_message_metadata(row))
            .collect::<Result<Vec<_>>>()?;

        Ok(messages)
    }

    /// Get all replies to a message (thread view)
    pub async fn get_message_thread(
        &self,
        message_id: Uuid,
    ) -> Result<Vec<crate::models::MessageMetadata>> {
        let rows = sqlx::query(
            r#"
            SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.edited_at, m.pinned_at, m.pinned_by, m.reply_to, u.username,
                   rm.id as replied_message_id, rm.sender_id as replied_sender_id, rm.encrypted_payload as replied_payload, rm.created_at as replied_created_at, ru.username as replied_username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            LEFT JOIN messages rm ON m.reply_to = rm.id
            LEFT JOIN users ru ON rm.sender_id = ru.id
            WHERE m.reply_to = ?
            ORDER BY m.created_at ASC
            "#,
        )
        .bind(message_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query message thread")?;

        let messages: Vec<_> = rows
            .iter()
            .map(|row| parse_message_metadata(row))
            .collect::<Result<Vec<_>>>()?;

        Ok(messages)
    }

    // ── Direct Message Channel operations ──

    /// Create or get a DM channel between two users
    pub async fn create_or_get_dm_channel(
        &self,
        user1_id: Uuid,
        user2_id: Uuid,
    ) -> Result<crate::models::DmChannel> {
        // Ensure consistent ordering for unique constraint (user1 < user2)
        let (user1, user2) = if user1_id < user2_id {
            (user1_id, user2_id)
        } else {
            (user2_id, user1_id)
        };

        // Try to find existing DM channel
        let existing = sqlx::query(
            "SELECT id, user1_id, user2_id, created_at FROM dm_channels WHERE user1_id = ? AND user2_id = ?"
        )
        .bind(user1.to_string())
        .bind(user2.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query existing DM channel")?;

        if let Some(row) = existing {
            return Ok(crate::models::DmChannel {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                user1_id: Uuid::parse_str(&row.get::<String, _>("user1_id"))?,
                user2_id: Uuid::parse_str(&row.get::<String, _>("user2_id"))?,
                created_at: row.get::<i64, _>("created_at") as u64,
            });
        }

        // Create new DM channel
        let dm_id = Uuid::new_v4();
        let created_at = now();

        sqlx::query(
            "INSERT INTO dm_channels (id, user1_id, user2_id, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(dm_id.to_string())
        .bind(user1.to_string())
        .bind(user2.to_string())
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to create DM channel")?;

        // Create a channel entry for message infrastructure
        self.create_channel_with_id(dm_id, &format!("DM-{}", dm_id), Uuid::nil(), user1_id)
            .await?;

        // Add both users to the channel
        self.add_user_to_channel(dm_id, user1_id).await?;
        self.add_user_to_channel(dm_id, user2_id).await?;

        Ok(crate::models::DmChannel {
            id: dm_id,
            user1_id: user1,
            user2_id: user2,
            created_at,
        })
    }

    /// Get user's DM channels with last message preview
    pub async fn get_user_dm_channels(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<crate::models::DmChannelWithInfo>> {
        let rows = sqlx::query(
            r#"
            SELECT 
                dm.id, dm.user1_id, dm.user2_id, dm.created_at,
                u.id as other_user_id, u.username as other_username, u.public_key as other_public_key, u.created_at as other_user_created_at,
                up.display_name, up.avatar_url, up.bio, up.status, up.custom_status, up.updated_at
            FROM dm_channels dm
            JOIN users u ON (
                CASE 
                    WHEN dm.user1_id = ? THEN u.id = dm.user2_id
                    ELSE u.id = dm.user1_id
                END
            )
            LEFT JOIN user_profiles up ON u.id = up.user_id
            WHERE dm.user1_id = ? OR dm.user2_id = ?
            ORDER BY dm.created_at DESC
            "#,
        )
        .bind(user_id.to_string())
        .bind(user_id.to_string())
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query user DM channels")?;

        let mut dm_channels = Vec::new();
        for row in rows {
            let dm_id = Uuid::parse_str(&row.get::<String, _>("id"))?;

            // Get last message for this DM channel
            let last_message = self
                .get_channel_messages_paginated(dm_id, 1, None)
                .await?
                .into_iter()
                .next();

            // Get unread count (for now, we'll implement this later)
            let unread_count = 0u32;

            let other_user = crate::models::User {
                id: Uuid::parse_str(&row.get::<String, _>("other_user_id"))?,
                username: row.get("other_username"),
                public_key: row.get("other_public_key"),
                created_at: row.get::<i64, _>("other_user_created_at") as u64,
            };

            let other_user_profile = crate::models::UserProfile {
                user_id: other_user.id,
                display_name: row
                    .get::<Option<String>, _>("display_name")
                    .unwrap_or_else(|| other_user.username.clone()),
                avatar_url: row.get("avatar_url"),
                bio: row.get("bio"),
                status: row
                    .get::<Option<String>, _>("status")
                    .unwrap_or_else(|| "offline".to_string()),
                custom_status: row.get("custom_status"),
                updated_at: row
                    .get::<Option<i64>, _>("updated_at")
                    .map(|t| t as u64)
                    .unwrap_or(0),
            };

            dm_channels.push(crate::models::DmChannelWithInfo {
                id: dm_id,
                user1_id: Uuid::parse_str(&row.get::<String, _>("user1_id"))?,
                user2_id: Uuid::parse_str(&row.get::<String, _>("user2_id"))?,
                other_user,
                other_user_profile,
                last_message,
                unread_count,
                created_at: row.get::<i64, _>("created_at") as u64,
            });
        }

        Ok(dm_channels)
    }

    /// Get DM channel between two specific users
    pub async fn get_dm_channel_between_users(
        &self,
        user1_id: Uuid,
        user2_id: Uuid,
    ) -> Result<Option<crate::models::DmChannel>> {
        let (user1, user2) = if user1_id < user2_id {
            (user1_id, user2_id)
        } else {
            (user2_id, user1_id)
        };

        let row = sqlx::query(
            "SELECT id, user1_id, user2_id, created_at FROM dm_channels WHERE user1_id = ? AND user2_id = ?"
        )
        .bind(user1.to_string())
        .bind(user2.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query DM channel between users")?;

        if let Some(row) = row {
            Ok(Some(crate::models::DmChannel {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                user1_id: Uuid::parse_str(&row.get::<String, _>("user1_id"))?,
                user2_id: Uuid::parse_str(&row.get::<String, _>("user2_id"))?,
                created_at: row.get::<i64, _>("created_at") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Check if a channel is a DM channel
    pub async fn is_dm_channel(&self, channel_id: Uuid) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM dm_channels WHERE id = ?")
            .bind(channel_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("count") > 0)
    }

    // ── Audit Log operations ──

    /// Log an audit event for a Node
    pub async fn log_audit_event(
        &self,
        node_id: Uuid,
        actor_id: Uuid,
        action: &str,
        target_type: &str,
        target_id: Option<Uuid>,
        details: Option<&str>,
    ) -> Result<Uuid> {
        let audit_id = Uuid::new_v4();
        let created_at = now();

        sqlx::query(
            "INSERT INTO audit_log (id, node_id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(audit_id.to_string())
        .bind(node_id.to_string())
        .bind(actor_id.to_string())
        .bind(action)
        .bind(target_type)
        .bind(target_id.map(|id| id.to_string()))
        .bind(details)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to log audit event")?;

        Ok(audit_id)
    }

    /// Get paginated audit log entries for a Node
    pub async fn get_node_audit_log(
        &self,
        node_id: Uuid,
        limit: u32,
        before_id: Option<Uuid>,
    ) -> Result<Vec<crate::models::AuditLogWithActor>> {
        let query = if let Some(before_audit_id) = before_id {
            // Get the timestamp of the before_id entry for cursor pagination
            let before_timestamp: i64 =
                sqlx::query_scalar("SELECT created_at FROM audit_log WHERE id = ?")
                    .bind(before_audit_id.to_string())
                    .fetch_optional(&self.pool)
                    .await
                    .context("Failed to get before audit entry timestamp")?
                    .unwrap_or(0);

            sqlx::query(
                r#"
                SELECT a.id, a.node_id, a.actor_id, a.action, a.target_type, a.target_id, a.details, a.created_at, u.username
                FROM audit_log a
                JOIN users u ON a.actor_id = u.id
                WHERE a.node_id = ? AND a.created_at < ?
                ORDER BY a.created_at DESC
                LIMIT ?
                "#,
            )
            .bind(node_id.to_string())
            .bind(before_timestamp)
            .bind(limit as i64)
        } else {
            sqlx::query(
                r#"
                SELECT a.id, a.node_id, a.actor_id, a.action, a.target_type, a.target_id, a.details, a.created_at, u.username
                FROM audit_log a
                JOIN users u ON a.actor_id = u.id
                WHERE a.node_id = ?
                ORDER BY a.created_at DESC
                LIMIT ?
                "#,
            )
            .bind(node_id.to_string())
            .bind(limit as i64)
        };

        let rows = query
            .fetch_all(&self.pool)
            .await
            .context("Failed to query audit log")?;

        let entries: Vec<_> = rows
            .iter()
            .map(|row| -> Result<_> {
                let audit_id = Uuid::parse_str(&row.get::<String, _>("id"))?;
                let node_id = Uuid::parse_str(&row.get::<String, _>("node_id"))?;
                let actor_id = Uuid::parse_str(&row.get::<String, _>("actor_id"))?;
                let actor_username: String = row.get("username");
                let action: String = row.get("action");
                let target_type: String = row.get("target_type");
                let target_id = row
                    .get::<Option<String>, _>("target_id")
                    .and_then(|s| Uuid::parse_str(&s).ok());
                let details: Option<String> = row.get("details");
                let created_at = row.get::<i64, _>("created_at") as u64;

                Ok(crate::models::AuditLogWithActor {
                    id: audit_id,
                    node_id,
                    actor_id,
                    actor_username,
                    action,
                    target_type,
                    target_id,
                    details,
                    created_at,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(entries)
    }
}

// ── Helpers ──

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn parse_message_metadata(row: &sqlx::sqlite::SqliteRow) -> Result<crate::models::MessageMetadata> {
    let message_id = Uuid::parse_str(&row.get::<String, _>("id"))?;
    let channel_id = Uuid::parse_str(&row.get::<String, _>("channel_id"))?;
    let sender_id = Uuid::parse_str(&row.get::<String, _>("sender_id"))?;
    let sender_username: String = row.get("username");
    let encrypted_payload: Vec<u8> = row.get("encrypted_payload");
    let created_at = row.get::<i64, _>("created_at") as u64;
    let edited_at = row.get::<Option<i64>, _>("edited_at").map(|t| t as u64);
    let pinned_at = row.get::<Option<i64>, _>("pinned_at").map(|t| t as u64);
    let pinned_by = row
        .get::<Option<String>, _>("pinned_by")
        .and_then(|s| Uuid::parse_str(&s).ok());
    let reply_to = row
        .get::<Option<String>, _>("reply_to")
        .and_then(|s| Uuid::parse_str(&s).ok());

    let replied_message =
        if let Some(replied_id) = row.get::<Option<String>, _>("replied_message_id") {
            Some(crate::models::RepliedMessage {
                id: Uuid::parse_str(&replied_id)?,
                sender_id: Uuid::parse_str(&row.get::<String, _>("replied_sender_id"))?,
                sender_username: row.get("replied_username"),
                encrypted_payload: base64::engine::general_purpose::STANDARD
                    .encode(&row.get::<Vec<u8>, _>("replied_payload")),
                created_at: row.get::<i64, _>("replied_created_at") as u64,
            })
        } else {
            None
        };

    Ok(crate::models::MessageMetadata {
        id: message_id,
        channel_id,
        sender_id,
        sender_username,
        encrypted_payload: base64::engine::general_purpose::STANDARD.encode(&encrypted_payload),
        created_at,
        edited_at,
        pinned_at,
        pinned_by,
        reply_to,
        replied_message,
    })
}

fn parse_user(row: &sqlx::sqlite::SqliteRow) -> Result<User> {
    Ok(User {
        id: Uuid::parse_str(&row.get::<String, _>("id"))?,
        username: row.get("username"),
        public_key: row.get("public_key"),
        created_at: row.get::<i64, _>("created_at") as u64,
    })
}

fn parse_node(row: &sqlx::sqlite::SqliteRow) -> Result<Node> {
    Ok(Node {
        id: Uuid::parse_str(&row.get::<String, _>("id"))?,
        name: row.get("name"),
        owner_id: Uuid::parse_str(&row.get::<String, _>("owner_id"))?,
        description: row.get("description"),
        created_at: row.get::<i64, _>("created_at") as u64,
    })
}

fn parse_node_member(row: &sqlx::sqlite::SqliteRow) -> Result<NodeMember> {
    let role_str: String = row.get("role");
    Ok(NodeMember {
        node_id: Uuid::parse_str(&row.get::<String, _>("node_id"))?,
        user_id: Uuid::parse_str(&row.get::<String, _>("user_id"))?,
        role: NodeRole::from_str(&role_str).unwrap_or(NodeRole::Member),
        joined_at: row.get::<i64, _>("joined_at") as u64,
    })
}

fn parse_node_invite(row: &sqlx::sqlite::SqliteRow) -> Result<NodeInvite> {
    Ok(NodeInvite {
        id: Uuid::parse_str(&row.get::<String, _>("id"))?,
        node_id: Uuid::parse_str(&row.get::<String, _>("node_id"))?,
        created_by: Uuid::parse_str(&row.get::<String, _>("created_by"))?,
        invite_code: row.get("invite_code"),
        max_uses: row.get::<Option<i64>, _>("max_uses").map(|u| u as u32),
        current_uses: row.get::<i64, _>("current_uses") as u32,
        expires_at: row.get::<Option<i64>, _>("expires_at").map(|t| t as u64),
        created_at: row.get::<i64, _>("created_at") as u64,
    })
}

fn parse_user_profile(row: &sqlx::sqlite::SqliteRow) -> Result<crate::models::UserProfile> {
    Ok(crate::models::UserProfile {
        user_id: Uuid::parse_str(&row.get::<String, _>("user_id"))?,
        display_name: row.get("display_name"),
        avatar_url: row.get("avatar_url"),
        bio: row.get("bio"),
        status: row.get("status"),
        custom_status: row.get("custom_status"),
        updated_at: row.get::<i64, _>("updated_at") as u64,
    })
}

fn parse_member_with_profile(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<crate::models::MemberWithProfile> {
    use crate::node::NodeRole;

    let role_str: String = row.get("role");
    Ok(crate::models::MemberWithProfile {
        user_id: Uuid::parse_str(&row.get::<String, _>("user_id"))?,
        username: row.get("username"),
        role: NodeRole::from_str(&role_str).unwrap_or(NodeRole::Member),
        joined_at: row.get::<i64, _>("joined_at") as u64,
        profile: crate::models::UserProfile {
            user_id: Uuid::parse_str(&row.get::<String, _>("user_id"))?,
            display_name: row
                .get::<Option<String>, _>("display_name")
                .unwrap_or_else(|| row.get::<String, _>("username")),
            avatar_url: row.get("avatar_url"),
            bio: row.get("bio"),
            status: row
                .get::<Option<String>, _>("status")
                .unwrap_or_else(|| "offline".to_string()),
            custom_status: row.get("custom_status"),
            updated_at: 0, // Will be set properly when profile exists
        },
    })
}

fn parse_file_metadata(row: &sqlx::sqlite::SqliteRow) -> Result<crate::models::FileMetadata> {
    Ok(crate::models::FileMetadata {
        id: Uuid::parse_str(&row.get::<String, _>("id"))?,
        channel_id: Uuid::parse_str(&row.get::<String, _>("channel_id"))?,
        uploader_id: Uuid::parse_str(&row.get::<String, _>("uploader_id"))?,
        encrypted_filename: row.get::<Vec<u8>, _>("encrypted_filename"),
        file_size_bytes: row.get::<i64, _>("file_size_bytes"),
        content_hash: row.get("content_hash"),
        storage_path: row.get("storage_path"),
        created_at: row.get::<i64, _>("created_at") as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_initialization() {
        let _db = Database::new(":memory:")
            .await
            .expect("Failed to create in-memory database");
    }

    #[tokio::test]
    async fn test_user_operations() {
        let db = Database::new(":memory:").await.unwrap();

        let user = db
            .create_user("test_user", "test_public_key", "")
            .await
            .unwrap();
        assert_eq!(user.username, "test_user");

        let found = db.get_user_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(found.username, "test_user");

        let found = db.get_user_by_username("test_user").await.unwrap().unwrap();
        assert_eq!(found.id, user.id);

        assert!(db.username_exists("test_user").await.unwrap());
        assert!(!db.username_exists("nonexistent").await.unwrap());
    }

    #[tokio::test]
    async fn test_node_operations() {
        let db = Database::new(":memory:").await.unwrap();

        let user = db.create_user("node_owner", "key", "").await.unwrap();
        let node = db
            .create_node("Test Node", user.id, Some("A test node"))
            .await
            .unwrap();
        assert_eq!(node.name, "Test Node");
        assert_eq!(node.owner_id, user.id);

        // Owner should be admin member
        let members = db.get_node_members(node.id).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role, NodeRole::Admin);

        // Default general channel should exist
        let channels = db.get_node_channels(node.id).await.unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "general");

        // Add another member
        let user2 = db.create_user("member", "key2", "").await.unwrap();
        db.add_node_member(node.id, user2.id, NodeRole::Member)
            .await
            .unwrap();
        assert!(db.is_node_member(node.id, user2.id).await.unwrap());

        // Remove member
        db.remove_node_member(node.id, user2.id).await.unwrap();
        assert!(!db.is_node_member(node.id, user2.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_channel_operations() {
        let db = Database::new(":memory:").await.unwrap();

        let user = db.create_user("test_user", "test_key", "").await.unwrap();
        let node = db.create_node("Test Node", user.id, None).await.unwrap();

        let channel = db
            .create_channel("test_channel", node.id, user.id)
            .await
            .unwrap();
        assert_eq!(channel.name, "test_channel");
        assert_eq!(channel.node_id, node.id);
        assert_eq!(channel.members.len(), 1);

        let found = db.get_channel(channel.id).await.unwrap().unwrap();
        assert_eq!(found.name, "test_channel");

        let user2 = db.create_user("test_user2", "test_key2", "").await.unwrap();
        db.add_user_to_channel(channel.id, user2.id).await.unwrap();
        let members = db.get_channel_members(channel.id).await.unwrap();
        assert_eq!(members.len(), 2);

        db.remove_user_from_channel(channel.id, user2.id)
            .await
            .unwrap();
        let members = db.get_channel_members(channel.id).await.unwrap();
        assert_eq!(members.len(), 1);
    }

    #[tokio::test]
    async fn test_message_operations() {
        let db = Database::new(":memory:").await.unwrap();

        let user = db.create_user("test_user", "test_key", "").await.unwrap();
        let node = db.create_node("Test Node", user.id, None).await.unwrap();
        let channel = db
            .create_channel("test_channel", node.id, user.id)
            .await
            .unwrap();

        let encrypted_data = b"encrypted_message_data";
        let message_id = db
            .store_message(channel.id, user.id, encrypted_data, None)
            .await
            .unwrap();

        let messages = db.get_channel_messages(channel.id, 10, None).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].0, message_id);
        assert_eq!(messages[0].2, encrypted_data.to_vec());
    }
}
