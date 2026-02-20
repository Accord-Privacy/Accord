//! Per-Node database: channels, messages, reactions, invites, bans, audit logs, files

use anyhow::{Context, Result};
use sqlx::{sqlite::SqlitePool, Row};
use uuid::Uuid;

use crate::models::{self, Channel, FileMetadata, NodeInvite};

/// Per-Node SQLite database — contains all data scoped to a single Node
#[derive(Debug)]
pub struct NodeDatabase {
    pub(crate) pool: SqlitePool,
    pub(crate) node_id: Uuid,
}

impl NodeDatabase {
    pub async fn new(pool: SqlitePool, node_id: Uuid) -> Result<Self> {
        let db = Self { pool, node_id };
        db.run_migrations().await?;
        Ok(db)
    }

    async fn run_migrations(&self) -> Result<()> {
        // Channels
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                category_id TEXT,
                position INTEGER NOT NULL DEFAULT 0,
                encrypted_name BLOB,
                FOREIGN KEY (category_id) REFERENCES channel_categories (id) ON DELETE SET NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create channels table")?;

        sqlx::query("ALTER TABLE channels ADD COLUMN category_id TEXT")
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE channels ADD COLUMN position INTEGER NOT NULL DEFAULT 0")
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE channels ADD COLUMN encrypted_name BLOB")
            .execute(&self.pool)
            .await
            .ok();

        // Channel categories
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS channel_categories (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                encrypted_name BLOB
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create channel_categories table")?;

        sqlx::query("ALTER TABLE channel_categories ADD COLUMN encrypted_name BLOB")
            .execute(&self.pool)
            .await
            .ok();

        // Channel members
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS channel_members (
                channel_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                joined_at INTEGER NOT NULL,
                PRIMARY KEY (channel_id, user_id),
                FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create channel_members table")?;

        // Messages
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
                reply_to TEXT,
                FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create messages table")?;

        sqlx::query("ALTER TABLE messages ADD COLUMN edited_at INTEGER")
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE messages ADD COLUMN pinned_at INTEGER")
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE messages ADD COLUMN pinned_by TEXT")
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE messages ADD COLUMN reply_to TEXT")
            .execute(&self.pool)
            .await
            .ok();

        sqlx::query("ALTER TABLE messages ADD COLUMN seq INTEGER NOT NULL DEFAULT 0")
            .execute(&self.pool)
            .await
            .ok();

        // Add encryption_version column (0 = placeholder, 1 = Sender Keys)
        sqlx::query(
            "ALTER TABLE messages ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await
        .ok();

        // Sender Key distributions (store-and-forward for offline members)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sender_key_distributions (
                id TEXT PRIMARY KEY NOT NULL,
                channel_id TEXT NOT NULL,
                from_user_id TEXT NOT NULL,
                to_user_id TEXT NOT NULL,
                encrypted_payload BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                claimed INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create sender_key_distributions table")?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_skd_recipient ON sender_key_distributions (to_user_id, claimed)")
            .execute(&self.pool).await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_skd_channel ON sender_key_distributions (channel_id)",
        )
        .execute(&self.pool)
        .await?;

        // Message reactions
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS message_reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                emoji TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(message_id, user_id, emoji),
                FOREIGN KEY (message_id) REFERENCES messages (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create message_reactions table")?;

        // Node invites
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS node_invites (
                id TEXT PRIMARY KEY NOT NULL,
                created_by TEXT NOT NULL,
                invite_code TEXT NOT NULL UNIQUE,
                max_uses INTEGER,
                current_uses INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER,
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create node_invites table")?;

        // Node user profiles
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS node_user_profiles (
                user_id TEXT NOT NULL PRIMARY KEY,
                encrypted_display_name BLOB,
                encrypted_avatar_url BLOB,
                joined_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create node_user_profiles table")?;

        // Node bans
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS node_bans (
                public_key_hash TEXT NOT NULL PRIMARY KEY,
                banned_by TEXT NOT NULL,
                banned_at INTEGER NOT NULL,
                reason_encrypted BLOB,
                expires_at INTEGER,
                device_fingerprint_hash TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create node_bans table")?;

        sqlx::query("ALTER TABLE node_bans ADD COLUMN device_fingerprint_hash TEXT")
            .execute(&self.pool)
            .await
            .ok();

        // Files
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
                FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create files table")?;

        // Audit log
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                details TEXT,
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create audit_log table")?;

        // ── Indexes ──
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_channel_members_channel ON channel_members (channel_id)")
            .execute(&self.pool).await?;
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
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages (sender_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages (created_at DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_node_invites_code ON node_invites (invite_code)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_reactions_message ON message_reactions (message_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_reactions_user ON message_reactions (user_id)")
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
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log (created_at DESC)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log (actor_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_node_bans_key ON node_bans (public_key_hash)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_node_bans_fingerprint ON node_bans (device_fingerprint_hash)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_node_user_profiles_user ON node_user_profiles (user_id)")
            .execute(&self.pool).await?;

        // Read receipts
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS read_receipts (
                user_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                last_read_message_id TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, channel_id),
                FOREIGN KEY (channel_id) REFERENCES channels (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create read_receipts table")?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_read_receipts_channel ON read_receipts (channel_id)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ── Channel operations ──

    pub async fn create_channel(
        &self,
        channel_id: Uuid,
        name: &str,
        created_by: Uuid,
    ) -> Result<Channel> {
        let created_at = super::now();
        let position_row =
            sqlx::query("SELECT COALESCE(MAX(position), -1) + 1 as next_position FROM channels")
                .fetch_one(&self.pool)
                .await?;
        let position = position_row.get::<i64, _>("next_position");

        sqlx::query("INSERT INTO channels (id, name, created_by, created_at, position) VALUES (?, ?, ?, ?, ?)")
            .bind(channel_id.to_string())
            .bind(name)
            .bind(created_by.to_string())
            .bind(created_at as i64)
            .bind(position)
            .execute(&self.pool)
            .await
            .context("Failed to insert channel")?;

        self.add_user_to_channel(channel_id, created_by).await?;
        let members = self.get_channel_members(channel_id).await?;

        Ok(Channel {
            id: channel_id,
            name: name.to_string(),
            node_id: self.node_id,
            members,
            created_at,
        })
    }

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
                node_id: self.node_id,
                members,
                created_at: row.get::<i64, _>("created_at") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn get_node_channels(&self) -> Result<Vec<Channel>> {
        let rows = sqlx::query(
            "SELECT id, name, created_by, created_at FROM channels ORDER BY position ASC",
        )
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
                node_id: self.node_id,
                members,
                created_at: row.get::<i64, _>("created_at") as u64,
            });
        }
        Ok(channels)
    }

    pub async fn count_channels(&self) -> Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM channels")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("count") as u64)
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
        let joined_at = super::now();
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

    /// Get channels a user is a member of (across this node)
    pub async fn get_user_channels(&self) -> Result<Vec<Channel>> {
        // In per-node DB, all channels belong to this node
        self.get_node_channels().await
    }

    // ── Channel Category operations ──

    pub async fn create_channel_category(&self, name: &str) -> Result<models::ChannelCategory> {
        let category_id = Uuid::new_v4();
        let created_at = super::now();
        let position_row = sqlx::query(
            "SELECT COALESCE(MAX(position), -1) + 1 as next_position FROM channel_categories",
        )
        .fetch_one(&self.pool)
        .await?;
        let position = position_row.get::<i64, _>("next_position");

        sqlx::query(
            "INSERT INTO channel_categories (id, name, position, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(category_id.to_string())
        .bind(name)
        .bind(position)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to insert channel category")?;

        Ok(models::ChannelCategory {
            id: category_id,
            node_id: self.node_id,
            name: name.to_string(),
            position: position as u32,
            created_at,
        })
    }

    pub async fn get_category_by_id(
        &self,
        category_id: Uuid,
    ) -> Result<Option<models::ChannelCategory>> {
        let row = sqlx::query(
            "SELECT id, name, position, created_at FROM channel_categories WHERE id = ?",
        )
        .bind(category_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query channel category by ID")?;

        row.map(|r| -> Result<models::ChannelCategory> {
            Ok(models::ChannelCategory {
                id: Uuid::parse_str(&r.get::<String, _>("id"))?,
                node_id: self.node_id,
                name: r.get("name"),
                position: r.get::<i64, _>("position") as u32,
                created_at: r.get::<i64, _>("created_at") as u64,
            })
        })
        .transpose()
    }

    pub async fn get_node_categories(&self) -> Result<Vec<models::ChannelCategory>> {
        let rows = sqlx::query(
            "SELECT id, name, position, created_at FROM channel_categories ORDER BY position ASC",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to query channel categories")?;

        rows.iter()
            .map(|row| -> Result<models::ChannelCategory> {
                Ok(models::ChannelCategory {
                    id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                    node_id: self.node_id,
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
            return Ok(());
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
        sqlx::query("UPDATE channels SET category_id = NULL WHERE category_id = ?")
            .bind(category_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to uncategorize channels")?;
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

    pub async fn get_channels_with_categories(&self) -> Result<Vec<models::ChannelWithCategory>> {
        let rows = sqlx::query(
            r#"
            SELECT c.id, c.name, c.created_by, c.created_at, c.category_id, c.position,
                   cat.name as category_name
            FROM channels c
            LEFT JOIN channel_categories cat ON c.category_id = cat.id
            ORDER BY c.category_id ASC NULLS FIRST, c.position ASC
            "#,
        )
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

            channels.push(models::ChannelWithCategory {
                id: channel_id,
                name: row.get("name"),
                node_id: self.node_id,
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
    ) -> Result<(Uuid, i64)> {
        let message_id = Uuid::new_v4();
        let created_at = super::now();

        let seq: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE channel_id = ?",
        )
        .bind(channel_id.to_string())
        .fetch_one(&self.pool)
        .await
        .context("Failed to compute next sequence number")?;

        sqlx::query("INSERT INTO messages (id, channel_id, sender_id, encrypted_payload, created_at, reply_to, seq) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(message_id.to_string())
            .bind(channel_id.to_string())
            .bind(sender_id.to_string())
            .bind(encrypted_payload)
            .bind(created_at as i64)
            .bind(reply_to.map(|id| id.to_string()))
            .bind(seq)
            .execute(&self.pool)
            .await
            .context("Failed to store message")?;
        Ok((message_id, seq))
    }

    pub async fn get_channel_messages(
        &self,
        channel_id: Uuid,
        limit: u32,
        before: Option<u64>,
    ) -> Result<Vec<(Uuid, Uuid, Vec<u8>, u64)>> {
        let query = if let Some(before_timestamp) = before {
            sqlx::query("SELECT id, sender_id, encrypted_payload, created_at FROM messages WHERE channel_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?")
                .bind(channel_id.to_string())
                .bind(before_timestamp as i64)
                .bind(limit as i64)
        } else {
            sqlx::query("SELECT id, sender_id, encrypted_payload, created_at FROM messages WHERE channel_id = ? ORDER BY created_at DESC LIMIT ?")
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
        messages.reverse();
        Ok(messages)
    }

    /// Get channel messages with cursor-based pagination
    /// Note: This queries the node DB which doesn't have users table, so we need sender_public_key_hash passed in or do a simpler query.
    /// We'll do a simpler query here and let the DatabaseManager join with relay data.
    pub async fn get_channel_messages_paginated_raw(
        &self,
        channel_id: Uuid,
        limit: u32,
        before_id: Option<Uuid>,
    ) -> Result<Vec<models::MessageMetadataRaw>> {
        let query = if let Some(before_message_id) = before_id {
            let before_timestamp: Option<i64> =
                sqlx::query_scalar("SELECT created_at FROM messages WHERE id = ?")
                    .bind(before_message_id.to_string())
                    .fetch_optional(&self.pool)
                    .await
                    .context("Failed to get before message timestamp")?;
            let before_timestamp = before_timestamp.unwrap_or(0);

            sqlx::query(
                r#"
                SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.edited_at, m.pinned_at, m.pinned_by, m.reply_to,
                       rm.id as replied_message_id, rm.sender_id as replied_sender_id, rm.encrypted_payload as replied_payload, rm.created_at as replied_created_at
                FROM messages m
                LEFT JOIN messages rm ON m.reply_to = rm.id
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
                SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.edited_at, m.pinned_at, m.pinned_by, m.reply_to,
                       rm.id as replied_message_id, rm.sender_id as replied_sender_id, rm.encrypted_payload as replied_payload, rm.created_at as replied_created_at
                FROM messages m
                LEFT JOIN messages rm ON m.reply_to = rm.id
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
        rows.iter()
            .map(|row| parse_message_metadata_raw(row, self.node_id))
            .collect()
    }

    pub async fn search_messages_raw(
        &self,
        query_str: &str,
        channel_id_filter: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<models::SearchResultRaw>> {
        // Since we don't have user table here, we search by channel name only and return raw
        let search_pattern = format!("%{}%", query_str.to_lowercase());

        let (sql, needs_channel_filter) = if channel_id_filter.is_some() {
            (
                r#"
                SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at,
                       c.name as channel_name
                FROM messages m
                JOIN channels c ON m.channel_id = c.id
                WHERE c.id = ? AND LOWER(c.name) LIKE LOWER(?)
                ORDER BY m.created_at DESC
                LIMIT ?
            "#,
                true,
            )
        } else {
            (
                r#"
                SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at,
                       c.name as channel_name
                FROM messages m
                JOIN channels c ON m.channel_id = c.id
                WHERE LOWER(c.name) LIKE LOWER(?)
                ORDER BY m.created_at DESC
                LIMIT ?
            "#,
                false,
            )
        };

        let query_builder = if needs_channel_filter {
            sqlx::query(sql)
                .bind(channel_id_filter.unwrap().to_string())
                .bind(&search_pattern)
                .bind(limit as i64)
        } else {
            sqlx::query(sql).bind(&search_pattern).bind(limit as i64)
        };

        let rows = query_builder
            .fetch_all(&self.pool)
            .await
            .context("Failed to search messages")?;

        rows.iter()
            .map(|row| -> Result<models::SearchResultRaw> {
                Ok(models::SearchResultRaw {
                    message_id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                    channel_id: Uuid::parse_str(&row.get::<String, _>("channel_id"))?,
                    channel_name: row.get("channel_name"),
                    sender_id: Uuid::parse_str(&row.get::<String, _>("sender_id"))?,
                    created_at: row.get::<i64, _>("created_at") as u64,
                    encrypted_payload: row.get::<Vec<u8>, _>("encrypted_payload"),
                })
            })
            .collect()
    }

    pub async fn edit_message(
        &self,
        message_id: Uuid,
        sender_id: Uuid,
        new_encrypted_payload: &[u8],
    ) -> Result<bool> {
        let edited_at = super::now();
        let result = sqlx::query("UPDATE messages SET encrypted_payload = ?, edited_at = ? WHERE id = ? AND sender_id = ?")
            .bind(new_encrypted_payload)
            .bind(edited_at as i64)
            .bind(message_id.to_string())
            .bind(sender_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to edit message")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_message(
        &self,
        message_id: Uuid,
        requester_id: Uuid,
    ) -> Result<Option<(Uuid, Uuid)>> {
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
            let is_author = requester_id == sender_id;

            // For admin/mod check, we rely on the caller (DatabaseManager) to verify via relay DB
            // Here we just check authorship; admin check is done at the DatabaseManager level
            if is_author {
                let result = sqlx::query("DELETE FROM messages WHERE id = ?")
                    .bind(message_id.to_string())
                    .execute(&self.pool)
                    .await
                    .context("Failed to delete message")?;
                if result.rows_affected() > 0 {
                    return Ok(Some((channel_id, sender_id)));
                }
            }
            // Return channel/sender info for admin check at higher level
            Ok(Some((channel_id, sender_id)))
        } else {
            Ok(None)
        }
    }

    /// Force-delete a message (for admin/mod deletes after permission check)
    pub async fn force_delete_message(&self, message_id: Uuid) -> Result<Option<(Uuid, Uuid)>> {
        let message_info: Option<(String, String)> =
            sqlx::query_as("SELECT channel_id, sender_id FROM messages WHERE id = ?")
                .bind(message_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .context("Failed to query message")?;

        if let Some((channel_id_str, sender_id_str)) = message_info {
            let channel_id = Uuid::parse_str(&channel_id_str)?;
            let sender_id = Uuid::parse_str(&sender_id_str)?;
            sqlx::query("DELETE FROM messages WHERE id = ?")
                .bind(message_id.to_string())
                .execute(&self.pool)
                .await
                .context("Failed to delete message")?;
            Ok(Some((channel_id, sender_id)))
        } else {
            Ok(None)
        }
    }

    pub async fn get_message_details(
        &self,
        message_id: Uuid,
    ) -> Result<Option<(Uuid, Uuid, u64, Option<u64>)>> {
        let result: Option<(String, String, i64, Option<i64>)> = sqlx::query_as(
            "SELECT channel_id, sender_id, created_at, edited_at FROM messages WHERE id = ?",
        )
        .bind(message_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query message details")?;

        if let Some((channel_id_str, sender_id_str, created_at, edited_at)) = result {
            let channel_id = Uuid::parse_str(&channel_id_str)?;
            let sender_id = Uuid::parse_str(&sender_id_str)?;
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
        created_by: Uuid,
        invite_code: &str,
        max_uses: Option<u32>,
        expires_at: Option<u64>,
    ) -> Result<Uuid> {
        let invite_id = Uuid::new_v4();
        let created_at = super::now();
        sqlx::query("INSERT INTO node_invites (id, created_by, invite_code, max_uses, current_uses, expires_at, created_at) VALUES (?, ?, ?, ?, 0, ?, ?)")
            .bind(invite_id.to_string())
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
        let row = sqlx::query("SELECT id, created_by, invite_code, max_uses, current_uses, expires_at, created_at FROM node_invites WHERE invite_code = ?")
            .bind(invite_code)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query node invite by code")?;
        row.map(|r| self.parse_node_invite(&r)).transpose()
    }

    pub async fn get_node_invites(&self) -> Result<Vec<NodeInvite>> {
        let rows = sqlx::query("SELECT id, created_by, invite_code, max_uses, current_uses, expires_at, created_at FROM node_invites ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .context("Failed to query node invites")?;
        rows.iter().map(|r| self.parse_node_invite(r)).collect()
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
        let row = sqlx::query("SELECT id, created_by, invite_code, max_uses, current_uses, expires_at, created_at FROM node_invites WHERE id = ?")
            .bind(invite_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query node invite by ID")?;
        row.map(|r| self.parse_node_invite(&r)).transpose()
    }

    pub async fn delete_node_invite(&self, invite_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM node_invites WHERE id = ?")
            .bind(invite_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to delete node invite")?;
        Ok(())
    }

    fn parse_node_invite(&self, row: &sqlx::sqlite::SqliteRow) -> Result<NodeInvite> {
        Ok(NodeInvite {
            id: Uuid::parse_str(&row.get::<String, _>("id"))?,
            node_id: self.node_id,
            created_by: Uuid::parse_str(&row.get::<String, _>("created_by"))?,
            invite_code: row.get("invite_code"),
            max_uses: row.get::<Option<i64>, _>("max_uses").map(|u| u as u32),
            current_uses: row.get::<i64, _>("current_uses") as u32,
            expires_at: row.get::<Option<i64>, _>("expires_at").map(|t| t as u64),
            created_at: row.get::<i64, _>("created_at") as u64,
        })
    }

    // ── Node ban operations ──

    pub async fn ban_from_node_with_fingerprint(
        &self,
        public_key_hash: &str,
        banned_by: Uuid,
        reason_encrypted: Option<&[u8]>,
        expires_at: Option<u64>,
        device_fingerprint_hash: Option<&str>,
    ) -> Result<()> {
        let banned_at = super::now();
        sqlx::query(
            "INSERT OR REPLACE INTO node_bans (public_key_hash, banned_by, banned_at, reason_encrypted, expires_at, device_fingerprint_hash) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(public_key_hash)
        .bind(banned_by.to_string())
        .bind(banned_at as i64)
        .bind(reason_encrypted)
        .bind(expires_at.map(|t| t as i64))
        .bind(device_fingerprint_hash)
        .execute(&self.pool)
        .await
        .context("Failed to ban user from node")?;
        Ok(())
    }

    pub async fn unban_from_node(&self, public_key_hash: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM node_bans WHERE public_key_hash = ?")
            .bind(public_key_hash)
            .execute(&self.pool)
            .await
            .context("Failed to unban user from node")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn is_banned_from_node(&self, public_key_hash: &str) -> Result<bool> {
        let current_time = super::now() as i64;
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM node_bans WHERE public_key_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(public_key_hash)
        .bind(current_time)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("count") > 0)
    }

    pub async fn get_node_bans(&self) -> Result<Vec<models::NodeBan>> {
        let rows = sqlx::query(
            "SELECT public_key_hash, banned_by, banned_at, reason_encrypted, expires_at, device_fingerprint_hash FROM node_bans ORDER BY banned_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to query node bans")?;

        rows.iter()
            .map(|row| -> Result<models::NodeBan> {
                Ok(models::NodeBan {
                    node_id: self.node_id,
                    public_key_hash: row.get("public_key_hash"),
                    banned_by: Uuid::parse_str(&row.get::<String, _>("banned_by"))?,
                    banned_at: row.get::<i64, _>("banned_at") as u64,
                    reason_encrypted: row.get::<Option<Vec<u8>>, _>("reason_encrypted"),
                    expires_at: row.get::<Option<i64>, _>("expires_at").map(|t| t as u64),
                    device_fingerprint_hash: row
                        .get::<Option<String>, _>("device_fingerprint_hash"),
                })
            })
            .collect()
    }

    pub async fn ban_device_from_node(
        &self,
        device_fingerprint_hash: &str,
        banned_by: Uuid,
        reason_encrypted: Option<&[u8]>,
        expires_at: Option<u64>,
    ) -> Result<()> {
        let banned_at = super::now();
        let synthetic_pkh = format!("device:{}", device_fingerprint_hash);
        sqlx::query(
            "INSERT OR REPLACE INTO node_bans (public_key_hash, device_fingerprint_hash, banned_by, banned_at, reason_encrypted, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&synthetic_pkh)
        .bind(device_fingerprint_hash)
        .bind(banned_by.to_string())
        .bind(banned_at as i64)
        .bind(reason_encrypted)
        .bind(expires_at.map(|t| t as i64))
        .execute(&self.pool)
        .await
        .context("Failed to ban device from node")?;
        Ok(())
    }

    pub async fn is_device_banned_from_node(&self, device_fingerprint_hash: &str) -> Result<bool> {
        let current_time = super::now() as i64;
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM node_bans WHERE device_fingerprint_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(device_fingerprint_hash)
        .bind(current_time)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("count") > 0)
    }

    pub async fn unban_device_from_node(&self, device_fingerprint_hash: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM node_bans WHERE device_fingerprint_hash = ?")
            .bind(device_fingerprint_hash)
            .execute(&self.pool)
            .await
            .context("Failed to unban device from node")?;
        Ok(result.rows_affected() > 0)
    }

    // ── Node user profile operations ──

    pub async fn set_node_user_profile(
        &self,
        user_id: Uuid,
        encrypted_display_name: Option<&[u8]>,
        encrypted_avatar_url: Option<&[u8]>,
    ) -> Result<()> {
        let joined_at = super::now();
        sqlx::query(
            r#"
            INSERT INTO node_user_profiles (user_id, encrypted_display_name, encrypted_avatar_url, joined_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                encrypted_display_name = COALESCE(excluded.encrypted_display_name, node_user_profiles.encrypted_display_name),
                encrypted_avatar_url = COALESCE(excluded.encrypted_avatar_url, node_user_profiles.encrypted_avatar_url)
            "#,
        )
        .bind(user_id.to_string())
        .bind(encrypted_display_name)
        .bind(encrypted_avatar_url)
        .bind(joined_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to set node user profile")?;
        Ok(())
    }

    pub async fn get_node_user_profile(
        &self,
        user_id: Uuid,
    ) -> Result<Option<models::NodeUserProfile>> {
        let row = sqlx::query(
            "SELECT user_id, encrypted_display_name, encrypted_avatar_url, joined_at FROM node_user_profiles WHERE user_id = ?",
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query node user profile")?;

        row.map(|r| -> Result<models::NodeUserProfile> {
            Ok(models::NodeUserProfile {
                node_id: self.node_id,
                user_id: Uuid::parse_str(&r.get::<String, _>("user_id"))?,
                encrypted_display_name: r.get("encrypted_display_name"),
                encrypted_avatar_url: r.get("encrypted_avatar_url"),
                joined_at: r.get::<i64, _>("joined_at") as u64,
            })
        })
        .transpose()
    }

    pub async fn get_node_user_profiles(&self) -> Result<Vec<models::NodeUserProfile>> {
        let rows = sqlx::query(
            "SELECT user_id, encrypted_display_name, encrypted_avatar_url, joined_at FROM node_user_profiles",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to query node user profiles")?;

        rows.iter()
            .map(|r| -> Result<models::NodeUserProfile> {
                Ok(models::NodeUserProfile {
                    node_id: self.node_id,
                    user_id: Uuid::parse_str(&r.get::<String, _>("user_id"))?,
                    encrypted_display_name: r.get("encrypted_display_name"),
                    encrypted_avatar_url: r.get("encrypted_avatar_url"),
                    joined_at: r.get::<i64, _>("joined_at") as u64,
                })
            })
            .collect()
    }

    // ── Reaction operations ──

    pub async fn add_reaction(&self, message_id: Uuid, user_id: Uuid, emoji: &str) -> Result<()> {
        let created_at = super::now();
        sqlx::query("INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)")
            .bind(message_id.to_string())
            .bind(user_id.to_string())
            .bind(emoji)
            .bind(created_at as i64)
            .execute(&self.pool)
            .await
            .context("Failed to add reaction")?;
        Ok(())
    }

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

    pub async fn get_message_reactions(
        &self,
        message_id: Uuid,
    ) -> Result<Vec<models::MessageReaction>> {
        let rows = sqlx::query("SELECT emoji, user_id, created_at FROM message_reactions WHERE message_id = ? ORDER BY created_at ASC")
            .bind(message_id.to_string())
            .fetch_all(&self.pool)
            .await
            .context("Failed to query message reactions")?;

        let mut reaction_map: std::collections::HashMap<String, Vec<(Uuid, u64)>> =
            std::collections::HashMap::new();
        for row in rows {
            let emoji: String = row.get("emoji");
            let user_id = Uuid::parse_str(&row.get::<String, _>("user_id"))?;
            let created_at = row.get::<i64, _>("created_at") as u64;
            reaction_map
                .entry(emoji)
                .or_default()
                .push((user_id, created_at));
        }

        let mut reactions = Vec::new();
        for (emoji, users) in reaction_map {
            let created_at = users
                .iter()
                .map(|(_, time)| *time)
                .min()
                .unwrap_or(super::now());
            reactions.push(models::MessageReaction {
                emoji,
                count: users.len() as u32,
                users: users.into_iter().map(|(user_id, _)| user_id).collect(),
                created_at,
            });
        }
        reactions.sort_by_key(|r| r.created_at);
        Ok(reactions)
    }

    // ── Pinning operations ──

    pub async fn pin_message(&self, message_id: Uuid, pinned_by: Uuid) -> Result<bool> {
        let pinned_at = super::now();
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

    pub async fn unpin_message(&self, message_id: Uuid) -> Result<bool> {
        let result = sqlx::query("UPDATE messages SET pinned_at = NULL, pinned_by = NULL WHERE id = ? AND pinned_at IS NOT NULL")
            .bind(message_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to unpin message")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_pinned_messages_raw(
        &self,
        channel_id: Uuid,
    ) -> Result<Vec<models::MessageMetadataRaw>> {
        let rows = sqlx::query(
            r#"
            SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.edited_at, m.pinned_at, m.pinned_by, m.reply_to,
                   rm.id as replied_message_id, rm.sender_id as replied_sender_id, rm.encrypted_payload as replied_payload, rm.created_at as replied_created_at
            FROM messages m
            LEFT JOIN messages rm ON m.reply_to = rm.id
            WHERE m.channel_id = ? AND m.pinned_at IS NOT NULL
            ORDER BY m.pinned_at DESC
            "#,
        )
        .bind(channel_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query pinned messages")?;

        rows.iter()
            .map(|row| parse_message_metadata_raw(row, self.node_id))
            .collect()
    }

    pub async fn get_message_thread_raw(
        &self,
        message_id: Uuid,
    ) -> Result<Vec<models::MessageMetadataRaw>> {
        let rows = sqlx::query(
            r#"
            SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.edited_at, m.pinned_at, m.pinned_by, m.reply_to,
                   rm.id as replied_message_id, rm.sender_id as replied_sender_id, rm.encrypted_payload as replied_payload, rm.created_at as replied_created_at
            FROM messages m
            LEFT JOIN messages rm ON m.reply_to = rm.id
            WHERE m.reply_to = ?
            ORDER BY m.created_at ASC
            "#,
        )
        .bind(message_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query message thread")?;

        rows.iter()
            .map(|row| parse_message_metadata_raw(row, self.node_id))
            .collect()
    }

    // ── File operations ──

    #[allow(clippy::too_many_arguments)]
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
            "INSERT INTO files (id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(file_id.to_string())
        .bind(channel_id.to_string())
        .bind(uploader_id.to_string())
        .bind(encrypted_filename)
        .bind(file_size_bytes)
        .bind(content_hash)
        .bind(storage_path)
        .bind(super::now() as i64)
        .execute(&self.pool)
        .await
        .context("Failed to store file metadata")?;
        Ok(())
    }

    pub async fn get_file_metadata(&self, file_id: Uuid) -> Result<Option<FileMetadata>> {
        let row = sqlx::query("SELECT id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at FROM files WHERE id = ?")
            .bind(file_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query file metadata")?;
        match row {
            Some(row) => Ok(Some(super::parse_file_metadata(&row)?)),
            None => Ok(None),
        }
    }

    pub async fn list_channel_files(&self, channel_id: Uuid) -> Result<Vec<FileMetadata>> {
        let rows = sqlx::query("SELECT id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at FROM files WHERE channel_id = ? ORDER BY created_at DESC")
            .bind(channel_id.to_string())
            .fetch_all(&self.pool)
            .await
            .context("Failed to query channel files")?;
        rows.iter().map(super::parse_file_metadata).collect()
    }

    pub async fn delete_file_metadata(&self, file_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM files WHERE id = ?")
            .bind(file_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to delete file metadata")?;
        Ok(())
    }

    // ── Audit log operations ──

    pub async fn log_audit_event(
        &self,
        actor_id: Uuid,
        action: &str,
        target_type: &str,
        target_id: Option<Uuid>,
        details: Option<&str>,
    ) -> Result<Uuid> {
        let audit_id = Uuid::new_v4();
        let created_at = super::now();
        sqlx::query("INSERT INTO audit_log (id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(audit_id.to_string())
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

    /// Get audit log entries - returns raw rows without public_key_hash (that's in relay DB)
    pub async fn get_audit_log_raw(
        &self,
        limit: u32,
        before_id: Option<Uuid>,
    ) -> Result<Vec<models::AuditLogRaw>> {
        let query = if let Some(before_audit_id) = before_id {
            let before_timestamp: Option<i64> =
                sqlx::query_scalar("SELECT created_at FROM audit_log WHERE id = ?")
                    .bind(before_audit_id.to_string())
                    .fetch_optional(&self.pool)
                    .await
                    .context("Failed to get before audit entry timestamp")?;
            let before_timestamp = before_timestamp.unwrap_or(0);

            sqlx::query("SELECT id, actor_id, action, target_type, target_id, details, created_at FROM audit_log WHERE created_at < ? ORDER BY created_at DESC LIMIT ?")
                .bind(before_timestamp)
                .bind(limit as i64)
        } else {
            sqlx::query("SELECT id, actor_id, action, target_type, target_id, details, created_at FROM audit_log ORDER BY created_at DESC LIMIT ?")
                .bind(limit as i64)
        };

        let rows = query
            .fetch_all(&self.pool)
            .await
            .context("Failed to query audit log")?;
        rows.iter()
            .map(|row| -> Result<models::AuditLogRaw> {
                Ok(models::AuditLogRaw {
                    id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                    node_id: self.node_id,
                    actor_id: Uuid::parse_str(&row.get::<String, _>("actor_id"))?,
                    action: row.get("action"),
                    target_type: row.get("target_type"),
                    target_id: row
                        .get::<Option<String>, _>("target_id")
                        .and_then(|s| Uuid::parse_str(&s).ok()),
                    details: row.get("details"),
                    created_at: row.get::<i64, _>("created_at") as u64,
                })
            })
            .collect()
    }
    // ── Read receipt operations ──

    /// Mark a channel as read up to a specific message for a user
    pub async fn mark_channel_read(
        &self,
        user_id: Uuid,
        channel_id: Uuid,
        message_id: Uuid,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            "INSERT INTO read_receipts (user_id, channel_id, last_read_message_id, updated_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(user_id, channel_id) DO UPDATE SET last_read_message_id = excluded.last_read_message_id, updated_at = excluded.updated_at",
        )
        .bind(user_id.to_string())
        .bind(channel_id.to_string())
        .bind(message_id.to_string())
        .bind(now)
        .execute(&self.pool)
        .await
        .context("Failed to upsert read receipt")?;

        Ok(())
    }

    /// Get the last read message ID for a user in a channel
    pub async fn get_read_receipt(&self, user_id: Uuid, channel_id: Uuid) -> Result<Option<Uuid>> {
        let row = sqlx::query(
            "SELECT last_read_message_id FROM read_receipts WHERE user_id = ? AND channel_id = ?",
        )
        .bind(user_id.to_string())
        .bind(channel_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query read receipt")?;

        match row {
            Some(r) => {
                let id_str: String = r.get("last_read_message_id");
                Ok(Some(Uuid::parse_str(&id_str)?))
            }
            None => Ok(None),
        }
    }

    /// Get all read receipts for a channel (for showing who has read up to where)
    pub async fn get_channel_read_receipts(
        &self,
        channel_id: Uuid,
    ) -> Result<Vec<(Uuid, Uuid, u64)>> {
        let rows = sqlx::query(
            "SELECT user_id, last_read_message_id, updated_at FROM read_receipts WHERE channel_id = ?",
        )
        .bind(channel_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query channel read receipts")?;

        let mut receipts = Vec::new();
        for row in rows {
            let user_id = Uuid::parse_str(&row.get::<String, _>("user_id"))?;
            let message_id = Uuid::parse_str(&row.get::<String, _>("last_read_message_id"))?;
            let updated_at = row.get::<i64, _>("updated_at") as u64;
            receipts.push((user_id, message_id, updated_at));
        }
        Ok(receipts)
    }

    /// Get unread message count for a user in a channel
    pub async fn get_unread_count(&self, user_id: Uuid, channel_id: Uuid) -> Result<u32> {
        // Get the user's last read message created_at timestamp
        let last_read_row = sqlx::query(
            "SELECT m.created_at FROM read_receipts r \
             JOIN messages m ON m.id = r.last_read_message_id \
             WHERE r.user_id = ? AND r.channel_id = ?",
        )
        .bind(user_id.to_string())
        .bind(channel_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query last read timestamp")?;

        let count = match last_read_row {
            Some(row) => {
                let last_read_at: i64 = row.get("created_at");
                let count_row = sqlx::query(
                    "SELECT COUNT(*) as cnt FROM messages WHERE channel_id = ? AND created_at > ?",
                )
                .bind(channel_id.to_string())
                .bind(last_read_at)
                .fetch_one(&self.pool)
                .await?;
                count_row.get::<i64, _>("cnt") as u32
            }
            None => {
                // No read receipt — all messages are unread
                let count_row =
                    sqlx::query("SELECT COUNT(*) as cnt FROM messages WHERE channel_id = ?")
                        .bind(channel_id.to_string())
                        .fetch_one(&self.pool)
                        .await?;
                count_row.get::<i64, _>("cnt") as u32
            }
        };

        Ok(count)
    }
}

// ── Raw message metadata parsing (without user join) ──

fn parse_message_metadata_raw(
    row: &sqlx::sqlite::SqliteRow,
    node_id: Uuid,
) -> Result<models::MessageMetadataRaw> {
    let message_id = Uuid::parse_str(&row.get::<String, _>("id"))?;
    let channel_id = Uuid::parse_str(&row.get::<String, _>("channel_id"))?;
    let sender_id = Uuid::parse_str(&row.get::<String, _>("sender_id"))?;
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
            Some(models::RepliedMessageRaw {
                id: Uuid::parse_str(&replied_id)?,
                sender_id: Uuid::parse_str(&row.get::<String, _>("replied_sender_id"))?,
                encrypted_payload: row.get::<Vec<u8>, _>("replied_payload"),
                created_at: row.get::<i64, _>("replied_created_at") as u64,
            })
        } else {
            None
        };

    Ok(models::MessageMetadataRaw {
        id: message_id,
        channel_id,
        sender_id,
        encrypted_payload,
        created_at,
        edited_at,
        pinned_at,
        pinned_by,
        reply_to,
        replied_message,
        _node_id: node_id,
    })
}
