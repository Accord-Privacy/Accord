//! Relay-level database: user registration, node registry, memberships, friendships, DMs, keys

use anyhow::{Context, Result};
use sqlx::{sqlite::SqlitePool, Row};
use uuid::Uuid;

use crate::models::{self, User, UserProfile};
use crate::node::{Node, NodeMember, NodeRole};

/// Relay-level database — stores identity and cross-node data only
#[derive(Debug)]
pub struct RelayDatabase {
    pub(crate) pool: SqlitePool,
}

impl RelayDatabase {
    pub async fn new(pool: SqlitePool) -> Result<Self> {
        let db = Self { pool };
        db.run_migrations().await?;
        Ok(db)
    }

    async fn run_migrations(&self) -> Result<()> {
        // Users table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY NOT NULL,
                public_key_hash TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                password_hash TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create users table")?;

        // Backward compat columns
        sqlx::query("ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE users ADD COLUMN public_key_hash TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await
            .ok();

        // Nodes table (registry)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                description TEXT,
                created_at INTEGER NOT NULL,
                encrypted_name BLOB,
                encrypted_description BLOB,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create nodes table")?;

        // Encrypted metadata columns (migration)
        sqlx::query("ALTER TABLE nodes ADD COLUMN encrypted_name BLOB")
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("ALTER TABLE nodes ADD COLUMN encrypted_description BLOB")
            .execute(&self.pool)
            .await
            .ok();

        // Node members
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS node_members (
                node_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                joined_at INTEGER NOT NULL,
                device_fingerprint_hash TEXT,
                PRIMARY KEY (node_id, user_id),
                FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create node_members table")?;

        sqlx::query("ALTER TABLE node_members ADD COLUMN device_fingerprint_hash TEXT")
            .execute(&self.pool)
            .await
            .ok();

        // User profiles (relay-level)
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
                display_name_encrypted BLOB,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create user_profiles table")?;

        sqlx::query("ALTER TABLE user_profiles ADD COLUMN display_name_encrypted BLOB")
            .execute(&self.pool)
            .await
            .ok();

        // Key bundles (X3DH)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS key_bundles (
                user_id TEXT PRIMARY KEY NOT NULL,
                identity_key BLOB NOT NULL,
                signed_prekey BLOB NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create key_bundles table")?;

        // One-time prekeys
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS one_time_prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                prekey BLOB NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create one_time_prekeys table")?;

        // Prekey messages
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS prekey_messages (
                id TEXT PRIMARY KEY NOT NULL,
                recipient_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                message_data BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (recipient_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create prekey_messages table")?;

        // DM channels
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

        // Friend requests
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS friend_requests (
                id TEXT PRIMARY KEY NOT NULL,
                from_user_id TEXT NOT NULL,
                to_user_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                dm_key_bundle BLOB,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                FOREIGN KEY (from_user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (to_user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create friend_requests table")?;

        // Friendships
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS friendships (
                user_a_hash TEXT NOT NULL,
                user_b_hash TEXT NOT NULL,
                friendship_proof BLOB,
                established_at INTEGER NOT NULL,
                PRIMARY KEY (user_a_hash, user_b_hash)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create friendships table")?;

        // Device tokens
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS device_tokens (
                id TEXT PRIMARY KEY NOT NULL,
                user_id TEXT NOT NULL,
                platform TEXT NOT NULL,
                token TEXT NOT NULL,
                privacy_level TEXT NOT NULL DEFAULT 'partial',
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(user_id, token)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create device_tokens table")?;

        // Channel registry: lightweight mapping so we can route channel_id -> node_id
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS channel_registry (
                channel_id TEXT PRIMARY KEY NOT NULL,
                node_id TEXT NOT NULL,
                FOREIGN KEY (node_id) REFERENCES nodes (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create channel_registry table")?;

        // Auth tokens table — survives server restarts
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY NOT NULL,
                user_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create auth_tokens table")?;

        // ── Indexes ──
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_users_public_key_hash ON users (public_key_hash)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)")
            .execute(&self.pool)
            .await
            .ok();
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_nodes_owner ON nodes (owner_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_node_members_node ON node_members (node_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_node_members_user ON node_members (user_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_node_members_fingerprint ON node_members (device_fingerprint_hash)")
            .execute(&self.pool).await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_one_time_prekeys_user ON one_time_prekeys (user_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_prekey_messages_recipient ON prekey_messages (recipient_id)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_dm_channels_user1 ON dm_channels (user1_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_dm_channels_user2 ON dm_channels (user2_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_friend_requests_from ON friend_requests (from_user_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_friend_requests_to ON friend_requests (to_user_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_friend_requests_status ON friend_requests (status)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_friendships_a ON friendships (user_a_hash)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_friendships_b ON friendships (user_b_hash)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens (user_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_user_profiles_status ON user_profiles (status)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_channel_registry_node ON channel_registry (node_id)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ── Channel registry ──

    pub async fn register_channel(&self, channel_id: Uuid, node_id: Uuid) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO channel_registry (channel_id, node_id) VALUES (?, ?)")
            .bind(channel_id.to_string())
            .bind(node_id.to_string())
            .execute(&self.pool)
            .await
            .context("Failed to register channel")?;
        Ok(())
    }

    pub async fn unregister_channel(&self, channel_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM channel_registry WHERE channel_id = ?")
            .bind(channel_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn lookup_channel_node(&self, channel_id: Uuid) -> Result<Option<String>> {
        let row = sqlx::query("SELECT node_id FROM channel_registry WHERE channel_id = ?")
            .bind(channel_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("node_id")))
    }

    // ── User operations ──

    pub async fn create_user(&self, public_key: &str, password_hash: &str) -> Result<User> {
        let user_id = Uuid::new_v4();
        let created_at = super::now();
        let public_key_hash = super::compute_public_key_hash(public_key);

        sqlx::query(
            "INSERT INTO users (id, public_key_hash, public_key, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id.to_string())
        .bind(&public_key_hash)
        .bind(public_key)
        .bind(password_hash)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to insert user")?;

        // Create default user profile
        let default_display = format!("user-{}", &public_key_hash[..8]);
        self.create_user_profile(user_id, &default_display).await?;

        Ok(User {
            id: user_id,
            public_key_hash,
            public_key: public_key.to_string(),
            created_at,
        })
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, public_key_hash, public_key, created_at FROM users WHERE id = ?",
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query user by ID")?;
        row.map(|r| super::parse_user(&r)).transpose()
    }

    pub async fn get_user_by_public_key_hash(&self, public_key_hash: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, public_key_hash, public_key, created_at FROM users WHERE public_key_hash = ?",
        )
        .bind(public_key_hash)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query user by public_key_hash")?;
        row.map(|r| super::parse_user(&r)).transpose()
    }

    pub async fn get_user_password_hash_by_pkh(
        &self,
        public_key_hash: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query("SELECT password_hash FROM users WHERE public_key_hash = ?")
            .bind(public_key_hash)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query user password hash")?;
        Ok(row.map(|r| r.get::<String, _>("password_hash")))
    }

    pub async fn public_key_hash_exists(&self, public_key_hash: &str) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM users WHERE public_key_hash = ?")
            .bind(public_key_hash)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("count") > 0)
    }

    pub async fn get_user_public_key_hash(&self, user_id: Uuid) -> Result<Option<String>> {
        let row = sqlx::query("SELECT public_key_hash FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query user public_key_hash")?;
        Ok(row.map(|r| r.get::<String, _>("public_key_hash")))
    }

    // ── Node registry operations ──

    pub async fn create_node(
        &self,
        name: &str,
        owner_id: Uuid,
        description: Option<&str>,
    ) -> Result<Node> {
        let node_id = Uuid::new_v4();
        let created_at = super::now();

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

        Ok(Node {
            id: node_id,
            name: name.to_string(),
            owner_id,
            description: description.map(|s| s.to_string()),
            created_at,
            icon_hash: None,
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
        row.map(|r| super::parse_node(&r)).transpose()
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
        let query = format!("UPDATE nodes SET {} WHERE id = ?", query_parts.join(", "));
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
        // Also clean up channel registry entries for this node
        sqlx::query("DELETE FROM channel_registry WHERE node_id = ?")
            .bind(node_id.to_string())
            .execute(&self.pool)
            .await?;
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
        let joined_at = super::now();
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
        rows.iter().map(super::parse_node_member).collect()
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
        row.map(|r| super::parse_node_member(&r)).transpose()
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
        rows.iter().map(super::parse_node).collect()
    }

    pub async fn set_member_device_fingerprint(
        &self,
        node_id: Uuid,
        user_id: Uuid,
        device_fingerprint_hash: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE node_members SET device_fingerprint_hash = ? WHERE node_id = ? AND user_id = ?",
        )
        .bind(device_fingerprint_hash)
        .bind(node_id.to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .context("Failed to set member device fingerprint")?;
        Ok(())
    }

    // ── User profile operations ──

    pub async fn create_user_profile(&self, user_id: Uuid, display_name: &str) -> Result<()> {
        let updated_at = super::now();
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

    pub async fn get_user_profile(&self, user_id: Uuid) -> Result<Option<UserProfile>> {
        let row = sqlx::query("SELECT user_id, display_name, avatar_url, bio, status, custom_status, updated_at FROM user_profiles WHERE user_id = ?")
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .context("Failed to query user profile")?;
        row.map(|r| super::parse_user_profile(&r)).transpose()
    }

    pub async fn update_user_profile(
        &self,
        user_id: Uuid,
        display_name: Option<&str>,
        bio: Option<&str>,
        status: Option<&str>,
        custom_status: Option<&str>,
    ) -> Result<()> {
        let updated_at = super::now();
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
            return Ok(());
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
        let updated_at = super::now();
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
    ) -> Result<Vec<models::MemberWithProfile>> {
        let rows = sqlx::query(
            r#"
            SELECT
                nm.user_id, nm.role, nm.joined_at,
                u.public_key_hash,
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
        rows.iter().map(super::parse_member_with_profile).collect()
    }

    // ── Key bundle operations ──

    pub async fn publish_key_bundle(
        &self,
        user_id: Uuid,
        identity_key: &[u8],
        signed_prekey: &[u8],
        one_time_prekeys: &[Vec<u8>],
    ) -> Result<()> {
        let updated_at = super::now();
        sqlx::query(
            "INSERT INTO key_bundles (user_id, identity_key, signed_prekey, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET identity_key = excluded.identity_key, signed_prekey = excluded.signed_prekey, updated_at = excluded.updated_at",
        )
        .bind(user_id.to_string())
        .bind(identity_key)
        .bind(signed_prekey)
        .bind(updated_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to publish key bundle")?;

        sqlx::query("DELETE FROM one_time_prekeys WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await?;
        for opk in one_time_prekeys {
            sqlx::query("INSERT INTO one_time_prekeys (user_id, prekey) VALUES (?, ?)")
                .bind(user_id.to_string())
                .bind(opk.as_slice())
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn fetch_key_bundle(
        &self,
        user_id: Uuid,
    ) -> Result<Option<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)>> {
        let row =
            sqlx::query("SELECT identity_key, signed_prekey FROM key_bundles WHERE user_id = ?")
                .bind(user_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .context("Failed to fetch key bundle")?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let identity_key: Vec<u8> = row.get("identity_key");
        let signed_prekey: Vec<u8> = row.get("signed_prekey");

        let opk_row =
            sqlx::query("SELECT id, prekey FROM one_time_prekeys WHERE user_id = ? LIMIT 1")
                .bind(user_id.to_string())
                .fetch_optional(&self.pool)
                .await?;

        let one_time_prekey = if let Some(opk_row) = opk_row {
            let opk_id: i64 = opk_row.get("id");
            let prekey: Vec<u8> = opk_row.get("prekey");
            sqlx::query("DELETE FROM one_time_prekeys WHERE id = ?")
                .bind(opk_id)
                .execute(&self.pool)
                .await?;
            Some(prekey)
        } else {
            None
        };

        Ok(Some((identity_key, signed_prekey, one_time_prekey)))
    }

    pub async fn store_prekey_message(
        &self,
        recipient_id: Uuid,
        sender_id: Uuid,
        message_data: &[u8],
    ) -> Result<Uuid> {
        let msg_id = Uuid::new_v4();
        let created_at = super::now();
        sqlx::query(
            "INSERT INTO prekey_messages (id, recipient_id, sender_id, message_data, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(msg_id.to_string())
        .bind(recipient_id.to_string())
        .bind(sender_id.to_string())
        .bind(message_data)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to store prekey message")?;
        Ok(msg_id)
    }

    pub async fn get_prekey_messages(
        &self,
        recipient_id: Uuid,
    ) -> Result<Vec<(Uuid, Uuid, Vec<u8>, u64)>> {
        let rows = sqlx::query(
            "SELECT id, sender_id, message_data, created_at FROM prekey_messages WHERE recipient_id = ? ORDER BY created_at ASC",
        )
        .bind(recipient_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to get prekey messages")?;

        let mut messages = Vec::new();
        for row in &rows {
            let id = Uuid::parse_str(&row.get::<String, _>("id"))?;
            let sender_id = Uuid::parse_str(&row.get::<String, _>("sender_id"))?;
            let message_data: Vec<u8> = row.get("message_data");
            let created_at = row.get::<i64, _>("created_at") as u64;
            messages.push((id, sender_id, message_data, created_at));
        }

        sqlx::query("DELETE FROM prekey_messages WHERE recipient_id = ?")
            .bind(recipient_id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(messages)
    }

    // ── DM channel operations ──

    pub async fn create_or_get_dm_channel(
        &self,
        user1_id: Uuid,
        user2_id: Uuid,
    ) -> Result<models::DmChannel> {
        let (user1, user2) = if user1_id < user2_id {
            (user1_id, user2_id)
        } else {
            (user2_id, user1_id)
        };

        let existing = sqlx::query(
            "SELECT id, user1_id, user2_id, created_at FROM dm_channels WHERE user1_id = ? AND user2_id = ?"
        )
        .bind(user1.to_string())
        .bind(user2.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query existing DM channel")?;

        if let Some(row) = existing {
            return Ok(models::DmChannel {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                user1_id: Uuid::parse_str(&row.get::<String, _>("user1_id"))?,
                user2_id: Uuid::parse_str(&row.get::<String, _>("user2_id"))?,
                created_at: row.get::<i64, _>("created_at") as u64,
            });
        }

        let dm_id = Uuid::new_v4();
        let created_at = super::now();

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

        Ok(models::DmChannel {
            id: dm_id,
            user1_id: user1,
            user2_id: user2,
            created_at,
        })
    }

    pub async fn get_user_dm_channels_raw(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<sqlx::sqlite::SqliteRow>> {
        let rows = sqlx::query(
            r#"
            SELECT 
                dm.id, dm.user1_id, dm.user2_id, dm.created_at,
                u.id as other_user_id, u.public_key_hash as other_public_key_hash, u.public_key as other_public_key, u.created_at as other_user_created_at,
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
        Ok(rows)
    }

    pub async fn get_dm_channel_between_users(
        &self,
        user1_id: Uuid,
        user2_id: Uuid,
    ) -> Result<Option<models::DmChannel>> {
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
            Ok(Some(models::DmChannel {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                user1_id: Uuid::parse_str(&row.get::<String, _>("user1_id"))?,
                user2_id: Uuid::parse_str(&row.get::<String, _>("user2_id"))?,
                created_at: row.get::<i64, _>("created_at") as u64,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn is_dm_channel(&self, channel_id: Uuid) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM dm_channels WHERE id = ?")
            .bind(channel_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("count") > 0)
    }

    // ── Friendship operations ──

    pub async fn create_friend_request(
        &self,
        from_user_id: Uuid,
        to_user_id: Uuid,
        node_id: Uuid,
        dm_key_bundle: Option<&[u8]>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let created_at = super::now();
        sqlx::query(
            "INSERT INTO friend_requests (id, from_user_id, to_user_id, node_id, dm_key_bundle, created_at, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
        )
        .bind(id.to_string())
        .bind(from_user_id.to_string())
        .bind(to_user_id.to_string())
        .bind(node_id.to_string())
        .bind(dm_key_bundle)
        .bind(created_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to create friend request")?;
        Ok(id)
    }

    pub async fn accept_friend_request(
        &self,
        request_id: Uuid,
        friendship_proof: Option<&[u8]>,
    ) -> Result<bool> {
        let row = sqlx::query(
            "SELECT id, from_user_id, to_user_id, status FROM friend_requests WHERE id = ?",
        )
        .bind(request_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query friend request")?;

        let row = match row {
            Some(r) => r,
            None => return Ok(false),
        };

        let status: String = row.get("status");
        if status != "pending" {
            return Ok(false);
        }

        let from_user_id = Uuid::parse_str(&row.get::<String, _>("from_user_id"))?;
        let to_user_id = Uuid::parse_str(&row.get::<String, _>("to_user_id"))?;

        sqlx::query("UPDATE friend_requests SET status = 'accepted' WHERE id = ?")
            .bind(request_id.to_string())
            .execute(&self.pool)
            .await?;

        let from_hash = self
            .get_user_public_key_hash(from_user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("From user not found"))?;
        let to_hash = self
            .get_user_public_key_hash(to_user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("To user not found"))?;

        let (user_a, user_b) = if from_hash < to_hash {
            (from_hash, to_hash)
        } else {
            (to_hash, from_hash)
        };
        let established_at = super::now();

        sqlx::query(
            "INSERT OR IGNORE INTO friendships (user_a_hash, user_b_hash, friendship_proof, established_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&user_a)
        .bind(&user_b)
        .bind(friendship_proof)
        .bind(established_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to create friendship")?;

        Ok(true)
    }

    pub async fn reject_friend_request(&self, request_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE friend_requests SET status = 'rejected' WHERE id = ? AND status = 'pending'",
        )
        .bind(request_id.to_string())
        .execute(&self.pool)
        .await
        .context("Failed to reject friend request")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_pending_requests(&self, user_id: Uuid) -> Result<Vec<models::FriendRequest>> {
        let rows = sqlx::query(
            "SELECT id, from_user_id, to_user_id, node_id, dm_key_bundle, created_at, status FROM friend_requests WHERE to_user_id = ? AND status = 'pending' ORDER BY created_at DESC",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to query pending friend requests")?;

        rows.iter()
            .map(|row| -> Result<models::FriendRequest> {
                Ok(models::FriendRequest {
                    id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                    from_user_id: Uuid::parse_str(&row.get::<String, _>("from_user_id"))?,
                    to_user_id: Uuid::parse_str(&row.get::<String, _>("to_user_id"))?,
                    node_id: Uuid::parse_str(&row.get::<String, _>("node_id"))?,
                    dm_key_bundle: row.get("dm_key_bundle"),
                    created_at: row.get::<i64, _>("created_at") as u64,
                    status: row.get("status"),
                })
            })
            .collect()
    }

    pub async fn get_friends(&self, user_public_key_hash: &str) -> Result<Vec<models::Friendship>> {
        let rows = sqlx::query(
            "SELECT user_a_hash, user_b_hash, friendship_proof, established_at FROM friendships WHERE user_a_hash = ? OR user_b_hash = ? ORDER BY established_at DESC",
        )
        .bind(user_public_key_hash)
        .bind(user_public_key_hash)
        .fetch_all(&self.pool)
        .await
        .context("Failed to query friends")?;

        rows.iter()
            .map(|row| -> Result<models::Friendship> {
                Ok(models::Friendship {
                    user_a_hash: row.get("user_a_hash"),
                    user_b_hash: row.get("user_b_hash"),
                    friendship_proof: row.get("friendship_proof"),
                    established_at: row.get::<i64, _>("established_at") as u64,
                })
            })
            .collect()
    }

    pub async fn are_friends(&self, user_a_hash: &str, user_b_hash: &str) -> Result<bool> {
        let (a, b) = if user_a_hash < user_b_hash {
            (user_a_hash, user_b_hash)
        } else {
            (user_b_hash, user_a_hash)
        };
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM friendships WHERE user_a_hash = ? AND user_b_hash = ?",
        )
        .bind(a)
        .bind(b)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("count") > 0)
    }

    pub async fn remove_friend(&self, user_a_hash: &str, user_b_hash: &str) -> Result<bool> {
        let (a, b) = if user_a_hash < user_b_hash {
            (user_a_hash, user_b_hash)
        } else {
            (user_b_hash, user_a_hash)
        };
        let result =
            sqlx::query("DELETE FROM friendships WHERE user_a_hash = ? AND user_b_hash = ?")
                .bind(a)
                .bind(b)
                .execute(&self.pool)
                .await
                .context("Failed to remove friendship")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn share_a_node(&self, user_a_id: Uuid, user_b_id: Uuid) -> Result<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM node_members a JOIN node_members b ON a.node_id = b.node_id WHERE a.user_id = ? AND b.user_id = ?",
        )
        .bind(user_a_id.to_string())
        .bind(user_b_id.to_string())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("count") > 0)
    }

    pub async fn get_friend_request(
        &self,
        request_id: Uuid,
    ) -> Result<Option<models::FriendRequest>> {
        let row = sqlx::query(
            "SELECT id, from_user_id, to_user_id, node_id, dm_key_bundle, created_at, status FROM friend_requests WHERE id = ?",
        )
        .bind(request_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .context("Failed to query friend request")?;

        row.map(|r| -> Result<models::FriendRequest> {
            Ok(models::FriendRequest {
                id: Uuid::parse_str(&r.get::<String, _>("id"))?,
                from_user_id: Uuid::parse_str(&r.get::<String, _>("from_user_id"))?,
                to_user_id: Uuid::parse_str(&r.get::<String, _>("to_user_id"))?,
                node_id: Uuid::parse_str(&r.get::<String, _>("node_id"))?,
                dm_key_bundle: r.get("dm_key_bundle"),
                created_at: r.get::<i64, _>("created_at") as u64,
                status: r.get("status"),
            })
        })
        .transpose()
    }

    // ── Device token operations ──

    pub async fn register_device_token(
        &self,
        user_id: Uuid,
        platform: models::PushPlatform,
        token: &str,
        privacy_level: models::NotificationPrivacy,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let now = super::now();
        sqlx::query(
            r#"
            INSERT INTO device_tokens (id, user_id, platform, token, privacy_level, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, token) DO UPDATE SET
                platform = excluded.platform,
                privacy_level = excluded.privacy_level
            "#,
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .bind(platform.as_str())
        .bind(token)
        .bind(privacy_level.as_str())
        .bind(now as i64)
        .execute(&self.pool)
        .await
        .context("Failed to register device token")?;
        Ok(id)
    }

    pub async fn remove_device_token(&self, user_id: Uuid, token: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM device_tokens WHERE user_id = ? AND token = ?")
            .bind(user_id.to_string())
            .bind(token)
            .execute(&self.pool)
            .await
            .context("Failed to remove device token")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_device_tokens(&self, user_id: Uuid) -> Result<Vec<models::DeviceToken>> {
        let rows = sqlx::query(
            "SELECT id, user_id, platform, token, privacy_level, created_at FROM device_tokens WHERE user_id = ?",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .context("Failed to get device tokens")?;

        let mut tokens = Vec::new();
        for row in rows {
            tokens.push(models::DeviceToken {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                user_id: Uuid::parse_str(&row.get::<String, _>("user_id"))?,
                platform: row
                    .get::<String, _>("platform")
                    .parse()
                    .unwrap_or(models::PushPlatform::Android),
                token: row.get("token"),
                privacy_level: row
                    .get::<String, _>("privacy_level")
                    .parse()
                    .unwrap_or_default(),
                created_at: row.get::<i64, _>("created_at") as u64,
            });
        }
        Ok(tokens)
    }

    pub async fn update_push_privacy(
        &self,
        user_id: Uuid,
        token: Option<&str>,
        privacy_level: models::NotificationPrivacy,
    ) -> Result<u64> {
        let result = if let Some(token) = token {
            sqlx::query(
                "UPDATE device_tokens SET privacy_level = ? WHERE user_id = ? AND token = ?",
            )
            .bind(privacy_level.as_str())
            .bind(user_id.to_string())
            .bind(token)
            .execute(&self.pool)
            .await?
        } else {
            sqlx::query("UPDATE device_tokens SET privacy_level = ? WHERE user_id = ?")
                .bind(privacy_level.as_str())
                .bind(user_id.to_string())
                .execute(&self.pool)
                .await?
        };
        Ok(result.rows_affected())
    }

    // ── Auth Token Persistence ──

    pub async fn save_auth_token(&self, token: &str, user_id: Uuid, expires_at: u64) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO auth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
        )
        .bind(token)
        .bind(user_id.to_string())
        .bind(expires_at as i64)
        .execute(&self.pool)
        .await
        .context("Failed to save auth token")?;
        Ok(())
    }

    pub async fn load_auth_tokens(&self, current_time: u64) -> Result<Vec<(String, Uuid, u64)>> {
        let rows =
            sqlx::query("SELECT token, user_id, expires_at FROM auth_tokens WHERE expires_at > ?")
                .bind(current_time as i64)
                .fetch_all(&self.pool)
                .await
                .context("Failed to load auth tokens")?;

        let mut tokens = Vec::new();
        for row in rows {
            let token: String = row.get("token");
            let user_id_str: String = row.get("user_id");
            let expires_at: i64 = row.get("expires_at");
            if let Ok(uid) = Uuid::parse_str(&user_id_str) {
                tokens.push((token, uid, expires_at as u64));
            }
        }
        Ok(tokens)
    }

    pub async fn delete_expired_tokens(&self, current_time: u64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM auth_tokens WHERE expires_at <= ?")
            .bind(current_time as i64)
            .execute(&self.pool)
            .await
            .context("Failed to delete expired tokens")?;
        Ok(result.rows_affected())
    }

    pub async fn delete_auth_token(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM auth_tokens WHERE token = ?")
            .bind(token)
            .execute(&self.pool)
            .await
            .context("Failed to delete auth token")?;
        Ok(())
    }
}
