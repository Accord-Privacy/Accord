//! Migration from single-DB layout to per-Node database isolation
//!
//! Reads all data from the old monolithic SQLite database, splits node-scoped data
//! into per-Node SQLite files, and updates the relay database.

use anyhow::{Context, Result};
use sqlx::{sqlite::SqlitePool, Row};
use std::path::Path;
use uuid::Uuid;

use super::node_db::NodeDatabase;
use super::relay::RelayDatabase;

/// Migrate from a single monolithic database to per-Node isolation layout.
///
/// - `old_db_path`: path to the existing single `.sqlite` file
/// - `relay_db`: the new relay database (already initialized)
/// - `data_dir`: directory where per-Node `.sqlite` files will be created
///
/// Returns the list of node IDs that were migrated.
pub async fn migrate_single_to_per_node(
    old_db_path: &Path,
    relay_db: &RelayDatabase,
    data_dir: &Path,
) -> Result<Vec<Uuid>> {
    let old_url = format!("sqlite:{}", old_db_path.display());
    let old_pool = SqlitePool::connect(&old_url)
        .await
        .context("Failed to connect to old database")?;

    // 1. Migrate users (already in relay DB schema — copy over)
    let user_rows =
        sqlx::query("SELECT id, public_key_hash, public_key, password_hash, created_at FROM users")
            .fetch_all(&old_pool)
            .await
            .context("Failed to read users from old DB")?;

    for row in &user_rows {
        let id: String = row.get("id");
        let pkh: String = row.get("public_key_hash");
        let pk: String = row.get("public_key");
        let pw: String = row.get("password_hash");
        let created_at: i64 = row.get("created_at");

        sqlx::query("INSERT OR IGNORE INTO users (id, public_key_hash, public_key, password_hash, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&id).bind(&pkh).bind(&pk).bind(&pw).bind(created_at)
            .execute(&relay_db.pool)
            .await?;
    }

    // 2. Migrate user_profiles
    let profile_rows = sqlx::query("SELECT user_id, display_name, avatar_url, bio, status, custom_status, updated_at FROM user_profiles")
        .fetch_all(&old_pool).await.unwrap_or_default();

    for row in &profile_rows {
        let user_id: String = row.get("user_id");
        let display_name: String = row.get("display_name");
        let avatar_url: Option<String> = row.get("avatar_url");
        let bio: Option<String> = row.get("bio");
        let status: String = row.get("status");
        let custom_status: Option<String> = row.get("custom_status");
        let updated_at: i64 = row.get("updated_at");

        sqlx::query("INSERT OR IGNORE INTO user_profiles (user_id, display_name, avatar_url, bio, status, custom_status, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(&user_id).bind(&display_name).bind(&avatar_url).bind(&bio).bind(&status).bind(&custom_status).bind(updated_at)
            .execute(&relay_db.pool).await?;
    }

    // 3. Migrate nodes and node_members
    let node_rows = sqlx::query("SELECT id, name, owner_id, description, created_at FROM nodes")
        .fetch_all(&old_pool)
        .await
        .context("Failed to read nodes")?;

    let mut migrated_node_ids = Vec::new();

    for node_row in &node_rows {
        let node_id_str: String = node_row.get("id");
        let node_id = Uuid::parse_str(&node_id_str)?;
        let name: String = node_row.get("name");
        let owner_id: String = node_row.get("owner_id");
        let description: Option<String> = node_row.get("description");
        let created_at: i64 = node_row.get("created_at");

        // Insert into relay nodes
        sqlx::query("INSERT OR IGNORE INTO nodes (id, name, owner_id, description, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&node_id_str).bind(&name).bind(&owner_id).bind(&description).bind(created_at)
            .execute(&relay_db.pool).await?;

        // Insert node_members into relay
        let member_rows = sqlx::query("SELECT node_id, user_id, role, joined_at, device_fingerprint_hash FROM node_members WHERE node_id = ?")
            .bind(&node_id_str)
            .fetch_all(&old_pool).await?;

        for mrow in &member_rows {
            let nid: String = mrow.get("node_id");
            let uid: String = mrow.get("user_id");
            let role: String = mrow.get("role");
            let joined_at: i64 = mrow.get("joined_at");
            let dfh: Option<String> = mrow.get("device_fingerprint_hash");

            sqlx::query("INSERT OR IGNORE INTO node_members (node_id, user_id, role, joined_at, device_fingerprint_hash) VALUES (?, ?, ?, ?, ?)")
                .bind(&nid).bind(&uid).bind(&role).bind(joined_at).bind(&dfh)
                .execute(&relay_db.pool).await?;
        }

        // 4. Create per-Node database and migrate node-scoped data
        let node_dir = data_dir.join("nodes");
        tokio::fs::create_dir_all(&node_dir).await?;
        let node_db_path = node_dir.join(format!("{}.sqlite", node_id));
        let node_db_url = format!("sqlite:{}?mode=rwc", node_db_path.display());
        let node_pool = SqlitePool::connect(&node_db_url).await?;
        let node_db = NodeDatabase::new(node_pool, node_id).await?;

        // Migrate channels
        let channel_rows = sqlx::query("SELECT id, name, created_by, created_at, category_id, position FROM channels WHERE node_id = ?")
            .bind(&node_id_str)
            .fetch_all(&old_pool).await?;

        for crow in &channel_rows {
            let cid: String = crow.get("id");
            let cname: String = crow.get("name");
            let created_by: String = crow.get("created_by");
            let ccreated_at: i64 = crow.get("created_at");
            let cat_id: Option<String> = crow.get("category_id");
            let position: i64 = crow.get("position");

            sqlx::query("INSERT OR IGNORE INTO channels (id, name, created_by, created_at, category_id, position) VALUES (?, ?, ?, ?, ?, ?)")
                .bind(&cid).bind(&cname).bind(&created_by).bind(ccreated_at).bind(&cat_id).bind(position)
                .execute(&node_db.pool).await?;

            // Register in relay
            let channel_uuid = Uuid::parse_str(&cid)?;
            relay_db.register_channel(channel_uuid, node_id).await?;

            // Migrate channel_members
            let cm_rows = sqlx::query(
                "SELECT channel_id, user_id, joined_at FROM channel_members WHERE channel_id = ?",
            )
            .bind(&cid)
            .fetch_all(&old_pool)
            .await?;
            for cmrow in &cm_rows {
                let cmcid: String = cmrow.get("channel_id");
                let cmuid: String = cmrow.get("user_id");
                let cmjat: i64 = cmrow.get("joined_at");
                sqlx::query("INSERT OR IGNORE INTO channel_members (channel_id, user_id, joined_at) VALUES (?, ?, ?)")
                    .bind(&cmcid).bind(&cmuid).bind(cmjat)
                    .execute(&node_db.pool).await?;
            }
        }

        // Migrate channel_categories
        let cat_rows = sqlx::query(
            "SELECT id, name, position, created_at FROM channel_categories WHERE node_id = ?",
        )
        .bind(&node_id_str)
        .fetch_all(&old_pool)
        .await
        .unwrap_or_default();

        for catrow in &cat_rows {
            let catid: String = catrow.get("id");
            let catname: String = catrow.get("name");
            let catpos: i64 = catrow.get("position");
            let catca: i64 = catrow.get("created_at");
            sqlx::query("INSERT OR IGNORE INTO channel_categories (id, name, position, created_at) VALUES (?, ?, ?, ?)")
                .bind(&catid).bind(&catname).bind(catpos).bind(catca)
                .execute(&node_db.pool).await?;
        }

        // Migrate messages (for channels in this node)
        let msg_rows = sqlx::query(
            "SELECT m.id, m.channel_id, m.sender_id, m.encrypted_payload, m.created_at, m.edited_at, m.pinned_at, m.pinned_by, m.reply_to FROM messages m JOIN channels c ON m.channel_id = c.id WHERE c.node_id = ?"
        )
        .bind(&node_id_str)
        .fetch_all(&old_pool).await?;

        for mrow in &msg_rows {
            let mid: String = mrow.get("id");
            let mcid: String = mrow.get("channel_id");
            let msid: String = mrow.get("sender_id");
            let payload: Vec<u8> = mrow.get("encrypted_payload");
            let mca: i64 = mrow.get("created_at");
            let mea: Option<i64> = mrow.get("edited_at");
            let mpa: Option<i64> = mrow.get("pinned_at");
            let mpb: Option<String> = mrow.get("pinned_by");
            let mrt: Option<String> = mrow.get("reply_to");

            sqlx::query("INSERT OR IGNORE INTO messages (id, channel_id, sender_id, encrypted_payload, created_at, edited_at, pinned_at, pinned_by, reply_to) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&mid).bind(&mcid).bind(&msid).bind(&payload).bind(mca).bind(mea).bind(mpa).bind(&mpb).bind(&mrt)
                .execute(&node_db.pool).await?;
        }

        // Migrate message_reactions
        let reaction_rows = sqlx::query(
            "SELECT mr.message_id, mr.user_id, mr.emoji, mr.created_at FROM message_reactions mr JOIN messages m ON mr.message_id = m.id JOIN channels c ON m.channel_id = c.id WHERE c.node_id = ?"
        )
        .bind(&node_id_str)
        .fetch_all(&old_pool).await.unwrap_or_default();

        for rrow in &reaction_rows {
            let rmid: String = rrow.get("message_id");
            let ruid: String = rrow.get("user_id");
            let emoji: String = rrow.get("emoji");
            let rca: i64 = rrow.get("created_at");
            sqlx::query("INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji, created_at) VALUES (?, ?, ?, ?)")
                .bind(&rmid).bind(&ruid).bind(&emoji).bind(rca)
                .execute(&node_db.pool).await?;
        }

        // Migrate node_invites
        let invite_rows = sqlx::query("SELECT id, created_by, invite_code, max_uses, current_uses, expires_at, created_at FROM node_invites WHERE node_id = ?")
            .bind(&node_id_str)
            .fetch_all(&old_pool).await.unwrap_or_default();

        for irow in &invite_rows {
            let iid: String = irow.get("id");
            let icb: String = irow.get("created_by");
            let ic: String = irow.get("invite_code");
            let imu: Option<i64> = irow.get("max_uses");
            let icu: i64 = irow.get("current_uses");
            let iea: Option<i64> = irow.get("expires_at");
            let ica: i64 = irow.get("created_at");
            sqlx::query("INSERT OR IGNORE INTO node_invites (id, created_by, invite_code, max_uses, current_uses, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
                .bind(&iid).bind(&icb).bind(&ic).bind(imu).bind(icu).bind(iea).bind(ica)
                .execute(&node_db.pool).await?;
        }

        // Migrate node_user_profiles
        let nup_rows = sqlx::query("SELECT user_id, encrypted_display_name, encrypted_avatar_url, joined_at FROM node_user_profiles WHERE node_id = ?")
            .bind(&node_id_str)
            .fetch_all(&old_pool).await.unwrap_or_default();

        for nrow in &nup_rows {
            let nuid: String = nrow.get("user_id");
            let edn: Option<Vec<u8>> = nrow.get("encrypted_display_name");
            let eau: Option<Vec<u8>> = nrow.get("encrypted_avatar_url");
            let njat: i64 = nrow.get("joined_at");
            sqlx::query("INSERT OR IGNORE INTO node_user_profiles (user_id, encrypted_display_name, encrypted_avatar_url, joined_at) VALUES (?, ?, ?, ?)")
                .bind(&nuid).bind(&edn).bind(&eau).bind(njat)
                .execute(&node_db.pool).await?;
        }

        // Migrate node_bans
        let ban_rows = sqlx::query("SELECT public_key_hash, banned_by, banned_at, reason_encrypted, expires_at, device_fingerprint_hash FROM node_bans WHERE node_id = ?")
            .bind(&node_id_str)
            .fetch_all(&old_pool).await.unwrap_or_default();

        for brow in &ban_rows {
            let bpkh: String = brow.get("public_key_hash");
            let bby: String = brow.get("banned_by");
            let bat: i64 = brow.get("banned_at");
            let bre: Option<Vec<u8>> = brow.get("reason_encrypted");
            let bea: Option<i64> = brow.get("expires_at");
            let bdfh: Option<String> = brow.get("device_fingerprint_hash");
            sqlx::query("INSERT OR IGNORE INTO node_bans (public_key_hash, banned_by, banned_at, reason_encrypted, expires_at, device_fingerprint_hash) VALUES (?, ?, ?, ?, ?, ?)")
                .bind(&bpkh).bind(&bby).bind(bat).bind(&bre).bind(bea).bind(&bdfh)
                .execute(&node_db.pool).await?;
        }

        // Migrate files
        let file_rows = sqlx::query(
            "SELECT f.id, f.channel_id, f.uploader_id, f.encrypted_filename, f.file_size_bytes, f.content_hash, f.storage_path, f.created_at FROM files f JOIN channels c ON f.channel_id = c.id WHERE c.node_id = ?"
        )
        .bind(&node_id_str)
        .fetch_all(&old_pool).await.unwrap_or_default();

        for frow in &file_rows {
            let fid: String = frow.get("id");
            let fcid: String = frow.get("channel_id");
            let fuid: String = frow.get("uploader_id");
            let efn: Vec<u8> = frow.get("encrypted_filename");
            let fsb: i64 = frow.get("file_size_bytes");
            let fch: String = frow.get("content_hash");
            let fsp: String = frow.get("storage_path");
            let fca: i64 = frow.get("created_at");
            sqlx::query("INSERT OR IGNORE INTO files (id, channel_id, uploader_id, encrypted_filename, file_size_bytes, content_hash, storage_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&fid).bind(&fcid).bind(&fuid).bind(&efn).bind(fsb).bind(&fch).bind(&fsp).bind(fca)
                .execute(&node_db.pool).await?;
        }

        // Migrate audit_log
        let audit_rows = sqlx::query("SELECT id, actor_id, action, target_type, target_id, details, created_at FROM audit_log WHERE node_id = ?")
            .bind(&node_id_str)
            .fetch_all(&old_pool).await.unwrap_or_default();

        for arow in &audit_rows {
            let aid: String = arow.get("id");
            let aaid: String = arow.get("actor_id");
            let aaction: String = arow.get("action");
            let att: String = arow.get("target_type");
            let atid: Option<String> = arow.get("target_id");
            let adetails: Option<String> = arow.get("details");
            let aca: i64 = arow.get("created_at");
            sqlx::query("INSERT OR IGNORE INTO audit_log (id, actor_id, action, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
                .bind(&aid).bind(&aaid).bind(&aaction).bind(&att).bind(&atid).bind(&adetails).bind(aca)
                .execute(&node_db.pool).await?;
        }

        migrated_node_ids.push(node_id);
    }

    // Migrate relay-level tables that weren't covered above:
    // key_bundles, one_time_prekeys, prekey_messages, dm_channels, friend_requests, friendships, device_tokens

    // key_bundles
    let kb_rows =
        sqlx::query("SELECT user_id, identity_key, signed_prekey, updated_at FROM key_bundles")
            .fetch_all(&old_pool)
            .await
            .unwrap_or_default();
    for row in &kb_rows {
        let uid: String = row.get("user_id");
        let ik: Vec<u8> = row.get("identity_key");
        let sp: Vec<u8> = row.get("signed_prekey");
        let ua: i64 = row.get("updated_at");
        sqlx::query("INSERT OR IGNORE INTO key_bundles (user_id, identity_key, signed_prekey, updated_at) VALUES (?, ?, ?, ?)")
            .bind(&uid).bind(&ik).bind(&sp).bind(ua)
            .execute(&relay_db.pool).await?;
    }

    // one_time_prekeys
    let otpk_rows = sqlx::query("SELECT user_id, prekey FROM one_time_prekeys")
        .fetch_all(&old_pool)
        .await
        .unwrap_or_default();
    for row in &otpk_rows {
        let uid: String = row.get("user_id");
        let pk: Vec<u8> = row.get("prekey");
        sqlx::query("INSERT INTO one_time_prekeys (user_id, prekey) VALUES (?, ?)")
            .bind(&uid)
            .bind(&pk)
            .execute(&relay_db.pool)
            .await?;
    }

    // prekey_messages
    let pm_rows = sqlx::query(
        "SELECT id, recipient_id, sender_id, message_data, created_at FROM prekey_messages",
    )
    .fetch_all(&old_pool)
    .await
    .unwrap_or_default();
    for row in &pm_rows {
        let id: String = row.get("id");
        let rid: String = row.get("recipient_id");
        let sid: String = row.get("sender_id");
        let md: Vec<u8> = row.get("message_data");
        let ca: i64 = row.get("created_at");
        sqlx::query("INSERT OR IGNORE INTO prekey_messages (id, recipient_id, sender_id, message_data, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&id).bind(&rid).bind(&sid).bind(&md).bind(ca)
            .execute(&relay_db.pool).await?;
    }

    // dm_channels
    let dm_rows = sqlx::query("SELECT id, user1_id, user2_id, created_at FROM dm_channels")
        .fetch_all(&old_pool)
        .await
        .unwrap_or_default();
    for row in &dm_rows {
        let id: String = row.get("id");
        let u1: String = row.get("user1_id");
        let u2: String = row.get("user2_id");
        let ca: i64 = row.get("created_at");
        sqlx::query("INSERT OR IGNORE INTO dm_channels (id, user1_id, user2_id, created_at) VALUES (?, ?, ?, ?)")
            .bind(&id).bind(&u1).bind(&u2).bind(ca)
            .execute(&relay_db.pool).await?;
    }

    // friend_requests
    let fr_rows = sqlx::query("SELECT id, from_user_id, to_user_id, node_id, dm_key_bundle, created_at, status FROM friend_requests")
        .fetch_all(&old_pool).await.unwrap_or_default();
    for row in &fr_rows {
        let id: String = row.get("id");
        let fuid: String = row.get("from_user_id");
        let tuid: String = row.get("to_user_id");
        let nid: String = row.get("node_id");
        let dkb: Option<Vec<u8>> = row.get("dm_key_bundle");
        let ca: i64 = row.get("created_at");
        let status: String = row.get("status");
        sqlx::query("INSERT OR IGNORE INTO friend_requests (id, from_user_id, to_user_id, node_id, dm_key_bundle, created_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(&id).bind(&fuid).bind(&tuid).bind(&nid).bind(&dkb).bind(ca).bind(&status)
            .execute(&relay_db.pool).await?;
    }

    // friendships
    let fs_rows = sqlx::query(
        "SELECT user_a_hash, user_b_hash, friendship_proof, established_at FROM friendships",
    )
    .fetch_all(&old_pool)
    .await
    .unwrap_or_default();
    for row in &fs_rows {
        let ua: String = row.get("user_a_hash");
        let ub: String = row.get("user_b_hash");
        let fp: Option<Vec<u8>> = row.get("friendship_proof");
        let ea: i64 = row.get("established_at");
        sqlx::query("INSERT OR IGNORE INTO friendships (user_a_hash, user_b_hash, friendship_proof, established_at) VALUES (?, ?, ?, ?)")
            .bind(&ua).bind(&ub).bind(&fp).bind(ea)
            .execute(&relay_db.pool).await?;
    }

    // device_tokens
    let dt_rows = sqlx::query(
        "SELECT id, user_id, platform, token, privacy_level, created_at FROM device_tokens",
    )
    .fetch_all(&old_pool)
    .await
    .unwrap_or_default();
    for row in &dt_rows {
        let id: String = row.get("id");
        let uid: String = row.get("user_id");
        let platform: String = row.get("platform");
        let token: String = row.get("token");
        let pl: String = row.get("privacy_level");
        let ca: i64 = row.get("created_at");
        sqlx::query("INSERT OR IGNORE INTO device_tokens (id, user_id, platform, token, privacy_level, created_at) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&id).bind(&uid).bind(&platform).bind(&token).bind(&pl).bind(ca)
            .execute(&relay_db.pool).await?;
    }

    old_pool.close().await;

    Ok(migrated_node_ids)
}
