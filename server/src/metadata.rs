//! Metadata stripping for minimal metadata mode.
//!
//! When the relay runs in `Minimal` mode, these functions sanitize data before
//! database writes so the relay only persists what is needed for routing.

use crate::state::MetadataMode;

/// Placeholder used for required plaintext name columns in minimal mode.
/// Clients must use encrypted_name fields instead.
const MINIMAL_PLACEHOLDER: &str = "[redacted]";

/// Strip a node name for storage. In minimal mode returns a placeholder;
/// the encrypted_name blob (stored separately) is the authoritative source.
pub fn strip_node_name(mode: MetadataMode, name: &str) -> String {
    match mode {
        MetadataMode::Standard => name.to_string(),
        MetadataMode::Minimal => MINIMAL_PLACEHOLDER.to_string(),
    }
}

/// Strip an optional description. In minimal mode always returns `None`.
pub fn strip_description(mode: MetadataMode, description: Option<&str>) -> Option<String> {
    match mode {
        MetadataMode::Standard => description.map(|s| s.to_string()),
        MetadataMode::Minimal => None,
    }
}

/// Strip a channel name for storage. Same logic as node names.
pub fn strip_channel_name(mode: MetadataMode, name: &str) -> String {
    match mode {
        MetadataMode::Standard => name.to_string(),
        MetadataMode::Minimal => MINIMAL_PLACEHOLDER.to_string(),
    }
}

/// Strip a category name for storage.
pub fn strip_category_name(mode: MetadataMode, name: &str) -> String {
    match mode {
        MetadataMode::Standard => name.to_string(),
        MetadataMode::Minimal => MINIMAL_PLACEHOLDER.to_string(),
    }
}

/// Strip a user profile display name for storage.
pub fn strip_display_name(mode: MetadataMode, display_name: &str) -> String {
    match mode {
        MetadataMode::Standard => display_name.to_string(),
        MetadataMode::Minimal => MINIMAL_PLACEHOLDER.to_string(),
    }
}

/// Strip optional profile text fields (bio, custom_status).
/// In minimal mode these are always `None`.
pub fn strip_optional_text(mode: MetadataMode, text: Option<&str>) -> Option<String> {
    match mode {
        MetadataMode::Standard => text.map(|s| s.to_string()),
        MetadataMode::Minimal => None,
    }
}

// ── REST handlers: encrypted metadata (opaque NMK blobs) ──────────────────────
//
// The relay stores and returns these blobs without ever being able to decrypt
// them; clients derive the Node Metadata Key (NMK) and encrypt/decrypt locally.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use std::collections::HashMap;
use uuid::Uuid;

use crate::handlers::extract_user_from_token;
use crate::models::{
    EncryptedMetadataBundle, EncryptedNodeFields, ErrorResponse, UpdateEncryptedMetadataRequest,
};
use crate::state::SharedState;

/// Max decoded size for an encrypted name blob.
const MAX_ENCRYPTED_NAME_BYTES: usize = 1024;
/// Max decoded size for an encrypted description blob.
const MAX_ENCRYPTED_DESC_BYTES: usize = 16 * 1024;
/// Max channel + category entries in one bulk update.
const MAX_BULK_ENTRIES: usize = 500;
/// Wire format: version (1) + nonce (12) + GCM tag (16) — minimum valid blob.
const MIN_BLOB_BYTES: usize = 29;
const METADATA_VERSION: u8 = 1;

type ApiError = (StatusCode, Json<ErrorResponse>);

fn api_error(status: StatusCode, msg: &str) -> ApiError {
    (
        status,
        Json(ErrorResponse {
            error: msg.to_string(),
            code: status.as_u16(),
        }),
    )
}

/// Decode and sanity-check a base64 metadata blob. The relay does not (and
/// cannot) verify the ciphertext — only shape and size, to bound abuse.
fn decode_blob(b64: &str, max_bytes: usize, what: &str) -> Result<Vec<u8>, ApiError> {
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, &format!("{what}: invalid base64")))?;
    if blob.len() < MIN_BLOB_BYTES {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            &format!("{what}: blob too short"),
        ));
    }
    if blob.len() > max_bytes {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            &format!("{what}: blob exceeds {max_bytes} bytes"),
        ));
    }
    if blob[0] != METADATA_VERSION {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            &format!("{what}: unsupported metadata version"),
        ));
    }
    Ok(blob)
}

async fn require_role(
    state: &SharedState,
    node_id: Uuid,
    user_id: Uuid,
    admin_required: bool,
) -> Result<(), ApiError> {
    let member = state
        .db
        .get_node_member(node_id, user_id)
        .await
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"))?
        .ok_or_else(|| api_error(StatusCode::FORBIDDEN, "Not a member of this node"))?;
    if admin_required
        && !matches!(
            member.role,
            crate::node::NodeRole::Admin | crate::node::NodeRole::Moderator
        )
    {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "Insufficient permissions. Admin or moderator required.",
        ));
    }
    Ok(())
}

/// GET /api/nodes/:node_id/metadata/encrypted — full encrypted-metadata bundle.
/// Any node member may read; only NMK holders can decrypt.
pub async fn get_encrypted_metadata_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<EncryptedMetadataBundle>, ApiError> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_role(&state, node_id, user_id, false).await?;

    let (enc_name, enc_desc, enc_settings, channels, categories) = state
        .db
        .get_node_encrypted_metadata(node_id)
        .await
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"))?;

    let b64 = |raw: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(raw);
    Ok(Json(EncryptedMetadataBundle {
        node: EncryptedNodeFields {
            encrypted_name: enc_name.map(b64),
            encrypted_description: enc_desc.map(b64),
            encrypted_settings: enc_settings.map(b64),
        },
        channels: channels
            .into_iter()
            .map(|(id, raw)| (id, b64(raw)))
            .collect(),
        categories: categories
            .into_iter()
            .map(|(id, raw)| (id, b64(raw)))
            .collect(),
    }))
}

/// PUT /api/nodes/:node_id/metadata/encrypted — bulk update encrypted blobs.
/// Admin or moderator only. Channels/categories must belong to the node.
pub async fn update_encrypted_metadata_handler(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Json(request): Json<UpdateEncryptedMetadataRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user_id = extract_user_from_token(&state, &headers, &params).await?;
    require_role(&state, node_id, user_id, true).await?;

    let entry_count = request.channels.as_ref().map_or(0, |m| m.len())
        + request.categories.as_ref().map_or(0, |m| m.len());
    if entry_count > MAX_BULK_ENTRIES {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            &format!("Too many entries in one update (max {MAX_BULK_ENTRIES})"),
        ));
    }

    if let Some(node_fields) = &request.node {
        let name_blob = node_fields
            .encrypted_name
            .as_deref()
            .map(|b64| decode_blob(b64, MAX_ENCRYPTED_NAME_BYTES, "node encrypted_name"))
            .transpose()?;
        let desc_blob = node_fields
            .encrypted_description
            .as_deref()
            .map(|b64| decode_blob(b64, MAX_ENCRYPTED_DESC_BYTES, "node encrypted_description"))
            .transpose()?;
        let settings_blob = node_fields
            .encrypted_settings
            .as_deref()
            .map(|b64| decode_blob(b64, MAX_ENCRYPTED_DESC_BYTES, "node encrypted_settings"))
            .transpose()?;
        state
            .db
            .set_node_encrypted_metadata(
                node_id,
                name_blob.as_deref(),
                desc_blob.as_deref(),
                settings_blob.as_deref(),
            )
            .await
            .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"))?;
    }

    let mut unknown_ids: Vec<Uuid> = Vec::new();
    if let Some(channels) = &request.channels {
        for (channel_id, b64) in channels {
            let blob = decode_blob(b64, MAX_ENCRYPTED_NAME_BYTES, "channel encrypted_name")?;
            let updated = state
                .db
                .set_channel_encrypted_name(node_id, *channel_id, &blob)
                .await
                .map_err(|_| {
                    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                })?;
            if !updated {
                unknown_ids.push(*channel_id);
            }
        }
    }
    if let Some(categories) = &request.categories {
        for (category_id, b64) in categories {
            let blob = decode_blob(b64, MAX_ENCRYPTED_NAME_BYTES, "category encrypted_name")?;
            let updated = state
                .db
                .set_category_encrypted_name(node_id, *category_id, &blob)
                .await
                .map_err(|_| {
                    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                })?;
            if !updated {
                unknown_ids.push(*category_id);
            }
        }
    }

    if !unknown_ids.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            &format!("Unknown channel/category ids for this node: {unknown_ids:?}"),
        ));
    }

    // Tell node members metadata changed so they refetch + decrypt (e.g. adopt a
    // new disappearing-messages policy live, not just on next node open). Sent
    // over the node's channels, like member-join events. Opaque signal only.
    if let Ok(channels) = state.db.get_node_channels(node_id).await {
        let event =
            serde_json::json!({ "type": "metadata_updated", "node_id": node_id }).to_string();
        for channel in &channels {
            let _ = state.send_to_channel(channel.id, event.clone()).await;
        }
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_mode_passthrough() {
        assert_eq!(
            strip_node_name(MetadataMode::Standard, "My Node"),
            "My Node"
        );
        assert_eq!(
            strip_description(MetadataMode::Standard, Some("desc")),
            Some("desc".to_string())
        );
        assert_eq!(
            strip_channel_name(MetadataMode::Standard, "general"),
            "general"
        );
        assert_eq!(strip_display_name(MetadataMode::Standard, "Alice"), "Alice");
        assert_eq!(
            strip_optional_text(MetadataMode::Standard, Some("bio")),
            Some("bio".to_string())
        );
    }

    #[test]
    fn minimal_mode_strips() {
        assert_eq!(
            strip_node_name(MetadataMode::Minimal, "My Node"),
            "[redacted]"
        );
        assert_eq!(strip_description(MetadataMode::Minimal, Some("desc")), None);
        assert_eq!(
            strip_channel_name(MetadataMode::Minimal, "general"),
            "[redacted]"
        );
        assert_eq!(
            strip_display_name(MetadataMode::Minimal, "Alice"),
            "[redacted]"
        );
        assert_eq!(
            strip_optional_text(MetadataMode::Minimal, Some("bio")),
            None
        );
    }
}
