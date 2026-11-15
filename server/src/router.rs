//! The relay's route tables and HTTP middleware.
//!
//! The binary and the tests build their routers here, so both serve one route
//! table with the same middleware (SPEC-01 section 10.1). Later relay routes
//! are added to [`build_public_router_with`] and are then covered by every
//! test that starts the relay.

use crate::admin;
use crate::attachments::http::{
    delete_attachment_handler, download_attachment_handler, upload_attachment_handler,
};
use crate::attachments::legacy::{
    legacy_delete_handler, legacy_download_handler, legacy_list_handler, legacy_upload_handler,
};
use crate::batch_handlers;
use crate::bot_api;
use crate::federation;
use crate::handlers::{
    accept_friend_request_handler, ack_sender_keys_handler, add_build_allowlist_handler,
    add_reaction_handler, approve_join_request_handler, assign_member_role_handler, auth_handler,
    ban_check_handler, ban_user_handler, block_user_handler, build_info_handler,
    create_channel_category_handler, create_channel_handler, create_dm_channel_handler,
    create_invite_handler, create_node_handler, create_role_handler,
    delete_channel_category_handler, delete_channel_handler, delete_channel_overwrite_handler,
    delete_custom_emoji_handler, delete_message_handler, delete_role_handler,
    deny_join_request_handler, deregister_push_token_handler, edit_message_handler,
    fetch_key_bundle_handler, get_blocked_users_handler, get_build_allowlist_handler,
    get_channel_messages_handler, get_channel_threads_handler, get_dm_channels_handler,
    get_effective_permissions_handler, get_emoji_image_handler, get_member_roles_handler,
    get_message_reactions_handler, get_message_thread_handler, get_node_audit_log_handler,
    get_node_handler, get_node_icon_handler, get_node_members_handler, get_node_presence_handler,
    get_node_user_profiles_handler, get_pending_sender_keys_handler, get_pinned_messages_handler,
    get_prekey_messages_handler, get_slow_mode_handler, get_user_avatar_handler,
    get_user_profile_handler, health_handler, import_discord_template_handler,
    invite_preview_handler, join_node_handler, kick_user_handler, leave_node_handler,
    link_preview_handler, list_bans_handler, list_channel_overwrites_handler,
    list_custom_emojis_handler, list_friend_requests_handler, list_friends_handler,
    list_invites_handler, list_join_requests_handler, list_node_channels_handler,
    list_roles_handler, list_user_nodes_handler, mark_channel_read_handler, pin_message_handler,
    publish_key_bundle_handler, purge_channel_before_handler, register_handler,
    register_push_token_handler, reject_friend_request_handler, remove_build_allowlist_handler,
    remove_friend_handler, remove_member_role_handler, remove_reaction_handler,
    reorder_channels_handler, reorder_roles_handler, revoke_invite_by_code_handler,
    revoke_invite_handler, search_messages_handler, send_friend_request_handler,
    set_build_allowlist_handler, set_channel_overwrite_handler, set_node_user_profile_handler,
    set_slow_mode_handler, store_prekey_message_handler, store_sender_key_handler,
    unban_user_handler, unblock_user_handler, unpin_message_handler,
    update_channel_category_handler, update_channel_handler, update_node_handler,
    update_push_preferences_handler, update_role_handler, update_user_profile_handler,
    upload_custom_emoji_handler, upload_node_icon_handler, upload_user_avatar_handler,
    use_invite_handler, withdraw_join_request_handler, ws_handler,
};
use crate::metadata;
use crate::state::SharedState;
use crate::webhooks::{
    create_webhook_handler, delete_webhook_handler, list_webhooks_handler, test_webhook_handler,
    update_webhook_handler,
};
use axum::http::HeaderValue;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use tracing::{info, warn};

/// Settings of the public router that come from the operator's command line.
#[derive(Debug, Clone, Default)]
pub struct RouterConfig {
    /// `--cors-origins`: comma-separated origins, or `*` for any.
    pub cors_origins: Option<String>,
    /// `--no-tls`: without explicit origins, allow the local development
    /// origins instead of same-origin only.
    pub dev_cors: bool,
    /// `--frontend`: directory of a built web client to serve as the fallback.
    pub frontend: Option<String>,
}

/// The public relay router with every route and middleware and the default
/// configuration (same-origin CORS, no frontend). Tests use this.
pub fn build_public_router(state: SharedState) -> Router {
    build_public_router_with(state, &RouterConfig::default())
}

/// The public relay router as the binary serves it.
///
/// Serve it with `into_make_service_with_connect_info::<SocketAddr>()`: the
/// IP-ban layer keys on the socket peer address.
pub fn build_public_router_with(state: SharedState, config: &RouterConfig) -> Router {
    let app = public_routes().with_state(state.clone());

    let app = if let Some(ref frontend_path) = config.frontend {
        let index_path = format!("{}/index.html", frontend_path);
        info!("Serving frontend from: {}", frontend_path);
        app.fallback_service(
            ServeDir::new(frontend_path).not_found_service(ServeFile::new(index_path)),
        )
    } else {
        app
    };

    app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        middleware::rate_limit_layer,
    ))
    .layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            // ── Security response headers ──
            .layer(SetResponseHeaderLayer::overriding(
                axum::http::header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                axum::http::header::X_FRAME_OPTIONS,
                HeaderValue::from_static("DENY"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                axum::http::header::X_XSS_PROTECTION,
                HeaderValue::from_static("0"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                axum::http::header::REFERRER_POLICY,
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                axum::http::header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    // SPEC-02 §6.8: audio and video previews of verified
                    // attachments play from `blob:` URLs. `script-src`
                    // stays without `blob:`.
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                     img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' http: https: wss: ws:; frame-ancestors 'none'",
                ),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                axum::http::HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("camera=(self), microphone=(self), geolocation=()"),
            ))
            // ── CORS ──
            .layer(cors_layer(config)),
    )
    // IP ban check — outermost so banned IPs are dropped before any other work.
    .layer(axum::middleware::from_fn_with_state(
        state,
        middleware::ip_ban_layer,
    ))
}

/// The CORS policy for the configured origins.
fn cors_layer(config: &RouterConfig) -> CorsLayer {
    let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any);
    let effective_cors = config.cors_origins.clone().unwrap_or_else(|| {
        if config.dev_cors {
            // Dev mode: allow common local dev origins
            // (1420 = Vite/Tauri dev server for desktop/frontend)
            "http://localhost:1420,http://localhost:3000,http://localhost:5173,http://localhost:8080"
                .to_string()
        } else {
            // Production: same-origin only (no extra origins)
            String::new()
        }
    });
    if effective_cors.trim() == "*" {
        warn!("CORS: allowing any origin — use --cors-origins to restrict in production");
        cors.allow_origin(Any)
    } else {
        // The desktop app's webview runs on a custom app scheme
        // (tauri://localhost on Linux/macOS, http(s)://tauri.localhost
        // on Windows). No web page can ever have these origins, so
        // always allowing them lets the desktop client reach any
        // relay without weakening browser-facing CORS.
        let tauri_origins = [
            "tauri://localhost",
            "https://tauri.localhost",
            "http://tauri.localhost",
        ];
        let mut origins: Vec<HeaderValue> = effective_cors
            .split(',')
            .filter_map(|o| o.trim().parse().ok())
            .collect();
        origins.extend(
            tauri_origins
                .iter()
                .filter_map(|o| o.parse::<HeaderValue>().ok()),
        );
        info!("CORS: allowed origins: {:?}", origins);
        cors.allow_origin(AllowOrigin::list(origins))
    }
}

/// The public route table (admin routes are never mounted here).
fn public_routes() -> Router<SharedState> {
    Router::new()
        .route("/health", get(health_handler))
        .route("/api/build-info", get(build_info_handler))
        .route("/register", post(register_handler))
        .route("/auth", post(auth_handler))
        // Node endpoints
        .route(
            "/nodes",
            get(list_user_nodes_handler).post(create_node_handler),
        )
        .route("/nodes/:id", get(get_node_handler))
        .route("/nodes/:id", patch(update_node_handler))
        .route(
            "/nodes/:id/channels",
            get(list_node_channels_handler).post(create_channel_handler),
        )
        .route("/nodes/:id/join", post(join_node_handler))
        .route("/nodes/:id/leave", post(leave_node_handler))
        .route("/nodes/:id/members/:user_id", delete(kick_user_handler))
        // Join requests (SPEC-01 REQ-29 to REQ-33)
        .route("/nodes/:id/join-requests", get(list_join_requests_handler))
        .route(
            "/nodes/:id/join-requests/:user_id/approve",
            post(approve_join_request_handler),
        )
        .route(
            "/nodes/:id/join-requests/:user_id/deny",
            post(deny_join_request_handler),
        )
        .route(
            "/nodes/:id/join-request",
            delete(withdraw_join_request_handler),
        )
        // Ban endpoints
        .route("/nodes/:id/bans", post(ban_user_handler))
        .route("/nodes/:id/bans", delete(unban_user_handler))
        .route("/nodes/:id/bans", get(list_bans_handler))
        .route("/nodes/:id/ban-check", get(ban_check_handler))
        .route("/api/presence/:id", get(get_node_presence_handler))
        // Build hash allowlist
        .route(
            "/nodes/:id/build-allowlist",
            get(get_build_allowlist_handler)
                .put(set_build_allowlist_handler)
                .post(add_build_allowlist_handler),
        )
        .route(
            "/nodes/:id/build-allowlist/:hash",
            delete(remove_build_allowlist_handler),
        )
        // Node user profile endpoints
        .route("/nodes/:id/profile", put(set_node_user_profile_handler))
        .route("/nodes/:id/profiles", get(get_node_user_profiles_handler))
        // Channel category endpoints
        .route(
            "/nodes/:id/categories",
            post(create_channel_category_handler),
        )
        .route("/categories/:id", patch(update_channel_category_handler))
        .route("/categories/:id", delete(delete_channel_category_handler))
        // ── Role endpoints ──
        .route(
            "/nodes/:id/roles",
            get(list_roles_handler).post(create_role_handler),
        )
        .route("/nodes/:id/roles/reorder", patch(reorder_roles_handler))
        .route(
            "/nodes/:id/roles/:role_id",
            patch(update_role_handler).delete(delete_role_handler),
        )
        // ── Discord template import ──
        .route(
            "/nodes/:id/import-discord-template",
            post(import_discord_template_handler),
        )
        // ── Member role endpoints ──
        .route(
            "/nodes/:id/members/:user_id/roles",
            get(get_member_roles_handler),
        )
        .route(
            "/nodes/:id/members/:user_id/roles/:role_id",
            put(assign_member_role_handler).delete(remove_member_role_handler),
        )
        // Custom emoji endpoints
        .route(
            "/nodes/:id/emojis",
            get(list_custom_emojis_handler).post(upload_custom_emoji_handler),
        )
        .route(
            "/nodes/:id/emojis/:emoji_id",
            delete(delete_custom_emoji_handler),
        )
        .route("/api/emojis/:content_hash", get(get_emoji_image_handler))
        // Auto-mod is client-side (relay blind to node policy) — no relay endpoints.
        // Channel endpoints
        .route("/nodes/:id/channels/reorder", put(reorder_channels_handler))
        .route("/channels/:id", patch(update_channel_handler))
        .route(
            "/channels/:id/slow-mode",
            put(set_slow_mode_handler).get(get_slow_mode_handler),
        )
        .route("/channels/:id", delete(delete_channel_handler))
        .route("/channels/:id/messages", get(get_channel_messages_handler))
        .route("/channels/:id/read", post(mark_channel_read_handler))
        // ── Message editing and deletion ──
        .route("/messages/:id", patch(edit_message_handler))
        .route("/messages/:id", delete(delete_message_handler))
        .route(
            "/channels/:id/purge_before",
            post(purge_channel_before_handler),
        )
        // ── Message threading ──
        .route("/channels/:id/threads", get(get_channel_threads_handler))
        .route("/messages/:id/thread", get(get_message_thread_handler))
        // ── Message reactions ──
        .route(
            "/messages/:id/reactions",
            get(get_message_reactions_handler),
        )
        .route("/messages/:id/reactions/:emoji", put(add_reaction_handler))
        .route(
            "/messages/:id/reactions/:emoji",
            delete(remove_reaction_handler),
        )
        // ── Message pinning ──
        .route("/messages/:id/pin", put(pin_message_handler))
        .route("/messages/:id/pin", delete(unpin_message_handler))
        .route("/channels/:id/pins", get(get_pinned_messages_handler))
        // ── Channel permission overwrite endpoints ──
        .route(
            "/channels/:id/permissions",
            get(list_channel_overwrites_handler),
        )
        .route(
            "/channels/:id/permissions/:role_id",
            put(set_channel_overwrite_handler).delete(delete_channel_overwrite_handler),
        )
        .route(
            "/channels/:id/effective-permissions",
            get(get_effective_permissions_handler),
        )
        // Version-2 attachments (SPEC-02 section 6.4). The upload handler
        // reads the raw body stream, so no body limit or buffering applies.
        .route("/channels/:id/attachments", post(upload_attachment_handler))
        .route(
            "/attachments/:id",
            get(download_attachment_handler).delete(delete_attachment_handler),
        )
        // Legacy file routes, read-only since SPEC-02 (sections 6.4.4,
        // 6.4.5): uploads answer 410, and every route answers 410 once legacy
        // files are retired (section 7.7).
        .route("/channels/:id/files", post(legacy_upload_handler))
        .route("/channels/:id/files", get(legacy_list_handler))
        .route("/files/:id", get(legacy_download_handler))
        .route("/files/:id", delete(legacy_delete_handler))
        // Search endpoints
        .route("/nodes/:id/search", get(search_messages_handler))
        // Link preview endpoint
        .route("/api/link-preview", get(link_preview_handler))
        // User profile endpoints
        .route("/users/:id/profile", get(get_user_profile_handler))
        .route("/users/me/profile", patch(update_user_profile_handler))
        // Icon / Avatar endpoints
        .route(
            "/nodes/:id/icon",
            put(upload_node_icon_handler).get(get_node_icon_handler),
        )
        .route("/users/me/avatar", put(upload_user_avatar_handler))
        .route("/users/:id/avatar", get(get_user_avatar_handler))
        .route("/nodes/:id/members", get(get_node_members_handler))
        // Audit log endpoints
        .route("/nodes/:id/audit-log", get(get_node_audit_log_handler))
        // Node invite endpoints
        .route("/nodes/:id/invites", post(create_invite_handler))
        .route("/nodes/:id/invites", get(list_invites_handler))
        .route(
            "/nodes/:id/invites/:code",
            delete(revoke_invite_by_code_handler),
        )
        .route("/invites/:invite_id", delete(revoke_invite_handler))
        .route("/invites/:code/join", post(use_invite_handler))
        .route("/invites/:code/preview", get(invite_preview_handler))
        // Webhook endpoints
        .route(
            "/nodes/:id/webhooks",
            get(list_webhooks_handler).post(create_webhook_handler),
        )
        .route(
            "/webhooks/:id",
            patch(update_webhook_handler).delete(delete_webhook_handler),
        )
        .route("/webhooks/:id/test", post(test_webhook_handler))
        // Key bundle endpoints (Double Ratchet / X3DH)
        .route("/keys/bundle", post(publish_key_bundle_handler))
        .route("/keys/bundle/:user_id", get(fetch_key_bundle_handler))
        .route("/keys/prekey-message", post(store_prekey_message_handler))
        .route("/keys/prekey-messages", get(get_prekey_messages_handler))
        // Sender Key distribution endpoints (E2EE Sender Keys)
        .route("/channels/:id/sender-keys", post(store_sender_key_handler))
        .route("/sender-keys/pending", get(get_pending_sender_keys_handler))
        .route("/sender-keys/ack", post(ack_sender_keys_handler))
        // Push notification endpoints
        .route("/push/register", post(register_push_token_handler))
        .route("/push/register", delete(deregister_push_token_handler))
        .route("/push/preferences", put(update_push_preferences_handler))
        // Batch API endpoints (N+1 elimination)
        .route(
            "/api/nodes/:node_id/members/batch",
            get(batch_handlers::batch_members_handler),
        )
        .route(
            "/api/nodes/:node_id/channels/batch",
            get(batch_handlers::batch_channels_handler),
        )
        .route(
            "/api/nodes/:node_id/overview",
            get(batch_handlers::node_overview_handler),
        )
        // Encrypted metadata (opaque NMK blobs — relay never decrypts)
        .route(
            "/api/nodes/:node_id/metadata/encrypted",
            get(metadata::get_encrypted_metadata_handler)
                .put(metadata::update_encrypted_metadata_handler),
        )
        // Bot API v2 endpoints (airgapped command architecture)
        .route(
            "/api/nodes/:node_id/bots",
            get(bot_api::list_bots_handler).post(bot_api::install_bot_handler),
        )
        .route(
            "/api/nodes/:node_id/bots/:bot_id",
            delete(bot_api::uninstall_bot_handler),
        )
        .route(
            "/api/nodes/:node_id/bots/:bot_id/commands",
            get(bot_api::get_bot_commands_handler),
        )
        .route(
            "/api/nodes/:node_id/bots/:bot_id/invoke",
            post(bot_api::invoke_command_handler),
        )
        .route("/api/bots/respond", post(bot_api::bot_respond_handler))
        // Friend system endpoints
        .route("/friends/request", post(send_friend_request_handler))
        .route("/friends/accept", post(accept_friend_request_handler))
        .route("/friends/reject", post(reject_friend_request_handler))
        .route("/friends", get(list_friends_handler))
        .route("/friends/requests", get(list_friend_requests_handler))
        .route("/friends/:user_id", delete(remove_friend_handler))
        // User block endpoints
        .route("/users/:id/block", post(block_user_handler))
        .route("/users/:id/block", delete(unblock_user_handler))
        .route("/api/blocked-users", get(get_blocked_users_handler))
        // Federation discovery endpoints
        .route("/federation/relays", get(federation::list_relays_handler))
        .route(
            "/federation/register",
            post(federation::register_relay_handler),
        )
        .route("/federation/heartbeat", post(federation::heartbeat_handler))
        // Direct Message endpoints
        .route("/dm/:user_id", post(create_dm_channel_handler))
        .route("/dm", get(get_dm_channels_handler))
        // WebSocket endpoint
        .route("/ws", get(ws_handler))
}

/// The relay owner's admin dashboard router.
///
/// The binary binds it to 127.0.0.1 only, on its own listener: localhost
/// access is the relay owner, so these routes carry no login. The surface is
/// deliberately narrow: aggregate stats, a node registry, the relay log
/// stream, the connection log, IP bans and the build-hash allowlist. It never
/// exposes node membership, a user list or per-node governance.
pub fn build_admin_router(state: SharedState, log_tx: Arc<admin::LogBroadcast>) -> Router {
    Router::new()
        .route("/admin", get(admin::admin_page_handler))
        .route("/admin/stats", get(admin::admin_stats_handler))
        .route("/admin/nodes", get(admin::admin_nodes_handler))
        .route("/admin/connections", get(admin::admin_connections_handler))
        .route(
            "/admin/ip-bans",
            get(admin::admin_ip_bans_list_handler).post(admin::admin_ip_ban_add_handler),
        )
        .route(
            "/admin/ip-bans/:ip",
            delete(admin::admin_ip_ban_remove_handler),
        )
        .route(
            "/api/admin/build-allowlist",
            get(admin::admin_build_allowlist_get_handler)
                .put(admin::admin_build_allowlist_set_handler)
                .post(admin::admin_build_allowlist_add_handler),
        )
        .route(
            "/api/admin/build-allowlist/:hash",
            delete(admin::admin_build_allowlist_remove_handler),
        )
        .with_state(state)
        .merge(
            Router::new()
                .route("/admin/logs", get(admin::admin_logs_ws_handler))
                .with_state(log_tx),
        )
}

/// Middleware of the public router.
pub mod middleware {
    use crate::rate_limit::ActionType;
    use crate::state::SharedState;
    use axum::{
        body::Body,
        extract::{ConnectInfo, State},
        http::{Request, StatusCode},
        middleware::Next,
        response::{IntoResponse, Response},
    };
    use std::net::SocketAddr;

    /// True for the exact path shape of invite creation, `/nodes/<id>/invites`
    /// (SPEC-01 REQ-27). Invite redemption (`/invites/<code>/join`) is not
    /// matched: membership actions are limited inside their handlers.
    pub fn is_invite_creation_path(path: &str) -> bool {
        let mut segments = path.split('/');
        matches!(
            (
                segments.next(),
                segments.next(),
                segments.next(),
                segments.next(),
                segments.next(),
            ),
            (Some(""), Some("nodes"), Some(id), Some("invites"), None) if !id.is_empty()
        )
    }

    /// Applies per-user rate limits to `?token=` requests, by path shape.
    pub async fn rate_limit_layer(
        State(state): State<SharedState>,
        request: Request<Body>,
        next: Next,
    ) -> Response {
        // Determine action type from the request path/method
        let action = match (request.method().as_str(), request.uri().path()) {
            ("POST", path) if path.contains("/files") => Some(ActionType::FileUpload),
            ("PUT", path) if path.contains("/reactions") => Some(ActionType::Reaction),
            ("PATCH", "/users/me/profile") => Some(ActionType::ProfileUpdate),
            ("POST", path) if path.starts_with("/dm/") => Some(ActionType::DirectMessage),
            ("POST", path) if path.contains("/messages") => Some(ActionType::Message),
            ("POST", path) if is_invite_creation_path(path) => Some(ActionType::InviteCreate),
            ("POST", "/nodes") => Some(ActionType::NodeCreate),
            _ => None,
        };

        if let Some(action) = action {
            // Extract token from query string
            if let Some(query) = request.uri().query() {
                let token = query.split('&').find_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    if parts.next() == Some("token") {
                        parts.next()
                    } else {
                        None
                    }
                });

                if let Some(token) = token {
                    if let Some(user_id) = state.validate_token(token).await {
                        if let Err(err) = state.rate_limiter.check(user_id, action).await {
                            if action == ActionType::InviteCreate {
                                // The JSON body of SPEC-01 section 6.2.
                                return crate::admission::AdmissionError::RateLimited {
                                    retry_after: err.retry_after_secs,
                                }
                                .into_rest()
                                .into_response();
                            }
                            return (
                                StatusCode::TOO_MANY_REQUESTS,
                                format!(
                                    "Rate limit exceeded: {}. Retry after {}s",
                                    err.message, err.retry_after_secs
                                ),
                            )
                                .into_response();
                        }
                    }
                }
            }
        }

        next.run(request).await
    }

    /// Outermost middleware: reject transport-banned IPs before any routing or
    /// rate-limit work (cheap DoS/DDoS rejection). Bans key on the real socket
    /// peer address — never on a spoofable forwarded header. Relay-owner only;
    /// the ban set is never correlated to a node.
    ///
    /// The binary always serves with connect information. A router served
    /// without it (some tests) has no peer address, so there is nothing to
    /// match against the ban set.
    pub async fn ip_ban_layer(
        connect_info: Option<ConnectInfo<SocketAddr>>,
        State(state): State<SharedState>,
        request: Request<Body>,
        next: Next,
    ) -> Response {
        if let Some(ConnectInfo(addr)) = connect_info {
            let ip = addr.ip().to_string();
            if state.is_ip_banned(&ip).await {
                return (StatusCode::FORBIDDEN, "IP banned").into_response();
            }
        }
        next.run(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::middleware::is_invite_creation_path;

    /// REQ-27: the invite-creation limit matches only `/nodes/<id>/invites`.
    #[test]
    fn invite_creation_path_shape() {
        assert!(is_invite_creation_path("/nodes/abc/invites"));
        assert!(!is_invite_creation_path("/invites/CODE/join"));
        assert!(!is_invite_creation_path("/nodes/abc/invites/CODE"));
        assert!(!is_invite_creation_path("/nodes//invites"));
        assert!(!is_invite_creation_path("/x/nodes/abc/invites"));
    }
}
