//! # Accord Relay Server
//!
//! Zero-knowledge relay server that routes encrypted messages
//! without having access to decrypt user content.

// Federation and Bot API modules are scaffolding — allow unused until fully integrated.
#![allow(dead_code)]

mod bot_api;
#[allow(dead_code)]
mod db;
#[allow(dead_code)]
mod files;
mod handlers;
mod metadata;
#[allow(dead_code)]
mod models;
mod node;
mod permissions;
pub mod push;
#[allow(dead_code)]
mod rate_limit;
mod state;

use anyhow::Result;
use axum::{
    routing::{delete, get, post},
    Router,
};
use clap::Parser;
use handlers::{
    accept_friend_request_handler, add_reaction_handler, admin_page_handler, admin_stats_handler,
    auth_handler, ban_check_handler, ban_user_handler, build_info_handler,
    create_channel_category_handler, create_channel_handler, create_dm_channel_handler,
    create_invite_handler, create_node_handler, delete_channel_category_handler,
    delete_channel_handler, delete_file_handler, delete_message_handler,
    deregister_push_token_handler, download_file_handler, edit_message_handler,
    fetch_key_bundle_handler, get_channel_messages_handler, get_dm_channels_handler,
    get_message_reactions_handler, get_message_thread_handler, get_node_audit_log_handler,
    get_node_handler, get_node_members_handler, get_node_user_profiles_handler,
    get_pinned_messages_handler, get_prekey_messages_handler, get_user_profile_handler,
    health_handler, join_node_handler, kick_user_handler, leave_node_handler, list_bans_handler,
    list_channel_files_handler, list_friend_requests_handler, list_friends_handler,
    list_invites_handler, list_node_channels_handler, list_user_nodes_handler, pin_message_handler,
    publish_key_bundle_handler, register_handler, register_push_token_handler,
    reject_friend_request_handler, remove_friend_handler, remove_reaction_handler,
    revoke_invite_handler, search_messages_handler, send_friend_request_handler,
    set_node_user_profile_handler, store_prekey_message_handler, unban_user_handler,
    unpin_message_handler, update_channel_category_handler, update_channel_handler,
    update_node_handler, update_push_preferences_handler, update_user_profile_handler,
    upload_file_handler, use_invite_handler, ws_handler,
};
use state::{AppState, SharedState};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{info, warn};

mod rate_limit_middleware {
    use crate::rate_limit::ActionType;
    use crate::state::SharedState;
    use axum::{
        body::Body,
        extract::State,
        http::{Request, StatusCode},
        middleware::Next,
        response::{IntoResponse, Response},
    };

    /// Axum middleware that applies rate limiting based on the authenticated user.
    /// Extracts the token from query params, resolves the user, and checks the rate limiter.
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
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server bind address
    #[arg(short = 'a', long, default_value = "0.0.0.0")]
    host: String,

    /// Server port
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// Configuration file path
    #[arg(short, long)]
    config: Option<String>,

    /// Allowed CORS origins (comma-separated). Use '*' for any (dev only).
    #[arg(long, default_value = "http://localhost:3000,http://localhost:5173")]
    cors_origins: String,

    /// Database file path
    #[arg(short = 'd', long, default_value = "accord.db")]
    database: String,

    /// Metadata storage mode: 'standard' (store everything) or 'minimal' (strip optional metadata)
    #[arg(long, default_value = "standard")]
    metadata_mode: String,

    /// Path to frontend dist directory to serve (optional)
    #[arg(long)]
    frontend: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    info!("Starting Accord Relay Server");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Bind address: {}:{}", args.host, args.port);

    if args.tls {
        info!("TLS enabled");
    } else {
        warn!("Running without TLS - only use for development!");
    }

    // Parse metadata mode
    let metadata_mode: state::MetadataMode = args
        .metadata_mode
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    info!("Metadata mode: {}", metadata_mode);

    // Initialize shared state with database
    info!("Initializing database: {}", args.database);
    let mut app_state = AppState::new(&args.database).await?;
    app_state.metadata_mode = metadata_mode;
    let state: SharedState = Arc::new(app_state);

    // Restore auth tokens from database so sessions survive restarts
    let restored = state.load_persisted_tokens().await;
    if restored > 0 {
        info!("Restored {} auth tokens from database", restored);
    }

    // Build the router with all endpoints
    let app = Router::new()
        // REST endpoints
        .route("/admin", get(admin_page_handler))
        .route("/admin/stats", get(admin_stats_handler))
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
        .route("/nodes/:id", axum::routing::patch(update_node_handler))
        .route(
            "/nodes/:id/channels",
            get(list_node_channels_handler).post(create_channel_handler),
        )
        .route("/nodes/:id/join", post(join_node_handler))
        .route("/nodes/:id/leave", post(leave_node_handler))
        .route("/nodes/:id/members/:user_id", delete(kick_user_handler))
        // Ban endpoints
        .route("/nodes/:id/bans", post(ban_user_handler))
        .route("/nodes/:id/bans", delete(unban_user_handler))
        .route("/nodes/:id/bans", get(list_bans_handler))
        .route("/nodes/:id/ban-check", get(ban_check_handler))
        // Node user profile endpoints
        .route(
            "/nodes/:id/profile",
            axum::routing::put(set_node_user_profile_handler),
        )
        .route("/nodes/:id/profiles", get(get_node_user_profiles_handler))
        // Channel category endpoints
        .route(
            "/nodes/:id/categories",
            post(create_channel_category_handler),
        )
        .route(
            "/categories/:id",
            axum::routing::patch(update_channel_category_handler),
        )
        .route("/categories/:id", delete(delete_channel_category_handler))
        // Channel endpoints
        .route(
            "/channels/:id",
            axum::routing::patch(update_channel_handler),
        )
        .route("/channels/:id", delete(delete_channel_handler))
        .route("/channels/:id/messages", get(get_channel_messages_handler))
        // ── Message editing and deletion ──
        .route("/messages/:id", axum::routing::patch(edit_message_handler))
        .route("/messages/:id", delete(delete_message_handler))
        // ── Message threading ──
        .route("/messages/:id/thread", get(get_message_thread_handler))
        // ── Message reactions ──
        .route(
            "/messages/:id/reactions",
            get(get_message_reactions_handler),
        )
        .route(
            "/messages/:id/reactions/:emoji",
            axum::routing::put(add_reaction_handler),
        )
        .route(
            "/messages/:id/reactions/:emoji",
            delete(remove_reaction_handler),
        )
        // ── Message pinning ──
        .route("/messages/:id/pin", axum::routing::put(pin_message_handler))
        .route("/messages/:id/pin", delete(unpin_message_handler))
        .route("/channels/:id/pins", get(get_pinned_messages_handler))
        // File sharing endpoints
        .route("/channels/:id/files", post(upload_file_handler))
        .route("/channels/:id/files", get(list_channel_files_handler))
        .route("/files/:id", get(download_file_handler))
        .route("/files/:id", delete(delete_file_handler))
        // Search endpoints
        .route("/nodes/:id/search", get(search_messages_handler))
        // User profile endpoints
        .route("/users/:id/profile", get(get_user_profile_handler))
        .route(
            "/users/me/profile",
            axum::routing::patch(update_user_profile_handler),
        )
        .route("/nodes/:id/members", get(get_node_members_handler))
        // Audit log endpoints
        .route("/nodes/:id/audit-log", get(get_node_audit_log_handler))
        // Node invite endpoints
        .route("/nodes/:id/invites", post(create_invite_handler))
        .route("/nodes/:id/invites", get(list_invites_handler))
        .route("/invites/:invite_id", delete(revoke_invite_handler))
        .route("/invites/:code/join", post(use_invite_handler))
        // Key bundle endpoints (Double Ratchet / X3DH)
        .route("/keys/bundle", post(publish_key_bundle_handler))
        .route("/keys/bundle/:user_id", get(fetch_key_bundle_handler))
        .route("/keys/prekey-message", post(store_prekey_message_handler))
        .route("/keys/prekey-messages", get(get_prekey_messages_handler))
        // Push notification endpoints
        .route("/push/register", post(register_push_token_handler))
        .route("/push/register", delete(deregister_push_token_handler))
        .route(
            "/push/preferences",
            axum::routing::put(update_push_preferences_handler),
        )
        // Bot API endpoints
        .route("/bots", post(bot_api::register_bot_handler))
        .route("/bots/:id", get(bot_api::get_bot_handler))
        .route(
            "/bots/:id",
            axum::routing::patch(bot_api::update_bot_handler),
        )
        .route("/bots/:id", delete(bot_api::delete_bot_handler))
        .route(
            "/bots/:id/regenerate-token",
            post(bot_api::regenerate_bot_token_handler),
        )
        .route("/bots/invite", post(bot_api::invite_bot_to_channel_handler))
        .route(
            "/bots/:bot_id/channels/:channel_id",
            delete(bot_api::remove_bot_from_channel_handler),
        )
        .route(
            "/bot/channels/:channel_id/messages",
            post(bot_api::bot_send_message_handler),
        )
        .route(
            "/channels/:id/bots",
            get(bot_api::list_channel_bots_handler),
        )
        // Friend system endpoints
        .route("/friends/request", post(send_friend_request_handler))
        .route("/friends/accept", post(accept_friend_request_handler))
        .route("/friends/reject", post(reject_friend_request_handler))
        .route("/friends", get(list_friends_handler))
        .route("/friends/requests", get(list_friend_requests_handler))
        .route("/friends/:user_id", delete(remove_friend_handler))
        // Direct Message endpoints
        .route("/dm/:user_id", post(create_dm_channel_handler))
        .route("/dm", get(get_dm_channels_handler))
        // WebSocket endpoint
        .route("/ws", get(ws_handler))
        // Add shared state
        .with_state(state.clone());

    // Optionally serve frontend static files
    let app = if let Some(ref frontend_path) = args.frontend {
        let index_path = format!("{}/index.html", frontend_path);
        info!("Serving frontend from: {}", frontend_path);
        app.fallback_service(
            ServeDir::new(frontend_path).not_found_service(ServeFile::new(index_path)),
        )
    } else {
        app
    }
    // Add middleware
    .layer(axum::middleware::from_fn_with_state(
        state.clone(),
        rate_limit_middleware::rate_limit_layer,
    ))
    .layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer({
                let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any);
                if args.cors_origins.trim() == "*" {
                    warn!("CORS: allowing ANY origin — only use in development!");
                    cors.allow_origin(Any)
                } else {
                    let origins: Vec<_> = args
                        .cors_origins
                        .split(',')
                        .filter_map(|o| o.trim().parse().ok())
                        .collect();
                    info!("CORS: allowed origins: {:?}", origins);
                    cors.allow_origin(AllowOrigin::list(origins))
                }
            }),
    );

    println!("🚀 Accord Relay Server starting...");
    println!("📡 Listening on {}:{}", args.host, args.port);
    println!("🔒 Zero-knowledge design: Server cannot decrypt user content");
    println!("⚡ Ready to route encrypted messages");
    println!();
    println!("Endpoints:");
    println!("  GET    /health            - Health check");
    println!("  POST   /register          - User registration");
    println!("  POST   /auth              - User authentication");
    println!("  POST   /nodes             - Create a Node (?token=)");
    println!("  GET    /nodes/:id         - Get Node info");
    println!("  PATCH  /nodes/:id         - Update Node settings (?token=) [Admin]");
    println!("  POST   /nodes/:id/join    - Join a Node (?token=)");
    println!("  POST   /nodes/:id/leave   - Leave a Node (?token=)");
    println!("  DELETE /nodes/:id/members/:user_id - Kick user (?token=) [Admin/Mod]");
    println!("  DELETE /channels/:id      - Delete channel (?token=) [Admin]");
    println!("  GET    /channels/:id/messages - Get channel message history (?token=&limit=50&before=msg_id)");
    println!("  GET    /messages/:id/reactions - Get message reactions (?token=)");
    println!("  PUT    /messages/:id/reactions/:emoji - Add reaction (?token=)");
    println!("  DELETE /messages/:id/reactions/:emoji - Remove reaction (?token=)");
    println!(
        "  GET    /nodes/:id/search  - Search messages in Node (?token=&q=query&channel=ch_id)"
    );
    println!("  GET    /users/:id/profile - Get user profile (?token=)");
    println!("  PATCH  /users/me/profile  - Update own profile (?token=)");
    println!("  GET    /nodes/:id/members - Get Node members with profiles (?token=)");
    println!("  POST   /nodes/:id/invites - Create Node invite (?token=) [Admin/Mod]");
    println!("  GET    /nodes/:id/invites - List Node invites (?token=) [Admin/Mod]");
    println!("  DELETE /invites/:id       - Revoke invite (?token=) [Admin/Mod]");
    println!("  POST   /invites/:code/join - Join Node via invite (?token=)");
    println!("  POST   /dm/:user_id       - Create/get DM channel (?token=)");
    println!("  GET    /dm                - List user's DM channels (?token=)");
    println!("  WS     /ws                - WebSocket messaging (?token=)");
    println!();

    // Spawn periodic token cleanup task (H3)
    {
        let cleanup_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // every 5 min
            loop {
                interval.tick().await;
                let removed = cleanup_state.cleanup_expired_tokens().await;
                if removed > 0 {
                    info!("Cleaned up {} expired auth tokens", removed);
                }
            }
        });
    }

    // Create the server
    let listener = tokio::net::TcpListener::bind(&format!("{}:{}", args.host, args.port)).await?;

    info!("Server successfully bound to {}:{}", args.host, args.port);

    // Start the server
    axum::serve(listener, app).await?;

    info!("Shutting down server...");
    Ok(())
}
