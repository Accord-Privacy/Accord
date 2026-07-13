//! # Accord Relay Server
//!
//! Zero-knowledge relay server that routes encrypted messages
//! without having access to decrypt user content.

// Federation and Bot API modules are scaffolding — allow unused until fully integrated.
#![allow(dead_code)]

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod admin;
mod backup;
mod batch_handlers;
mod bot_api;
#[allow(dead_code)]
mod db;
mod federation;
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
mod relay_mesh;
mod state;
mod validation;
mod webhooks;

use anyhow::Result;
use axum::http::HeaderValue;
use axum::{
    routing::{delete, get, post},
    Router,
};
use clap::Parser;
use handlers::{
    accept_friend_request_handler, ack_sender_keys_handler, add_build_allowlist_handler,
    add_reaction_handler, assign_member_role_handler, auth_handler, ban_check_handler,
    ban_user_handler, block_user_handler, build_info_handler, create_channel_category_handler,
    create_channel_handler, create_dm_channel_handler, create_invite_handler, create_node_handler,
    create_role_handler, delete_channel_category_handler, delete_channel_handler,
    delete_channel_overwrite_handler, delete_custom_emoji_handler, delete_file_handler,
    delete_message_handler, delete_role_handler, deregister_push_token_handler,
    download_file_handler, edit_message_handler, fetch_key_bundle_handler,
    get_blocked_users_handler, get_build_allowlist_handler, get_channel_messages_handler,
    get_channel_threads_handler, get_dm_channels_handler, get_effective_permissions_handler,
    get_emoji_image_handler, get_member_roles_handler, get_message_reactions_handler,
    get_message_thread_handler, get_node_audit_log_handler, get_node_handler,
    get_node_icon_handler, get_node_members_handler, get_node_presence_handler,
    get_node_user_profiles_handler, get_pending_sender_keys_handler, get_pinned_messages_handler,
    get_prekey_messages_handler, get_slow_mode_handler, get_user_avatar_handler,
    get_user_profile_handler, health_handler, import_discord_template_handler,
    invite_preview_handler, join_node_handler, kick_user_handler, leave_node_handler,
    link_preview_handler, list_bans_handler, list_channel_files_handler,
    list_channel_overwrites_handler, list_custom_emojis_handler, list_friend_requests_handler,
    list_friends_handler, list_invites_handler, list_node_channels_handler, list_roles_handler,
    list_user_nodes_handler, mark_channel_read_handler, pin_message_handler,
    publish_key_bundle_handler, purge_channel_before_handler, register_handler,
    register_push_token_handler, reject_friend_request_handler, remove_build_allowlist_handler,
    remove_friend_handler, remove_member_role_handler, remove_reaction_handler,
    reorder_channels_handler, reorder_roles_handler, revoke_invite_handler,
    search_messages_handler, send_friend_request_handler, set_build_allowlist_handler,
    set_channel_overwrite_handler, set_node_user_profile_handler, set_slow_mode_handler,
    store_prekey_message_handler, store_sender_key_handler, unban_user_handler,
    unblock_user_handler, unpin_message_handler, update_channel_category_handler,
    update_channel_handler, update_node_handler, update_push_preferences_handler,
    update_role_handler, update_user_profile_handler, upload_custom_emoji_handler,
    upload_file_handler, upload_node_icon_handler, upload_user_avatar_handler, use_invite_handler,
    ws_handler,
};
use serde::Deserialize;
use state::{AppState, SharedState};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use webhooks::{
    create_webhook_handler, delete_webhook_handler, list_webhooks_handler, test_webhook_handler,
    update_webhook_handler,
};

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
            ("POST", path) if path.contains("/messages") => Some(ActionType::Message),
            ("POST", path) if path.contains("/invites") => Some(ActionType::InviteCreate),
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

mod ip_ban_middleware {
    use crate::state::SharedState;
    use axum::{
        body::Body,
        extract::{ConnectInfo, State},
        http::{Request, StatusCode},
        middleware::Next,
        response::{IntoResponse, Response},
    };
    use std::net::SocketAddr;

    /// Outermost middleware: reject transport-banned IPs before any routing or
    /// rate-limit work (cheap DoS/DDoS rejection). Bans key on the real socket
    /// peer address — never on a spoofable forwarded header. Relay-owner only;
    /// the ban set is never correlated to a node.
    pub async fn ip_ban_layer(
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        State(state): State<SharedState>,
        request: Request<Body>,
        next: Next,
    ) -> Response {
        let ip = addr.ip().to_string();
        if state.is_ip_banned(&ip).await {
            return (StatusCode::FORBIDDEN, "IP banned").into_response();
        }
        next.run(request).await
    }
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Start the Accord relay server (default)
    Serve,
    /// Back up the database to a compressed archive
    Backup {
        /// Path to the database file
        #[arg(short = 'd', long, default_value = "accord.db")]
        database: String,

        /// Output archive path (default: accord-backup-<timestamp>.tar.gz)
        #[arg(short, long)]
        output: Option<String>,

        /// Enable SQLCipher encryption (reads key from <database>.key)
        #[arg(long, default_value_t = true)]
        database_encryption: bool,

        /// Force hot backup via VACUUM INTO (even if DB doesn't appear locked)
        #[arg(long)]
        hot: bool,
    },
    /// Restore the database from a backup archive
    Restore {
        /// Path to the backup archive (.tar.gz)
        archive: String,

        /// Path to restore the database to
        #[arg(short = 'd', long, default_value = "accord.db")]
        database: String,

        /// Enable SQLCipher encryption (reads key from <database>.key)
        #[arg(long, default_value_t = true)]
        database_encryption: bool,

        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Server bind address
    #[arg(short = 'a', long, default_value = "0.0.0.0")]
    host: String,

    /// Server port
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Path to TLS certificate PEM file (enables HTTPS/WSS when paired with --tls-key)
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to TLS private key PEM file (enables HTTPS/WSS when paired with --tls-cert)
    #[arg(long)]
    tls_key: Option<String>,

    /// Disable TLS entirely (plain HTTP, for development or behind a reverse proxy)
    #[arg(long)]
    no_tls: bool,

    /// Auto-generate a self-signed TLS certificate on startup (default when no cert is provided)
    #[arg(long)]
    auto_tls: bool,

    /// Relay admin dashboard port (bound to 127.0.0.1 only — localhost access IS the
    /// relay owner, no login). The dashboard is never exposed on the public interface.
    #[arg(long, default_value_t = 6789)]
    admin_port: u16,

    /// Disable the localhost admin dashboard entirely.
    #[arg(long)]
    no_admin: bool,

    /// Configuration file path
    #[arg(short, long)]
    config: Option<String>,

    /// Allowed CORS origins (comma-separated). Use '*' for any (dev only).
    /// CORS allowed origins (comma-separated, or "*" for any). Defaults to "*" when
    /// binding to 0.0.0.0, or "http://localhost:3000,http://localhost:5173" for localhost.
    #[arg(long)]
    cors_origins: Option<String>,

    /// Database file path
    #[arg(short = 'd', long, default_value = "accord.db")]
    database: String,

    /// Enable SQLCipher encryption at rest for the database (requires 'sqlcipher' feature)
    #[arg(long, default_value_t = true)]
    database_encryption: bool,

    /// Metadata storage mode: 'standard' (store everything) or 'minimal' (strip optional metadata)
    #[arg(long, default_value = "standard")]
    metadata_mode: String,

    /// Path to frontend dist directory to serve (optional)
    #[arg(long)]
    frontend: Option<String>,

    /// Relay-level build hash enforcement: 'off' (allow all), 'warn' (log unverified), 'strict' (reject unverified)
    #[arg(long, default_value = "off")]
    build_hash_enforcement: String,

    /// DEV/LOAD-TESTING ONLY: disable all rate limiting. Never use in production.
    #[arg(long)]
    disable_rate_limits: bool,

    /// Enable relay mesh networking for cross-relay DMs
    #[arg(long)]
    mesh_enabled: bool,

    /// Mesh listen port for peer relay connections
    #[arg(long, default_value_t = 9443)]
    mesh_port: u16,

    /// Mesh bootstrap peers (comma-separated host:port)
    #[arg(long, default_value = "")]
    mesh_peers: String,

    /// Mesh data directory for relay identity and peer state
    #[arg(long, default_value = "mesh_data")]
    mesh_data_dir: String,

    /// Shared secret for relay mesh authentication (all relays must share this)
    #[arg(long)]
    mesh_secret: Option<String>,

    /// Path to TLS certificate PEM file for mesh relay-to-relay connections
    #[arg(long)]
    mesh_tls_cert: Option<String>,

    /// Path to TLS private key PEM file for mesh relay-to-relay connections
    #[arg(long)]
    mesh_tls_key: Option<String>,
}

/// TOML config file schema. All fields optional — CLI flags override.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FileConfig {
    host: Option<String>,
    port: Option<u16>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    no_tls: Option<bool>,
    auto_tls: Option<bool>,
    cors_origins: Option<String>,
    database: Option<String>,
    database_encryption: Option<bool>,
    metadata_mode: Option<String>,
    frontend: Option<String>,
    build_hash_enforcement: Option<String>,
    mesh_enabled: Option<bool>,
    mesh_port: Option<u16>,
    mesh_peers: Option<String>,
    mesh_data_dir: Option<String>,
    mesh_secret: Option<String>,
    mesh_tls_cert: Option<String>,
    mesh_tls_key: Option<String>,
}

impl FileConfig {
    fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", path, e))?;
        toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", path, e))
    }
}

/// Merge: CLI explicit values win over config file values.
/// We detect "was this flag actually passed on CLI?" by checking against clap defaults.
fn merge_args_with_config(args: &mut Args, cfg: FileConfig) {
    // Helper: only apply config value if the CLI arg still has its default
    macro_rules! apply {
        ($field:ident, $default:expr) => {
            if let Some(v) = cfg.$field {
                if args.$field == $default {
                    args.$field = v;
                }
            }
        };
    }
    macro_rules! apply_opt {
        ($field:ident) => {
            if args.$field.is_none() {
                args.$field = cfg.$field;
            }
        };
    }

    apply!(host, "0.0.0.0");
    apply!(port, 8080);
    if args.cors_origins.is_none() {
        args.cors_origins = cfg.cors_origins;
    }
    apply!(database, "accord.db");
    apply!(database_encryption, true);
    apply!(metadata_mode, "standard");
    apply!(build_hash_enforcement, "off");
    apply!(mesh_port, 9443);
    apply!(mesh_peers, "");
    apply!(mesh_data_dir, "mesh_data");

    apply_opt!(tls_cert);
    apply_opt!(tls_key);
    if let Some(true) = cfg.no_tls {
        if !args.no_tls {
            args.no_tls = true;
        }
    }
    if let Some(true) = cfg.auto_tls {
        if !args.auto_tls {
            args.auto_tls = true;
        }
    }
    apply_opt!(frontend);
    apply_opt!(mesh_secret);
    apply_opt!(mesh_tls_cert);
    apply_opt!(mesh_tls_key);

    if let Some(true) = cfg.mesh_enabled {
        if !args.mesh_enabled {
            args.mesh_enabled = true;
        }
    }
}

/// Generate or reuse a self-signed TLS certificate for local/dev use.
/// Stores cert at `data/tls/cert.pem` and key at `data/tls/key.pem`.
/// Returns `(cert_path, key_path)`.
fn ensure_auto_tls_cert() -> Result<(String, String)> {
    let tls_dir = std::path::Path::new("data/tls");
    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    // Reuse existing cert if both files exist
    if cert_path.exists() && key_path.exists() {
        info!(
            "Auto-TLS: reusing existing certificate at {}",
            cert_path.display()
        );
        return Ok((
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
        ));
    }

    std::fs::create_dir_all(tls_dir)?;

    // Gather SANs: localhost, 127.0.0.1, and machine hostname
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut san_names: Vec<String> = vec!["localhost".to_string()];
    if !hostname.is_empty() && hostname != "localhost" {
        san_names.push(hostname.clone());
    }

    let mut params = rcgen::CertificateParams::new(san_names.clone())?;
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(127, 0, 0, 1),
        )));

    // Valid for 365 days
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2030, 1, 1);

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;

    info!(
        "Auto-TLS: generated self-signed certificate at {} (SANs: {:?})",
        cert_path.display(),
        san_names
    );

    Ok((
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider before anything else
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize logging with broadcast writer for admin log streaming
    let log_tx = admin::new_log_broadcast();
    let log_writer = admin::TeeWriter::new(log_tx.clone());
    tracing_subscriber::fmt().with_writer(log_writer).init();

    let mut args = Args::parse();

    // Handle backup/restore subcommands (these don't start the server)
    match &args.command {
        Some(Command::Backup {
            database,
            output,
            database_encryption,
            hot,
        }) => {
            let db_path = std::path::Path::new(database);
            let encryption_key: Option<String> = if *database_encryption {
                #[cfg(feature = "sqlcipher")]
                {
                    let key_path = db::encryption::key_file_path(db_path);
                    if key_path.exists() {
                        Some(db::encryption::read_or_create_key(db_path)?)
                    } else {
                        None
                    }
                }
                #[cfg(not(feature = "sqlcipher"))]
                {
                    None
                }
            } else {
                None
            };
            let output_path = output.as_ref().map(|p| std::path::Path::new(p.as_str()));
            backup::create_backup(db_path, output_path, encryption_key.as_deref(), *hot)?;
            return Ok(());
        }
        Some(Command::Restore {
            archive,
            database,
            database_encryption,
            yes,
        }) => {
            let archive_path = std::path::Path::new(archive);
            let db_path = std::path::Path::new(database);
            let encryption_key: Option<String> = if *database_encryption {
                #[cfg(feature = "sqlcipher")]
                {
                    let key_path = db::encryption::key_file_path(db_path);
                    if key_path.exists() {
                        Some(db::encryption::read_or_create_key(db_path)?)
                    } else {
                        None
                    }
                }
                #[cfg(not(feature = "sqlcipher"))]
                {
                    None
                }
            } else {
                None
            };
            backup::restore_backup(archive_path, db_path, encryption_key.as_deref(), *yes)?;
            return Ok(());
        }
        Some(Command::Serve) | None => {
            // Continue to server startup below
        }
    }

    // Load config file if specified
    if let Some(ref config_path) = args.config.clone() {
        let cfg = FileConfig::load(config_path)?;
        info!("Loaded config from: {}", config_path);
        merge_args_with_config(&mut args, cfg);
    }

    info!("Starting Accord Relay Server");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Bind address: {}:{}", args.host, args.port);

    // Resolve TLS mode: --no-tls > --tls-cert/--tls-key > --auto-tls > default (auto-tls)
    if !args.no_tls && args.tls_cert.is_none() && args.tls_key.is_none() {
        // Default behaviour: auto-generate self-signed cert
        let (cert, key) = ensure_auto_tls_cert()?;
        args.tls_cert = Some(cert);
        args.tls_key = Some(key);
        info!("TLS mode: auto-generated self-signed certificate (HTTPS/WSS)");
    } else if args.no_tls {
        // Explicitly strip any cert paths when --no-tls is passed
        args.tls_cert = None;
        args.tls_key = None;
        warn!("TLS mode: disabled (--no-tls) — plain HTTP/WS only. Use for development or behind a reverse proxy.");
    } else if args.tls_cert.is_some() && args.tls_key.is_some() {
        info!("TLS mode: using provided certificate (HTTPS/WSS)");
    }

    // Parse metadata mode
    let metadata_mode: state::MetadataMode = args
        .metadata_mode
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    info!("Metadata mode: {}", metadata_mode);

    // Initialize shared state with database
    info!("Initializing database: {}", args.database);
    let mut app_state =
        AppState::new_with_encryption(&args.database, args.database_encryption).await?;
    app_state.metadata_mode = metadata_mode;
    app_state.federation_enabled = args.mesh_enabled;
    if args.disable_rate_limits {
        // This flag also disables the per-device account cap and registration
        // throttling. Gate it behind --no-tls so it cannot be enabled on a
        // TLS-terminated (i.e. production-shaped) deployment by accident.
        if !args.no_tls {
            anyhow::bail!(
                "--disable-rate-limits requires --no-tls (dev/load-testing only). \
                 Refusing to disable abuse protection on a TLS deployment."
            );
        }
        warn!("╔══════════════════════════════════════════════════════════════╗");
        warn!("║ RATE LIMITING + DEVICE CAP DISABLED (--disable-rate-limits).    ║");
        warn!("║ Dev/load-testing ONLY. NEVER run this in production.           ║");
        warn!("╚══════════════════════════════════════════════════════════════╝");
        app_state.rate_limiter = rate_limit::RateLimiter::new_disabled();
    }

    // Parse build hash enforcement mode
    let build_hash_enforcement: state::BuildHashEnforcementMode = args
        .build_hash_enforcement
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    app_state.build_hash_enforcement = build_hash_enforcement;
    if build_hash_enforcement != state::BuildHashEnforcementMode::Off {
        info!("Relay build hash enforcement: {}", build_hash_enforcement);
    }

    // NOTE: No "Management Node" / "first user becomes server admin" bootstrap.
    // The relay has no in-band owner account — relay ownership IS localhost access
    // to the admin dashboard (bound to 127.0.0.1). See GOVERNANCE.md and admin.rs.

    // Load the IP ban cache (DoS/DDoS defense) before serving.
    app_state.load_ip_bans().await;

    // Migrate any pre-existing nodes to the custom-role model: seed the
    // owner-editable Admin/Moderator roles and assign them to members that carry
    // the legacy node_members.role marker. Idempotent — safe on every boot.
    if let Err(e) = app_state.db.migrate_legacy_roles().await {
        warn!("Legacy role migration failed (continuing): {}", e);
    }

    let state: SharedState = Arc::new(app_state);

    // Start mesh service if enabled
    if args.mesh_enabled {
        let mesh_peers: Vec<String> = args
            .mesh_peers
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mesh_config = relay_mesh::config::MeshConfig {
            enabled: true,
            listen_port: args.mesh_port,
            known_peers: mesh_peers,
            max_peers: 50,
            mesh_secret: args.mesh_secret.clone(),
            mesh_tls_cert: args.mesh_tls_cert.clone(),
            mesh_tls_key: args.mesh_tls_key.clone(),
            mesh_rate_limit: 30,
        };

        let data_dir = std::path::Path::new(&args.mesh_data_dir);
        match relay_mesh::MeshNode::init(data_dir, mesh_config) {
            Ok(node) => {
                info!("Mesh: relay_id={}", node.relay_id());
                match relay_mesh::service::MeshService::start(node, state.clone()).await {
                    Ok(handle) => {
                        *state.mesh_handle.write().await = Some(handle);
                        info!("Mesh service started on port {}", args.mesh_port);
                    }
                    Err(e) => {
                        warn!("Failed to start mesh service: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to init mesh node: {}", e);
            }
        }
    }

    // Restore auth tokens from database so sessions survive restarts
    let restored = state.load_persisted_tokens().await;
    if restored > 0 {
        info!("Restored {} auth tokens from database", restored);
    }

    let log_tx_arc = Arc::new(log_tx);

    // ── Relay admin dashboard ──
    // Bound to 127.0.0.1 ONLY and served on a separate listener (see below), so
    // "whoever has localhost access is the relay owner" — no token, no login, and
    // never reachable from the public interface. The relay owner's surface is
    // deliberately narrow: aggregate stats, a node registry (name/description +
    // create/delete), the relay log stream, and the build-hash allowlist. It must
    // never expose node membership, a user list, per-node governance, or any end
    // user's IP beyond the node-correlation-free connection log.
    let admin_app = Router::new()
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
        .with_state(state.clone())
        .merge(
            Router::new()
                .route("/admin/logs", get(admin::admin_logs_ws_handler))
                .with_state(log_tx_arc.clone()),
        );

    // Build the public router (admin routes are NOT mounted here).
    let app = Router::new()
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
        // ── Role endpoints ──
        .route(
            "/nodes/:id/roles",
            get(list_roles_handler).post(create_role_handler),
        )
        .route(
            "/nodes/:id/roles/reorder",
            axum::routing::patch(reorder_roles_handler),
        )
        .route(
            "/nodes/:id/roles/:role_id",
            axum::routing::patch(update_role_handler).delete(delete_role_handler),
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
            axum::routing::put(assign_member_role_handler).delete(remove_member_role_handler),
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
        .route(
            "/nodes/:id/channels/reorder",
            axum::routing::put(reorder_channels_handler),
        )
        .route(
            "/channels/:id",
            axum::routing::patch(update_channel_handler),
        )
        .route(
            "/channels/:id/slow-mode",
            axum::routing::put(set_slow_mode_handler).get(get_slow_mode_handler),
        )
        .route("/channels/:id", delete(delete_channel_handler))
        .route("/channels/:id/messages", get(get_channel_messages_handler))
        .route("/channels/:id/read", post(mark_channel_read_handler))
        // ── Message editing and deletion ──
        .route("/messages/:id", axum::routing::patch(edit_message_handler))
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
        // ── Channel permission overwrite endpoints ──
        .route(
            "/channels/:id/permissions",
            get(list_channel_overwrites_handler),
        )
        .route(
            "/channels/:id/permissions/:role_id",
            axum::routing::put(set_channel_overwrite_handler)
                .delete(delete_channel_overwrite_handler),
        )
        .route(
            "/channels/:id/effective-permissions",
            get(get_effective_permissions_handler),
        )
        // File sharing endpoints
        .route("/channels/:id/files", post(upload_file_handler))
        .route("/channels/:id/files", get(list_channel_files_handler))
        .route("/files/:id", get(download_file_handler))
        .route("/files/:id", delete(delete_file_handler))
        // Search endpoints
        .route("/nodes/:id/search", get(search_messages_handler))
        // Link preview endpoint
        .route("/api/link-preview", get(link_preview_handler))
        // User profile endpoints
        .route("/users/:id/profile", get(get_user_profile_handler))
        .route(
            "/users/me/profile",
            axum::routing::patch(update_user_profile_handler),
        )
        // Icon / Avatar endpoints
        .route(
            "/nodes/:id/icon",
            axum::routing::put(upload_node_icon_handler).get(get_node_icon_handler),
        )
        .route(
            "/users/me/avatar",
            axum::routing::put(upload_user_avatar_handler),
        )
        .route("/users/:id/avatar", get(get_user_avatar_handler))
        .route("/nodes/:id/members", get(get_node_members_handler))
        // Audit log endpoints
        .route("/nodes/:id/audit-log", get(get_node_audit_log_handler))
        // Node invite endpoints
        .route("/nodes/:id/invites", post(create_invite_handler))
        .route("/nodes/:id/invites", get(list_invites_handler))
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
            axum::routing::patch(update_webhook_handler).delete(delete_webhook_handler),
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
        .route(
            "/push/preferences",
            axum::routing::put(update_push_preferences_handler),
        )
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
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                     img-src 'self' data: blob:; connect-src 'self' http: https: wss: ws:; frame-ancestors 'none'",
                ),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                axum::http::HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("camera=(self), microphone=(self), geolocation=()"),
            ))
            // ── CORS ──
            .layer({
                let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any);
                let effective_cors = args.cors_origins.clone().unwrap_or_else(|| {
                    if args.no_tls {
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
            }),
    )
    // IP ban check — outermost so banned IPs are dropped before any other work.
    .layer(axum::middleware::from_fn_with_state(
        state.clone(),
        ip_ban_middleware::ip_ban_layer,
    ));

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

    // Spawn periodic disappearing-messages sweep. Deletes rows whose
    // sender-supplied expiry has passed — timestamp-only, the relay never reads
    // content. Belt-and-suspenders with the on-read filter in get_channel_messages.
    {
        let sweep_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                // Start the fresh timer on any read-gated message whose audience
                // has now seen it, then sweep everything whose expiry has passed.
                match sweep_state.db.resolve_read_gates(now).await {
                    Ok(n) if n > 0 => info!("Started expiry timer on {} read-gated messages", n),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("Read-gate sweep error: {}", e),
                }
                match sweep_state.db.delete_expired_messages(now).await {
                    Ok(n) if n > 0 => info!("Swept {} expired (disappearing) messages", n),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("Disappearing-messages sweep error: {}", e),
                }
            }
        });
    }

    // Spawn periodic stale-state cleanup task (memory leak prevention)
    {
        let stale_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // every 5 min
            loop {
                interval.tick().await;
                stale_state.cleanup_stale_state().await;
            }
        });
    }

    // Federation relay health-check background task (every 5 min)
    federation::spawn_federation_maintenance(state.clone());

    // Idle detection background task (check every 60 seconds)
    {
        let idle_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(err) = idle_state.check_idle_users().await {
                    tracing::warn!("Idle check error: {}", err);
                }
            }
        });
    }

    // Create and start the server with graceful shutdown
    let addr = format!("{}:{}", args.host, args.port);

    // Create a shutdown signal that listens for SIGTERM and SIGINT
    let shutdown_state = state.clone();
    let shutdown_signal = async move {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => info!("Received SIGINT (Ctrl+C), initiating graceful shutdown..."),
            _ = terminate => info!("Received SIGTERM, initiating graceful shutdown..."),
        }

        // Graceful shutdown sequence
        info!("Shutdown: stopping new connections...");

        // Send close frames to all connected WebSocket clients
        info!("Shutdown: notifying WebSocket clients...");
        {
            let connections = shutdown_state.connections.read().await;
            let close_msg = serde_json::json!({
                "type": "server_shutdown",
                "message": "Server is shutting down"
            })
            .to_string();
            let mut total = 0usize;
            for (user_id, devices) in connections.iter() {
                for sender in devices.values() {
                    let _ = sender.send(close_msg.clone());
                    total += 1;
                }
                tracing::debug!("Sent shutdown notice to user {}", user_id);
            }
            info!("Shutdown: notified {} WebSocket clients", total);
        }

        // Wait briefly for in-flight requests to complete (up to 10s)
        info!("Shutdown: waiting up to 10s for in-flight requests...");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        info!("Shutdown: complete.");
    };

    // Spawn the admin dashboard on a localhost-only listener. Plain HTTP is fine:
    // it never leaves 127.0.0.1, and localhost access is the ownership boundary.
    if !args.no_admin {
        let admin_addr = format!("127.0.0.1:{}", args.admin_port);
        match tokio::net::TcpListener::bind(&admin_addr).await {
            Ok(admin_listener) => {
                info!(
                    "Relay admin dashboard on http://{} (localhost only — no login)",
                    admin_addr
                );
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(admin_listener, admin_app).await {
                        error!("Admin dashboard listener error: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!(
                    "Could not bind admin dashboard on {} ({}). Continuing without it.",
                    admin_addr, e
                );
            }
        }
    }

    match (args.tls_cert, args.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            // TLS mode
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to load TLS cert/key ({}, {}): {}",
                            cert_path,
                            key_path,
                            e
                        )
                    })?;

            info!("Server starting with TLS (HTTPS/WSS) on {}", addr);
            let handle = axum_server::Handle::new();
            let handle_clone = handle.clone();

            // Spawn shutdown listener that triggers the axum_server handle
            tokio::spawn(async move {
                shutdown_signal.await;
                handle_clone.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });

            axum_server::bind_rustls(addr.parse()?, tls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        (None, None) => {
            // Plain HTTP mode
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            info!("Server starting in plain HTTP/WS mode on {}", addr);
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal)
            .await?;
        }
        _ => {
            anyhow::bail!("Both --tls-cert and --tls-key must be provided together for TLS mode");
        }
    }

    info!("Server shut down cleanly.");
    Ok(())
}
