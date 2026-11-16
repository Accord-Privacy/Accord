//! # Accord Relay Server
//!
//! Zero-knowledge relay server that routes encrypted messages
//! without having access to decrypt user content.

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// The binary uses the library crate, so the relay and its tests share one
// module tree, one `SharedState` type and one route table (SPEC-01 §10.1).
use accord_server::{
    admin,
    attachments::{self, AttachmentConfig},
    backup, db, federation, rate_limit, relay_mesh,
    router::{self, RouterConfig},
    screen::{ScreenConfig, ScreenRelay},
    socket_opts,
    state::{self, AppState, AppStateOptions, SharedState},
};
use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, warn};

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
    /// Retire legacy (pre-version-2) attachments now: delete every legacy
    /// file and its blob, and answer every legacy file route with 410 from
    /// then on (SPEC-02 section 7.7). Uses the relay's --database, --config
    /// and attachment options, given before the subcommand. A relay running
    /// on the same database answers 410 on its next legacy request, and its
    /// next storage reconciliation deletes anything left behind.
    PurgeLegacyAttachments,
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

    /// Grace period, in hours, after which invites created before the
    /// admission upgrade without an expiry stop working (applied once, at the
    /// first boot of this version). 0 makes them expire at once.
    #[arg(long, default_value_t = 168)]
    legacy_invite_grace_hours: u64,

    /// Keep invites created before the admission upgrade without an expiry
    /// permanent. The choice is recorded at the first boot and is final.
    #[arg(long)]
    keep_legacy_permanent_invites: bool,

    /// Unauthenticated invite previews allowed per 60 s per client network
    /// (IPv4 address or IPv6 /64 of the socket peer). 0 disables the limit.
    /// Loopback peers (a reverse proxy on the same host) are never limited.
    #[arg(long, default_value_t = accord_server::rate_limit::DEFAULT_PREVIEW_LIMIT)]
    preview_rate_limit: usize,

    /// Encrypted screen sharing over the relay (SPEC-03 §6.12): 'on'
    /// advertises `screen/1`; 'off' removes it and answers screen-sharing
    /// requests with `disabled`.
    #[arg(long, default_value = "on", value_parser = ["on", "off"])]
    screen_share: String,

    /// Screen shares allowed at once in one voice channel (1 to 8).
    #[arg(
        long,
        default_value_t = accord_server::screen::DEFAULT_MAX_SHARERS,
        value_parser = clap::value_parser!(u8).range(1..=8)
    )]
    screen_max_sharers: u8,

    /// Bytes per second per screen share (at least 200000). The burst is
    /// 3 × this rate and at least 1,100,000 bytes. Clients size their video
    /// bitrate from it.
    #[arg(
        long,
        default_value_t = accord_server::screen::DEFAULT_MAX_BYTES_PER_SECOND,
        value_parser = clap::value_parser!(u64).range(200_000..)
    )]
    screen_max_rate: u64,

    /// Directory of version-2 attachment blobs (SPEC-02). The relay refuses
    /// to start if it is the database's directory or an ancestor of it,
    /// overlaps the legacy file directory, or is a non-empty directory
    /// without the marker file it writes.
    #[arg(long, default_value = "./data/attachments")]
    attachments_dir: String,

    /// Largest accepted attachment blob, in bytes.
    #[arg(long, default_value_t = 104_857_600)]
    attachment_max_blob_bytes: u64,

    /// Lifetime of an uploaded attachment that no message has claimed, in
    /// seconds (300 to 86400).
    #[arg(long, default_value_t = 3600)]
    attachment_pending_ttl_secs: u64,

    /// Pending and uploading attachments allowed per user.
    #[arg(long, default_value_t = 32)]
    attachment_max_pending_per_user: u64,

    /// Attachment bytes per uploader (uploading, pending and claimed); 0 means
    /// unlimited.
    #[arg(long, default_value_t = 1_073_741_824)]
    attachment_quota_user_bytes: u64,

    /// Attachment bytes per node, DM channels excluded; 0 means unlimited.
    #[arg(long, default_value_t = 10_737_418_240)]
    attachment_quota_node_bytes: u64,

    /// Refuse attachment uploads when less than this many bytes would stay
    /// free.
    #[arg(long, default_value_t = 1_073_741_824)]
    attachments_min_free_bytes: u64,

    /// Attachment garbage-collection interval in seconds (1 to 3600).
    #[arg(long, default_value_t = 60)]
    attachment_gc_interval_secs: u64,

    /// Attachment storage reconciliation interval in seconds (60 to 86400).
    #[arg(long, default_value_t = 3600)]
    attachment_reconcile_interval_secs: u64,

    /// Legacy attachments (uploads before version 2): 'read-only' or 'retired'.
    #[arg(long, default_value = "read-only")]
    legacy_attachments: String,

    /// Days after the first start of this version after which legacy
    /// attachments are retired.
    #[arg(long, default_value_t = 90)]
    legacy_attachments_retire_after_days: u64,

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
    attachments_dir: Option<String>,
    attachment_max_blob_bytes: Option<u64>,
    attachment_pending_ttl_secs: Option<u64>,
    attachment_max_pending_per_user: Option<u64>,
    attachment_quota_user_bytes: Option<u64>,
    attachment_quota_node_bytes: Option<u64>,
    attachments_min_free_bytes: Option<u64>,
    attachment_gc_interval_secs: Option<u64>,
    attachment_reconcile_interval_secs: Option<u64>,
    legacy_attachments: Option<String>,
    legacy_attachments_retire_after_days: Option<u64>,
    screen_share: Option<String>,
    screen_max_sharers: Option<u8>,
    screen_max_rate: Option<u64>,
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
    apply!(attachments_dir, "./data/attachments");
    apply!(attachment_max_blob_bytes, 104_857_600);
    apply!(attachment_pending_ttl_secs, 3600);
    apply!(attachment_max_pending_per_user, 32);
    apply!(attachment_quota_user_bytes, 1_073_741_824);
    apply!(attachment_quota_node_bytes, 10_737_418_240);
    apply!(attachments_min_free_bytes, 1_073_741_824);
    apply!(attachment_gc_interval_secs, 60);
    apply!(attachment_reconcile_interval_secs, 3600);
    apply!(legacy_attachments, "read-only");
    apply!(legacy_attachments_retire_after_days, 90);
    apply!(screen_share, "on");
    apply!(
        screen_max_sharers,
        accord_server::screen::DEFAULT_MAX_SHARERS
    );
    apply!(
        screen_max_rate,
        accord_server::screen::DEFAULT_MAX_BYTES_PER_SECOND
    );
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

/// The version-2 attachment settings (SPEC-02 section 6.6.4). Errors name
/// the setting.
fn attachment_config(args: &Args) -> Result<AttachmentConfig> {
    let config = AttachmentConfig {
        dir: std::path::PathBuf::from(&args.attachments_dir),
        max_blob_bytes: args.attachment_max_blob_bytes,
        pending_ttl_secs: args.attachment_pending_ttl_secs,
        max_pending_per_user: args.attachment_max_pending_per_user,
        quota_user_bytes: args.attachment_quota_user_bytes,
        quota_node_bytes: args.attachment_quota_node_bytes,
        min_free_bytes: args.attachments_min_free_bytes,
        gc_interval_secs: args.attachment_gc_interval_secs,
        reconcile_interval_secs: args.attachment_reconcile_interval_secs,
        legacy_mode: args
            .legacy_attachments
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?,
        legacy_retire_after_days: args.legacy_attachments_retire_after_days,
        ..AttachmentConfig::default()
    };
    config.validate()?;
    Ok(config)
}

/// The screen-sharing settings (SPEC-03 §6.12.5). The command line is
/// checked by clap; values from a configuration file are checked here.
/// Errors name the setting.
fn screen_config(args: &Args) -> Result<ScreenConfig> {
    let enabled = match args.screen_share.as_str() {
        "on" => true,
        "off" => false,
        other => anyhow::bail!("--screen-share must be 'on' or 'off', got '{other}'"),
    };
    ScreenConfig::new(enabled, args.screen_max_sharers, args.screen_max_rate)
        .map_err(|e| anyhow::anyhow!(e))
}

/// `accord-server purge-legacy-attachments` (SPEC-02 section 7.7): open the
/// relay's database and storage as the server does, retire every legacy file
/// now, and record the `spec02_legacy_retired` ledger row.
async fn purge_legacy_attachments(args: &Args) -> Result<()> {
    let attachment_settings = attachment_config(args)?;
    let state = AppState::new_with_options(
        &args.database,
        AppStateOptions {
            database_encryption: args.database_encryption,
            db: db::DbOptions {
                legacy_invite_grace_secs: args.legacy_invite_grace_hours.saturating_mul(3600),
                keep_legacy_permanent_invites: args.keep_legacy_permanent_invites,
                ..db::DbOptions::default()
            },
            file_config: Some(accord_server::files::FileConfig::default()),
            attachments: Some(attachment_settings),
        },
    )
    .await?;
    let report = state
        .attachments
        .retire_legacy_now(&state.db, &state.file_handler)
        .await?;
    info!(
        "Legacy attachments retired: {} files and {} blobs deleted, {} blobs left for the reconciliation",
        report.rows, report.blobs, report.blob_failures
    );
    Ok(())
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
        Some(Command::Serve) | Some(Command::PurgeLegacyAttachments) | None => {
            // Continue to server startup below
        }
    }

    // Load config file if specified
    if let Some(ref config_path) = args.config.clone() {
        let cfg = FileConfig::load(config_path)?;
        info!("Loaded config from: {}", config_path);
        merge_args_with_config(&mut args, cfg);
    }

    if matches!(args.command, Some(Command::PurgeLegacyAttachments)) {
        return purge_legacy_attachments(&args).await;
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
    // Opening the database runs the admission boot repair, creates the
    // admission triggers and applies the one-time ledger migrations
    // (SPEC-01 §6.6). Any failure there stops the relay before it serves.
    let db_options = db::DbOptions {
        legacy_invite_grace_secs: args.legacy_invite_grace_hours.saturating_mul(3600),
        keep_legacy_permanent_invites: args.keep_legacy_permanent_invites,
        ..db::DbOptions::default()
    };
    // The attachment directory is checked before the database is opened
    // (SPEC-02 REQ-42); a misconfiguration stops the relay here.
    let attachment_settings = attachment_config(&args)?;
    let screen_settings = screen_config(&args)?;
    let mut app_state = AppState::new_with_options(
        &args.database,
        AppStateOptions {
            database_encryption: args.database_encryption,
            db: db_options,
            // The legacy blob directory stays `./data/files`.
            file_config: Some(accord_server::files::FileConfig::default()),
            attachments: Some(attachment_settings),
        },
    )
    .await?;
    app_state.metadata_mode = metadata_mode;
    app_state.federation_enabled = args.mesh_enabled;
    app_state.screen = ScreenRelay::new(screen_settings);
    if screen_settings.enabled {
        info!(
            "Screen sharing: on (screen/1), {} shares per channel, {} bytes per second per share",
            screen_settings.max_sharers, screen_settings.max_bytes_per_second
        );
    } else {
        info!("Screen sharing: off");
    }
    app_state
        .rate_limiter
        .set_preview_limit(args.preview_rate_limit);
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
        app_state
            .rate_limiter
            .set_preview_limit(args.preview_rate_limit);
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

    // The legacy role conversion is not run here: it ran once, as the
    // ledger-gated step `spec01_legacy_roles` (SPEC-01 REQ-48), when the
    // database was opened above.

    let state: SharedState = Arc::new(app_state);

    // Version-2 attachment garbage collection and storage reconciliation
    // (SPEC-02 REQ-40 to REQ-42).
    attachments::lifecycle::spawn_background_tasks(&state);

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
    let admin_app = router::build_admin_router(state.clone(), log_tx_arc.clone());

    // Build the public router (admin routes are NOT mounted here). The route
    // table and middleware live in the library, shared with the tests.
    let app = router::build_public_router_with(
        state.clone(),
        &RouterConfig {
            cors_origins: args.cors_origins.clone(),
            dev_cors: args.no_tls,
            frontend: args.frontend.clone(),
        },
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
    println!(
        "  GET    /nodes/:id/join-requests - List join requests (?token=) [admission authority]"
    );
    println!(
        "  POST   /nodes/:id/join-requests/:user_id/approve - Approve a join request (?token=)"
    );
    println!("  POST   /nodes/:id/join-requests/:user_id/deny - Deny a join request (?token=)");
    println!("  DELETE /nodes/:id/join-request - Withdraw own join request (?token=)");
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
                // Expired join requests are ignored by every read and
                // approval, and purged here (SPEC-01 REQ-33).
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if cleanup_state
                    .db
                    .purge_expired_join_requests(now)
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        target: accord_server::admission::LOG_TARGET,
                        "expired join request purge failed"
                    );
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
                // The attachment GC runs right after (SPEC-02 REQ-40).
                let (started, swept) = sweep_state.run_expiry_sweep(now).await;
                if started > 0 {
                    info!("Started expiry timer on {} read-gated messages", started);
                }
                if swept > 0 {
                    info!("Swept {} expired (disappearing) messages", swept);
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

            // SPEC-03 A2 (§6.12.3): TCP_NOTSENT_LOWAT on every client
            // connection, set before the TLS handshake; the support is
            // logged once when the listener is built.
            socket_opts::tls_server(addr.parse()?, tls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        (None, None) => {
            // Plain HTTP mode
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            info!("Server starting in plain HTTP/WS mode on {}", addr);
            let handle = axum_server::Handle::new();
            let handle_clone = handle.clone();
            tokio::spawn(async move {
                shutdown_signal.await;
                handle_clone.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });
            // axum_server rather than axum::serve, so that every accepted
            // connection gets TCP_NOTSENT_LOWAT (SPEC-03 A2, §6.12.3); the
            // support is logged once when the listener is built.
            socket_opts::plain_server(listener.into_std()?)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        _ => {
            anyhow::bail!("Both --tls-cert and --tls-key must be provided together for TLS mode");
        }
    }

    info!("Server shut down cleanly.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use accord_server::attachments::LegacyAttachmentsMode;
    use std::path::PathBuf;

    /// SPEC-02 section 7.7: `purge-legacy-attachments` is a subcommand that
    /// takes the relay's options given before it.
    #[test]
    fn purge_legacy_attachments_is_a_subcommand() {
        let args = Args::try_parse_from([
            "accord-server",
            "--database",
            "relay.db",
            "--legacy-attachments",
            "read-only",
            "purge-legacy-attachments",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(Command::PurgeLegacyAttachments)
        ));
        assert_eq!(args.database, "relay.db");
        assert!(attachment_config(&args).is_ok());
    }

    /// SPEC-02 section 6.6.4 (OD-35): each attachment setting is a CLI flag
    /// and a TOML key of the same name, with the decided defaults; the CLI
    /// wins over the file, and a value out of range names its setting.
    #[test]
    fn attachment_settings_are_flags_and_toml_keys() {
        let defaults =
            attachment_config(&Args::try_parse_from(["accord-server"]).unwrap()).unwrap();
        assert_eq!(defaults.dir, PathBuf::from("./data/attachments"));
        assert_eq!(defaults.max_blob_bytes, 104_857_600);
        assert_eq!(defaults.pending_ttl_secs, 3600);
        assert_eq!(defaults.max_pending_per_user, 32);
        assert_eq!(defaults.quota_user_bytes, 1_073_741_824);
        assert_eq!(defaults.quota_node_bytes, 10_737_418_240);
        assert_eq!(defaults.min_free_bytes, 1_073_741_824);
        assert_eq!(defaults.gc_interval_secs, 60);
        assert_eq!(defaults.reconcile_interval_secs, 3600);
        assert_eq!(defaults.legacy_mode, LegacyAttachmentsMode::ReadOnly);
        assert_eq!(defaults.legacy_retire_after_days, 90);

        let flags = Args::try_parse_from([
            "accord-server",
            "--attachments-dir",
            "/srv/blobs",
            "--attachment-max-blob-bytes",
            "1000",
            "--attachment-pending-ttl-secs",
            "600",
            "--attachment-max-pending-per-user",
            "5",
            "--attachment-quota-user-bytes",
            "0",
            "--attachment-quota-node-bytes",
            "0",
            "--attachments-min-free-bytes",
            "7",
            "--attachment-gc-interval-secs",
            "2",
            "--attachment-reconcile-interval-secs",
            "120",
            "--legacy-attachments",
            "retired",
            "--legacy-attachments-retire-after-days",
            "30",
        ])
        .unwrap();
        let config = attachment_config(&flags).unwrap();
        assert_eq!(config.dir, PathBuf::from("/srv/blobs"));
        assert_eq!(
            (
                config.max_blob_bytes,
                config.pending_ttl_secs,
                config.max_pending_per_user
            ),
            (1000, 600, 5)
        );
        assert_eq!(
            (
                config.quota_user_bytes,
                config.quota_node_bytes,
                config.min_free_bytes
            ),
            (0, 0, 7)
        );
        assert_eq!(
            (config.gc_interval_secs, config.reconcile_interval_secs),
            (2, 120)
        );
        assert_eq!(config.legacy_mode, LegacyAttachmentsMode::Retired);
        assert_eq!(config.legacy_retire_after_days, 30);

        let file: FileConfig = toml::from_str(
            r#"
            attachments_dir = "/srv/toml"
            attachment_max_blob_bytes = 2000
            attachment_pending_ttl_secs = 900
            attachment_max_pending_per_user = 8
            attachment_quota_user_bytes = 11
            attachment_quota_node_bytes = 12
            attachments_min_free_bytes = 13
            attachment_gc_interval_secs = 5
            attachment_reconcile_interval_secs = 300
            legacy_attachments = "retired"
            legacy_attachments_retire_after_days = 10
            "#,
        )
        .unwrap();
        let mut args =
            Args::try_parse_from(["accord-server", "--attachment-gc-interval-secs", "9"]).unwrap();
        merge_args_with_config(&mut args, file);
        let config = attachment_config(&args).unwrap();
        assert_eq!(config.dir, PathBuf::from("/srv/toml"));
        assert_eq!(config.max_blob_bytes, 2000);
        assert_eq!(config.pending_ttl_secs, 900);
        assert_eq!(config.max_pending_per_user, 8);
        assert_eq!(
            (
                config.quota_user_bytes,
                config.quota_node_bytes,
                config.min_free_bytes
            ),
            (11, 12, 13)
        );
        // The flag given on the command line wins over the file.
        assert_eq!(config.gc_interval_secs, 9);
        assert_eq!(config.reconcile_interval_secs, 300);
        assert_eq!(config.legacy_mode, LegacyAttachmentsMode::Retired);
        assert_eq!(config.legacy_retire_after_days, 10);

        for (flag, value, setting) in [
            (
                "--attachment-pending-ttl-secs",
                "299",
                "attachment_pending_ttl_secs",
            ),
            (
                "--attachment-pending-ttl-secs",
                "86401",
                "attachment_pending_ttl_secs",
            ),
            (
                "--attachment-gc-interval-secs",
                "0",
                "attachment_gc_interval_secs",
            ),
            (
                "--attachment-gc-interval-secs",
                "3601",
                "attachment_gc_interval_secs",
            ),
            (
                "--attachment-reconcile-interval-secs",
                "59",
                "attachment_reconcile_interval_secs",
            ),
            (
                "--attachment-reconcile-interval-secs",
                "86401",
                "attachment_reconcile_interval_secs",
            ),
            ("--legacy-attachments", "readonly", "legacy_attachments"),
        ] {
            let args = Args::try_parse_from(["accord-server", flag, value]).unwrap();
            let error = attachment_config(&args).unwrap_err().to_string();
            assert!(error.contains(setting), "{flag} {value}: {error}");
        }
    }

    /// SPEC-03 §6.12.5 (T-55): the screen-sharing flags, their OD-109
    /// defaults, and the values refused at startup.
    #[test]
    fn screen_flags() {
        let args = Args::try_parse_from(["accord-server"]).unwrap();
        let config = screen_config(&args).unwrap();
        assert_eq!(config, ScreenConfig::default());
        assert!(config.enabled);
        assert_eq!(config.max_sharers, 2);
        assert_eq!(config.max_bytes_per_second, 500_000);

        let args = Args::try_parse_from([
            "accord-server",
            "--screen-share",
            "off",
            "--screen-max-sharers",
            "8",
            "--screen-max-rate",
            "200000",
        ])
        .unwrap();
        let config = screen_config(&args).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.max_sharers, 8);
        assert_eq!(config.max_bytes_per_second, 200_000);
        assert_eq!(config.burst_bytes(), 1_100_000);

        for (flag, value) in [
            ("--screen-max-rate", "199999"),
            ("--screen-max-rate", "0"),
            ("--screen-max-sharers", "0"),
            ("--screen-max-sharers", "9"),
            ("--screen-share", "maybe"),
        ] {
            assert!(
                Args::try_parse_from(["accord-server", flag, value]).is_err(),
                "{flag} {value} was accepted"
            );
        }

        // A configuration file sets them too, checked the same way.
        let file: FileConfig = toml::from_str(
            r#"
            screen_share = "off"
            screen_max_sharers = 4
            screen_max_rate = 300000
            "#,
        )
        .unwrap();
        let mut args = Args::try_parse_from(["accord-server"]).unwrap();
        merge_args_with_config(&mut args, file);
        let config = screen_config(&args).unwrap();
        assert_eq!(config, ScreenConfig::new(false, 4, 300_000).unwrap());
        for (setting, toml) in [
            ("--screen-max-rate", "screen_max_rate = 199999"),
            ("--screen-max-sharers", "screen_max_sharers = 9"),
            ("--screen-share", "screen_share = \"yes\""),
        ] {
            let file: FileConfig = toml::from_str(toml).unwrap();
            let mut args = Args::try_parse_from(["accord-server"]).unwrap();
            merge_args_with_config(&mut args, file);
            let error = screen_config(&args).unwrap_err().to_string();
            assert!(error.contains(setting), "{toml}: {error}");
        }
    }
}
