//! # Accord Relay Server
//! 
//! Zero-knowledge relay server that routes encrypted messages
//! without having access to decrypt user content.

mod db;
mod handlers;
mod models;
mod node;
mod permissions;
mod state;

use anyhow::Result;
use axum::{
    routing::{delete, get, post},
    Router,
};
use clap::Parser;
use handlers::{auth_handler, create_invite_handler, create_node_handler, delete_channel_handler, get_node_handler, join_node_handler, kick_user_handler, leave_node_handler, list_invites_handler, revoke_invite_handler, update_node_handler, use_invite_handler, health_handler, register_handler, ws_handler};
use state::{AppState, SharedState};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server bind address
    #[arg(short = 'a', long, default_value = "127.0.0.1")]
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

    /// Database file path
    #[arg(short = 'd', long, default_value = "accord.db")]
    database: String,
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

    // Initialize shared state with database
    info!("Initializing database: {}", args.database);
    let app_state = AppState::new(&args.database).await?;
    let state: SharedState = Arc::new(app_state);
    
    // Build the router with all endpoints
    let app = Router::new()
        // REST endpoints
        .route("/health", get(health_handler))
        .route("/register", post(register_handler))
        .route("/auth", post(auth_handler))
        // Node endpoints
        .route("/nodes", post(create_node_handler))
        .route("/nodes/:id", get(get_node_handler))
        .route("/nodes/:id", axum::routing::patch(update_node_handler))
        .route("/nodes/:id/join", post(join_node_handler))
        .route("/nodes/:id/leave", post(leave_node_handler))
        .route("/nodes/:id/members/:user_id", delete(kick_user_handler))
        // Channel endpoints
        .route("/channels/:id", delete(delete_channel_handler))
        // Node invite endpoints
        .route("/nodes/:id/invites", post(create_invite_handler))
        .route("/nodes/:id/invites", get(list_invites_handler))
        .route("/invites/:invite_id", delete(revoke_invite_handler))
        .route("/invites/:code/join", post(use_invite_handler))
        // WebSocket endpoint
        .route("/ws", get(ws_handler))
        // Add shared state
        .with_state(state)
        // Add middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::new()
                        .allow_methods(Any)
                        .allow_headers(Any)
                        .allow_origin(Any)
                ),
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
    println!("  POST   /nodes/:id/invites - Create Node invite (?token=) [Admin/Mod]");
    println!("  GET    /nodes/:id/invites - List Node invites (?token=) [Admin/Mod]");
    println!("  DELETE /invites/:id       - Revoke invite (?token=) [Admin/Mod]");
    println!("  POST   /invites/:code/join - Join Node via invite (?token=)");
    println!("  WS     /ws                - WebSocket messaging (?token=)");
    println!();

    // Create the server
    let listener = tokio::net::TcpListener::bind(&format!("{}:{}", args.host, args.port)).await?;
    
    info!("Server successfully bound to {}:{}", args.host, args.port);

    // Start the server
    axum::serve(listener, app)
        .await?;

    info!("Shutting down server...");
    Ok(())
}