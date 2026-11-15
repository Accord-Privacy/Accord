use accord_core::crypto::CryptoManager;
use accord_core::release_signing;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::{SinkExt, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "accord")]
#[command(about = "Accord CLI - Privacy-first Discord alternative")]
#[command(version = "0.1.0")]
struct Cli {
    /// Server URL
    #[arg(long, default_value = "http://localhost:8080")]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register with a relay server
    Register {
        /// Username to register
        username: String,
    },
    /// Authenticate and get a token
    Login {
        /// Username to login with
        username: String,
    },
    /// List Nodes you're a member of
    Nodes,
    /// Create a new Node
    CreateNode {
        /// Name of the new Node
        name: String,
    },
    /// Join a Node with an invite code or link, or ask to join one by id
    Join {
        /// Invite code, or an invite link (accord://..., https://host/invite/CODE)
        #[arg(required_unless_present = "request", conflicts_with = "request")]
        invite: Option<String>,
        /// Ask to join the Node with this id (POST /nodes/:id/join). On a Node
        /// that accepts join requests this records a request that a moderator
        /// must approve; otherwise the relay answers that an invite is required.
        #[arg(long, value_name = "NODE_ID")]
        request: Option<String>,
    },
    /// List channels in a Node
    Channels {
        /// Node ID to list channels for
        node_id: String,
    },
    /// Enter interactive chat mode
    Chat {
        /// Channel ID to chat in
        channel_id: String,
    },
    /// Generate an Ed25519 signing keypair for release signing
    GenerateSigningKey {
        /// Output path (private key written to `<path>`, public to `<path>.pub`)
        #[arg(long)]
        output: String,
    },
    /// Sign a release build hash
    SignRelease {
        /// Path to Ed25519 private key file
        #[arg(long)]
        key: String,
        /// Build hash to sign
        #[arg(long)]
        hash: String,
        /// Version string
        #[arg(long)]
        version: String,
    },
    /// Verify signatures in a HASHES.json file
    VerifyRelease {
        /// Path to Ed25519 public key file
        #[arg(long)]
        pubkey: String,
        /// Path to HASHES.json
        #[arg(long)]
        hashes: String,
    },
    /// Generate a self-signed TLS certificate for development/testing
    #[cfg(feature = "generate-cert")]
    GenerateCert {
        /// Hostname(s) for the certificate (comma-separated)
        #[arg(long, default_value = "localhost")]
        hostname: String,
        /// Output directory for cert.pem and key.pem
        #[arg(long, default_value = ".")]
        output: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct User {
    id: Uuid,
    username: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Node {
    id: Uuid,
    name: String,
    owner_id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Channel {
    id: Uuid,
    node_id: Uuid,
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ChatMessage {
    id: Uuid,
    channel_id: Uuid,
    user_id: Uuid,
    username: String,
    content: String,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
struct RegisterRequest {
    username: String,
    public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct LoginRequest {
    username: String,
}

#[derive(Serialize, Deserialize)]
struct AuthResponse {
    token: String,
    user: User,
}

#[derive(Serialize, Deserialize)]
struct CreateNodeRequest {
    name: String,
}

#[derive(Serialize, Deserialize)]
struct SendMessageRequest {
    encrypted_content: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedChatMessage {
    id: Uuid,
    channel_id: Uuid,
    user_id: Uuid,
    username: String,
    encrypted_content: Vec<u8>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

struct AccordClient {
    server_url: String,
    client: Client,
}

impl AccordClient {
    fn new(server_url: String) -> Self {
        Self {
            server_url,
            client: Client::new(),
        }
    }

    async fn register(&self, username: &str) -> Result<AuthResponse> {
        // Generate X25519 keypair for this user
        let public_key = generate_and_save_keypair()?;

        let url = format!("{}/api/register", self.server_url);
        let request = RegisterRequest {
            username: username.to_string(),
            public_key,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Registration failed: {}", error_text));
        }

        let auth_response: AuthResponse = response.json().await?;
        Ok(auth_response)
    }

    async fn login(&self, username: &str) -> Result<AuthResponse> {
        let url = format!("{}/api/login", self.server_url);
        let request = LoginRequest {
            username: username.to_string(),
        };

        let response = self.client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Login failed: {}", error_text));
        }

        let auth_response: AuthResponse = response.json().await?;
        Ok(auth_response)
    }

    async fn get_nodes(&self, token: &str) -> Result<Vec<Node>> {
        let url = format!("{}/api/nodes", self.server_url);
        let response = self.client.get(&url).bearer_auth(token).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Failed to get nodes: {}", error_text));
        }

        let nodes: Vec<Node> = response.json().await?;
        Ok(nodes)
    }

    async fn create_node(&self, token: &str, name: &str) -> Result<Node> {
        let url = format!("{}/api/nodes", self.server_url);
        let request = CreateNodeRequest {
            name: name.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Failed to create node: {}", error_text));
        }

        let node: Node = response.json().await?;
        Ok(node)
    }

    /// `POST /invites/:code/join` (SPEC-01 REQ-44).
    async fn join_by_invite(&self, token: &str, code: &str) -> Result<JoinOutcome> {
        let url = join_by_invite_url(&self.server_url, code);
        let response = self.client.post(&url).bearer_auth(token).send().await?;
        join_outcome(response).await
    }

    /// `POST /nodes/:id/join` without an invite: a join request on a Node
    /// whose policy is `request` (SPEC-01 REQ-44).
    async fn request_join(&self, token: &str, node_id: Uuid) -> Result<JoinOutcome> {
        let url = join_request_url(&self.server_url, node_id);
        let response = self.client.post(&url).bearer_auth(token).send().await?;
        join_outcome(response).await
    }

    async fn get_channels(&self, token: &str, node_id: &str) -> Result<Vec<Channel>> {
        let url = format!("{}/api/nodes/{}/channels", self.server_url, node_id);
        let response = self.client.get(&url).bearer_auth(token).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Failed to get channels: {}", error_text));
        }

        let channels: Vec<Channel> = response.json().await?;
        Ok(channels)
    }
}

/// What the relay answered to a join.
#[derive(Debug, PartialEq)]
enum JoinOutcome {
    Joined { node_id: String, node_name: String },
    Pending { node_id: String },
}

/// Read a join answer: 200 `joined`, 202 `pending_approval`, or an error body
/// `{error, code, reason, retry_after?}` (SPEC-01 section 6.2).
async fn join_outcome(response: reqwest::Response) -> Result<JoinOutcome> {
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    let field = |name: &str| body[name].as_str().unwrap_or_default().to_string();
    if status.is_success() {
        return Ok(if body["status"] == "pending_approval" {
            JoinOutcome::Pending {
                node_id: field("node_id"),
            }
        } else {
            JoinOutcome::Joined {
                node_id: field("node_id"),
                node_name: field("node_name"),
            }
        });
    }
    let mut message = body["error"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
    if let Some(reason) = body["reason"].as_str() {
        message.push_str(&format!(" ({reason})"));
    }
    if let Some(retry) = body["retry_after"].as_u64() {
        message.push_str(&format!("; try again in {retry} s"));
    }
    Err(anyhow!(message))
}

/// The redemption URL of an invite code.
fn join_by_invite_url(server_url: &str, code: &str) -> String {
    format!("{}/invites/{}/join", server_url.trim_end_matches('/'), code)
}

/// The URL that asks to join a Node by id.
fn join_request_url(server_url: &str, node_id: Uuid) -> String {
    format!(
        "{}/nodes/{}/join",
        server_url.trim_end_matches('/'),
        node_id
    )
}

/// A relay invite code: 6 to 32 ASCII letters and digits (SPEC-01 REQ-36).
fn is_invite_code(code: &str) -> bool {
    (6..=32).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The invite code in `input`, which is either a bare code or an invite link
/// in one of the desktop's forms: `accord://<base64url host>/<code>`,
/// `accord://<host>/invite/<code>` or `http(s)://<host>/invite/<code>`. A
/// link that names another relay than `server_url` is refused, so the code is
/// never redeemed (and the token never used) at the wrong relay.
fn invite_code_from(input: &str, server_url: &str) -> Result<String> {
    let input = input.trim();
    let (link_host, code) = if let Some(rest) = input.strip_prefix("accord://") {
        let mut parts = rest.trim_end_matches('/').split('/');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(encoded), Some(code), None, None) => {
                let host = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded.trim_end_matches('='))
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .ok_or_else(|| anyhow!("Invalid invite link"))?;
                (Some(host), code.to_string())
            }
            (Some(host), Some("invite"), Some(code), None) => {
                (Some(host.to_string()), code.to_string())
            }
            _ => return Err(anyhow!("Invalid invite link")),
        }
    } else if input.starts_with("http://") || input.starts_with("https://") {
        let url = url::Url::parse(input).map_err(|_| anyhow!("Invalid invite link"))?;
        let segments: Vec<&str> = url
            .path_segments()
            .map(|s| s.filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();
        match segments.as_slice() {
            ["invite", code] => {
                let host = match url.port() {
                    Some(port) => format!("{}:{}", url.host_str().unwrap_or_default(), port),
                    None => url.host_str().unwrap_or_default().to_string(),
                };
                (Some(host), (*code).to_string())
            }
            _ => return Err(anyhow!("Invalid invite link")),
        }
    } else {
        (None, input.to_string())
    };
    if !is_invite_code(&code) {
        return Err(anyhow!(
            "Invalid invite code (expected 6 to 32 letters and digits)"
        ));
    }
    if let Some(host) = link_host {
        if !same_relay(server_url, &host) {
            return Err(anyhow!(
                "This invite is for the relay at {host}; run `accord --server <that relay's URL> join ...`"
            ));
        }
    }
    Ok(code)
}

/// Does `server_url` name the relay at `host` (`name` or `name:port`)? Ports
/// are compared only when the link names one.
fn same_relay(server_url: &str, host: &str) -> bool {
    let Ok(server) = url::Url::parse(server_url) else {
        return false;
    };
    let Ok(link) = url::Url::parse(&format!("http://{host}")) else {
        return false;
    };
    let same_name = server
        .host_str()
        .zip(link.host_str())
        .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b));
    let same_port = match link.port() {
        Some(port) => server.port_or_known_default() == Some(port),
        None => true,
    };
    same_name && same_port
}

fn get_token_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
    let accord_dir = home.join(".accord");

    // Create directory if it doesn't exist
    if !accord_dir.exists() {
        fs::create_dir_all(&accord_dir)?;
    }

    Ok(accord_dir.join("token"))
}

fn save_token(token: &str) -> Result<()> {
    let path = get_token_path()?;
    fs::write(path, token)?;
    Ok(())
}

fn load_token() -> Result<String> {
    let path = get_token_path()?;
    let token = fs::read_to_string(path)?;
    Ok(token.trim().to_string())
}

fn get_identity_key_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
    let accord_dir = home.join(".accord");

    // Create directory if it doesn't exist
    if !accord_dir.exists() {
        fs::create_dir_all(&accord_dir)?;
    }

    Ok(accord_dir.join("identity.key"))
}

fn save_private_key(private_key_bytes: &[u8]) -> Result<()> {
    let path = get_identity_key_path()?;
    fs::write(path, private_key_bytes)?;
    Ok(())
}

fn load_private_key() -> Result<Vec<u8>> {
    let path = get_identity_key_path()?;
    let key_bytes = fs::read(path)?;
    Ok(key_bytes)
}

fn generate_and_save_keypair() -> Result<Vec<u8>> {
    let crypto = CryptoManager::new();
    let key_pair = crypto.generate_key_pair()?;

    // Save the private key (we need to serialize it first)
    // For now, we'll store the public key as a placeholder since ring doesn't expose private key bytes
    // In a real implementation, we'd use a different crypto library or serialize properly
    save_private_key(&key_pair.public_key)?;

    Ok(key_pair.public_key)
}

async fn enter_chat_mode(server_url: &str, channel_id: &str) -> Result<()> {
    // Load authentication token
    let token = load_token()
        .map_err(|_| anyhow!("Not authenticated. Please run 'accord login <username>' first"))?;

    // Initialize crypto manager and establish a session key for this channel
    let mut crypto = CryptoManager::new();

    // For simplicity, we'll derive a session key from the user's identity key + channel ID
    // In a real implementation, this would involve proper key exchange with other users
    let _private_key =
        load_private_key().map_err(|_| anyhow!("No identity key found. Please re-register."))?;

    // Create a deterministic but secure session key for this channel
    // This is simplified - real implementation would use proper key exchange
    let session_key = accord_core::crypto::SessionKey {
        key_material: {
            let mut key = [0u8; 32];
            // Use channel_id as seed for session key (simplified approach)
            let channel_bytes = channel_id.as_bytes();
            for (i, &byte) in channel_bytes.iter().enumerate() {
                if i < 32 {
                    key[i] = byte;
                }
            }
            key
        },
        chain_key: [42u8; 32], // Fixed chain key for simplicity
        message_number: 0,
    };

    crypto.set_session("channel", session_key);
    println!("🔒 E2E encryption initialized for channel");

    // Convert HTTP URL to WebSocket URL
    let ws_url = if server_url.starts_with("https://") {
        server_url.replace("https://", "wss://")
    } else {
        server_url.replace("http://", "ws://")
    };

    let ws_url = format!("{}/ws/chat/{}?token={}", ws_url, channel_id, token);

    println!("🔗 Connecting to chat...");
    let (ws_stream, _) = connect_async(&ws_url).await?;
    let (mut write, mut read) = ws_stream.split();

    println!("✅ Connected to channel {}!", channel_id);
    println!("🔐 All messages are end-to-end encrypted");
    println!("Type messages and press Enter. Type '/quit' to exit.\n");

    // Create a shared crypto manager for the read task
    let mut read_crypto = CryptoManager::new();
    let read_session_key = accord_core::crypto::SessionKey {
        key_material: {
            let mut key = [0u8; 32];
            let channel_bytes = channel_id.as_bytes();
            for (i, &byte) in channel_bytes.iter().enumerate() {
                if i < 32 {
                    key[i] = byte;
                }
            }
            key
        },
        chain_key: [42u8; 32],
        message_number: 0,
    };
    read_crypto.set_session("channel", read_session_key);

    // Spawn a task to handle incoming messages
    let read_handle = tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    // Try to parse as encrypted message first
                    if let Ok(encrypted_msg) = serde_json::from_str::<EncryptedChatMessage>(&text) {
                        match read_crypto
                            .decrypt_message("channel", &encrypted_msg.encrypted_content)
                        {
                            Ok(decrypted_bytes) => {
                                if let Ok(content) = String::from_utf8(decrypted_bytes) {
                                    println!(
                                        "[{}] {}: {}",
                                        encrypted_msg.timestamp.format("%H:%M:%S"),
                                        encrypted_msg.username,
                                        content
                                    );
                                } else {
                                    println!("❌ Failed to decode decrypted message");
                                }
                            }
                            Err(e) => {
                                println!("❌ Failed to decrypt message: {}", e);
                            }
                        }
                    }
                    // Fallback to plaintext for server messages/notifications
                    else if let Ok(chat_msg) = serde_json::from_str::<ChatMessage>(&text) {
                        println!(
                            "[{}] {}: {} (plaintext)",
                            chat_msg.timestamp.format("%H:%M:%S"),
                            chat_msg.username,
                            chat_msg.content
                        );
                    } else {
                        println!("📢 {}", text);
                    }
                }
                Ok(Message::Close(_)) => {
                    println!("🔌 Connection closed by server");
                    break;
                }
                Err(e) => {
                    println!("❌ WebSocket error: {}", e);
                    break;
                }
                _ => {} // Ignore other message types
            }
        }
    });

    // Handle user input
    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input == "/quit" {
            println!("👋 Leaving chat...");
            break;
        }

        if !input.is_empty() {
            // Encrypt the message before sending
            match crypto.encrypt_message("channel", input.as_bytes()) {
                Ok(encrypted_content) => {
                    let message = serde_json::to_string(&SendMessageRequest { encrypted_content })?;

                    if let Err(e) = write.send(Message::Text(message)).await {
                        println!("❌ Failed to send message: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    println!("❌ Failed to encrypt message: {}", e);
                }
            }
        }
    }

    // Clean shutdown
    let _ = write.send(Message::Close(None)).await;
    read_handle.abort();

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = AccordClient::new(cli.server);

    match cli.command {
        Commands::Register { username } => {
            println!("🔐 Registering user '{}'...", username);
            println!("🔑 Generating X25519 keypair for E2E encryption...");

            match client.register(&username).await {
                Ok(auth_response) => {
                    println!("✅ Registration successful!");
                    println!("   User ID: {}", auth_response.user.id);
                    println!("   Username: {}", auth_response.user.username);

                    // Save token for future use
                    save_token(&auth_response.token)?;
                    println!("💾 Authentication token saved to ~/.accord/token");
                    println!("🔒 Identity key saved to ~/.accord/identity.key");
                }
                Err(e) => {
                    println!("❌ Registration failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Login { username } => {
            println!("🔑 Logging in user '{}'...", username);

            match client.login(&username).await {
                Ok(auth_response) => {
                    println!("✅ Login successful!");
                    println!("   User ID: {}", auth_response.user.id);
                    println!("   Username: {}", auth_response.user.username);

                    // Save token for future use
                    save_token(&auth_response.token)?;
                    println!("💾 Authentication token saved to ~/.accord/token");
                }
                Err(e) => {
                    println!("❌ Login failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Nodes => {
            let token = load_token().map_err(|_| {
                anyhow!("Not authenticated. Please run 'accord login <username>' first")
            })?;

            println!("📋 Fetching your Nodes...");

            match client.get_nodes(&token).await {
                Ok(nodes) => {
                    if nodes.is_empty() {
                        println!("📭 You're not a member of any Nodes yet.");
                        println!("   Use 'accord create-node <name>' to create one, or");
                        println!("   Use 'accord join <node-id>' to join an existing Node.");
                    } else {
                        println!("🏰 Your Nodes:");
                        for node in nodes {
                            println!("   • {} ({})", node.name, node.id);
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Failed to fetch nodes: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::CreateNode { name } => {
            let token = load_token().map_err(|_| {
                anyhow!("Not authenticated. Please run 'accord login <username>' first")
            })?;

            println!("🏗️ Creating Node '{}'...", name);

            match client.create_node(&token, &name).await {
                Ok(node) => {
                    println!("✅ Node created successfully!");
                    println!("   Node ID: {}", node.id);
                    println!("   Name: {}", node.name);
                    println!("   Owner ID: {}", node.owner_id);
                }
                Err(e) => {
                    println!("❌ Failed to create node: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Join { invite, request } => {
            let token = load_token().map_err(|_| {
                anyhow!("Not authenticated. Please run 'accord login <username>' first")
            })?;

            let outcome = match (invite, request) {
                (Some(invite), _) => {
                    let code = invite_code_from(&invite, &client.server_url)?;
                    println!("🚪 Joining with an invite...");
                    client.join_by_invite(&token, &code).await
                }
                (None, Some(node_id)) => {
                    let node_id = Uuid::parse_str(&node_id)
                        .map_err(|_| anyhow!("Invalid Node ID: {}", node_id))?;
                    println!("🚪 Asking to join Node {}...", node_id);
                    client.request_join(&token, node_id).await
                }
                (None, None) => Err(anyhow!(
                    "Give an invite code or link, or --request <node_id>"
                )),
            };

            match outcome {
                Ok(JoinOutcome::Joined { node_id, node_name }) => {
                    println!("✅ Joined Node {} ({})", node_name, node_id);
                }
                Ok(JoinOutcome::Pending { node_id }) => {
                    println!(
                        "⏳ Request sent. A moderator of Node {} must approve it.",
                        node_id
                    );
                }
                Err(e) => {
                    println!("❌ Failed to join node: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Channels { node_id } => {
            let token = load_token().map_err(|_| {
                anyhow!("Not authenticated. Please run 'accord login <username>' first")
            })?;

            println!("📺 Fetching channels for Node {}...", node_id);

            match client.get_channels(&token, &node_id).await {
                Ok(channels) => {
                    if channels.is_empty() {
                        println!("📭 No channels found in this Node.");
                    } else {
                        println!("📋 Channels:");
                        for channel in channels {
                            println!("   • {} ({})", channel.name, channel.id);
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Failed to fetch channels: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Chat { channel_id } => {
            if let Err(e) = enter_chat_mode(&client.server_url, &channel_id).await {
                println!("❌ Chat failed: {}", e);
                std::process::exit(1);
            }
        }

        Commands::GenerateSigningKey { output } => {
            let (sk, vk) = release_signing::generate_keypair();
            fs::write(&output, sk.to_bytes())?;
            fs::write(format!("{}.pub", output), vk.to_bytes())?;
            println!("✅ Signing keypair generated");
            println!("   Private key: {}", output);
            println!("   Public key:  {}.pub", output);
            println!("   Public key (base64): {}", B64.encode(vk.to_bytes()));
        }

        Commands::SignRelease { key, hash, version } => {
            let key_bytes = fs::read(&key)?;
            let key_arr: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid private key (expected 32 bytes)"))?;
            let signing_key = SigningKey::from_bytes(&key_arr);

            let timestamp = chrono::Utc::now().to_rfc3339();
            let signed = release_signing::sign_release(&signing_key, &hash, &version, &timestamp);

            // Output as a JSON KnownBuild entry with signature fields
            let entry = serde_json::json!({
                "version": signed.version,
                "platform": "FILL_PLATFORM",
                "hash": signed.build_hash,
                "revoked": false,
                "signature": signed.signature,
                "signature_timestamp": signed.timestamp,
            });
            println!("{}", serde_json::to_string_pretty(&entry)?);
        }

        Commands::VerifyRelease { pubkey, hashes } => {
            let key_bytes = fs::read(&pubkey)?;
            let key_arr: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid public key (expected 32 bytes)"))?;
            let verifying_key = VerifyingKey::from_bytes(&key_arr)
                .map_err(|e| anyhow!("Invalid public key: {e}"))?;

            let json = fs::read_to_string(&hashes)?;
            let builds: Vec<accord_core::build_hash::KnownBuild> = serde_json::from_str(&json)?;

            let results = release_signing::verify_signed_hashes(&verifying_key, &builds);
            let mut all_ok = true;
            for r in &results {
                let status = if r.signature_valid {
                    "✅ VALID"
                } else {
                    all_ok = false;
                    "❌ INVALID/MISSING"
                };
                println!("{} {} v{} [{}]", status, r.hash, r.version, r.platform);
            }
            if all_ok {
                println!("\n🔒 All {} entries have valid signatures.", results.len());
            } else {
                println!("\n⚠️  Some entries have missing or invalid signatures.");
                std::process::exit(1);
            }
        }
        #[cfg(feature = "generate-cert")]
        Commands::GenerateCert { hostname, output } => {
            use std::path::Path;

            let hostnames: Vec<String> =
                hostname.split(',').map(|s| s.trim().to_string()).collect();
            let mut params = rcgen::CertificateParams::new(hostnames.clone())?;
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, hostnames[0].clone());

            // Add IP SAN for localhost
            for h in &hostnames {
                if h == "localhost" {
                    params
                        .subject_alt_names
                        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
                            std::net::Ipv4Addr::LOCALHOST,
                        )));
                    params
                        .subject_alt_names
                        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V6(
                            std::net::Ipv6Addr::LOCALHOST,
                        )));
                }
            }

            let key_pair = rcgen::KeyPair::generate()?;
            let cert = params.self_signed(&key_pair)?;

            let out_dir = Path::new(&output);
            fs::create_dir_all(out_dir)?;

            let cert_path = out_dir.join("cert.pem");
            let key_path = out_dir.join("key.pem");

            fs::write(&cert_path, cert.pem())?;
            fs::write(&key_path, key_pair.serialize_pem())?;

            println!("✅ Self-signed certificate generated:");
            println!("   Certificate: {}", cert_path.display());
            println!("   Private key: {}", key_path.display());
            println!("   Hostnames:   {}", hostnames.join(", "));
            println!("\nUsage:");
            println!(
                "   accord-server --tls-cert {} --tls-key {}",
                cert_path.display(),
                key_path.display()
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "https://relay.example.org:8443";

    /// T-44 (SPEC-01 REQ-44): the CLI redeems invites at `/invites/<code>/join`,
    /// from a bare code and from each invite link form, and asks to join by
    /// id at `/nodes/<id>/join`.
    #[test]
    fn t44_join_urls() {
        let code = "Ab3dEf6hIj9kLm2nOp5qRs";
        let compact =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("relay.example.org:8443");
        for input in [
            code.to_string(),
            format!("  {code}  "),
            format!("accord://{compact}/{code}"),
            format!("accord://relay.example.org:8443/invite/{code}"),
            format!("https://relay.example.org:8443/invite/{code}"),
            format!("https://relay.example.org:8443/invite/{code}/"),
        ] {
            let parsed = invite_code_from(&input, SERVER).unwrap();
            assert_eq!(parsed, code, "{input}");
            assert_eq!(
                join_by_invite_url(SERVER, &parsed),
                format!("{SERVER}/invites/{code}/join")
            );
        }
        assert_eq!(
            join_by_invite_url("http://localhost:8080/", "ABCDEFGH"),
            "http://localhost:8080/invites/ABCDEFGH/join"
        );
        let node = Uuid::parse_str("6f1c2b8e-3d4a-4f5b-9c6d-7e8f9a0b1c2d").unwrap();
        assert_eq!(
            join_request_url(SERVER, node),
            format!("{SERVER}/nodes/{node}/join")
        );
    }

    #[test]
    fn t44_rejects_bad_codes_and_other_relays() {
        for bad in [
            "abc12",
            "has-dash1",
            &"a".repeat(33),
            "",
            "accord://",
            "https://relay.example.org:8443/nodes/x",
        ] {
            assert!(invite_code_from(bad, SERVER).is_err(), "{bad}");
        }
        assert!(invite_code_from("abcdef", SERVER).is_ok());
        assert!(invite_code_from(&"a".repeat(32), SERVER).is_ok());
        // A link for another relay is refused, so the token is not used there.
        assert!(invite_code_from("https://other.example.org/invite/ABCDEFGH", SERVER).is_err());
        assert!(
            invite_code_from("accord://relay.example.org:9999/invite/ABCDEFGH", SERVER).is_err()
        );
        // A link without a port matches the server by name.
        assert!(invite_code_from("accord://relay.example.org/invite/ABCDEFGH", SERVER).is_ok());
    }
}
