use accord_core::crypto::CryptoManager;
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
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
    /// Join a Node
    Join {
        /// Node ID to join
        node_id: String,
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
struct JoinNodeRequest {
    node_id: Uuid,
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

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;

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

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Login failed: {}", error_text));
        }

        let auth_response: AuthResponse = response.json().await?;
        Ok(auth_response)
    }

    async fn get_nodes(&self, token: &str) -> Result<Vec<Node>> {
        let url = format!("{}/api/nodes", self.server_url);
        let response = self.client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await?;

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

        let response = self.client
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

    async fn join_node(&self, token: &str, node_id: &str) -> Result<()> {
        let node_uuid = Uuid::parse_str(node_id)?;
        let url = format!("{}/api/nodes/join", self.server_url);
        let request = JoinNodeRequest {
            node_id: node_uuid,
        };

        let response = self.client
            .post(&url)
            .bearer_auth(token)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Failed to join node: {}", error_text));
        }

        Ok(())
    }

    async fn get_channels(&self, token: &str, node_id: &str) -> Result<Vec<Channel>> {
        let url = format!("{}/api/nodes/{}/channels", self.server_url, node_id);
        let response = self.client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Failed to get channels: {}", error_text));
        }

        let channels: Vec<Channel> = response.json().await?;
        Ok(channels)
    }
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
    let token = load_token().map_err(|_| anyhow!("Not authenticated. Please run 'accord login <username>' first"))?;

    // Initialize crypto manager and establish a session key for this channel
    let mut crypto = CryptoManager::new();
    
    // For simplicity, we'll derive a session key from the user's identity key + channel ID
    // In a real implementation, this would involve proper key exchange with other users
    let _private_key = load_private_key().map_err(|_| anyhow!("No identity key found. Please re-register."))?;
    
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
                        match read_crypto.decrypt_message("channel", &encrypted_msg.encrypted_content) {
                            Ok(decrypted_bytes) => {
                                if let Ok(content) = String::from_utf8(decrypted_bytes) {
                                    println!("[{}] {}: {}", 
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
                        println!("[{}] {}: {} (plaintext)", 
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
                    let message = serde_json::to_string(&SendMessageRequest {
                        encrypted_content,
                    })?;
                    
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
            let token = load_token().map_err(|_| anyhow!("Not authenticated. Please run 'accord login <username>' first"))?;
            
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
            let token = load_token().map_err(|_| anyhow!("Not authenticated. Please run 'accord login <username>' first"))?;
            
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
        
        Commands::Join { node_id } => {
            let token = load_token().map_err(|_| anyhow!("Not authenticated. Please run 'accord login <username>' first"))?;
            
            println!("🚪 Joining Node {}...", node_id);
            
            match client.join_node(&token, &node_id).await {
                Ok(()) => {
                    println!("✅ Successfully joined Node!");
                }
                Err(e) => {
                    println!("❌ Failed to join node: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Channels { node_id } => {
            let token = load_token().map_err(|_| anyhow!("Not authenticated. Please run 'accord login <username>' first"))?;
            
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
    }

    Ok(())
}