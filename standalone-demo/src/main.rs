//! # Accord Standalone Demo
//!
//! Completely self-contained demonstration of Accord concepts
//! Uses only Rust standard library - no external dependencies

use std::collections::HashMap;
use std::io::{self, Write};

/// Simple ID type (replacing UUID)
type Id = u64;

/// Generate simple ID
fn generate_id() -> Id {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Simple encryption (XOR cipher for demo - NOT production ready)
fn simple_encrypt(data: &[u8], key: u64) -> Vec<u8> {
    let key_bytes = key.to_le_bytes();
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_bytes[i % 8])
        .collect()
}

/// Simple decryption (same as encryption for XOR)
fn simple_decrypt(data: &[u8], key: u64) -> Vec<u8> {
    simple_encrypt(data, key)
}

/// User in the Accord system
#[derive(Clone, Debug)]
struct User {
    id: Id,
    username: String,
    crypto_key: u64,
}

/// Channel types in Accord
#[derive(Clone, Debug)]
enum ChannelType {
    Lobby,
    Private { visible: bool },
    Voice,
}

/// Channel permissions
#[derive(Clone, Debug)]
struct Permissions {
    can_speak: bool,
    can_approve: bool,
    can_invite: bool,
}

impl Permissions {
    fn member() -> Self {
        Self {
            can_speak: true,
            can_approve: false,
            can_invite: false,
        }
    }

    fn admin() -> Self {
        Self {
            can_speak: true,
            can_approve: true,
            can_invite: true,
        }
    }
}

/// Channel member
#[derive(Clone, Debug)]
struct Member {
    user_id: Id,
    permissions: Permissions,
}

/// Entry request for private channels
#[derive(Clone, Debug)]
struct EntryRequest {
    id: Id,
    user_id: Id,
    channel_id: Id,
    message: String,
}

/// Channel in the server
#[derive(Clone, Debug)]
struct Channel {
    id: Id,
    name: String,
    channel_type: ChannelType,
    creator: Id,
    members: HashMap<Id, Member>,
    pending_requests: Vec<EntryRequest>,
}

/// Server containing channels
#[derive(Clone, Debug)]
struct Server {
    id: Id,
    name: String,
    channels: HashMap<Id, Channel>,
}

/// Encrypted message
#[derive(Clone, Debug)]
struct Message {
    id: Id,
    sender: Id,
    channel: Id,
    encrypted_content: Vec<u8>,
}

/// Main Accord demo system
struct AccordDemo {
    users: HashMap<Id, User>,
    servers: HashMap<Id, Server>,
    session_keys: HashMap<(Id, Id), u64>, // (user1, user2) -> shared key
}

impl AccordDemo {
    fn new() -> Self {
        Self {
            users: HashMap::new(),
            servers: HashMap::new(),
            session_keys: HashMap::new(),
        }
    }

    fn create_user(&mut self, username: String) -> Id {
        let id = generate_id();
        let user = User {
            id,
            username: username.clone(),
            crypto_key: generate_id(), // Simple key generation
        };
        self.users.insert(id, user);
        println!("👤 Created user: {} (ID: {})", username, id);
        id
    }

    fn create_server(&mut self, name: String, owner: Id) -> Result<Id, String> {
        if !self.users.contains_key(&owner) {
            return Err("Owner not found".to_string());
        }

        let id = generate_id();
        let server = Server {
            id,
            name: name.clone(),
            channels: HashMap::new(),
        };
        self.servers.insert(id, server);
        println!("🏰 Created server: {} (ID: {})", name, id);
        Ok(id)
    }

    fn create_channel(
        &mut self,
        server_id: Id,
        name: String,
        channel_type: ChannelType,
        creator: Id,
    ) -> Result<Id, String> {
        let server = self.servers.get_mut(&server_id).ok_or("Server not found")?;

        let id = generate_id();
        let mut members = HashMap::new();
        members.insert(
            creator,
            Member {
                user_id: creator,
                permissions: Permissions::admin(),
            },
        );

        let channel = Channel {
            id,
            name: name.clone(),
            channel_type: channel_type.clone(),
            creator,
            members,
            pending_requests: Vec::new(),
        };

        server.channels.insert(id, channel);
        println!(
            "📺 Created channel: {} ({:?}) in server {}",
            name, channel_type, server_id
        );
        Ok(id)
    }

    fn join_lobby_channel(
        &mut self,
        server_id: Id,
        channel_id: Id,
        user_id: Id,
    ) -> Result<(), String> {
        let server = self.servers.get_mut(&server_id).ok_or("Server not found")?;
        let channel = server
            .channels
            .get_mut(&channel_id)
            .ok_or("Channel not found")?;

        match channel.channel_type {
            ChannelType::Lobby | ChannelType::Voice => {
                if channel.members.contains_key(&user_id) {
                    return Err("Already a member".to_string());
                }

                channel.members.insert(
                    user_id,
                    Member {
                        user_id,
                        permissions: Permissions::member(),
                    },
                );

                let username = &self.users[&user_id].username;
                println!("✅ {} joined lobby channel {}", username, channel.name);
                Ok(())
            }
            ChannelType::Private { .. } => Err("Cannot directly join private channel".to_string()),
        }
    }

    fn request_entry(
        &mut self,
        server_id: Id,
        channel_id: Id,
        user_id: Id,
        message: String,
    ) -> Result<Id, String> {
        let server = self.servers.get_mut(&server_id).ok_or("Server not found")?;
        let channel = server
            .channels
            .get_mut(&channel_id)
            .ok_or("Channel not found")?;

        match channel.channel_type {
            ChannelType::Private { .. } => {
                if channel.members.contains_key(&user_id) {
                    return Err("Already a member".to_string());
                }

                let request_id = generate_id();
                let request = EntryRequest {
                    id: request_id,
                    user_id,
                    channel_id,
                    message,
                };

                channel.pending_requests.push(request);
                let username = &self.users[&user_id].username;
                println!(
                    "📝 {} requested entry to private channel {}",
                    username, channel.name
                );
                Ok(request_id)
            }
            _ => Err("Can only request entry to private channels".to_string()),
        }
    }

    fn approve_entry(&mut self, server_id: Id, request_id: Id, approver: Id) -> Result<(), String> {
        let server = self.servers.get_mut(&server_id).ok_or("Server not found")?;

        for channel in server.channels.values_mut() {
            if let Some(pos) = channel
                .pending_requests
                .iter()
                .position(|r| r.id == request_id)
            {
                // Check permissions
                let approver_member = channel.members.get(&approver).ok_or("Not a member")?;
                if !approver_member.permissions.can_approve {
                    return Err("No permission to approve".to_string());
                }

                let request = channel.pending_requests.remove(pos);
                channel.members.insert(
                    request.user_id,
                    Member {
                        user_id: request.user_id,
                        permissions: Permissions::member(),
                    },
                );

                let username = &self.users[&request.user_id].username;
                let approver_name = &self.users[&approver].username;
                println!(
                    "✅ {} approved {}'s entry to {}",
                    approver_name, username, channel.name
                );
                return Ok(());
            }
        }

        Err("Request not found".to_string())
    }

    fn establish_session(&mut self, user1: Id, user2: Id) {
        // Simple shared key derivation (NOT secure - demo only)
        let key1 = self.users[&user1].crypto_key;
        let key2 = self.users[&user2].crypto_key;
        let shared_key = key1 ^ key2; // XOR for demo

        self.session_keys.insert((user1, user2), shared_key);
        self.session_keys.insert((user2, user1), shared_key);

        let name1 = &self.users[&user1].username;
        let name2 = &self.users[&user2].username;
        println!(
            "🔐 Established encrypted session between {} and {}",
            name1, name2
        );
    }

    fn send_message(
        &self,
        sender: Id,
        recipient: Id,
        channel: Id,
        content: &str,
    ) -> Result<Message, String> {
        let shared_key = self
            .session_keys
            .get(&(sender, recipient))
            .ok_or("No session established")?;

        let encrypted_content = simple_encrypt(content.as_bytes(), *shared_key);

        let content_len = encrypted_content.len();

        let message = Message {
            id: generate_id(),
            sender,
            channel,
            encrypted_content,
        };

        let sender_name = &self.users[&sender].username;
        println!(
            "📨 {} sent encrypted message (length: {} bytes)",
            sender_name, content_len
        );
        Ok(message)
    }

    fn receive_message(&self, recipient: Id, message: &Message) -> Result<String, String> {
        let shared_key = self
            .session_keys
            .get(&(message.sender, recipient))
            .ok_or("No session established")?;

        let decrypted = simple_decrypt(&message.encrypted_content, *shared_key);
        let content = String::from_utf8(decrypted).map_err(|_| "Invalid UTF-8")?;

        let sender_name = &self.users[&message.sender].username;
        let recipient_name = &self.users[&recipient].username;
        println!(
            "📥 {} received message from {}: \"{}\"",
            recipient_name, sender_name, content
        );
        Ok(content)
    }

    fn generate_invite(&self, server_id: Id, creator: Id, hours: u32) -> String {
        // Simple invite format: server_id:creator:expires_timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires = now + (hours as u64 * 3600);

        let invite = format!("{}:{}:{}", server_id, creator, expires);
        let creator_name = &self.users[&creator].username;
        let server_name = &self.servers[&server_id].name;
        println!(
            "🎫 {} created invite for '{}': {}",
            creator_name, server_name, invite
        );
        invite
    }

    fn use_invite(&self, user_id: Id, invite_code: &str) -> Result<Id, String> {
        let parts: Vec<&str> = invite_code.split(':').collect();
        if parts.len() != 3 {
            return Err("Invalid invite format".to_string());
        }

        let server_id: Id = parts[0].parse().map_err(|_| "Invalid server ID")?;
        let _creator: Id = parts[1].parse().map_err(|_| "Invalid creator ID")?;
        let expires: u64 = parts[2].parse().map_err(|_| "Invalid expiration")?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > expires {
            return Err("Invite has expired".to_string());
        }

        let username = &self.users[&user_id].username;
        let server_name = &self.servers[&server_id].name;
        println!("🎫 {} used invite to join '{}'", username, server_name);
        Ok(server_id)
    }

    fn print_status(&self) {
        println!("\n=== Accord System Status ===");
        println!("👥 Users: {}", self.users.len());
        println!("🏰 Servers: {}", self.servers.len());

        for server in self.servers.values() {
            println!(
                "📺 Server '{}': {} channels",
                server.name,
                server.channels.len()
            );
        }

        println!("🔐 Active sessions: {}", self.session_keys.len() / 2);
    }

    fn run_complete_demo(&mut self) {
        println!("🚀 Accord Complete Standalone Demo\n");

        // Create users
        let alice = self.create_user("Alice".to_string());
        let bob = self.create_user("Bob".to_string());
        let charlie = self.create_user("Charlie".to_string());
        println!();

        // Create server
        let server = self
            .create_server("Demo Server".to_string(), alice)
            .unwrap();
        println!();

        // Create channels
        let lobby = self
            .create_channel(server, "General".to_string(), ChannelType::Lobby, alice)
            .unwrap();
        let voice = self
            .create_channel(server, "Voice Chat".to_string(), ChannelType::Voice, alice)
            .unwrap();
        let private = self
            .create_channel(
                server,
                "Staff Only".to_string(),
                ChannelType::Private { visible: true },
                alice,
            )
            .unwrap();
        println!();

        // Bob joins public channels
        self.join_lobby_channel(server, lobby, bob).unwrap();
        self.join_lobby_channel(server, voice, bob).unwrap();
        println!();

        // Charlie requests private access
        let request = self
            .request_entry(
                server,
                private,
                charlie,
                "Please let me join the staff channel!".to_string(),
            )
            .unwrap();

        // Alice approves
        self.approve_entry(server, request, alice).unwrap();
        println!();

        // Establish encrypted sessions
        self.establish_session(alice, bob);
        self.establish_session(alice, charlie);
        println!();

        // Send encrypted messages
        let msg1 = self
            .send_message(alice, bob, lobby, "Welcome to Accord, Bob!")
            .unwrap();
        self.receive_message(bob, &msg1).unwrap();

        let msg2 = self
            .send_message(alice, charlie, private, "Thanks for joining staff!")
            .unwrap();
        self.receive_message(charlie, &msg2).unwrap();
        println!();

        // Invite system demo
        let invite = self.generate_invite(server, alice, 24);
        let dave = self.create_user("Dave".to_string());
        self.use_invite(dave, &invite).unwrap();
        println!();

        self.print_status();
        println!("\n✅ Demo completed successfully!");
    }
}

fn main() {
    println!("🚀 Accord Standalone Demo");
    println!("Privacy-First Discord Alternative");
    println!("Using only Rust standard library");
    println!("=================================\n");

    loop {
        println!("Demo Options:");
        println!("1. Run complete demo");
        println!("2. Interactive demo");
        println!("3. Show architecture info");
        println!("4. Quit");

        print!("\nChoice: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => {
                println!();
                let mut demo = AccordDemo::new();
                demo.run_complete_demo();
                println!("\nPress Enter to continue...");
                let mut _input = String::new();
                io::stdin().read_line(&mut _input).unwrap();
            }
            "2" => {
                println!("\n🎯 Interactive Demo");
                println!("(Simplified for standalone version)");
                let mut demo = AccordDemo::new();

                let alice = demo.create_user("Alice".to_string());
                let server = demo.create_server("My Server".to_string(), alice).unwrap();
                let _channel = demo
                    .create_channel(server, "General".to_string(), ChannelType::Lobby, alice)
                    .unwrap();

                println!("✅ Created basic server structure");
                demo.print_status();

                println!("\nPress Enter to continue...");
                let mut _input = String::new();
                io::stdin().read_line(&mut _input).unwrap();
            }
            "3" => {
                println!("\n🏗️ Accord Architecture");
                println!("• Zero-knowledge server design");
                println!("• End-to-end encrypted messaging");
                println!("• Hybrid lobby/private channels");
                println!("• Direct invite system");
                println!("• Privacy-preserving bots");
                println!("• Real-time encrypted voice");
                println!("• Open source & self-hostable");

                println!("\n🔒 This demo shows:");
                println!("• Channel access control");
                println!("• Entry request/approval");
                println!("• Encrypted messaging");
                println!("• Invite generation/usage");
                println!("• Session establishment");

                println!("\n⚠️ Production differences:");
                println!("• Uses audited crypto libraries");
                println!("• Proper key exchange protocols");
                println!("• Forward secrecy");
                println!("• Network protocol implementation");

                println!("\nPress Enter to continue...");
                let mut _input = String::new();
                io::stdin().read_line(&mut _input).unwrap();
            }
            "4" | "q" | "quit" => {
                println!("👋 Thanks for trying Accord!");
                break;
            }
            _ => println!("Invalid choice, please try again.\n"),
        }
    }
}
