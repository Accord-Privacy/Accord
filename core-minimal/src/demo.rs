//! # Accord Demo
//! 
//! Demonstrates the complete Accord system working together

use crate::{
    crypto_minimal::SimpleCrypto,
    channel_types::{ChannelManager, ChannelType, VoiceAccessType},
    User, Server, AccordMessage, MessageType,
};
use uuid::Uuid;
use std::collections::HashMap;

/// Complete Accord system demonstration
pub struct AccordDemo {
    pub users: HashMap<Uuid, User>,
    pub servers: HashMap<Uuid, Server>,
    pub crypto_instances: HashMap<Uuid, SimpleCrypto>,
    pub channel_managers: HashMap<Uuid, ChannelManager>, // server_id -> channel_manager
}

impl AccordDemo {
    /// Create a new demo instance
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            servers: HashMap::new(),
            crypto_instances: HashMap::new(),
            channel_managers: HashMap::new(),
        }
    }

    /// Create a new user
    pub fn create_user(&mut self, username: String) -> Uuid {
        let user_id = Uuid::new_v4();
        let crypto = SimpleCrypto::new(user_id);
        let public_key_fingerprint = crypto.get_public_fingerprint().to_string();
        
        let user = User {
            id: user_id,
            username,
            public_key_fingerprint,
            created_at: chrono::Utc::now(),
        };

        self.users.insert(user_id, user);
        self.crypto_instances.insert(user_id, crypto);
        
        println!("👤 Created user: {} ({})", self.users[&user_id].username, user_id);
        user_id
    }

    /// Create a new server
    pub fn create_server(&mut self, name: String, owner_id: Uuid) -> Result<Uuid, String> {
        if !self.users.contains_key(&owner_id) {
            return Err("Owner user not found".to_string());
        }

        let server_id = Uuid::new_v4();
        let server = Server {
            id: server_id,
            name: name.clone(),
            member_count: 1, // Owner is first member
            created_at: chrono::Utc::now(),
        };

        let channel_manager = ChannelManager::new();

        self.servers.insert(server_id, server);
        self.channel_managers.insert(server_id, channel_manager);
        
        println!("🏰 Created server: {} ({})", name, server_id);
        Ok(server_id)
    }

    /// Create a channel in a server
    pub fn create_channel(
        &mut self,
        server_id: Uuid,
        name: String,
        channel_type: ChannelType,
        creator_id: Uuid,
    ) -> Result<Uuid, String> {
        let creator = self.users.get(&creator_id)
            .ok_or("Creator user not found")?;
        
        let channel_manager = self.channel_managers.get_mut(&server_id)
            .ok_or("Server not found")?;

        let channel_id = channel_manager.create_channel(
            name.clone(),
            channel_type.clone(),
            creator_id,
            creator.username.clone(),
            None,
        );

        println!("📺 Created channel: {} ({:?}) in server {}", name, channel_type, server_id);
        Ok(channel_id)
    }

    /// Join a lobby channel
    pub fn join_lobby_channel(
        &mut self,
        server_id: Uuid,
        channel_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), String> {
        let user = self.users.get(&user_id)
            .ok_or("User not found")?;
        
        let channel_manager = self.channel_managers.get_mut(&server_id)
            .ok_or("Server not found")?;

        channel_manager.join_lobby_channel(channel_id, user_id, user.username.clone())?;
        
        println!("✅ User {} joined lobby channel {}", user.username, channel_id);
        Ok(())
    }

    /// Request entry to private channel
    pub fn request_private_entry(
        &mut self,
        server_id: Uuid,
        channel_id: Uuid,
        user_id: Uuid,
        message: Option<String>,
    ) -> Result<Uuid, String> {
        let user = self.users.get(&user_id)
            .ok_or("User not found")?;
        
        let channel_manager = self.channel_managers.get_mut(&server_id)
            .ok_or("Server not found")?;

        let request_id = channel_manager.request_entry(
            channel_id,
            user_id,
            user.username.clone(),
            message,
        )?;

        println!("📝 User {} requested entry to private channel {}", user.username, channel_id);
        Ok(request_id)
    }

    /// Approve entry request
    pub fn approve_entry_request(
        &mut self,
        server_id: Uuid,
        request_id: Uuid,
        approver_id: Uuid,
    ) -> Result<(), String> {
        let approver = self.users.get(&approver_id)
            .ok_or("Approver not found")?;
        
        let channel_manager = self.channel_managers.get_mut(&server_id)
            .ok_or("Server not found")?;

        channel_manager.approve_entry(request_id, approver_id)?;
        
        println!("✅ {} approved entry request {}", approver.username, request_id);
        Ok(())
    }

    /// Send encrypted message
    pub fn send_message(
        &mut self,
        sender_id: Uuid,
        recipient_id: Uuid,
        channel_id: Uuid,
        content: &str,
    ) -> Result<AccordMessage, String> {
        let sender_crypto = self.crypto_instances.get_mut(&sender_id)
            .ok_or("Sender crypto not found")?;

        // Encrypt the message
        let plaintext = content.as_bytes();
        let encrypted_envelope = sender_crypto.encrypt_message(recipient_id, plaintext)?;
        let encrypted_payload = serde_json::to_vec(&encrypted_envelope)
            .map_err(|e| format!("Serialization error: {}", e))?;

        let message = AccordMessage {
            id: Uuid::new_v4(),
            message_type: MessageType::TextMessage,
            sender: Some(sender_id),
            channel: Some(channel_id),
            timestamp: chrono::Utc::now(),
            encrypted_payload,
        };

        let sender = &self.users[&sender_id];
        println!("📨 {} sent encrypted message to channel {}", sender.username, channel_id);
        
        Ok(message)
    }

    /// Decrypt and display message
    pub fn receive_message(
        &mut self,
        recipient_id: Uuid,
        message: &AccordMessage,
    ) -> Result<String, String> {
        let recipient_crypto = self.crypto_instances.get(&recipient_id)
            .ok_or("Recipient crypto not found")?;

        let sender_id = message.sender.ok_or("Message missing sender")?;

        // Deserialize encrypted envelope
        let encrypted_envelope: crate::crypto_minimal::EncryptedEnvelope = 
            serde_json::from_slice(&message.encrypted_payload)
                .map_err(|e| format!("Deserialization error: {}", e))?;

        // Decrypt the message
        let decrypted = recipient_crypto.decrypt_message(sender_id, &encrypted_envelope)?;
        let content = String::from_utf8(decrypted)
            .map_err(|_| "Invalid UTF-8 in decrypted message")?;

        let sender = &self.users[&sender_id];
        let recipient = &self.users[&recipient_id];
        println!("📥 {} received message from {}: \"{}\"", recipient.username, sender.username, content);
        
        Ok(content)
    }

    /// Generate server invite
    pub fn generate_invite(
        &mut self,
        server_id: Uuid,
        creator_id: Uuid,
        expires_hours: u32,
    ) -> Result<String, String> {
        let creator_crypto = self.crypto_instances.get(&creator_id)
            .ok_or("Creator crypto not found")?;

        let invite_code = creator_crypto.generate_invite_code(server_id, expires_hours);
        
        let creator = &self.users[&creator_id];
        let server = &self.servers[&server_id];
        println!("🎫 {} created invite for server '{}': {}", creator.username, server.name, invite_code);
        
        Ok(invite_code)
    }

    /// Use server invite
    pub fn use_invite(
        &mut self,
        user_id: Uuid,
        invite_code: &str,
    ) -> Result<(Uuid, chrono::DateTime<chrono::Utc>), String> {
        let user_crypto = self.crypto_instances.get(&user_id)
            .ok_or("User crypto not found")?;

        let (server_id, expires_at, creator_id) = user_crypto.decode_invite(invite_code)?;
        
        let user = &self.users[&user_id];
        let server = &self.servers[&server_id];
        let creator = &self.users[&creator_id];
        
        println!("🎫 {} used invite to join server '{}' (created by {})", 
                user.username, server.name, creator.username);
        
        Ok((server_id, expires_at))
    }

    /// Establish encrypted session between users
    pub fn establish_crypto_session(&mut self, user1_id: Uuid, user2_id: Uuid) -> Result<(), String> {
        // Get public key fingerprints
        let user1_key = self.crypto_instances.get(&user1_id)
            .ok_or("User 1 crypto not found")?
            .get_public_fingerprint().to_string();
        let user2_key = self.crypto_instances.get(&user2_id)
            .ok_or("User 2 crypto not found")?
            .get_public_fingerprint().to_string();

        // Establish sessions
        let crypto1 = self.crypto_instances.get_mut(&user1_id).unwrap();
        let session1 = crypto1.establish_session(user2_id, &user2_key);

        let crypto2 = self.crypto_instances.get_mut(&user2_id).unwrap();
        let session2 = crypto2.establish_session(user1_id, &user1_key);

        let user1 = &self.users[&user1_id];
        let user2 = &self.users[&user2_id];
        
        println!("🔐 Established encrypted session between {} and {}", user1.username, user2.username);
        println!("   Session fingerprints: {} <-> {}", session1, session2);
        
        Ok(())
    }

    /// Run complete demo scenario
    pub fn run_complete_demo(&mut self) {
        println!("🚀 Starting Accord Complete Demo\n");

        // Create users
        let alice_id = self.create_user("Alice".to_string());
        let bob_id = self.create_user("Bob".to_string());
        let charlie_id = self.create_user("Charlie".to_string());
        println!();

        // Create server
        let server_id = self.create_server("Demo Server".to_string(), alice_id).unwrap();
        println!();

        // Create channels
        let lobby_channel = self.create_channel(
            server_id, 
            "General".to_string(), 
            ChannelType::Lobby, 
            alice_id
        ).unwrap();

        let voice_lobby = self.create_channel(
            server_id,
            "Voice Lobby".to_string(),
            ChannelType::Voice { access_type: VoiceAccessType::Lobby },
            alice_id
        ).unwrap();

        let private_channel = self.create_channel(
            server_id,
            "Staff Only".to_string(),
            ChannelType::Private { visible_in_list: true },
            alice_id
        ).unwrap();
        println!();

        // Bob joins lobby channels
        self.join_lobby_channel(server_id, lobby_channel, bob_id).unwrap();
        self.join_lobby_channel(server_id, voice_lobby, bob_id).unwrap();
        println!();

        // Charlie requests private channel access
        let request_id = self.request_private_entry(
            server_id,
            private_channel,
            charlie_id,
            Some("I'd like to help with moderation!".to_string()),
        ).unwrap();

        // Alice approves Charlie's request
        self.approve_entry_request(server_id, request_id, alice_id).unwrap();
        println!();

        // Establish crypto sessions
        self.establish_crypto_session(alice_id, bob_id).unwrap();
        self.establish_crypto_session(alice_id, charlie_id).unwrap();
        println!();

        // Send encrypted messages
        let msg1 = self.send_message(alice_id, bob_id, lobby_channel, "Welcome to Accord, Bob!").unwrap();
        self.receive_message(bob_id, &msg1).unwrap();

        let msg2 = self.send_message(alice_id, charlie_id, private_channel, "Thanks for joining the staff team!").unwrap();
        self.receive_message(charlie_id, &msg2).unwrap();
        println!();

        // Create and use invite
        let invite_code = self.generate_invite(server_id, alice_id, 24).unwrap();
        let dave_id = self.create_user("Dave".to_string());
        self.use_invite(dave_id, &invite_code).unwrap();
        println!();

        println!("✅ Accord demo completed successfully!");
        println!("🔒 All messages were end-to-end encrypted");
        println!("🏰 Hybrid channel system demonstrated");
        println!("🎫 Private invite system working");
        println!("👥 Entry request/approval workflow tested");
    }

    /// Print system status
    pub fn print_status(&self) {
        println!("\n=== Accord System Status ===");
        println!("👥 Users: {}", self.users.len());
        println!("🏰 Servers: {}", self.servers.len());
        
        for (server_id, channel_manager) in &self.channel_managers {
            let server = &self.servers[server_id];
            let visible_channels = channel_manager.get_visible_channels(Uuid::new_v4()); // Get all channels
            println!("📺 Server '{}': {} channels", server.name, visible_channels.len());
        }
        
        println!("🔐 Crypto instances: {}", self.crypto_instances.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_demo() {
        let mut demo = AccordDemo::new();
        demo.run_complete_demo();
        
        // Verify the demo created the expected entities
        assert_eq!(demo.users.len(), 4); // Alice, Bob, Charlie, Dave
        assert_eq!(demo.servers.len(), 1);
        assert_eq!(demo.crypto_instances.len(), 4);
    }

    #[test]
    fn test_encrypted_messaging() {
        let mut demo = AccordDemo::new();
        
        let alice_id = demo.create_user("Alice".to_string());
        let bob_id = demo.create_user("Bob".to_string());
        let server_id = demo.create_server("Test".to_string(), alice_id).unwrap();
        let channel_id = demo.create_channel(server_id, "Test".to_string(), ChannelType::Text, alice_id).unwrap();
        
        // Establish crypto session
        demo.establish_crypto_session(alice_id, bob_id).unwrap();
        
        // Send and receive message
        let message = demo.send_message(alice_id, bob_id, channel_id, "Hello, Bob!").unwrap();
        let decrypted = demo.receive_message(bob_id, &message).unwrap();
        
        assert_eq!(decrypted, "Hello, Bob!");
    }
}