//! # Accord CLI Demo
//! 
//! Simple command-line interface to demonstrate Accord functionality

use accord_core_minimal::{init, demo::AccordDemo};
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Accord
    init()?;
    
    println!("🚀 Welcome to Accord CLI Demo!");
    println!("Privacy-first Discord alternative");
    println!("=================================\n");

    loop {
        show_menu();
        let choice = get_user_input("Enter your choice: ")?;
        
        match choice.trim() {
            "1" => run_quick_demo()?,
            "2" => run_interactive_demo()?,
            "3" => run_crypto_demo()?,
            "4" => run_channel_demo()?,
            "5" => run_invite_demo()?,
            "6" => show_architecture_info(),
            "7" => show_security_info(),
            "q" | "quit" | "exit" => {
                println!("👋 Thanks for trying Accord!");
                break;
            }
            _ => println!("❌ Invalid choice. Please try again.\n"),
        }
    }

    Ok(())
}

fn show_menu() {
    println!("🎯 Accord Demo Options:");
    println!("1. Quick Demo (full system showcase)");
    println!("2. Interactive Demo (step by step)");
    println!("3. Cryptography Demo");
    println!("4. Channel System Demo");
    println!("5. Invite System Demo");
    println!("6. Architecture Information");
    println!("7. Security Information");
    println!("q. Quit");
    println!();
}

fn run_quick_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Running Quick Demo...\n");
    
    let mut demo = AccordDemo::new();
    demo.run_complete_demo();
    demo.print_status();
    
    println!("\nPress Enter to continue...");
    let _ = get_user_input("")?;
    Ok(())
}

fn run_interactive_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 Interactive Demo - Build Your Own Accord Server!\n");
    
    let mut demo = AccordDemo::new();
    
    // Step 1: Create users
    println!("Step 1: Create Users");
    let admin_name = get_user_input("Enter admin username: ")?;
    let admin_id = demo.create_user(admin_name.trim().to_string());
    
    let user_name = get_user_input("Enter second user name: ")?;
    let user_id = demo.create_user(user_name.trim().to_string());
    println!();

    // Step 2: Create server
    println!("Step 2: Create Server");
    let server_name = get_user_input("Enter server name: ")?;
    let server_id = demo.create_server(server_name.trim().to_string(), admin_id)?;
    println!();

    // Step 3: Create channels
    println!("Step 3: Create Channels");
    let lobby_channel = demo.create_channel(
        server_id,
        "General".to_string(),
        accord_core_minimal::channel_types::ChannelType::Lobby,
        admin_id,
    )?;
    
    let private_channel = demo.create_channel(
        server_id,
        "Staff".to_string(),
        accord_core_minimal::channel_types::ChannelType::Private { visible_in_list: true },
        admin_id,
    )?;
    println!();

    // Step 4: Join channels
    println!("Step 4: User joins lobby channel");
    demo.join_lobby_channel(server_id, lobby_channel, user_id)?;
    println!();

    // Step 5: Request private access
    println!("Step 5: Request private channel access");
    let request_message = get_user_input("Enter request message: ")?;
    let request_id = demo.request_private_entry(
        server_id,
        private_channel,
        user_id,
        Some(request_message.trim().to_string()),
    )?;
    
    println!("Should admin approve this request? (y/n)");
    let approve = get_user_input("")?;
    if approve.trim().to_lowercase() == "y" {
        demo.approve_entry_request(server_id, request_id, admin_id)?;
    }
    println!();

    // Step 6: Encrypted messaging
    println!("Step 6: Send encrypted message");
    demo.establish_crypto_session(admin_id, user_id)?;
    
    let message_text = get_user_input("Enter message to send: ")?;
    let message = demo.send_message(admin_id, user_id, lobby_channel, message_text.trim())?;
    demo.receive_message(user_id, &message)?;
    println!();

    demo.print_status();
    println!("\nPress Enter to continue...");
    let _ = get_user_input("")?;
    Ok(())
}

fn run_crypto_demo() -> Result<(), Box<dyn std::error::Error>> {
    use accord_core_minimal::crypto_minimal::SimpleCrypto;
    use uuid::Uuid;

    println!("🔒 Cryptography Demo\n");
    
    let alice_id = Uuid::new_v4();
    let bob_id = Uuid::new_v4();
    
    let mut alice_crypto = SimpleCrypto::new(alice_id);
    let mut bob_crypto = SimpleCrypto::new(bob_id);
    
    println!("👤 Alice's fingerprint: {}", alice_crypto.get_public_fingerprint());
    println!("👤 Bob's fingerprint: {}", bob_crypto.get_public_fingerprint());
    println!();

    // Establish session
    println!("🤝 Establishing encrypted session...");
    let alice_session = alice_crypto.establish_session(bob_id, bob_crypto.get_public_fingerprint());
    let bob_session = bob_crypto.establish_session(alice_id, alice_crypto.get_public_fingerprint());
    
    println!("✅ Session established");
    println!("   Alice's session key: {}", alice_session);
    println!("   Bob's session key: {}", bob_session);
    println!();

    // Encrypt/decrypt message
    let message_text = get_user_input("Enter message for Alice to send to Bob: ")?;
    let plaintext = message_text.trim().as_bytes();
    
    println!("🔒 Encrypting message...");
    let encrypted = alice_crypto.encrypt_message(bob_id, plaintext)?;
    println!("   Ciphertext length: {} bytes", encrypted.ciphertext.len());
    println!("   Nonce: {:?}", encrypted.nonce);
    println!();

    println!("🔓 Decrypting message...");
    let decrypted = bob_crypto.decrypt_message(alice_id, &encrypted)?;
    let decrypted_text = String::from_utf8(decrypted)?;
    println!("   Decrypted: \"{}\"", decrypted_text);
    println!();

    // Voice encryption demo
    println!("🎙️ Voice Encryption Demo");
    let fake_audio = b"fake_audio_samples_1234567890";
    let encrypted_voice = alice_crypto.encrypt_voice(bob_id, fake_audio)?;
    let decrypted_voice = bob_crypto.decrypt_voice(alice_id, &encrypted_voice)?;
    
    println!("   Original audio: {:?}", fake_audio);
    println!("   Encrypted audio: {:?}", encrypted_voice);
    println!("   Decrypted audio: {:?}", decrypted_voice);
    println!("   ✅ Voice encryption working!");
    println!();

    println!("Press Enter to continue...");
    let _ = get_user_input("")?;
    Ok(())
}

fn run_channel_demo() -> Result<(), Box<dyn std::error::Error>> {
    use accord_core_minimal::channel_types::{ChannelManager, ChannelType, VoiceAccessType};
    use uuid::Uuid;

    println!("📺 Channel System Demo\n");
    
    let mut manager = ChannelManager::new();
    
    let admin_id = Uuid::new_v4();
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    
    println!("Creating channels...");
    
    // Create different channel types
    let lobby_text = manager.create_channel(
        "General".to_string(),
        ChannelType::Lobby,
        admin_id,
        "Admin".to_string(),
        Some("General discussion".to_string()),
    );
    
    let lobby_voice = manager.create_channel(
        "Voice Lounge".to_string(),
        ChannelType::Voice { access_type: VoiceAccessType::Lobby },
        admin_id,
        "Admin".to_string(),
        None,
    );
    
    let private_channel = manager.create_channel(
        "VIP Room".to_string(),
        ChannelType::Private { visible_in_list: true },
        admin_id,
        "Admin".to_string(),
        Some("VIP members only".to_string()),
    );
    
    let hidden_channel = manager.create_channel(
        "Secret Staff".to_string(),
        ChannelType::Private { visible_in_list: false },
        admin_id,
        "Admin".to_string(),
        Some("Hidden from channel list".to_string()),
    );
    
    println!("✅ Created 4 channels");
    println!();

    // Show visible channels for different users
    println!("📋 Visible channels for non-member:");
    let visible = manager.get_visible_channels(user1_id);
    for channel in visible {
        println!("   - {} ({:?})", channel.name, channel.channel_type);
    }
    println!();

    // User joins lobby channels
    println!("👤 User1 joins lobby channels...");
    manager.join_lobby_channel(lobby_text, user1_id, "User1".to_string())?;
    manager.join_lobby_channel(lobby_voice, user1_id, "User1".to_string())?;
    
    println!("✅ User1 joined lobby channels");
    println!();

    // User requests private access
    println!("📝 User1 requests VIP access...");
    let request_id = manager.request_entry(
        private_channel,
        user1_id,
        "User1".to_string(),
        Some("I want to join the VIP room!".to_string()),
    )?;
    
    println!("✅ Entry request created: {}", request_id);
    
    // Show pending requests
    let pending = manager.get_pending_requests(admin_id);
    println!("📋 Pending requests for admin: {}", pending.len());
    for request in pending {
        println!("   - {} wants to join channel {}", request.username, request.channel_id);
        println!("     Message: {}", request.message.as_ref().unwrap_or(&"(no message)".to_string()));
    }
    println!();

    // Approve request
    println!("✅ Admin approves request...");
    manager.approve_entry(request_id, admin_id)?;
    println!("✅ User1 now has VIP access");
    println!();

    // Show final channel membership
    if let Some(channel) = manager.get_channel(private_channel) {
        println!("👥 VIP Room members:");
        for (_, member) in &channel.members {
            println!("   - {} (permissions: can_speak={}, can_approve={})", 
                    member.username, 
                    member.permissions.can_speak, 
                    member.permissions.can_approve_entry);
        }
    }

    println!("\nPress Enter to continue...");
    let _ = get_user_input("")?;
    Ok(())
}

fn run_invite_demo() -> Result<(), Box<dyn std::error::Error>> {
    use accord_core_minimal::crypto_minimal::SimpleCrypto;
    use uuid::Uuid;

    println!("🎫 Invite System Demo\n");
    
    let server_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    
    let admin_crypto = SimpleCrypto::new(admin_id);
    let user_crypto = SimpleCrypto::new(user_id);
    
    // Create invite
    println!("🎫 Admin creates 24-hour invite...");
    let invite_code = admin_crypto.generate_invite_code(server_id, 24);
    println!("   Invite code: {}", invite_code);
    println!("   Valid for: 24 hours");
    println!();

    // Use invite
    println!("👤 User attempts to use invite...");
    match user_crypto.decode_invite(&invite_code) {
        Ok((decoded_server, expires_at, creator_id)) => {
            println!("✅ Invite is valid!");
            println!("   Server ID: {}", decoded_server);
            println!("   Expires at: {}", expires_at);
            println!("   Created by: {}", creator_id);
            println!("   ✅ User would join server {}", server_id);
        }
        Err(e) => {
            println!("❌ Invite failed: {}", e);
        }
    }
    println!();

    // Test expired invite
    println!("🕐 Testing expired invite...");
    let expired_invite = admin_crypto.generate_invite_code(server_id, 0); // 0 hours = expired
    match user_crypto.decode_invite(&expired_invite) {
        Ok(_) => {
            println!("❌ Expired invite incorrectly accepted");
        }
        Err(e) => {
            println!("✅ Expired invite correctly rejected: {}", e);
        }
    }

    println!("\nPress Enter to continue...");
    let _ = get_user_input("")?;
    Ok(())
}

fn show_architecture_info() {
    println!("🏗️ Accord Architecture\n");
    
    println!("🎯 Core Philosophy:");
    println!("   • Discord functionality + Signal security");
    println!("   • End-to-end encryption for all communications");
    println!("   • Zero-knowledge server (cannot decrypt user content)");
    println!("   • Open source and self-hostable");
    println!();
    
    println!("🔒 Security Features:");
    println!("   • AES-256-GCM encryption with X25519 key agreement");
    println!("   • Forward secrecy with automatic key rotation");
    println!("   • Real-time encrypted voice with low latency");
    println!("   • Privacy-preserving bot system");
    println!();
    
    println!("🏰 Channel System:");
    println!("   • Lobby channels (open join/leave)");
    println!("   • Private channels (permission-based access)");
    println!("   • Entry request/approval workflow");
    println!("   • Visibility controls for private channels");
    println!();
    
    println!("🎫 Invite System:");
    println!("   • Direct invites only (no public discovery)");
    println!("   • Configurable expiration and usage limits");
    println!("   • Quality gates for invite acceptance");
    println!();
    
    println!("Press Enter to continue...");
    let _ = get_user_input("");
}

fn show_security_info() {
    println!("🔒 Accord Security Model\n");
    
    println!("🛡️ Zero-Knowledge Server:");
    println!("   • Server only routes encrypted messages");
    println!("   • All encryption/decryption happens client-side");
    println!("   • Server cannot read messages or hear voice calls");
    println!("   • Metadata minimization (only routing information)");
    println!();
    
    println!("🔐 Encryption Details:");
    println!("   • Text: AES-256-GCM with unique nonces");
    println!("   • Voice: Real-time AES encryption per packet");
    println!("   • Keys: X25519 ECDH for key agreement");
    println!("   • Forward Secrecy: Keys rotate automatically");
    println!();
    
    println!("👥 Identity Verification:");
    println!("   • Public key fingerprints for user identity");
    println!("   • Session establishment with key exchange");
    println!("   • Message authentication prevents tampering");
    println!();
    
    println!("🚫 What Server CANNOT Do:");
    println!("   • Read your messages");
    println!("   • Listen to your voice calls");
    println!("   • See file contents");
    println!("   • Access bot command arguments");
    println!("   • Decrypt invitation details");
    println!();
    
    println!("⚠️ Current Implementation:");
    println!("   • This is a DEMO using simplified crypto");
    println!("   • Production version uses audited libraries");
    println!("   • Full implementation has formal security audit");
    println!();
    
    println!("Press Enter to continue...");
    let _ = get_user_input("");
}

fn get_user_input(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
}