//! # Accord Desktop Application
//! 
//! Cross-platform desktop client built with Tauri.
//! Provides Discord-like interface with Signal-level security.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use accord_core::{init, PROTOCOL_VERSION};

#[tauri::command]
fn get_version() -> String {
    format!("Accord Desktop v{} (Protocol v{})", 
            env!("CARGO_PKG_VERSION"), 
            PROTOCOL_VERSION)
}

#[tauri::command]
async fn initialize_crypto() -> Result<String, String> {
    init().map_err(|e| e.to_string())?;
    Ok("Cryptography initialized".to_string())
}

fn main() {
    tauri::Builder::default()
        .setup(|_app| {
            // Initialize Accord core
            init().expect("Failed to initialize Accord core");
            
            println!("🚀 Accord Desktop starting...");
            println!("🔒 End-to-end encryption enabled");
            println!("📱 Cross-platform desktop client");
            
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_version,
            initialize_crypto
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}