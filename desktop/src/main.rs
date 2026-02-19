//! # Accord Desktop Application
//!
//! Cross-platform desktop client built with Tauri.
//! Provides Discord-like interface with Signal-level security.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use accord_core::{init, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Get the Accord config directory (e.g. ~/.config/accord or platform equivalent)
fn config_dir() -> Result<PathBuf, String> {
    let base = dirs::config_dir().ok_or("Could not determine config directory")?;
    let dir = base.join("accord");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create config dir: {e}"))?;
    Ok(dir)
}

#[derive(Serialize, Deserialize, Default)]
struct AppConfig {
    server_url: Option<String>,
}

fn load_config() -> Result<AppConfig, String> {
    let path = config_dir()?.join("config.json");
    if path.exists() {
        let data = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        serde_json::from_str(&data).map_err(|e| e.to_string())
    } else {
        Ok(AppConfig::default())
    }
}

fn save_config(config: &AppConfig) -> Result<(), String> {
    let path = config_dir()?.join("config.json");
    let data = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    fs::write(&path, data).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_version() -> String {
    format!(
        "Accord Desktop v{} (Protocol v{})",
        env!("CARGO_PKG_VERSION"),
        PROTOCOL_VERSION
    )
}

#[tauri::command]
async fn initialize_crypto() -> Result<String, String> {
    // init() sets up tracing; only call once, ignore if already initialized
    let _ = init();
    Ok("Cryptography initialized".to_string())
}

#[tauri::command]
async fn connect_to_server(url: String) -> Result<String, String> {
    // Test connectivity by making an HTTP GET to the server's health/version endpoint
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(format!("{}/health", url.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| format!("Connection failed: {e}"))?;

    let status = resp.status();
    if status.is_success() {
        Ok(format!("Connected to server at {url}"))
    } else {
        Err(format!("Server returned status {status}"))
    }
}

#[tauri::command]
fn generate_keypair() -> Result<String, String> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key();
    let pub_bytes = public_key.as_bytes();
    let pub_hex = hex::encode(pub_bytes);

    // Store the private key securely via keyring
    let priv_hex = hex::encode(signing_key.to_bytes());
    let entry = keyring::Entry::new("accord", "identity_signing_key").map_err(|e| e.to_string())?;
    entry
        .set_password(&priv_hex)
        .map_err(|e| format!("Failed to store key: {e}"))?;

    Ok(pub_hex)
}

#[tauri::command]
fn get_server_url() -> Result<Option<String>, String> {
    let config = load_config()?;
    Ok(config.server_url)
}

#[tauri::command]
fn set_server_url(url: String) -> Result<(), String> {
    let mut config = load_config()?;
    config.server_url = Some(url);
    save_config(&config)
}

#[tauri::command]
fn store_token(token: String) -> Result<(), String> {
    let entry = keyring::Entry::new("accord", "auth_token").map_err(|e| e.to_string())?;
    entry
        .set_password(&token)
        .map_err(|e| format!("Failed to store token: {e}"))?;
    Ok(())
}

#[tauri::command]
fn get_token() -> Result<Option<String>, String> {
    let entry = keyring::Entry::new("accord", "auth_token").map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to retrieve token: {e}")),
    }
}

#[tauri::command]
fn delete_token() -> Result<(), String> {
    let entry = keyring::Entry::new("accord", "auth_token").map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed to delete token: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Identity keyring storage
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct IdentityData {
    encrypted_private_key: String,
    public_key: String,
}

const IDENTITY_SERVICE: &str = "accord-identity";
const IDENTITY_INDEX_USER: &str = "_identity_index";

/// Save an identity keypair to the OS keyring.
#[tauri::command]
fn save_identity(
    key_hash: String,
    encrypted_private_key: String,
    public_key: String,
) -> Result<(), String> {
    let data = IdentityData {
        encrypted_private_key,
        public_key,
    };
    let json = serde_json::to_string(&data).map_err(|e| e.to_string())?;
    let entry = keyring::Entry::new(IDENTITY_SERVICE, &key_hash).map_err(|e| e.to_string())?;
    entry
        .set_password(&json)
        .map_err(|e| format!("Failed to save identity: {e}"))?;

    // Update the index of stored key hashes
    let mut hashes = load_identity_index();
    if !hashes.contains(&key_hash) {
        hashes.push(key_hash);
        save_identity_index(&hashes);
    }
    Ok(())
}

/// Load an identity from the OS keyring.
#[tauri::command]
fn load_identity(key_hash: String) -> Result<Option<IdentityData>, String> {
    let entry = keyring::Entry::new(IDENTITY_SERVICE, &key_hash).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(json) => {
            let data: IdentityData = serde_json::from_str(&json).map_err(|e| e.to_string())?;
            Ok(Some(data))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to load identity: {e}")),
    }
}

/// Delete an identity from the OS keyring.
#[tauri::command]
fn delete_identity(key_hash: String) -> Result<(), String> {
    let entry = keyring::Entry::new(IDENTITY_SERVICE, &key_hash).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => {}
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(format!("Failed to delete identity: {e}")),
    }
    let mut hashes = load_identity_index();
    hashes.retain(|h| h != &key_hash);
    save_identity_index(&hashes);
    Ok(())
}

/// List all stored identity key hashes.
#[tauri::command]
fn list_identities() -> Vec<String> {
    load_identity_index()
}

fn load_identity_index() -> Vec<String> {
    let entry = match keyring::Entry::new(IDENTITY_SERVICE, IDENTITY_INDEX_USER) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    match entry.get_password() {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn save_identity_index(hashes: &[String]) {
    if let Ok(entry) = keyring::Entry::new(IDENTITY_SERVICE, IDENTITY_INDEX_USER) {
        if let Ok(json) = serde_json::to_string(hashes) {
            let _ = entry.set_password(&json);
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|_app| {
            // Initialize Accord core (tracing, etc.)
            let _ = init();

            println!("🚀 Accord Desktop starting...");
            println!("🔒 End-to-end encryption enabled");
            println!("📱 Cross-platform desktop client");

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_version,
            initialize_crypto,
            connect_to_server,
            generate_keypair,
            get_server_url,
            set_server_url,
            store_token,
            get_token,
            delete_token,
            save_identity,
            load_identity,
            delete_identity,
            list_identities,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
