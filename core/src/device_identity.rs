//! Deterministic device identity for auth-level device keypair derivation.
//!
//! Unlike `device_fingerprint` (soft signals for ban enforcement), this module
//! uses stable hardware identifiers to derive a deterministic X25519 keypair.
//! Same hardware = same keypair every time. The private key never leaves the device.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Salt for HKDF key derivation — changing this invalidates all existing device keypairs
const HKDF_SALT: &[u8] = b"accord-device-identity-v1";
/// Info string for HKDF — domain separation
const HKDF_INFO: &[u8] = b"x25519-device-key";

/// Result of device identity derivation
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    /// SHA-256 hash of the machine ID (sent to server for anti-alt tracking)
    pub fingerprint_hash: String,
    /// X25519 public key (hex-encoded, sent to server)
    pub public_key_hex: String,
    /// X25519 private key (32 bytes, never leaves device)
    pub private_key: [u8; 32],
    /// Human-readable device label
    pub device_label: String,
}

/// Get the stable machine identifier for the current platform.
///
/// - **Linux:** `/etc/machine-id` (stable across reboots, unique per OS install)
/// - **macOS:** `IOPlatformUUID` via `ioreg`
/// - **Windows:** `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
pub fn get_machine_id() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/machine-id")
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("Failed to read /etc/machine-id: {}", e))
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .map_err(|e| format!("Failed to run ioreg: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(uuid) = line.split('"').nth(3) {
                    return Ok(uuid.to_string());
                }
            }
        }
        Err("IOPlatformUUID not found in ioreg output".to_string())
    }

    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .map_err(|e| format!("Failed to query registry: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("MachineGuid") {
                if let Some(guid) = line.split_whitespace().last() {
                    return Ok(guid.to_string());
                }
            }
        }
        Err("MachineGuid not found in registry".to_string())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err("Unsupported platform for hardware identity".to_string())
    }
}

/// Compute the device fingerprint hash from a machine ID.
/// This is the value sent to the server for anti-alt tracking.
pub fn compute_fingerprint_hash(machine_id: &str) -> String {
    let hash = Sha256::digest(machine_id.as_bytes());
    hex::encode(hash)
}

/// Derive a deterministic X25519 keypair from a machine ID using HKDF.
/// Same machine ID always produces the same keypair.
pub fn derive_device_keypair(machine_id: &str) -> (StaticSecret, PublicKey) {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), machine_id.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("HKDF expand failed — output length is valid");

    let secret = StaticSecret::from(okm);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Derive the full device identity from hardware signals.
/// Returns fingerprint hash, keypair, and device label.
pub fn derive_device_identity() -> Result<DeviceIdentity, String> {
    let machine_id = get_machine_id()?;
    let fingerprint_hash = compute_fingerprint_hash(&machine_id);
    let (secret, public) = derive_device_keypair(&machine_id);

    let device_label = get_device_label();

    Ok(DeviceIdentity {
        fingerprint_hash,
        public_key_hex: hex::encode(public.as_bytes()),
        private_key: secret.to_bytes(),
        device_label,
    })
}

/// Get a human-readable device label from hostname and OS.
fn get_device_label() -> String {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    let os = std::env::consts::OS;
    format!("{} ({})", hostname, os)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_keypair_is_deterministic() {
        let (_, pub1) = derive_device_keypair("test-machine-id-123");
        let (_, pub2) = derive_device_keypair("test-machine-id-123");
        assert_eq!(pub1.as_bytes(), pub2.as_bytes());
    }

    #[test]
    fn different_machine_ids_produce_different_keys() {
        let (_, pub1) = derive_device_keypair("machine-a");
        let (_, pub2) = derive_device_keypair("machine-b");
        assert_ne!(pub1.as_bytes(), pub2.as_bytes());
    }

    #[test]
    fn fingerprint_hash_is_deterministic() {
        let h1 = compute_fingerprint_hash("test-id");
        let h2 = compute_fingerprint_hash("test-id");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn device_label_is_nonempty() {
        let label = get_device_label();
        assert!(!label.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn get_machine_id_works_on_linux() {
        let id = get_machine_id();
        assert!(id.is_ok(), "Failed: {:?}", id);
        assert!(!id.unwrap().is_empty());
    }
}
