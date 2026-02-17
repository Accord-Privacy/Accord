//! Device fingerprinting for ban enforcement
//!
//! Collects device-level signals, hashes them into a single fingerprint hash,
//! and transmits ONLY the hash to the relay. Raw signals never leave the device.
//!
//! See `docs/device-fingerprinting.md` for the full transparency document.

use sha2::{Digest, Sha256};

/// Signals collected from the device for fingerprinting.
///
/// **IMPORTANT:** Only the SHA-256 hash of these signals is ever transmitted.
/// The raw values stay on-device and are never sent to any server.
#[derive(Debug, Clone)]
pub struct DeviceFingerprint {
    /// Platform-specific device identifier (e.g., Android ID, Windows MachineGuid)
    pub device_id: String,
    /// Screen resolution (e.g., "1920x1080")
    pub screen_resolution: String,
    /// IANA timezone name (e.g., "America/New_York")
    pub timezone: String,
    /// GPU renderer string from the graphics driver
    pub gpu_renderer: String,
    /// Operating system version string (e.g., "Windows 11 23H2", "Android 14")
    pub os_version: String,
    /// System locale (e.g., "en-US")
    pub locale: String,
}

impl DeviceFingerprint {
    /// Compute the SHA-256 fingerprint hash from all signals.
    ///
    /// Signals are concatenated with a null byte separator to prevent ambiguity,
    /// then hashed. Returns the hex-encoded hash string.
    ///
    /// This is the ONLY value that leaves the device.
    pub fn compute_fingerprint_hash(&self) -> String {
        let mut hasher = Sha256::new();
        // Use null byte separator to prevent signal boundary ambiguity
        hasher.update(self.device_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.screen_resolution.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.timezone.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.gpu_renderer.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.os_version.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.locale.as_bytes());

        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Returns a human-readable disclosure of exactly what signals are collected.
    ///
    /// This is shown to the user before fingerprinting so they know exactly
    /// what data contributes to their fingerprint hash.
    pub fn fingerprint_disclosure() -> &'static str {
        r#"Accord Device Fingerprinting — Transparency Disclosure

The following device signals are collected to generate your fingerprint hash:

  1. Device ID — A platform-specific device identifier
     (e.g., Android ID, Windows MachineGuid)
  2. Screen Resolution — Your display resolution (e.g., "1920x1080")
  3. Timezone — Your IANA timezone name (e.g., "America/New_York")
  4. GPU Renderer — Your graphics driver renderer string
  5. OS Version — Your operating system version string
  6. Locale — Your system locale (e.g., "en-US")

How it works:
  - These signals are concatenated and hashed with SHA-256
  - ONLY the resulting hash (a 64-character hex string) leaves your device
  - The raw signal values are NEVER transmitted to any server
  - The hash is stored encrypted with the Node's metadata key
  - Only the Node admin can associate it with your membership

What it's used for:
  - Ban enforcement only — if you are banned from a Node, the fingerprint
    hash prevents circumvention by creating a new keypair
  - It is NOT used for tracking, analytics, or advertising

Scope:
  - Fingerprint hashes are per-Node — they are NOT shared between Nodes
  - There is no global fingerprint database
  - Node admins can choose whether to require fingerprinting

The fingerprinting code is open source. You can audit the exact function
that computes your hash in: core/src/device_fingerprint.rs"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_hash_deterministic() {
        let fp = DeviceFingerprint {
            device_id: "abc123".to_string(),
            screen_resolution: "1920x1080".to_string(),
            timezone: "America/New_York".to_string(),
            gpu_renderer: "NVIDIA GeForce RTX 3080".to_string(),
            os_version: "Windows 11 23H2".to_string(),
            locale: "en-US".to_string(),
        };
        let hash1 = fp.compute_fingerprint_hash();
        let hash2 = fp.compute_fingerprint_hash();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_fingerprint_hash_differs_on_different_input() {
        let fp1 = DeviceFingerprint {
            device_id: "device-a".to_string(),
            screen_resolution: "1920x1080".to_string(),
            timezone: "UTC".to_string(),
            gpu_renderer: "Intel UHD 630".to_string(),
            os_version: "Linux 6.8".to_string(),
            locale: "en-US".to_string(),
        };
        let fp2 = DeviceFingerprint {
            device_id: "device-b".to_string(),
            screen_resolution: "1920x1080".to_string(),
            timezone: "UTC".to_string(),
            gpu_renderer: "Intel UHD 630".to_string(),
            os_version: "Linux 6.8".to_string(),
            locale: "en-US".to_string(),
        };
        assert_ne!(
            fp1.compute_fingerprint_hash(),
            fp2.compute_fingerprint_hash()
        );
    }

    #[test]
    fn test_fingerprint_hash_is_valid_hex() {
        let fp = DeviceFingerprint {
            device_id: "test".to_string(),
            screen_resolution: "800x600".to_string(),
            timezone: "Europe/London".to_string(),
            gpu_renderer: "Mesa".to_string(),
            os_version: "Android 14".to_string(),
            locale: "fr-FR".to_string(),
        };
        let hash = fp.compute_fingerprint_hash();
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_separator_prevents_ambiguity() {
        // "ab" + "cd" should differ from "a" + "bcd" because of null separators
        let fp1 = DeviceFingerprint {
            device_id: "ab".to_string(),
            screen_resolution: "cd".to_string(),
            timezone: "".to_string(),
            gpu_renderer: "".to_string(),
            os_version: "".to_string(),
            locale: "".to_string(),
        };
        let fp2 = DeviceFingerprint {
            device_id: "a".to_string(),
            screen_resolution: "bcd".to_string(),
            timezone: "".to_string(),
            gpu_renderer: "".to_string(),
            os_version: "".to_string(),
            locale: "".to_string(),
        };
        assert_ne!(
            fp1.compute_fingerprint_hash(),
            fp2.compute_fingerprint_hash()
        );
    }

    #[test]
    fn test_disclosure_is_not_empty() {
        let disclosure = DeviceFingerprint::fingerprint_disclosure();
        assert!(disclosure.contains("SHA-256"));
        assert!(disclosure.contains("Device ID"));
        assert!(disclosure.contains("Screen Resolution"));
        assert!(disclosure.contains("NEVER transmitted"));
    }
}
