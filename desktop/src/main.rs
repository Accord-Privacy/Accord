//! # Accord Desktop Application
//!
//! Cross-platform desktop client built with Tauri.
//! Provides Discord-like interface with Signal-level security.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod save_attachment;

use accord_core::{init, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

/// True only while the user is in a voice call. Gates the WebKitGTK
/// user-media permission handler (`decide_user_media`): microphone requests
/// and display-capture requests (Share Screen, SPEC-03 REQ-57) are allowed
/// only while it is set, so an XSS payload cannot silently open the mic or
/// capture the screen outside a call. Camera requests are always denied.
static VOICE_CAPTURE_ARMED: AtomicBool = AtomicBool::new(false);

/// Called by the frontend when it joins or leaves a voice channel, arming or
/// disarming capture. While armed, microphone and display-capture requests
/// are allowed; a display-capture request still goes through the platform's
/// own picker, so the user chooses what is shared. Camera is never granted:
/// Accord has no camera feature.
#[tauri::command]
fn set_voice_capture_armed(armed: bool) {
    VOICE_CAPTURE_ARMED.store(armed, Ordering::SeqCst);
}

/// Whether this desktop app can capture the screen for Share Screen
/// (SPEC-03 REQ-57, §6.13.1). The frontend runs it once per voice session,
/// before its capture probe and never from the Share Screen click handler,
/// which must call `getDisplayMedia` before any `await` (REQ-43).
///
/// - Linux (WebKitGTK): true. The permission handler allows display capture
///   during calls, and WebKitGTK captures through PipeWire and the desktop
///   portal, whose picker the user sees.
/// - Windows (WebView2): true. WebView2 shows its own screen-capture UI; the
///   shell neither suppresses nor auto-approves it.
/// - macOS (WKWebView): false. WKWebView has no public display-capture
///   permission, so the macOS app offers viewing only (OD-112, Q17); there is
///   no native capture code and no private API.
/// - Any other target: false.
#[tauri::command]
fn display_capture_supported() -> bool {
    display_capture_supported_on(std::env::consts::OS)
}

/// `display_capture_supported` for a given `std::env::consts::OS` value.
fn display_capture_supported_on(target_os: &str) -> bool {
    matches!(target_os, "linux" | "windows")
}

/// What the WebKitGTK permission handler answers to a user-media request.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MediaPermission {
    Allow,
    Deny,
}

/// The decision of the Linux user-media permission handler (SPEC-03 REQ-57).
///
/// The display flag is tested first: WebKitGTK does not document how it sets
/// the video flag on a display-capture request, so a `getDisplayMedia`
/// request must never reach the camera test. Then:
///
/// - display capture: allowed only while a call is armed;
/// - video (camera): always denied, also when combined with audio;
/// - audio (microphone): allowed only while a call is armed;
/// - a request that names none of them: denied.
#[cfg(any(target_os = "linux", test))]
fn decide_user_media(
    is_display: bool,
    is_video: bool,
    is_audio: bool,
    armed: bool,
) -> MediaPermission {
    if is_display {
        return if armed {
            MediaPermission::Allow
        } else {
            MediaPermission::Deny
        };
    }
    if is_video {
        return MediaPermission::Deny;
    }
    if is_audio && armed {
        MediaPermission::Allow
    } else {
        MediaPermission::Deny
    }
}

/// Whether a WebKitGTK user-media request is for a display device, through
/// `webkit_user_media_permission_is_for_display_device` (WebKitGTK 2.34 and
/// later). The safe permission-request trait of the locked `webkit2gtk` 2.0.2
/// offers only the audio and video flags, so this is the shell's one raw call
/// into WebKitGTK, made through the crate's `webkit2gtk-sys` bindings
/// (re-exported as `webkit2gtk::ffi`).
///
/// # Safety
///
/// `request` must point to a live `WebKitUserMediaPermissionRequest` for the
/// duration of the call. The function only reads the request.
#[cfg(target_os = "linux")]
unsafe fn request_is_for_display_device(
    request: *mut webkit2gtk::ffi::WebKitUserMediaPermissionRequest,
) -> bool {
    webkit2gtk::ffi::webkit_user_media_permission_is_for_display_device(request) != 0
}

/// Screenshot protection: exclude the window from OS screen capture / recording.
/// Enforced by the compositor — reliable on Windows (WDA_EXCLUDEFROMCAPTURE) and
/// macOS (NSWindowSharingNone); on Linux/Wayland most compositors ignore it, so
/// it's friction, not a hard boundary (the UI says as much). Applied per the
/// viewed channel's policy, so it toggles as the user moves between channels.
#[tauri::command]
fn set_content_protected(window: tauri::Window, enabled: bool) -> Result<(), String> {
    window
        .set_content_protected(enabled)
        .map_err(|e| e.to_string())
}

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
// Storage master key (at-rest key hardening)
// ---------------------------------------------------------------------------
//
// A per-user random 256-bit secret held in the OS keyring. The frontend mixes
// it (as an HKDF salt) with the user's password to derive the keys that
// encrypt local stores. This makes at-rest encryption two-factor: deriving
// anything requires BOTH the password (knowledge) AND this device secret
// (possession). A locked, seized device cannot recover history without the
// password, and a leaked password is useless without the device's keyring.

const SMK_SERVICE: &str = "accord-smk";

/// Fetch the user's storage master key, creating a fresh random one on first
/// use. Returned base64-encoded (32 random bytes).
#[tauri::command]
fn get_or_create_smk(user_id: String) -> Result<String, String> {
    use base64::Engine;
    let entry = keyring::Entry::new(SMK_SERVICE, &user_id).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(existing) => Ok(existing),
        Err(keyring::Error::NoEntry) => {
            let mut bytes = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            entry
                .set_password(&b64)
                .map_err(|e| format!("Failed to store storage master key: {e}"))?;
            Ok(b64)
        }
        Err(e) => Err(format!("Failed to read storage master key: {e}")),
    }
}

/// Delete the user's storage master key (used by account deletion / panic-wipe).
#[tauri::command]
fn delete_smk(user_id: String) -> Result<(), String> {
    let entry = keyring::Entry::new(SMK_SERVICE, &user_id).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed to delete storage master key: {e}")),
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

/// Device identity response for the frontend
#[derive(Serialize)]
struct DeviceIdentityResponse {
    device_fingerprint_hash: String,
    device_public_key: String,
    device_label: String,
}

/// Get deterministic device identity derived from hardware signals.
/// Same device always returns the same keypair and fingerprint.
#[tauri::command]
fn get_device_identity() -> Result<DeviceIdentityResponse, String> {
    let identity = accord_core::device_identity::derive_device_identity()?;
    Ok(DeviceIdentityResponse {
        device_fingerprint_hash: identity.fingerprint_hash,
        device_public_key: identity.public_key_hex,
        device_label: identity.device_label,
    })
}

fn main() {
    // WebKitGTK's DMA-BUF renderer fails on NVIDIA proprietary drivers
    // ("Failed to create GBM buffer"), leaving a blank window. Disable it
    // when the NVIDIA kernel module is present, unless the user already set
    // the variable themselves.
    #[cfg(target_os = "linux")]
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none()
        && std::path::Path::new("/proc/driver/nvidia/version").exists()
    {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            // Initialize Accord core (tracing, etc.)
            let _ = init();

            println!("🚀 Accord Desktop starting...");
            println!("🔒 End-to-end encryption enabled");
            println!("📱 Cross-platform desktop client");

            // WebKitGTK has no permission UI in a plain webview, so every
            // getUserMedia and getDisplayMedia request reaches this handler,
            // and without it voice chat and screen sharing could not work.
            // It grants them narrowly (SPEC-03 REQ-57, decide_user_media):
            // display-capture requests (Share Screen) and microphone requests
            // are allowed *only while the user has joined a voice channel*
            // (VOICE_CAPTURE_ARMED, set by the frontend via
            // set_voice_capture_armed), and camera requests are always denied
            // (there is no camera feature). Display capture is classified
            // before the camera test, because WebKitGTK does not document how
            // it sets the video flag on a display-capture request; the desktop
            // portal's picker still lets the user choose what is shared. This
            // keeps an XSS payload from silently opening the mic or capturing
            // the screen outside a call, despite the strong CSP. WebRTC peer
            // connections stay off (enable-webrtc pinned to its documented
            // default, false) as defense in depth: the client never builds
            // one (REQ-39). ACCORD_MOCK_MEDIA=1 additionally swaps in WebKit's
            // mock capture devices so automated tests can join voice without
            // real hardware.
            #[cfg(target_os = "linux")]
            {
                use tauri::Manager;
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.with_webview(|webview| {
                        use webkit2gtk::glib::object::{Cast as _, ObjectType as _};
                        use webkit2gtk::{PermissionRequestExt, SettingsExt, WebViewExt};
                        let wv = webview.inner();
                        if let Some(settings) = WebViewExt::settings(&wv) {
                            settings.set_enable_webrtc(false);
                            if std::env::var("ACCORD_MOCK_MEDIA").as_deref() == Ok("1") {
                                settings.set_enable_mock_capture_devices(true);
                            }
                        }
                        wv.connect_permission_request(|_, request| {
                            use webkit2gtk::UserMediaPermissionRequest;
                            use webkit2gtk::UserMediaPermissionRequestExt;
                            let Some(media_req) =
                                request.dynamic_cast_ref::<UserMediaPermissionRequest>()
                            else {
                                return false;
                            };
                            // SAFETY: `media_req` borrows a live
                            // WebKitUserMediaPermissionRequest for this whole
                            // call, and the function only reads it.
                            let is_display =
                                unsafe { request_is_for_display_device(media_req.as_ptr()) };
                            let decision = decide_user_media(
                                is_display,
                                media_req.is_for_video_device(),
                                media_req.is_for_audio_device(),
                                VOICE_CAPTURE_ARMED.load(Ordering::SeqCst),
                            );
                            match decision {
                                MediaPermission::Allow => request.allow(),
                                MediaPermission::Deny => request.deny(),
                            }
                            true
                        });
                    });
                }
            }
            #[cfg(not(target_os = "linux"))]
            let _ = app;

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
            get_device_identity,
            set_voice_capture_armed,
            display_capture_supported,
            set_content_protected,
            get_or_create_smk,
            delete_smk,
            save_attachment::save_attachment,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    //! SPEC-03 T-57 (REQ-57), the shell part: the Linux decision function,
    //! the `display_capture_supported` report, and the static checks of the
    //! T-57 "CI grep" over this file. The release-checklist part of T-57
    //! (probes and manual shares on each platform) is manual.

    use super::*;

    use MediaPermission::{Allow, Deny};

    #[test]
    fn t57_decide_user_media_table() {
        // (is_display, is_video, is_audio, armed) -> expected
        let cases = [
            // Display capture and armed: allow.
            ((true, false, false, true), Allow),
            // Display capture and not armed: deny.
            ((true, false, false, false), Deny),
            // Video (camera): deny, armed or not, alone or with audio.
            ((false, true, false, true), Deny),
            ((false, true, false, false), Deny),
            ((false, true, true, true), Deny),
            ((false, true, true, false), Deny),
            // Audio and armed: allow. Audio and not armed: deny.
            ((false, false, true, true), Allow),
            ((false, false, true, false), Deny),
            // A request that names no device: deny.
            ((false, false, false, true), Deny),
            ((false, false, false, false), Deny),
        ];
        for ((display, video, audio, armed), expected) in cases {
            assert_eq!(
                decide_user_media(display, video, audio, armed),
                expected,
                "display={display} video={video} audio={audio} armed={armed}"
            );
        }
    }

    #[test]
    fn t57_display_is_classified_before_the_video_test() {
        // WebKitGTK may also set the video (or audio) flag on a display-capture
        // request; the display flag alone decides it, never the camera rule.
        for video in [false, true] {
            for audio in [false, true] {
                assert_eq!(decide_user_media(true, video, audio, true), Allow);
                assert_eq!(decide_user_media(true, video, audio, false), Deny);
            }
        }
    }

    #[test]
    fn t57_disarmed_shell_allows_nothing() {
        for display in [false, true] {
            for video in [false, true] {
                for audio in [false, true] {
                    assert_eq!(decide_user_media(display, video, audio, false), Deny);
                }
            }
        }
    }

    #[test]
    fn t57_display_capture_supported_per_platform() {
        assert!(!display_capture_supported_on("macos"));
        assert!(display_capture_supported_on("windows"));
        assert!(display_capture_supported_on("linux"));
        for other in ["ios", "android", "freebsd", "openbsd", ""] {
            assert!(!display_capture_supported_on(other), "{other}");
        }
    }

    #[test]
    fn t57_display_capture_supported_for_this_build() {
        #[cfg(target_os = "macos")]
        assert!(!display_capture_supported());
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        assert!(display_capture_supported());
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        assert!(!display_capture_supported());
    }

    /// This file without its test module, with full-line comments removed.
    fn shell_code() -> String {
        let source = include_str!("main.rs");
        let marker = "\n#[cfg(test)]\nmod tests {";
        let end = source
            .find(marker)
            .expect("main.rs keeps its test module last");
        source[..end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The text from `start` to the `close` that balances the first `open`
    /// at or after it.
    fn balanced<'a>(code: &'a str, start: &str, open: char, close: char) -> &'a str {
        let begin = code
            .find(start)
            .unwrap_or_else(|| panic!("`{start}` not found"));
        let mut depth = 0usize;
        for (offset, c) in code[begin..].char_indices() {
            if c == open {
                depth += 1;
            } else if c == close {
                depth -= 1;
                if depth == 0 {
                    return &code[begin..begin + offset + c.len_utf8()];
                }
            }
        }
        panic!("unbalanced `{open}` after `{start}`");
    }

    /// The text from `start` to the parenthesis that closes the first `(`
    /// at or after it.
    fn balanced_call<'a>(code: &'a str, start: &str) -> &'a str {
        balanced(code, start, '(', ')')
    }

    /// `text` without any whitespace.
    fn squeeze(text: &str) -> String {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// The attribute lines directly above the line that contains `needle`.
    fn attributes_above(code: &str, needle: &str) -> Vec<String> {
        let lines: Vec<&str> = code.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("`{needle}` not found"));
        lines[..at]
            .iter()
            .rev()
            .map(|line| line.trim())
            .take_while(|line| line.starts_with("#["))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn t57_linux_handler_tests_display_through_one_unsafe_call() {
        let code = shell_code();

        // The raw call lives in one small Linux-only function whose only
        // input is the request pointer.
        let raw = "webkit_user_media_permission_is_for_display_device(";
        assert_eq!(code.matches(raw).count(), 1, "exactly one raw call");
        assert!(
            attributes_above(&code, "unsafe fn request_is_for_display_device(")
                .iter()
                .any(|attr| attr == "#[cfg(target_os = \"linux\")]"),
            "the raw call is on the Linux path only"
        );
        let start = "unsafe fn request_is_for_display_device(";
        let signature = balanced_call(&code, start);
        let parameters = signature[start.len()..signature.len() - 1]
            .trim()
            .trim_end_matches(',');
        assert_eq!(
            parameters, "request: *mut webkit2gtk::ffi::WebKitUserMediaPermissionRequest",
            "one parameter, the request pointer"
        );
        assert_eq!(code.matches("unsafe fn").count(), 1);

        // The permission handler holds exactly one unsafe block, around that
        // call, and leaves the decision to decide_user_media, display first.
        let handler = balanced_call(&code, "connect_permission_request(");
        assert_eq!(
            handler.matches("unsafe").count(),
            1,
            "no other unsafe block in the permission handler"
        );
        assert!(handler.contains("unsafe { request_is_for_display_device(media_req.as_ptr()) }"));
        let display = handler.find("request_is_for_display_device(").unwrap();
        let video = handler.find("is_for_video_device()").unwrap();
        assert!(display < video, "the display flag is read first");
        // The flags reach decide_user_media in its parameter order
        // (is_display, is_video, is_audio, armed): the arguments are
        // positional bools, so a swap would compile and, for example, allow
        // a camera request while armed.
        assert_eq!(
            handler.matches("is_display").count(),
            2,
            "is_display is bound once, from the raw call, and used once"
        );
        let decide = squeeze(balanced_call(handler, "decide_user_media("));
        assert_eq!(
            decide.replace(",)", ")"),
            "decide_user_media(is_display,media_req.is_for_video_device(),\
             media_req.is_for_audio_device(),VOICE_CAPTURE_ARMED.load(Ordering::SeqCst))"
        );
        assert!(handler.contains("MediaPermission::Allow => request.allow()"));
        assert!(handler.contains("MediaPermission::Deny => request.deny()"));
    }

    #[test]
    fn t57_linux_webview_pins_webrtc_off_next_to_the_mock_devices() {
        let code = shell_code();
        assert_eq!(code.matches("set_enable_webrtc(false)").count(), 1);
        assert!(!code.contains("set_enable_webrtc(true)"));
        let webrtc = code.find("set_enable_webrtc(false)").unwrap();
        let mock_env = code.find("ACCORD_MOCK_MEDIA").unwrap();
        let mock = code.find("set_enable_mock_capture_devices(true)").unwrap();
        let settings = code.find("WebViewExt::settings(&wv)").unwrap();
        assert!(
            settings < webrtc && webrtc < mock_env && mock_env < mock,
            "same settings block, before the mock-device test"
        );
        // The pin is unconditional within the settings block, so production
        // builds get it: it is not inside the ACCORD_MOCK_MEDIA branch.
        let mock_branch = balanced(&code, "if std::env::var(\"ACCORD_MOCK_MEDIA\")", '{', '}');
        assert!(!mock_branch.contains("set_enable_webrtc"), "{mock_branch}");
        let settings_block = squeeze(balanced(
            &code,
            "if let Some(settings) = WebViewExt::settings(&wv)",
            '{',
            '}',
        ));
        assert_eq!(
            settings_block,
            "ifletSome(settings)=WebViewExt::settings(&wv){\
             settings.set_enable_webrtc(false);\
             ifstd::env::var(\"ACCORD_MOCK_MEDIA\").as_deref()==Ok(\"1\"){\
             settings.set_enable_mock_capture_devices(true);}}",
            "the pin is the settings block's first, unconditional statement"
        );
        let linux_block = code
            .find("#[cfg(target_os = \"linux\")]\n            {")
            .unwrap();
        assert!(linux_block < settings, "on the Linux path");
    }

    #[test]
    fn t57_display_capture_supported_is_a_registered_command() {
        let code = shell_code();
        let handlers = balanced(&code, "generate_handler![", '[', ']');
        let registered: Vec<&str> = handlers
            .trim_start_matches("generate_handler![")
            .trim_end_matches(']')
            .split(',')
            .map(str::trim)
            .collect();
        assert!(registered.contains(&"display_capture_supported"));
        assert!(registered.contains(&"set_voice_capture_armed"));
    }

    #[test]
    fn t57_no_screen_capture_auto_approval_on_windows() {
        // No code sets WebView2's ScreenCaptureStarting `Cancel` to false, and
        // nothing passes the Chromium switches that skip or answer the
        // capture picker by themselves (also not through the Tauri config).
        let sources = [
            ("main.rs", shell_code()),
            (
                "tauri.conf.json",
                include_str!("../tauri.conf.json").to_owned(),
            ),
            (
                "tauri.ci.conf.json",
                include_str!("../tauri.ci.conf.json").to_owned(),
            ),
        ];
        for (name, text) in sources {
            let squeezed = squeeze(&text).to_lowercase();
            for forbidden in [
                "cancel(false)",
                "cancel=false",
                "cancel:false",
                "auto-select-desktop-capture-source",
                "auto-select-tab-capture-source-by-title",
                "auto-accept-this-tab-capture",
                "use-fake-ui-for-media-stream",
            ] {
                assert!(!squeezed.contains(forbidden), "{name} contains {forbidden}");
            }
        }
    }
}
