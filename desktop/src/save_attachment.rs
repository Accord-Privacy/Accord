//! The `save_attachment` shell command (SPEC-02 REQ-22, owner decision OD-47).
//!
//! The webview hands over only a file name and the verified attachment bytes;
//! it never supplies a path. The name travels percent-encoded in the
//! `x-accord-file-name` IPC header (headers carry no non-ASCII text) and the
//! bytes as the raw IPC body, never as JSON. The shell sanitizes the name
//! again (REQ-23), shows the native save dialog from Rust, and writes only to
//! the path the user picked. The webview holds no dialog or file-system
//! permission of its own.
//!
//! The dialog comes from `rfd`, the library behind `tauri-plugin-dialog`'s
//! Rust API, driven the way that plugin drives it (created on the main
//! thread, awaited on another). The plugin itself is not registered: it
//! injects a script that replaces `window.alert` and `window.confirm` with
//! dialog IPC calls, which would need a webview dialog permission and would
//! turn the app's synchronous `confirm()` guards into no-ops.
//!
//! This departs from the wording of OD-47 (the Rust API of
//! `tauri-plugin-dialog`) and awaits the owner's sign-off as an amendment in
//! `specs/DECISIONS.md`. T-22's release check must exercise this dialog on
//! WebView2 (Windows), WKWebView (macOS) and WebKitGTK (Linux).
//!
//! Frontend call (raw body, `@tauri-apps/api/core`):
//!
//! ```text
//! invoke('save_attachment', bytes, { headers: { 'x-accord-file-name': encodeURIComponent(name) } })
//!   -> true (saved) | false (the user cancelled); rejects with a fixed message on failure
//! ```
//!
//! Errors are fixed strings: they never contain the name, the path or the bytes.

use accord_core::attachment::{sanitize_file_name, CLIENT_MAX_BLOB_BYTES};
use std::path::PathBuf;
use tauri::ipc::{InvokeBody, Request};

/// The IPC header that carries the percent-encoded file name.
pub const NAME_HEADER: &str = "x-accord-file-name";

/// Why a save request was refused. `Display` gives the fixed text returned to
/// the webview.
#[derive(Debug, PartialEq, Eq)]
pub enum SaveError {
    /// No name header, or one that is not percent-encoded UTF-8.
    BadName,
    /// The body is not raw bytes, or is larger than any attachment can be.
    BadBody,
    /// The dialog could not return a usable local path.
    NoPath,
    /// Writing the file failed.
    WriteFailed,
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SaveError::BadName => "invalid file name",
            SaveError::BadBody => "invalid attachment data",
            SaveError::NoPath => "the chosen location cannot be used",
            SaveError::WriteFailed => "the file could not be written",
        })
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode `encodeURIComponent` output. `None` for a malformed escape or a
/// result that is not UTF-8.
pub fn percent_decode_utf8(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex_digit(*bytes.get(i + 1)?)?;
            let lo = hex_digit(*bytes.get(i + 2)?)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The save name from the IPC header value: decoded, then sanitized again
/// whatever the webview already did (REQ-23).
pub fn save_name(header: Option<&str>) -> Result<String, SaveError> {
    let raw = percent_decode_utf8(header.ok_or(SaveError::BadName)?).ok_or(SaveError::BadName)?;
    Ok(sanitize_file_name(&raw))
}

/// The bytes to save: only a raw IPC body, at most one attachment's size.
pub fn save_bytes(body: &InvokeBody) -> Result<&[u8], SaveError> {
    match body {
        InvokeBody::Raw(bytes) if bytes.len() as u64 <= CLIENT_MAX_BLOB_BYTES => Ok(bytes),
        _ => Err(SaveError::BadBody),
    }
}

/// Show the native save dialog, parented to `window`, with `name` proposed.
/// `Ok(None)` when the user cancels.
async fn pick_save_path(
    app: &tauri::AppHandle,
    window: tauri::WebviewWindow,
    name: String,
) -> Result<Option<PathBuf>, SaveError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.run_on_main_thread(move || {
        let dialog = rfd::AsyncFileDialog::new()
            .set_parent(&window)
            .set_file_name(name)
            .set_can_create_directories(true)
            .save_file();
        std::thread::spawn(move || {
            let picked = tauri::async_runtime::block_on(dialog);
            let _ = tx.send(picked.map(|handle| handle.path().to_path_buf()));
        });
    })
    .map_err(|_| SaveError::NoPath)?;
    rx.await.map_err(|_| SaveError::NoPath)
}

/// Show the native save dialog for one verified attachment and write it to
/// the chosen path. `Ok(false)` when the user cancels.
#[tauri::command]
pub async fn save_attachment(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    request: Request<'_>,
) -> Result<bool, String> {
    let name = save_name(
        request
            .headers()
            .get(NAME_HEADER)
            .and_then(|v| v.to_str().ok()),
    )
    .map_err(|e| e.to_string())?;
    let bytes = save_bytes(request.body()).map_err(|e| e.to_string())?;

    let path = pick_save_path(&app, window, name)
        .await
        .map_err(|e| e.to_string())?;
    let Some(path) = path else {
        return Ok(false);
    };
    tokio::fs::write(&path, bytes)
        .await
        .map_err(|_| SaveError::WriteFailed.to_string())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_encode_uri_component_output() {
        assert_eq!(
            percent_decode_utf8("report.pdf").as_deref(),
            Some("report.pdf")
        );
        assert_eq!(
            percent_decode_utf8("caf%C3%A9%20menu.txt").as_deref(),
            Some("caf\u{e9} menu.txt")
        );
        assert_eq!(
            percent_decode_utf8("%E2%80%AE").as_deref(),
            Some("\u{202e}")
        );
        assert_eq!(percent_decode_utf8("%zz"), None);
        assert_eq!(percent_decode_utf8("%4"), None);
        assert_eq!(percent_decode_utf8("%C3"), None);
    }

    #[test]
    fn sanitizes_the_name_again() {
        assert_eq!(
            save_name(Some("invoice%E2%80%AEfdp.exe")).unwrap(),
            "invoicefdp.exe"
        );
        assert_eq!(
            save_name(Some("..%2F..%2Fetc%2Fpasswd")).unwrap(),
            "_.._etc_passwd"
        );
        assert_eq!(save_name(Some("")).unwrap(), "attachment");
        assert_eq!(save_name(None), Err(SaveError::BadName));
        assert_eq!(save_name(Some("%FF")), Err(SaveError::BadName));
    }

    #[test]
    fn accepts_only_raw_bodies() {
        assert_eq!(
            save_bytes(&InvokeBody::Raw(vec![1, 2, 3])).unwrap(),
            &[1, 2, 3]
        );
        assert_eq!(
            save_bytes(&InvokeBody::Json(
                serde_json::json!({ "path": "/etc/passwd" })
            )),
            Err(SaveError::BadBody)
        );
    }

    #[test]
    fn errors_are_fixed_texts() {
        for e in [
            SaveError::BadName,
            SaveError::BadBody,
            SaveError::NoPath,
            SaveError::WriteFailed,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
