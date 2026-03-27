//! # C-compatible FFI for accord-core
//!
//! Provides a C ABI interface for use from Swift (iOS) and other foreign languages.
//! All functions use opaque pointers, pointer+length for bytes/strings, and
//! explicit create/destroy patterns for memory management.
//!
//! # Safety
//! All functions marked `unsafe` require valid pointers. Null checks are performed
//! where possible, returning null/error codes on invalid input.

use crate::double_ratchet::{DoubleRatchetMessage, PreKeyBundle};
use crate::session_manager::{LocalKeyMaterial, SessionId, SessionManager, X3DHInitialMessage};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

// ─── Result codes ────────────────────────────────────────────────────────────

/// FFI result code.
pub type AccordResult = i32;

pub const ACCORD_OK: AccordResult = 0;
pub const ACCORD_ERR_NULL_PTR: AccordResult = -1;
pub const ACCORD_ERR_INVALID_UTF8: AccordResult = -2;
pub const ACCORD_ERR_CRYPTO: AccordResult = -3;
pub const ACCORD_ERR_SERIALIZATION: AccordResult = -4;
pub const ACCORD_ERR_NO_SESSION: AccordResult = -5;

// ─── Byte buffer for returning owned data across FFI ─────────────────────────

/// Owned byte buffer returned across FFI. Caller must free with `accord_buffer_free`.
#[repr(C)]
pub struct AccordBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl AccordBuffer {
    fn from_vec(v: Vec<u8>) -> *mut Self {
        let mut v = v.into_boxed_slice();
        let buf = Box::new(AccordBuffer {
            data: v.as_mut_ptr(),
            len: v.len(),
        });
        std::mem::forget(v); // ownership transferred to AccordBuffer
        Box::into_raw(buf)
    }

    fn null() -> *mut Self {
        ptr::null_mut()
    }
}

/// Free an `AccordBuffer` returned by any accord FFI function.
///
/// # Safety
/// `buf` must be a pointer returned by an accord FFI function, or null.
#[no_mangle]
pub unsafe extern "C" fn accord_buffer_free(buf: *mut AccordBuffer) {
    if buf.is_null() {
        return;
    }
    let buf = Box::from_raw(buf);
    if !buf.data.is_null() && buf.len > 0 {
        drop(Vec::from_raw_parts(buf.data, buf.len, buf.len));
    }
}

// ─── Helper macros ───────────────────────────────────────────────────────────

macro_rules! null_check {
    ($ptr:expr, $ret:expr) => {
        if $ptr.is_null() {
            return $ret;
        }
    };
}

unsafe fn c_str_to_str<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }
    CStr::from_ptr(s).to_str().ok()
}

unsafe fn bytes_from_raw(ptr: *const u8, len: usize) -> Option<&'static [u8]> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

// ─── Key Material ────────────────────────────────────────────────────────────

/// Opaque handle to local key material.
pub struct AccordKeyMaterial(LocalKeyMaterial);

/// Generate new local key material with `num_one_time_prekeys` one-time prekeys.
#[no_mangle]
pub extern "C" fn accord_keymaterial_generate(num_one_time_prekeys: u32) -> *mut AccordKeyMaterial {
    let km = LocalKeyMaterial::generate(num_one_time_prekeys as usize);
    Box::into_raw(Box::new(AccordKeyMaterial(km)))
}

/// Free key material.
///
/// # Safety
/// `km` must be a pointer returned by `accord_keymaterial_generate`, or null.
#[no_mangle]
pub unsafe extern "C" fn accord_keymaterial_free(km: *mut AccordKeyMaterial) {
    if !km.is_null() {
        drop(Box::from_raw(km));
    }
}

/// Get the identity public key (32 bytes) from key material.
/// Returns a new AccordBuffer. Caller must free.
///
/// # Safety
/// `km` must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_keymaterial_identity_key(
    km: *const AccordKeyMaterial,
) -> *mut AccordBuffer {
    null_check!(km, AccordBuffer::null());
    let km = &(*km).0;
    AccordBuffer::from_vec(km.identity.public.to_bytes().to_vec())
}

/// Get the signed prekey public key (32 bytes).
///
/// # Safety
/// `km` must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_keymaterial_signed_prekey(
    km: *const AccordKeyMaterial,
) -> *mut AccordBuffer {
    null_check!(km, AccordBuffer::null());
    let km = &(*km).0;
    AccordBuffer::from_vec(km.signed_prekey.public.to_bytes().to_vec())
}

/// Get the publishable key bundle as serialized bytes (bincode).
/// Returns AccordBuffer with serialized PublishableKeyBundle.
///
/// # Safety
/// `km` must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_keymaterial_publishable_bundle(
    km: *const AccordKeyMaterial,
) -> *mut AccordBuffer {
    null_check!(km, AccordBuffer::null());
    let km = &(*km).0;
    let bundle = km.to_publishable_bundle();
    match bincode::serialize(&bundle) {
        Ok(data) => AccordBuffer::from_vec(data),
        Err(_) => AccordBuffer::null(),
    }
}

// ─── Session Manager ─────────────────────────────────────────────────────────

/// Opaque handle to a session manager.
pub struct AccordSessionManager(SessionManager);

/// Create a new session manager.
#[no_mangle]
pub extern "C" fn accord_session_manager_new() -> *mut AccordSessionManager {
    Box::into_raw(Box::new(AccordSessionManager(SessionManager::new())))
}

/// Free a session manager.
///
/// # Safety
/// `mgr` must be valid or null.
#[no_mangle]
pub unsafe extern "C" fn accord_session_manager_free(mgr: *mut AccordSessionManager) {
    if !mgr.is_null() {
        drop(Box::from_raw(mgr));
    }
}

/// Check if a session exists for the given peer/channel.
///
/// # Safety
/// All pointers must be valid. Returns 0 for false, 1 for true, negative on error.
#[no_mangle]
pub unsafe extern "C" fn accord_session_manager_has_session(
    mgr: *const AccordSessionManager,
    peer_user_id: *const c_char,
    channel_id: *const c_char,
) -> i32 {
    null_check!(mgr, ACCORD_ERR_NULL_PTR);
    let peer = match c_str_to_str(peer_user_id) {
        Some(s) => s,
        None => return ACCORD_ERR_INVALID_UTF8,
    };
    let channel = match c_str_to_str(channel_id) {
        Some(s) => s,
        None => return ACCORD_ERR_INVALID_UTF8,
    };
    let sid = SessionId {
        peer_user_id: peer.to_string(),
        channel_id: channel.to_string(),
    };
    if (*mgr).0.has_session(&sid) {
        1
    } else {
        0
    }
}

/// Initiate a session (Alice's side). Creates a new Double Ratchet session
/// and returns the serialized X3DHInitialMessage to send to the peer.
///
/// # Parameters
/// - `their_bundle_data`/`their_bundle_len`: serialized PreKeyBundle (bincode)
/// - `first_message`/`first_message_len`: plaintext of first message
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_session_manager_initiate(
    mgr: *mut AccordSessionManager,
    km: *const AccordKeyMaterial,
    peer_user_id: *const c_char,
    channel_id: *const c_char,
    their_bundle_data: *const u8,
    their_bundle_len: usize,
    first_message: *const u8,
    first_message_len: usize,
) -> *mut AccordBuffer {
    null_check!(mgr, AccordBuffer::null());
    null_check!(km, AccordBuffer::null());

    let peer = match c_str_to_str(peer_user_id) {
        Some(s) => s,
        None => return AccordBuffer::null(),
    };
    let channel = match c_str_to_str(channel_id) {
        Some(s) => s,
        None => return AccordBuffer::null(),
    };
    let bundle_bytes = match bytes_from_raw(their_bundle_data, their_bundle_len) {
        Some(b) => b,
        None => return AccordBuffer::null(),
    };
    let plaintext = match bytes_from_raw(first_message, first_message_len) {
        Some(b) => b,
        None => return AccordBuffer::null(),
    };

    let bundle: PreKeyBundle = match bincode::deserialize(bundle_bytes) {
        Ok(b) => b,
        Err(_) => return AccordBuffer::null(),
    };

    let sid = SessionId {
        peer_user_id: peer.to_string(),
        channel_id: channel.to_string(),
    };

    match (*mgr).0.initiate_session(&(*km).0, &bundle, sid, plaintext) {
        Ok(initial_msg) => match bincode::serialize(&initial_msg) {
            Ok(data) => AccordBuffer::from_vec(data),
            Err(_) => AccordBuffer::null(),
        },
        Err(_) => AccordBuffer::null(),
    }
}

/// Receive an initial X3DH message (Bob's side) and establish a session.
/// Returns the decrypted first message.
///
/// # Safety
/// All pointers must be valid. `km` is mutated (one-time prekey consumed).
#[no_mangle]
pub unsafe extern "C" fn accord_session_manager_receive_initial(
    mgr: *mut AccordSessionManager,
    km: *mut AccordKeyMaterial,
    peer_user_id: *const c_char,
    channel_id: *const c_char,
    initial_msg_data: *const u8,
    initial_msg_len: usize,
) -> *mut AccordBuffer {
    null_check!(mgr, AccordBuffer::null());
    null_check!(km, AccordBuffer::null());

    let peer = match c_str_to_str(peer_user_id) {
        Some(s) => s,
        None => return AccordBuffer::null(),
    };
    let channel = match c_str_to_str(channel_id) {
        Some(s) => s,
        None => return AccordBuffer::null(),
    };
    let msg_bytes = match bytes_from_raw(initial_msg_data, initial_msg_len) {
        Some(b) => b,
        None => return AccordBuffer::null(),
    };

    let initial_msg: X3DHInitialMessage = match bincode::deserialize(msg_bytes) {
        Ok(m) => m,
        Err(_) => return AccordBuffer::null(),
    };

    let sid = SessionId {
        peer_user_id: peer.to_string(),
        channel_id: channel.to_string(),
    };

    match (*mgr)
        .0
        .receive_initial_message(&mut (*km).0, &initial_msg, sid)
    {
        Ok(plaintext) => AccordBuffer::from_vec(plaintext),
        Err(_) => AccordBuffer::null(),
    }
}

/// Encrypt a message for an established session.
/// Returns serialized DoubleRatchetMessage.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_session_manager_encrypt(
    mgr: *mut AccordSessionManager,
    peer_user_id: *const c_char,
    channel_id: *const c_char,
    plaintext: *const u8,
    plaintext_len: usize,
) -> *mut AccordBuffer {
    null_check!(mgr, AccordBuffer::null());

    let peer = match c_str_to_str(peer_user_id) {
        Some(s) => s,
        None => return AccordBuffer::null(),
    };
    let channel = match c_str_to_str(channel_id) {
        Some(s) => s,
        None => return AccordBuffer::null(),
    };
    let plain = match bytes_from_raw(plaintext, plaintext_len) {
        Some(b) => b,
        None => return AccordBuffer::null(),
    };

    let sid = SessionId {
        peer_user_id: peer.to_string(),
        channel_id: channel.to_string(),
    };

    match (*mgr).0.encrypt_message(&sid, plain) {
        Ok(msg) => match bincode::serialize(&msg) {
            Ok(data) => AccordBuffer::from_vec(data),
            Err(_) => AccordBuffer::null(),
        },
        Err(_) => AccordBuffer::null(),
    }
}

/// Decrypt a message from an established session.
/// Returns the plaintext.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_session_manager_decrypt(
    mgr: *mut AccordSessionManager,
    peer_user_id: *const c_char,
    channel_id: *const c_char,
    ciphertext: *const u8,
    ciphertext_len: usize,
) -> *mut AccordBuffer {
    null_check!(mgr, AccordBuffer::null());

    let peer = match c_str_to_str(peer_user_id) {
        Some(s) => s,
        None => return AccordBuffer::null(),
    };
    let channel = match c_str_to_str(channel_id) {
        Some(s) => s,
        None => return AccordBuffer::null(),
    };
    let cipher = match bytes_from_raw(ciphertext, ciphertext_len) {
        Some(b) => b,
        None => return AccordBuffer::null(),
    };

    let msg: DoubleRatchetMessage = match bincode::deserialize(cipher) {
        Ok(m) => m,
        Err(_) => return AccordBuffer::null(),
    };

    let sid = SessionId {
        peer_user_id: peer.to_string(),
        channel_id: channel.to_string(),
    };

    match (*mgr).0.decrypt_message(&sid, &msg) {
        Ok(plaintext) => AccordBuffer::from_vec(plaintext),
        Err(_) => AccordBuffer::null(),
    }
}

// ─── Serialization helpers for PreKeyBundle ──────────────────────────────────

/// Serialize a PreKeyBundle from its components.
/// `identity_key`, `signed_prekey`: 32-byte keys
/// `one_time_prekey`: optional 32-byte key (null if none)
///
/// # Safety
/// Key pointers must point to 32 bytes each.
#[no_mangle]
pub unsafe extern "C" fn accord_prekey_bundle_serialize(
    identity_key: *const u8,
    signed_prekey: *const u8,
    one_time_prekey: *const u8, // null if none
) -> *mut AccordBuffer {
    null_check!(identity_key, AccordBuffer::null());
    null_check!(signed_prekey, AccordBuffer::null());

    let ik: [u8; 32] = slice::from_raw_parts(identity_key, 32).try_into().unwrap();
    let spk: [u8; 32] = slice::from_raw_parts(signed_prekey, 32).try_into().unwrap();
    let opk = if one_time_prekey.is_null() {
        None
    } else {
        Some(
            slice::from_raw_parts(one_time_prekey, 32)
                .try_into()
                .unwrap(),
        )
    };

    let bundle = PreKeyBundle {
        identity_key: ik,
        signed_prekey: spk,
        one_time_prekey: opk,
    };

    match bincode::serialize(&bundle) {
        Ok(data) => AccordBuffer::from_vec(data),
        Err(_) => AccordBuffer::null(),
    }
}

// ─── Background Voice ────────────────────────────────────────────────────────

use crate::background_voice::{
    BackgroundVoiceConfig, SharedBackgroundVoiceSession, VoiceLifecycleState,
};

/// Opaque handle to a background voice session.
pub struct AccordBackgroundVoice(SharedBackgroundVoiceSession);

/// Create a new background voice session with default configuration.
#[no_mangle]
pub extern "C" fn accord_background_voice_new() -> *mut AccordBackgroundVoice {
    let session = crate::background_voice::create_shared_session(BackgroundVoiceConfig::default());
    Box::into_raw(Box::new(AccordBackgroundVoice(session)))
}

/// Free a background voice session.
///
/// # Safety
/// `handle` must be valid or null.
#[no_mangle]
pub unsafe extern "C" fn accord_background_voice_free(handle: *mut AccordBackgroundVoice) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Notify that the app has entered the background.
/// `now_ms` is a monotonic timestamp in milliseconds.
/// Returns 0 on success, negative on invalid transition.
///
/// # Safety
/// `handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_voice_enter_background(
    handle: *mut AccordBackgroundVoice,
    now_ms: u64,
) -> AccordResult {
    null_check!(handle, ACCORD_ERR_NULL_PTR);
    match (*handle).0.enter_background(now_ms) {
        Some(_) => ACCORD_OK,
        None => -10, // invalid state transition
    }
}

/// Notify that the app has entered the foreground.
/// `now_ms` is a monotonic timestamp in milliseconds.
/// Returns 0 on success, negative on invalid transition.
///
/// # Safety
/// `handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_voice_enter_foreground(
    handle: *mut AccordBackgroundVoice,
    now_ms: u64,
) -> AccordResult {
    null_check!(handle, ACCORD_ERR_NULL_PTR);
    match (*handle).0.enter_foreground(now_ms) {
        Some(_) => ACCORD_OK,
        None => -10,
    }
}

/// Check if the voice session is still active (not suspended).
/// Returns 1 if active, 0 if suspended/inactive, negative on error.
///
/// # Safety
/// `handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_voice_is_active(handle: *const AccordBackgroundVoice) -> i32 {
    null_check!(handle, ACCORD_ERR_NULL_PTR);
    if (*handle).0.is_active() {
        1
    } else {
        0
    }
}

/// FFI-safe stats structure.
#[repr(C)]
pub struct AccordVoiceStats {
    pub total_background_ms: u64,
    pub packets_received_in_background: u64,
    pub keepalives_sent: u64,
    pub reconnection_count: u32,
    pub failed_reconnections: u32,
    pub frames_dropped: u64,
    /// 0=Active, 1=Backgrounded, 2=Reconnecting, 3=Suspended
    pub current_state: i32,
}

fn state_to_int(s: Option<VoiceLifecycleState>) -> i32 {
    match s {
        Some(VoiceLifecycleState::Active) => 0,
        Some(VoiceLifecycleState::Backgrounded) => 1,
        Some(VoiceLifecycleState::Reconnecting) => 2,
        Some(VoiceLifecycleState::Suspended) => 3,
        None => -1,
    }
}

/// Get voice session statistics.
/// Writes stats to `out`. Returns 0 on success.
///
/// # Safety
/// `handle` and `out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn accord_voice_get_stats(
    handle: *const AccordBackgroundVoice,
    out: *mut AccordVoiceStats,
) -> AccordResult {
    null_check!(handle, ACCORD_ERR_NULL_PTR);
    null_check!(out, ACCORD_ERR_NULL_PTR);
    let stats = (*handle).0.stats();
    *out = AccordVoiceStats {
        total_background_ms: stats.total_background_ms,
        packets_received_in_background: stats.packets_received_in_background,
        keepalives_sent: stats.keepalives_sent,
        reconnection_count: stats.reconnection_count,
        failed_reconnections: stats.failed_reconnections,
        frames_dropped: stats.frames_dropped,
        current_state: state_to_int(stats.current_state),
    };
    ACCORD_OK
}

// ─── Sender Keys FFI ─────────────────────────────────────────────────────────

use crate::sender_keys::{self, SenderKeyStore};

/// Create a new SenderKeyStore. Caller must free with `accord_sender_key_store_free`.
#[no_mangle]
pub extern "C" fn accord_sender_key_store_create() -> *mut SenderKeyStore {
    Box::into_raw(Box::new(SenderKeyStore::new()))
}

/// Free a SenderKeyStore.
///
/// # Safety
/// `store` must be a valid pointer returned by `accord_sender_key_store_create`, or null.
#[no_mangle]
pub unsafe extern "C" fn accord_sender_key_store_free(store: *mut SenderKeyStore) {
    if !store.is_null() {
        drop(Box::from_raw(store));
    }
}

/// Encrypt a channel message. Returns an AccordBuffer containing the JSON envelope.
///
/// # Safety
/// All pointers must be valid. `store` must be a live SenderKeyStore.
#[no_mangle]
pub unsafe extern "C" fn accord_sender_key_encrypt(
    store: *mut SenderKeyStore,
    channel_id: *const c_char,
    plaintext: *const u8,
    plaintext_len: usize,
) -> *mut AccordBuffer {
    if store.is_null() || channel_id.is_null() || plaintext.is_null() {
        return AccordBuffer::null();
    }
    let store = &mut *store;
    let channel_id = match CStr::from_ptr(channel_id).to_str() {
        Ok(s) => s,
        Err(_) => return AccordBuffer::null(),
    };
    let plaintext_str = match std::str::from_utf8(slice::from_raw_parts(plaintext, plaintext_len)) {
        Ok(s) => s,
        Err(_) => return AccordBuffer::null(),
    };
    match sender_keys::encrypt_channel_message(store, channel_id, plaintext_str) {
        Ok(json) => AccordBuffer::from_vec(json.into_bytes()),
        Err(_) => AccordBuffer::null(),
    }
}

/// Decrypt a channel message. Returns an AccordBuffer containing the plaintext.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_sender_key_decrypt(
    store: *mut SenderKeyStore,
    channel_id: *const c_char,
    sender_id: *const c_char,
    envelope_json: *const c_char,
) -> *mut AccordBuffer {
    if store.is_null() || channel_id.is_null() || sender_id.is_null() || envelope_json.is_null() {
        return AccordBuffer::null();
    }
    let store = &mut *store;
    let channel_id = match CStr::from_ptr(channel_id).to_str() {
        Ok(s) => s,
        Err(_) => return AccordBuffer::null(),
    };
    let sender_id = match CStr::from_ptr(sender_id).to_str() {
        Ok(s) => s,
        Err(_) => return AccordBuffer::null(),
    };
    let envelope_json = match CStr::from_ptr(envelope_json).to_str() {
        Ok(s) => s,
        Err(_) => return AccordBuffer::null(),
    };
    match sender_keys::decrypt_channel_message(store, channel_id, sender_id, envelope_json) {
        Ok(plaintext) => AccordBuffer::from_vec(plaintext.into_bytes()),
        Err(_) => AccordBuffer::null(),
    }
}

/// Create a distribution message JSON for a channel. Returns AccordBuffer with JSON.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_sender_key_create_distribution(
    store: *mut SenderKeyStore,
    channel_id: *const c_char,
) -> *mut AccordBuffer {
    if store.is_null() || channel_id.is_null() {
        return AccordBuffer::null();
    }
    let store = &mut *store;
    let channel_id = match CStr::from_ptr(channel_id).to_str() {
        Ok(s) => s,
        Err(_) => return AccordBuffer::null(),
    };
    let sk = store.get_or_create_my_key(channel_id).clone();
    let dist = sender_keys::build_distribution_message(channel_id, &sk, None);
    match serde_json::to_string(&dist) {
        Ok(json) => AccordBuffer::from_vec(json.into_bytes()),
        Err(_) => AccordBuffer::null(),
    }
}

/// Process a received distribution message JSON, storing the peer's key.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn accord_sender_key_process_distribution(
    store: *mut SenderKeyStore,
    channel_id: *const c_char,
    sender_id: *const c_char,
    distribution_json: *const c_char,
) -> AccordResult {
    if store.is_null() || channel_id.is_null() || sender_id.is_null() || distribution_json.is_null()
    {
        return ACCORD_ERR_NULL_PTR;
    }
    let store = &mut *store;
    let channel_id = match CStr::from_ptr(channel_id).to_str() {
        Ok(s) => s,
        Err(_) => return ACCORD_ERR_INVALID_UTF8,
    };
    let sender_id = match CStr::from_ptr(sender_id).to_str() {
        Ok(s) => s,
        Err(_) => return ACCORD_ERR_INVALID_UTF8,
    };
    let dist_json = match CStr::from_ptr(distribution_json).to_str() {
        Ok(s) => s,
        Err(_) => return ACCORD_ERR_INVALID_UTF8,
    };
    let dist: sender_keys::SenderKeyDistributionMessage = match serde_json::from_str(dist_json) {
        Ok(d) => d,
        Err(_) => return ACCORD_ERR_SERIALIZATION,
    };
    match sender_keys::parse_distribution_message(&dist) {
        Ok((_, state)) => {
            store.set_peer_key(channel_id, sender_id, state);
            ACCORD_OK
        }
        Err(_) => ACCORD_ERR_CRYPTO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // ─── AccordBuffer ─────────────────────────────────────────────────────────

    #[test]
    fn test_buffer_free_null_no_crash() {
        // Must not crash when passed null
        unsafe {
            accord_buffer_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_buffer_lifecycle() {
        // Create a buffer via keymaterial and verify we can read then free it
        unsafe {
            let km = accord_keymaterial_generate(1);
            assert!(!km.is_null());
            let buf = accord_keymaterial_identity_key(km);
            assert!(!buf.is_null());
            assert_eq!((*buf).len, 32);
            assert!(!(*buf).data.is_null());
            accord_buffer_free(buf);
            accord_keymaterial_free(km);
        }
    }

    // ─── AccordKeyMaterial ───────────────────────────────────────────────────

    #[test]
    fn test_keymaterial_roundtrip() {
        unsafe {
            let km = accord_keymaterial_generate(5);
            assert!(!km.is_null());

            let ik = accord_keymaterial_identity_key(km);
            assert!(!ik.is_null());
            assert_eq!((*ik).len, 32);

            let spk = accord_keymaterial_signed_prekey(km);
            assert!(!spk.is_null());
            assert_eq!((*spk).len, 32);

            let bundle = accord_keymaterial_publishable_bundle(km);
            assert!(!bundle.is_null());
            assert!((*bundle).len > 0);

            accord_buffer_free(ik);
            accord_buffer_free(spk);
            accord_buffer_free(bundle);
            accord_keymaterial_free(km);
        }
    }

    #[test]
    fn test_keymaterial_generate_returns_nonnull() {
        unsafe {
            let km = accord_keymaterial_generate(0);
            assert!(!km.is_null());
            accord_keymaterial_free(km);
        }
    }

    #[test]
    fn test_keymaterial_generate_produces_unique_keys() {
        unsafe {
            let km1 = accord_keymaterial_generate(5);
            let km2 = accord_keymaterial_generate(5);
            assert!(!km1.is_null());
            assert!(!km2.is_null());

            let ik1 = accord_keymaterial_identity_key(km1);
            let ik2 = accord_keymaterial_identity_key(km2);
            assert!(!ik1.is_null());
            assert!(!ik2.is_null());

            let bytes1 = slice::from_raw_parts((*ik1).data, (*ik1).len);
            let bytes2 = slice::from_raw_parts((*ik2).data, (*ik2).len);
            // Two independently generated identity keys must differ
            assert_ne!(bytes1, bytes2);

            accord_buffer_free(ik1);
            accord_buffer_free(ik2);
            accord_keymaterial_free(km1);
            accord_keymaterial_free(km2);
        }
    }

    #[test]
    fn test_keymaterial_identity_key_is_32_bytes() {
        unsafe {
            let km = accord_keymaterial_generate(3);
            let buf = accord_keymaterial_identity_key(km);
            assert!(!buf.is_null());
            assert_eq!((*buf).len, 32);
            accord_buffer_free(buf);
            accord_keymaterial_free(km);
        }
    }

    #[test]
    fn test_keymaterial_signed_prekey_is_32_bytes() {
        unsafe {
            let km = accord_keymaterial_generate(3);
            let buf = accord_keymaterial_signed_prekey(km);
            assert!(!buf.is_null());
            assert_eq!((*buf).len, 32);
            accord_buffer_free(buf);
            accord_keymaterial_free(km);
        }
    }

    #[test]
    fn test_keymaterial_publishable_bundle_nonempty() {
        unsafe {
            let km = accord_keymaterial_generate(5);
            let buf = accord_keymaterial_publishable_bundle(km);
            assert!(!buf.is_null());
            assert!((*buf).len > 0);
            accord_buffer_free(buf);
            accord_keymaterial_free(km);
        }
    }

    #[test]
    fn test_keymaterial_free_null_no_crash() {
        unsafe {
            accord_keymaterial_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_keymaterial_null_ptr_returns_null_buffers() {
        unsafe {
            assert!(accord_keymaterial_identity_key(ptr::null()).is_null());
            assert!(accord_keymaterial_signed_prekey(ptr::null()).is_null());
            assert!(accord_keymaterial_publishable_bundle(ptr::null()).is_null());
        }
    }

    // ─── AccordSessionManager ────────────────────────────────────────────────

    #[test]
    fn test_session_manager_lifecycle() {
        unsafe {
            let mgr = accord_session_manager_new();
            assert!(!mgr.is_null());
            accord_session_manager_free(mgr);
        }
    }

    #[test]
    fn test_session_manager_free_null_no_crash() {
        unsafe {
            accord_session_manager_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_session_manager_has_session_unknown_returns_zero() {
        unsafe {
            let mgr = accord_session_manager_new();
            let peer = CString::new("unknown_peer").unwrap();
            let channel = CString::new("unknown_channel").unwrap();
            let result = accord_session_manager_has_session(mgr, peer.as_ptr(), channel.as_ptr());
            assert_eq!(result, 0);
            accord_session_manager_free(mgr);
        }
    }

    #[test]
    fn test_session_manager_has_session_null_mgr() {
        unsafe {
            let peer = CString::new("bob").unwrap();
            let channel = CString::new("general").unwrap();
            assert_eq!(
                accord_session_manager_has_session(ptr::null(), peer.as_ptr(), channel.as_ptr()),
                ACCORD_ERR_NULL_PTR
            );
        }
    }

    #[test]
    fn test_session_manager_has_session_null_strings() {
        unsafe {
            let mgr = accord_session_manager_new();
            // null peer_user_id → ACCORD_ERR_INVALID_UTF8
            let channel = CString::new("general").unwrap();
            assert_eq!(
                accord_session_manager_has_session(mgr, ptr::null(), channel.as_ptr()),
                ACCORD_ERR_INVALID_UTF8
            );
            // null channel_id → ACCORD_ERR_INVALID_UTF8
            let peer = CString::new("bob").unwrap();
            assert_eq!(
                accord_session_manager_has_session(mgr, peer.as_ptr(), ptr::null()),
                ACCORD_ERR_INVALID_UTF8
            );
            accord_session_manager_free(mgr);
        }
    }

    #[test]
    fn test_session_manager_ffi_roundtrip() {
        unsafe {
            let alice_km = accord_keymaterial_generate(5);
            let bob_km = accord_keymaterial_generate(5);

            let alice_mgr = accord_session_manager_new();
            let bob_mgr = accord_session_manager_new();

            // Get Bob's bundle
            let bob_ik_buf = accord_keymaterial_identity_key(bob_km);
            let bob_spk_buf = accord_keymaterial_signed_prekey(bob_km);

            // Serialize Bob's PreKeyBundle
            let bob_bundle_buf = accord_prekey_bundle_serialize(
                (*bob_ik_buf).data,
                (*bob_spk_buf).data,
                ptr::null(),
            );

            let peer_bob = CString::new("bob").unwrap();
            let peer_alice = CString::new("alice").unwrap();
            let channel = CString::new("general").unwrap();
            let first_msg = b"Hello Bob!";

            // Alice initiates
            let initial_buf = accord_session_manager_initiate(
                alice_mgr,
                alice_km,
                peer_bob.as_ptr(),
                channel.as_ptr(),
                (*bob_bundle_buf).data,
                (*bob_bundle_buf).len,
                first_msg.as_ptr(),
                first_msg.len(),
            );
            assert!(!initial_buf.is_null());

            // Bob receives
            let decrypted_buf = accord_session_manager_receive_initial(
                bob_mgr,
                bob_km,
                peer_alice.as_ptr(),
                channel.as_ptr(),
                (*initial_buf).data,
                (*initial_buf).len,
            );
            assert!(!decrypted_buf.is_null());

            let decrypted = slice::from_raw_parts((*decrypted_buf).data, (*decrypted_buf).len);
            assert_eq!(decrypted, b"Hello Bob!");

            // Bob encrypts reply
            let reply = b"Hello Alice!";
            let encrypted_buf = accord_session_manager_encrypt(
                bob_mgr,
                peer_alice.as_ptr(),
                channel.as_ptr(),
                reply.as_ptr(),
                reply.len(),
            );
            assert!(!encrypted_buf.is_null());

            // Alice decrypts
            let dec2_buf = accord_session_manager_decrypt(
                alice_mgr,
                peer_bob.as_ptr(),
                channel.as_ptr(),
                (*encrypted_buf).data,
                (*encrypted_buf).len,
            );
            assert!(!dec2_buf.is_null());
            let dec2 = slice::from_raw_parts((*dec2_buf).data, (*dec2_buf).len);
            assert_eq!(dec2, b"Hello Alice!");

            // After handshake, both sides should have a session
            assert_eq!(
                accord_session_manager_has_session(alice_mgr, peer_bob.as_ptr(), channel.as_ptr()),
                1
            );
            assert_eq!(
                accord_session_manager_has_session(bob_mgr, peer_alice.as_ptr(), channel.as_ptr()),
                1
            );

            // Cleanup
            accord_buffer_free(bob_ik_buf);
            accord_buffer_free(bob_spk_buf);
            accord_buffer_free(bob_bundle_buf);
            accord_buffer_free(initial_buf);
            accord_buffer_free(decrypted_buf);
            accord_buffer_free(encrypted_buf);
            accord_buffer_free(dec2_buf);
            accord_session_manager_free(alice_mgr);
            accord_session_manager_free(bob_mgr);
            accord_keymaterial_free(alice_km);
            accord_keymaterial_free(bob_km);
        }
    }

    #[test]
    fn test_session_manager_encrypt_null_mgr_returns_null() {
        unsafe {
            let peer = CString::new("bob").unwrap();
            let channel = CString::new("general").unwrap();
            let msg = b"hi";
            let result = accord_session_manager_encrypt(
                ptr::null_mut(),
                peer.as_ptr(),
                channel.as_ptr(),
                msg.as_ptr(),
                msg.len(),
            );
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_session_manager_decrypt_null_mgr_returns_null() {
        unsafe {
            let peer = CString::new("bob").unwrap();
            let channel = CString::new("general").unwrap();
            let data = b"garbage";
            let result = accord_session_manager_decrypt(
                ptr::null_mut(),
                peer.as_ptr(),
                channel.as_ptr(),
                data.as_ptr(),
                data.len(),
            );
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_session_manager_initiate_null_mgr_returns_null() {
        unsafe {
            let km = accord_keymaterial_generate(1);
            let peer = CString::new("bob").unwrap();
            let channel = CString::new("ch").unwrap();
            let dummy = [0u8; 8];
            let result = accord_session_manager_initiate(
                ptr::null_mut(),
                km,
                peer.as_ptr(),
                channel.as_ptr(),
                dummy.as_ptr(),
                dummy.len(),
                dummy.as_ptr(),
                dummy.len(),
            );
            assert!(result.is_null());
            accord_keymaterial_free(km);
        }
    }

    #[test]
    fn test_session_manager_receive_initial_null_mgr_returns_null() {
        unsafe {
            let km = accord_keymaterial_generate(1);
            let peer = CString::new("alice").unwrap();
            let channel = CString::new("ch").unwrap();
            let dummy = [0u8; 8];
            let result = accord_session_manager_receive_initial(
                ptr::null_mut(),
                km,
                peer.as_ptr(),
                channel.as_ptr(),
                dummy.as_ptr(),
                dummy.len(),
            );
            assert!(result.is_null());
            accord_keymaterial_free(km);
        }
    }

    // ─── AccordBackgroundVoice ───────────────────────────────────────────────

    #[test]
    fn test_background_voice_lifecycle() {
        unsafe {
            let voice = accord_background_voice_new();
            assert!(!voice.is_null());
            accord_background_voice_free(voice);
        }
    }

    #[test]
    fn test_background_voice_free_null_no_crash() {
        unsafe {
            accord_background_voice_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_voice_is_active_initially_true() {
        // A freshly created session starts in Active state → is_active() == 1
        unsafe {
            let voice = accord_background_voice_new();
            assert!(!voice.is_null());
            let active = accord_voice_is_active(voice);
            assert_eq!(active, 1);
            accord_background_voice_free(voice);
        }
    }

    #[test]
    fn test_voice_is_active_null_returns_error() {
        unsafe {
            let result = accord_voice_is_active(ptr::null());
            assert_eq!(result, ACCORD_ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_voice_enter_background_foreground_transitions() {
        unsafe {
            let voice = accord_background_voice_new();
            assert!(!voice.is_null());

            // Enter background
            let rc = accord_voice_enter_background(voice, 1000);
            assert_eq!(rc, ACCORD_OK);

            // Enter foreground
            let rc = accord_voice_enter_foreground(voice, 5000);
            assert_eq!(rc, ACCORD_OK);

            // After returning to foreground, session should be active again
            assert_eq!(accord_voice_is_active(voice), 1);

            accord_background_voice_free(voice);
        }
    }

    #[test]
    fn test_voice_enter_background_null_returns_error() {
        unsafe {
            assert_eq!(
                accord_voice_enter_background(ptr::null_mut(), 0),
                ACCORD_ERR_NULL_PTR
            );
        }
    }

    #[test]
    fn test_voice_enter_foreground_null_returns_error() {
        unsafe {
            assert_eq!(
                accord_voice_enter_foreground(ptr::null_mut(), 0),
                ACCORD_ERR_NULL_PTR
            );
        }
    }

    #[test]
    fn test_voice_get_stats_valid() {
        unsafe {
            let voice = accord_background_voice_new();
            assert!(!voice.is_null());

            let mut stats = AccordVoiceStats {
                total_background_ms: 0,
                packets_received_in_background: 0,
                keepalives_sent: 0,
                reconnection_count: 0,
                failed_reconnections: 0,
                frames_dropped: 0,
                current_state: -1,
            };

            let rc = accord_voice_get_stats(voice, &mut stats as *mut AccordVoiceStats);
            assert_eq!(rc, ACCORD_OK);
            // Fresh session is in Active state (int 0)
            assert_eq!(stats.current_state, 0);

            accord_background_voice_free(voice);
        }
    }

    #[test]
    fn test_voice_get_stats_null_handle_returns_error() {
        unsafe {
            let mut stats = AccordVoiceStats {
                total_background_ms: 0,
                packets_received_in_background: 0,
                keepalives_sent: 0,
                reconnection_count: 0,
                failed_reconnections: 0,
                frames_dropped: 0,
                current_state: -1,
            };
            let rc = accord_voice_get_stats(ptr::null(), &mut stats as *mut AccordVoiceStats);
            assert_eq!(rc, ACCORD_ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_voice_get_stats_null_out_returns_error() {
        unsafe {
            let voice = accord_background_voice_new();
            let rc = accord_voice_get_stats(voice, ptr::null_mut());
            assert_eq!(rc, ACCORD_ERR_NULL_PTR);
            accord_background_voice_free(voice);
        }
    }

    #[test]
    fn test_voice_stats_after_background_cycle() {
        unsafe {
            let voice = accord_background_voice_new();

            accord_voice_enter_background(voice, 1000);
            accord_voice_enter_foreground(voice, 6000);

            let mut stats = AccordVoiceStats {
                total_background_ms: 0,
                packets_received_in_background: 0,
                keepalives_sent: 0,
                reconnection_count: 0,
                failed_reconnections: 0,
                frames_dropped: 0,
                current_state: -1,
            };
            let rc = accord_voice_get_stats(voice, &mut stats as *mut AccordVoiceStats);
            assert_eq!(rc, ACCORD_OK);
            // At least 5000 ms should have been tracked as background time
            assert!(stats.total_background_ms >= 5000);

            accord_background_voice_free(voice);
        }
    }

    // ─── SenderKeyStore ──────────────────────────────────────────────────────

    #[test]
    fn test_sender_key_store_lifecycle() {
        unsafe {
            let store = accord_sender_key_store_create();
            assert!(!store.is_null());
            accord_sender_key_store_free(store);
        }
    }

    #[test]
    fn test_sender_key_store_free_null_no_crash() {
        unsafe {
            accord_sender_key_store_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_sender_key_distribution_roundtrip() {
        unsafe {
            let sender_store = accord_sender_key_store_create();
            let receiver_store = accord_sender_key_store_create();

            let channel = CString::new("room-1").unwrap();
            let sender_id = CString::new("alice").unwrap();

            // Create distribution
            let dist_buf = accord_sender_key_create_distribution(sender_store, channel.as_ptr());
            assert!(!dist_buf.is_null());
            assert!((*dist_buf).len > 0);

            // Convert buffer to a C string for process_distribution
            let dist_json =
                std::str::from_utf8(slice::from_raw_parts((*dist_buf).data, (*dist_buf).len))
                    .expect("distribution JSON must be valid UTF-8");
            let dist_cstring = CString::new(dist_json).expect("no null bytes in JSON");

            let rc = accord_sender_key_process_distribution(
                receiver_store,
                channel.as_ptr(),
                sender_id.as_ptr(),
                dist_cstring.as_ptr(),
            );
            assert_eq!(rc, ACCORD_OK);

            accord_buffer_free(dist_buf);
            accord_sender_key_store_free(sender_store);
            accord_sender_key_store_free(receiver_store);
        }
    }

    #[test]
    fn test_sender_key_encrypt_decrypt_roundtrip() {
        unsafe {
            let sender_store = accord_sender_key_store_create();
            let receiver_store = accord_sender_key_store_create();

            let channel = CString::new("room-1").unwrap();
            let sender_id = CString::new("alice").unwrap();
            let plaintext = b"secret message";

            // Share distribution so receiver knows the sender key
            let dist_buf = accord_sender_key_create_distribution(sender_store, channel.as_ptr());
            assert!(!dist_buf.is_null());
            let dist_json =
                std::str::from_utf8(slice::from_raw_parts((*dist_buf).data, (*dist_buf).len))
                    .unwrap();
            let dist_cstring = CString::new(dist_json).unwrap();
            let rc = accord_sender_key_process_distribution(
                receiver_store,
                channel.as_ptr(),
                sender_id.as_ptr(),
                dist_cstring.as_ptr(),
            );
            assert_eq!(rc, ACCORD_OK);

            // Encrypt
            let enc_buf = accord_sender_key_encrypt(
                sender_store,
                channel.as_ptr(),
                plaintext.as_ptr(),
                plaintext.len(),
            );
            assert!(!enc_buf.is_null());
            assert!((*enc_buf).len > 0);

            // The envelope is JSON — convert to CString for decrypt
            let envelope_json =
                std::str::from_utf8(slice::from_raw_parts((*enc_buf).data, (*enc_buf).len))
                    .expect("envelope must be valid UTF-8");
            let envelope_cstring = CString::new(envelope_json).expect("no null bytes in envelope");

            // Decrypt
            let dec_buf = accord_sender_key_decrypt(
                receiver_store,
                channel.as_ptr(),
                sender_id.as_ptr(),
                envelope_cstring.as_ptr(),
            );
            assert!(!dec_buf.is_null());
            let recovered = slice::from_raw_parts((*dec_buf).data, (*dec_buf).len);
            assert_eq!(recovered, plaintext);

            accord_buffer_free(dist_buf);
            accord_buffer_free(enc_buf);
            accord_buffer_free(dec_buf);
            accord_sender_key_store_free(sender_store);
            accord_sender_key_store_free(receiver_store);
        }
    }

    #[test]
    fn test_sender_key_null_safety() {
        unsafe {
            let channel = CString::new("ch").unwrap();
            let sender = CString::new("alice").unwrap();
            let dist = CString::new("{}").unwrap();
            let msg = b"hi";

            // create_distribution with null store
            assert!(
                accord_sender_key_create_distribution(ptr::null_mut(), channel.as_ptr()).is_null()
            );
            // create_distribution with null channel
            let store = accord_sender_key_store_create();
            assert!(accord_sender_key_create_distribution(store, ptr::null()).is_null());
            accord_sender_key_store_free(store);

            // process_distribution with null store
            assert_eq!(
                accord_sender_key_process_distribution(
                    ptr::null_mut(),
                    channel.as_ptr(),
                    sender.as_ptr(),
                    dist.as_ptr()
                ),
                ACCORD_ERR_NULL_PTR
            );

            // encrypt with null store
            assert!(accord_sender_key_encrypt(
                ptr::null_mut(),
                channel.as_ptr(),
                msg.as_ptr(),
                msg.len()
            )
            .is_null());

            // decrypt with null store
            assert!(accord_sender_key_decrypt(
                ptr::null_mut(),
                channel.as_ptr(),
                sender.as_ptr(),
                dist.as_ptr()
            )
            .is_null());
        }
    }

    // ─── Legacy null safety (kept for regression) ────────────────────────────

    #[test]
    fn test_null_safety() {
        unsafe {
            // All functions should handle null gracefully
            accord_buffer_free(ptr::null_mut());
            accord_keymaterial_free(ptr::null_mut());
            accord_session_manager_free(ptr::null_mut());

            assert!(accord_keymaterial_identity_key(ptr::null()).is_null());
            assert!(accord_keymaterial_signed_prekey(ptr::null()).is_null());
            assert!(accord_keymaterial_publishable_bundle(ptr::null()).is_null());

            assert_eq!(
                accord_session_manager_has_session(ptr::null(), ptr::null(), ptr::null()),
                ACCORD_ERR_NULL_PTR
            );
        }
    }
}
