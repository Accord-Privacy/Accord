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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

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
