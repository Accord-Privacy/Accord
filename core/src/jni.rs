//! # JNI bindings for accord-core
//!
//! Provides JNI (Java Native Interface) bindings for use from Kotlin/Android.
//! Wraps the same underlying crypto as the C FFI (`ffi.rs`), but uses JNI
//! conventions: byte arrays, strings, and Java exceptions for error handling.
//!
//! All functions follow the naming convention:
//!   `Java_com_accord_core_AccordCore_<methodName>`

#![cfg(feature = "android")]

use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use crate::double_ratchet::{DoubleRatchetMessage, PreKeyBundle};
use crate::session_manager::{LocalKeyMaterial, SessionId, SessionManager, X3DHInitialMessage};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn throw_accord_exception(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", msg);
}

fn jbytearray_to_vec(env: &mut JNIEnv, arr: &JByteArray) -> Result<Vec<u8>, String> {
    env.convert_byte_array(arr)
        .map_err(|e| format!("Failed to convert byte array: {e}"))
}

fn jstring_to_string(env: &mut JNIEnv, s: &JString) -> Result<String, String> {
    env.get_string(s)
        .map(|s| s.into())
        .map_err(|e| format!("Failed to convert string: {e}"))
}

fn vec_to_jbytearray(env: &mut JNIEnv, data: &[u8]) -> jbyteArray {
    match env.byte_array_from_slice(data) {
        Ok(arr) => arr.into_raw(),
        Err(_) => JObject::null().into_raw(),
    }
}

// ─── Key Material ────────────────────────────────────────────────────────────

/// Generate new key material. Returns an opaque pointer as jlong.
#[no_mangle]
pub extern "system" fn Java_com_accord_core_AccordCore_nativeKeyMaterialGenerate(
    _env: JNIEnv,
    _class: JClass,
    num_one_time_prekeys: jint,
) -> jlong {
    let km = LocalKeyMaterial::generate(num_one_time_prekeys as usize);
    Box::into_raw(Box::new(km)) as jlong
}

/// Free key material.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeKeyMaterialFree(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    if ptr != 0 {
        drop(Box::from_raw(ptr as *mut LocalKeyMaterial));
    }
}

/// Get identity public key (32 bytes).
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeKeyMaterialIdentityKey(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jbyteArray {
    if ptr == 0 {
        throw_accord_exception(&mut env, "Null key material pointer");
        return JObject::null().into_raw();
    }
    let km = &*(ptr as *const LocalKeyMaterial);
    vec_to_jbytearray(&mut env, &km.identity.public.to_bytes())
}

/// Get signed prekey public key (32 bytes).
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeKeyMaterialSignedPrekey(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jbyteArray {
    if ptr == 0 {
        throw_accord_exception(&mut env, "Null key material pointer");
        return JObject::null().into_raw();
    }
    let km = &*(ptr as *const LocalKeyMaterial);
    vec_to_jbytearray(&mut env, &km.signed_prekey.public.to_bytes())
}

/// Get publishable bundle as serialized bytes (bincode).
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeKeyMaterialPublishableBundle(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jbyteArray {
    if ptr == 0 {
        throw_accord_exception(&mut env, "Null key material pointer");
        return JObject::null().into_raw();
    }
    let km = &*(ptr as *const LocalKeyMaterial);
    let bundle = km.to_publishable_bundle();
    match bincode::serialize(&bundle) {
        Ok(data) => vec_to_jbytearray(&mut env, &data),
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Serialization failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

// ─── Session Manager ─────────────────────────────────────────────────────────

/// Create a new session manager. Returns opaque pointer as jlong.
#[no_mangle]
pub extern "system" fn Java_com_accord_core_AccordCore_nativeSessionManagerNew(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    Box::into_raw(Box::new(SessionManager::new())) as jlong
}

/// Free a session manager.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeSessionManagerFree(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    if ptr != 0 {
        drop(Box::from_raw(ptr as *mut SessionManager));
    }
}

/// Check if a session exists.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeSessionManagerHasSession(
    mut env: JNIEnv,
    _class: JClass,
    mgr_ptr: jlong,
    peer_user_id: JString,
    channel_id: JString,
) -> jboolean {
    if mgr_ptr == 0 {
        throw_accord_exception(&mut env, "Null session manager pointer");
        return JNI_FALSE;
    }
    let mgr = &*(mgr_ptr as *const SessionManager);

    let peer = match jstring_to_string(&mut env, &peer_user_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JNI_FALSE;
        }
    };
    let channel = match jstring_to_string(&mut env, &channel_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JNI_FALSE;
        }
    };

    let sid = SessionId {
        peer_user_id: peer,
        channel_id: channel,
    };
    if mgr.has_session(&sid) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Initiate a session (Alice side). Returns serialized X3DHInitialMessage.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeSessionManagerInitiate(
    mut env: JNIEnv,
    _class: JClass,
    mgr_ptr: jlong,
    km_ptr: jlong,
    peer_user_id: JString,
    channel_id: JString,
    their_bundle: JByteArray,
    first_message: JByteArray,
) -> jbyteArray {
    if mgr_ptr == 0 || km_ptr == 0 {
        throw_accord_exception(&mut env, "Null pointer");
        return JObject::null().into_raw();
    }
    let mgr = &mut *(mgr_ptr as *mut SessionManager);
    let km = &*(km_ptr as *const LocalKeyMaterial);

    let peer = match jstring_to_string(&mut env, &peer_user_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let channel = match jstring_to_string(&mut env, &channel_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let bundle_bytes = match jbytearray_to_vec(&mut env, &their_bundle) {
        Ok(b) => b,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let plaintext = match jbytearray_to_vec(&mut env, &first_message) {
        Ok(b) => b,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };

    let bundle: PreKeyBundle = match bincode::deserialize(&bundle_bytes) {
        Ok(b) => b,
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Failed to deserialize bundle: {e}"));
            return JObject::null().into_raw();
        }
    };

    let sid = SessionId {
        peer_user_id: peer,
        channel_id: channel,
    };

    match mgr.initiate_session(km, &bundle, sid, &plaintext) {
        Ok(initial_msg) => match bincode::serialize(&initial_msg) {
            Ok(data) => vec_to_jbytearray(&mut env, &data),
            Err(e) => {
                throw_accord_exception(&mut env, &format!("Serialization failed: {e}"));
                JObject::null().into_raw()
            }
        },
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Session initiation failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Receive an initial X3DH message (Bob side). Returns decrypted first message.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeSessionManagerReceiveInitial(
    mut env: JNIEnv,
    _class: JClass,
    mgr_ptr: jlong,
    km_ptr: jlong,
    peer_user_id: JString,
    channel_id: JString,
    initial_msg_data: JByteArray,
) -> jbyteArray {
    if mgr_ptr == 0 || km_ptr == 0 {
        throw_accord_exception(&mut env, "Null pointer");
        return JObject::null().into_raw();
    }
    let mgr = &mut *(mgr_ptr as *mut SessionManager);
    let km = &mut *(km_ptr as *mut LocalKeyMaterial);

    let peer = match jstring_to_string(&mut env, &peer_user_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let channel = match jstring_to_string(&mut env, &channel_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let msg_bytes = match jbytearray_to_vec(&mut env, &initial_msg_data) {
        Ok(b) => b,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };

    let initial_msg: X3DHInitialMessage = match bincode::deserialize(&msg_bytes) {
        Ok(m) => m,
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Failed to deserialize message: {e}"));
            return JObject::null().into_raw();
        }
    };

    let sid = SessionId {
        peer_user_id: peer,
        channel_id: channel,
    };

    match mgr.receive_initial_message(km, &initial_msg, sid) {
        Ok(plaintext) => vec_to_jbytearray(&mut env, &plaintext),
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Receive initial failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Encrypt a message for an established session.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeSessionManagerEncrypt(
    mut env: JNIEnv,
    _class: JClass,
    mgr_ptr: jlong,
    peer_user_id: JString,
    channel_id: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    if mgr_ptr == 0 {
        throw_accord_exception(&mut env, "Null session manager pointer");
        return JObject::null().into_raw();
    }
    let mgr = &mut *(mgr_ptr as *mut SessionManager);

    let peer = match jstring_to_string(&mut env, &peer_user_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let channel = match jstring_to_string(&mut env, &channel_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let plain = match jbytearray_to_vec(&mut env, &plaintext) {
        Ok(b) => b,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };

    let sid = SessionId {
        peer_user_id: peer,
        channel_id: channel,
    };

    match mgr.encrypt_message(&sid, &plain) {
        Ok(msg) => match bincode::serialize(&msg) {
            Ok(data) => vec_to_jbytearray(&mut env, &data),
            Err(e) => {
                throw_accord_exception(&mut env, &format!("Serialization failed: {e}"));
                JObject::null().into_raw()
            }
        },
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Encryption failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Decrypt a message from an established session.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeSessionManagerDecrypt(
    mut env: JNIEnv,
    _class: JClass,
    mgr_ptr: jlong,
    peer_user_id: JString,
    channel_id: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    if mgr_ptr == 0 {
        throw_accord_exception(&mut env, "Null session manager pointer");
        return JObject::null().into_raw();
    }
    let mgr = &mut *(mgr_ptr as *mut SessionManager);

    let peer = match jstring_to_string(&mut env, &peer_user_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let channel = match jstring_to_string(&mut env, &channel_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let cipher = match jbytearray_to_vec(&mut env, &ciphertext) {
        Ok(b) => b,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };

    let msg: DoubleRatchetMessage = match bincode::deserialize(&cipher) {
        Ok(m) => m,
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Failed to deserialize message: {e}"));
            return JObject::null().into_raw();
        }
    };

    let sid = SessionId {
        peer_user_id: peer,
        channel_id: channel,
    };

    match mgr.decrypt_message(&sid, &msg) {
        Ok(plaintext) => vec_to_jbytearray(&mut env, &plaintext),
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Decryption failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Serialize a PreKeyBundle from component keys.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativePreKeyBundleSerialize(
    mut env: JNIEnv,
    _class: JClass,
    identity_key: JByteArray,
    signed_prekey: JByteArray,
    one_time_prekey: JByteArray, // may be null/empty
) -> jbyteArray {
    let ik = match jbytearray_to_vec(&mut env, &identity_key) {
        Ok(b) if b.len() == 32 => b,
        Ok(_) => {
            throw_accord_exception(&mut env, "Identity key must be 32 bytes");
            return JObject::null().into_raw();
        }
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let spk = match jbytearray_to_vec(&mut env, &signed_prekey) {
        Ok(b) if b.len() == 32 => b,
        Ok(_) => {
            throw_accord_exception(&mut env, "Signed prekey must be 32 bytes");
            return JObject::null().into_raw();
        }
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };

    let opk = if one_time_prekey.is_null() {
        None
    } else {
        match jbytearray_to_vec(&mut env, &one_time_prekey) {
            Ok(b) if b.is_empty() => None,
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Some(arr)
            }
            Ok(_) => {
                throw_accord_exception(&mut env, "One-time prekey must be 32 bytes");
                return JObject::null().into_raw();
            }
            Err(_) => None,
        }
    };

    let mut ik_arr = [0u8; 32];
    ik_arr.copy_from_slice(&ik);
    let mut spk_arr = [0u8; 32];
    spk_arr.copy_from_slice(&spk);

    let bundle = PreKeyBundle {
        identity_key: ik_arr,
        signed_prekey: spk_arr,
        one_time_prekey: opk,
    };

    match bincode::serialize(&bundle) {
        Ok(data) => vec_to_jbytearray(&mut env, &data),
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Serialization failed: {e}"));
            JObject::null().into_raw()
        }
    }
}
