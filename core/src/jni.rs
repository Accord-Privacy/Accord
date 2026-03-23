//! # JNI bindings for accord-core
//!
//! Provides JNI (Java Native Interface) bindings for use from Kotlin/Android.
//! Wraps the same underlying crypto as the C FFI (`ffi.rs`), but uses JNI
//! conventions: byte arrays, strings, and Java exceptions for error handling.
//!
//! All functions follow the naming convention:
//!   `Java_com_accord_core_AccordCore_<methodName>`

// All JNI exports share the same safety contract: the JVM must provide valid
// JNIEnv and JClass pointers, and all jobject / jbyteArray / jstring arguments
// must be valid JNI local references (or null where documented).  These
// invariants are guaranteed by the JVM when calling native methods.
#![allow(clippy::missing_safety_doc)]

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

// ─── Background Voice ────────────────────────────────────────────────────────

use crate::background_voice::{BackgroundVoiceConfig, BackgroundVoiceSession, VoiceLifecycleState};

/// Create a new background voice session. Returns opaque pointer as jlong.
#[no_mangle]
pub extern "system" fn Java_com_accord_core_AccordCore_nativeBackgroundVoiceNew(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let session = crate::background_voice::create_shared_session(BackgroundVoiceConfig::default());
    // Store the Arc as a raw pointer
    let ptr = std::sync::Arc::into_raw(session);
    ptr as jlong
}

/// Free a background voice session.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeBackgroundVoiceFree(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    if ptr != 0 {
        drop(std::sync::Arc::from_raw(
            ptr as *const BackgroundVoiceSession,
        ));
    }
}

/// Notify app entered background. Returns true on success.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeVoiceEnterBackground(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    now_ms: jlong,
) -> jboolean {
    if ptr == 0 {
        throw_accord_exception(&mut env, "Null background voice pointer");
        return JNI_FALSE;
    }
    let session = &*(ptr as *const BackgroundVoiceSession);
    match session.enter_background(now_ms as u64) {
        Some(_) => JNI_TRUE,
        None => JNI_FALSE,
    }
}

/// Notify app entered foreground. Returns true on success.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeVoiceEnterForeground(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
    now_ms: jlong,
) -> jboolean {
    if ptr == 0 {
        throw_accord_exception(&mut env, "Null background voice pointer");
        return JNI_FALSE;
    }
    let session = &*(ptr as *const BackgroundVoiceSession);
    match session.enter_foreground(now_ms as u64) {
        Some(_) => JNI_TRUE,
        None => JNI_FALSE,
    }
}

/// Check if voice session is active (not suspended).
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeVoiceIsActive(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jboolean {
    if ptr == 0 {
        throw_accord_exception(&mut env, "Null background voice pointer");
        return JNI_FALSE;
    }
    let session = &*(ptr as *const BackgroundVoiceSession);
    if session.is_active() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Get voice stats as a JSON-encoded byte array.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeVoiceGetStats(
    mut env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) -> jbyteArray {
    if ptr == 0 {
        throw_accord_exception(&mut env, "Null background voice pointer");
        return JObject::null().into_raw();
    }
    let session = &*(ptr as *const BackgroundVoiceSession);
    let stats = session.stats();

    // Encode stats as simple JSON for Kotlin consumption
    let json = format!(
        r#"{{"total_background_ms":{},"packets_received_in_background":{},"keepalives_sent":{},"reconnection_count":{},"failed_reconnections":{},"frames_dropped":{},"current_state":"{}"}}"#,
        stats.total_background_ms,
        stats.packets_received_in_background,
        stats.keepalives_sent,
        stats.reconnection_count,
        stats.failed_reconnections,
        stats.frames_dropped,
        match stats.current_state {
            Some(VoiceLifecycleState::Active) => "active",
            Some(VoiceLifecycleState::Backgrounded) => "backgrounded",
            Some(VoiceLifecycleState::Reconnecting) => "reconnecting",
            Some(VoiceLifecycleState::Suspended) => "suspended",
            None => "unknown",
        }
    );
    vec_to_jbytearray(&mut env, json.as_bytes())
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

// ─── Sender Keys ─────────────────────────────────────────────────────────────

use crate::sender_keys::{self, SenderKeyStore};

/// Create a new SenderKeyStore, returning an opaque pointer as jlong.
#[no_mangle]
pub extern "system" fn Java_com_accord_core_AccordCore_nativeSenderKeyStoreCreate(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    Box::into_raw(Box::new(SenderKeyStore::new())) as jlong
}

/// Free a SenderKeyStore.
#[no_mangle]
pub unsafe extern "system" fn Java_com_accord_core_AccordCore_nativeSenderKeyStoreFree(
    _env: JNIEnv,
    _class: JClass,
    ptr: jlong,
) {
    if ptr != 0 {
        drop(Box::from_raw(ptr as *mut SenderKeyStore));
    }
}

/// Encrypt a channel message. Returns JSON envelope as byte[].
#[no_mangle]
pub extern "system" fn Java_com_accord_core_AccordCore_nativeSenderKeyEncrypt(
    mut env: JNIEnv,
    _class: JClass,
    store_ptr: jlong,
    channel_id: JString,
    plaintext: JString,
) -> jbyteArray {
    let store = unsafe { &mut *(store_ptr as *mut SenderKeyStore) };
    let channel_id = match jstring_to_string(&mut env, &channel_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let plaintext = match jstring_to_string(&mut env, &plaintext) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    match sender_keys::encrypt_channel_message(store, &channel_id, &plaintext) {
        Ok(json) => vec_to_jbytearray(&mut env, json.as_bytes()),
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Encrypt failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Decrypt a channel message. Returns plaintext as byte[].
#[no_mangle]
pub extern "system" fn Java_com_accord_core_AccordCore_nativeSenderKeyDecrypt(
    mut env: JNIEnv,
    _class: JClass,
    store_ptr: jlong,
    channel_id: JString,
    sender_id: JString,
    envelope_json: JString,
) -> jbyteArray {
    let store = unsafe { &mut *(store_ptr as *mut SenderKeyStore) };
    let channel_id = match jstring_to_string(&mut env, &channel_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let sender_id = match jstring_to_string(&mut env, &sender_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let envelope_json = match jstring_to_string(&mut env, &envelope_json) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    match sender_keys::decrypt_channel_message(store, &channel_id, &sender_id, &envelope_json) {
        Ok(plaintext) => vec_to_jbytearray(&mut env, plaintext.as_bytes()),
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Decrypt failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Create a distribution message for a channel. Returns JSON as byte[].
#[no_mangle]
pub extern "system" fn Java_com_accord_core_AccordCore_nativeSenderKeyCreateDistribution(
    mut env: JNIEnv,
    _class: JClass,
    store_ptr: jlong,
    channel_id: JString,
) -> jbyteArray {
    let store = unsafe { &mut *(store_ptr as *mut SenderKeyStore) };
    let channel_id = match jstring_to_string(&mut env, &channel_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JObject::null().into_raw();
        }
    };
    let sk = store.get_or_create_my_key(&channel_id).clone();
    let dist = sender_keys::build_distribution_message(&channel_id, &sk, None);
    match serde_json::to_string(&dist) {
        Ok(json) => vec_to_jbytearray(&mut env, json.as_bytes()),
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Serialization failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Process a received distribution message, storing the peer's key.
#[no_mangle]
pub extern "system" fn Java_com_accord_core_AccordCore_nativeSenderKeyProcessDistribution(
    mut env: JNIEnv,
    _class: JClass,
    store_ptr: jlong,
    channel_id: JString,
    sender_id: JString,
    distribution_json: JString,
) -> jboolean {
    let store = unsafe { &mut *(store_ptr as *mut SenderKeyStore) };
    let channel_id = match jstring_to_string(&mut env, &channel_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JNI_FALSE;
        }
    };
    let sender_id = match jstring_to_string(&mut env, &sender_id) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JNI_FALSE;
        }
    };
    let dist_json = match jstring_to_string(&mut env, &distribution_json) {
        Ok(s) => s,
        Err(e) => {
            throw_accord_exception(&mut env, &e);
            return JNI_FALSE;
        }
    };
    let dist: sender_keys::SenderKeyDistributionMessage = match serde_json::from_str(&dist_json) {
        Ok(d) => d,
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Parse failed: {e}"));
            return JNI_FALSE;
        }
    };
    match sender_keys::parse_distribution_message(&dist) {
        Ok((_, state)) => {
            store.set_peer_key(&channel_id, &sender_id, state);
            JNI_TRUE
        }
        Err(e) => {
            throw_accord_exception(&mut env, &format!("Distribution failed: {e}"));
            JNI_FALSE
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::background_voice::{
        BackgroundVoiceConfig, BackgroundVoiceSession, VoiceLifecycleState,
    };
    use crate::double_ratchet::PreKeyBundle;
    use crate::sender_keys::{self, SenderKeyStore};
    use crate::session_manager::{LocalKeyMaterial, SessionId, SessionManager};

    // ─── LocalKeyMaterial::generate ─────────────────────────────────────

    #[test]
    fn key_material_generate_zero_prekeys() {
        let km = LocalKeyMaterial::generate(0);
        assert!(km.one_time_prekeys.is_empty());
        // Identity and signed prekey should always exist.
        let _ik = km.identity.public.to_bytes();
        let _spk = km.signed_prekey.public.to_bytes();
    }

    #[test]
    fn key_material_generate_one_prekey() {
        let km = LocalKeyMaterial::generate(1);
        assert_eq!(km.one_time_prekeys.len(), 1);
    }

    #[test]
    fn key_material_generate_many_prekeys() {
        let km = LocalKeyMaterial::generate(100);
        assert_eq!(km.one_time_prekeys.len(), 100);
    }

    #[test]
    fn key_material_unique_keys() {
        let km1 = LocalKeyMaterial::generate(1);
        let km2 = LocalKeyMaterial::generate(1);
        // Different generations should produce different identity keys.
        assert_ne!(
            km1.identity.public.to_bytes(),
            km2.identity.public.to_bytes()
        );
    }

    // ─── PreKeyBundle serialization round-trip ──────────────────────────

    #[test]
    fn prekey_bundle_round_trip_with_one_time() {
        let bundle = PreKeyBundle {
            identity_key: [1u8; 32],
            signed_prekey: [2u8; 32],
            one_time_prekey: Some([3u8; 32]),
        };
        let bytes = bincode::serialize(&bundle).unwrap();
        let restored: PreKeyBundle = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored.identity_key, [1u8; 32]);
        assert_eq!(restored.signed_prekey, [2u8; 32]);
        assert_eq!(restored.one_time_prekey, Some([3u8; 32]));
    }

    #[test]
    fn prekey_bundle_round_trip_without_one_time() {
        let bundle = PreKeyBundle {
            identity_key: [10u8; 32],
            signed_prekey: [20u8; 32],
            one_time_prekey: None,
        };
        let bytes = bincode::serialize(&bundle).unwrap();
        let restored: PreKeyBundle = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored.identity_key, [10u8; 32]);
        assert_eq!(restored.signed_prekey, [20u8; 32]);
        assert_eq!(restored.one_time_prekey, None);
    }

    #[test]
    fn prekey_bundle_different_serialized_sizes() {
        let with_opk = PreKeyBundle {
            identity_key: [0u8; 32],
            signed_prekey: [0u8; 32],
            one_time_prekey: Some([0u8; 32]),
        };
        let without_opk = PreKeyBundle {
            identity_key: [0u8; 32],
            signed_prekey: [0u8; 32],
            one_time_prekey: None,
        };
        let bytes_with = bincode::serialize(&with_opk).unwrap();
        let bytes_without = bincode::serialize(&without_opk).unwrap();
        // With OPK should be larger (32 bytes + option tag).
        assert!(bytes_with.len() > bytes_without.len());
    }

    #[test]
    fn prekey_bundle_invalid_bytes_deserialization() {
        let garbage = vec![0xFF, 0xFE, 0xFD];
        let result = bincode::deserialize::<PreKeyBundle>(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn prekey_bundle_empty_bytes_deserialization() {
        let result = bincode::deserialize::<PreKeyBundle>(&[]);
        assert!(result.is_err());
    }

    // ─── PublishableKeyBundle round-trip via LocalKeyMaterial ────────────

    #[test]
    fn publishable_bundle_serialization_round_trip() {
        let km = LocalKeyMaterial::generate(3);
        let bundle = km.to_publishable_bundle();
        let bytes = bincode::serialize(&bundle).unwrap();
        let restored: crate::session_manager::PublishableKeyBundle =
            bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored.identity_key, bundle.identity_key);
        assert_eq!(restored.signed_prekey, bundle.signed_prekey);
        assert_eq!(restored.one_time_prekeys.len(), 3);
    }

    // ─── SessionManager ─────────────────────────────────────────────────

    #[test]
    fn session_manager_new_is_empty() {
        let mgr = SessionManager::new();
        let sid = SessionId {
            peer_user_id: "alice".into(),
            channel_id: "ch1".into(),
        };
        assert!(!mgr.has_session(&sid));
    }

    #[test]
    fn session_manager_has_session_different_ids() {
        let mgr = SessionManager::new();
        let sid1 = SessionId {
            peer_user_id: "alice".into(),
            channel_id: "ch1".into(),
        };
        let sid2 = SessionId {
            peer_user_id: "bob".into(),
            channel_id: "ch2".into(),
        };
        assert!(!mgr.has_session(&sid1));
        assert!(!mgr.has_session(&sid2));
    }

    #[test]
    fn session_manager_encrypt_without_session_errors() {
        let mut mgr = SessionManager::new();
        let sid = SessionId {
            peer_user_id: "alice".into(),
            channel_id: "ch1".into(),
        };
        let result = mgr.encrypt_message(&sid, b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn session_manager_decrypt_without_session_errors() {
        let mut mgr = SessionManager::new();
        let sid = SessionId {
            peer_user_id: "alice".into(),
            channel_id: "ch1".into(),
        };
        // Build a fake DoubleRatchetMessage to attempt decryption.
        let fake_msg = crate::double_ratchet::DoubleRatchetMessage {
            header: crate::double_ratchet::MessageHeader {
                dh_public_key: [0u8; 32],
                previous_chain_length: 0,
                message_number: 0,
            },
            ciphertext: vec![0u8; 64],
        };
        let result = mgr.decrypt_message(&sid, &fake_msg);
        assert!(result.is_err());
    }

    // ─── Full session initiation and message exchange ───────────────────

    #[test]
    fn session_full_handshake_and_messages() {
        // Alice and Bob each generate key material.
        let alice_km = LocalKeyMaterial::generate(5);
        let mut bob_km = LocalKeyMaterial::generate(5);

        // Bob publishes a PreKeyBundle (simulating JNI serialization).
        let bob_bundle = PreKeyBundle {
            identity_key: bob_km.identity.public.to_bytes(),
            signed_prekey: bob_km.signed_prekey.public.to_bytes(),
            one_time_prekey: bob_km.one_time_prekeys.first().map(|k| k.public.to_bytes()),
        };

        // Serialize and deserialize the bundle (same as JNI layer does).
        let bundle_bytes = bincode::serialize(&bob_bundle).unwrap();
        let deserialized_bundle: PreKeyBundle = bincode::deserialize(&bundle_bytes).unwrap();

        // Alice initiates a session.
        let mut alice_mgr = SessionManager::new();
        let alice_sid = SessionId {
            peer_user_id: "bob".into(),
            channel_id: "ch1".into(),
        };
        let first_msg = b"Hello Bob!";
        let initial_msg = alice_mgr
            .initiate_session(
                &alice_km,
                &deserialized_bundle,
                alice_sid.clone(),
                first_msg,
            )
            .unwrap();

        // Serialize/deserialize X3DHInitialMessage (as JNI does).
        let initial_bytes = bincode::serialize(&initial_msg).unwrap();
        let deserialized_initial: crate::session_manager::X3DHInitialMessage =
            bincode::deserialize(&initial_bytes).unwrap();

        // Bob receives the initial message.
        let mut bob_mgr = SessionManager::new();
        let bob_sid = SessionId {
            peer_user_id: "alice".into(),
            channel_id: "ch1".into(),
        };
        let decrypted_first = bob_mgr
            .receive_initial_message(&mut bob_km, &deserialized_initial, bob_sid.clone())
            .unwrap();
        assert_eq!(decrypted_first, first_msg);

        // Alice now has a session and can encrypt.
        assert!(alice_mgr.has_session(&alice_sid));
        let msg2 = alice_mgr
            .encrypt_message(&alice_sid, b"Second message")
            .unwrap();

        // Serialize/deserialize the DoubleRatchetMessage.
        let msg2_bytes = bincode::serialize(&msg2).unwrap();
        let msg2_deser: crate::double_ratchet::DoubleRatchetMessage =
            bincode::deserialize(&msg2_bytes).unwrap();

        let plain2 = bob_mgr.decrypt_message(&bob_sid, &msg2_deser).unwrap();
        assert_eq!(plain2, b"Second message");
    }

    #[test]
    fn session_handshake_without_one_time_prekey() {
        let alice_km = LocalKeyMaterial::generate(0); // No one-time prekeys
        let mut bob_km = LocalKeyMaterial::generate(0);

        let bob_bundle = PreKeyBundle {
            identity_key: bob_km.identity.public.to_bytes(),
            signed_prekey: bob_km.signed_prekey.public.to_bytes(),
            one_time_prekey: None,
        };

        let mut alice_mgr = SessionManager::new();
        let sid = SessionId {
            peer_user_id: "bob".into(),
            channel_id: "ch1".into(),
        };

        let initial = alice_mgr
            .initiate_session(&alice_km, &bob_bundle, sid.clone(), b"no OPK")
            .unwrap();

        let mut bob_mgr = SessionManager::new();
        let bob_sid = SessionId {
            peer_user_id: "alice".into(),
            channel_id: "ch1".into(),
        };
        let plain = bob_mgr
            .receive_initial_message(&mut bob_km, &initial, bob_sid)
            .unwrap();
        assert_eq!(plain, b"no OPK");
    }

    #[test]
    fn session_empty_plaintext() {
        let alice_km = LocalKeyMaterial::generate(1);
        let mut bob_km = LocalKeyMaterial::generate(1);

        let bob_bundle = PreKeyBundle {
            identity_key: bob_km.identity.public.to_bytes(),
            signed_prekey: bob_km.signed_prekey.public.to_bytes(),
            one_time_prekey: bob_km.one_time_prekeys.first().map(|k| k.public.to_bytes()),
        };

        let mut alice_mgr = SessionManager::new();
        let sid = SessionId {
            peer_user_id: "bob".into(),
            channel_id: "ch1".into(),
        };

        // Empty plaintext should still work.
        let initial = alice_mgr
            .initiate_session(&alice_km, &bob_bundle, sid.clone(), b"")
            .unwrap();

        let mut bob_mgr = SessionManager::new();
        let bob_sid = SessionId {
            peer_user_id: "alice".into(),
            channel_id: "ch1".into(),
        };
        let plain = bob_mgr
            .receive_initial_message(&mut bob_km, &initial, bob_sid)
            .unwrap();
        assert_eq!(plain, b"");
    }

    #[test]
    fn session_large_message() {
        let alice_km = LocalKeyMaterial::generate(1);
        let mut bob_km = LocalKeyMaterial::generate(1);

        let bob_bundle = PreKeyBundle {
            identity_key: bob_km.identity.public.to_bytes(),
            signed_prekey: bob_km.signed_prekey.public.to_bytes(),
            one_time_prekey: bob_km.one_time_prekeys.first().map(|k| k.public.to_bytes()),
        };

        let mut alice_mgr = SessionManager::new();
        let sid = SessionId {
            peer_user_id: "bob".into(),
            channel_id: "ch1".into(),
        };

        let large_msg = vec![0xABu8; 64 * 1024]; // 64 KB
        let initial = alice_mgr
            .initiate_session(&alice_km, &bob_bundle, sid.clone(), &large_msg)
            .unwrap();

        let mut bob_mgr = SessionManager::new();
        let bob_sid = SessionId {
            peer_user_id: "alice".into(),
            channel_id: "ch1".into(),
        };
        let plain = bob_mgr
            .receive_initial_message(&mut bob_km, &initial, bob_sid)
            .unwrap();
        assert_eq!(plain, large_msg);
    }

    // ─── X3DHInitialMessage serialization ───────────────────────────────

    #[test]
    fn x3dh_initial_message_invalid_deserialization() {
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = bincode::deserialize::<crate::session_manager::X3DHInitialMessage>(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn double_ratchet_message_invalid_deserialization() {
        let garbage = vec![0x01, 0x02];
        let result = bincode::deserialize::<crate::double_ratchet::DoubleRatchetMessage>(&garbage);
        assert!(result.is_err());
    }

    // ─── SenderKeyStore ─────────────────────────────────────────────────

    #[test]
    fn sender_key_store_new_empty() {
        let store = SenderKeyStore::new();
        assert!(!store.has_channel_keys("ch1"));
        assert!(store.get_my_key("ch1").is_none());
    }

    #[test]
    fn sender_key_store_get_or_create_my_key() {
        let mut store = SenderKeyStore::new();
        let _key = store.get_or_create_my_key("channel-1");
        assert!(store.has_channel_keys("channel-1"));
        assert!(store.get_my_key("channel-1").is_some());
    }

    #[test]
    fn sender_key_store_idempotent_get_or_create() {
        let mut store = SenderKeyStore::new();
        let k1 = store.get_or_create_my_key("ch1").clone();
        let k2 = store.get_or_create_my_key("ch1").clone();
        // Should return the same key.
        assert_eq!(k1.chain_key, k2.chain_key);
        assert_eq!(k1.iteration, k2.iteration);
    }

    #[test]
    fn sender_key_encrypt_decrypt_round_trip() {
        let mut alice_store = SenderKeyStore::new();
        let mut bob_store = SenderKeyStore::new();

        let channel = "general";

        // Alice creates her key and builds a distribution message.
        let alice_sk = alice_store.get_or_create_my_key(channel).clone();
        let dist = sender_keys::build_distribution_message(channel, &alice_sk, None);

        // Bob processes the distribution.
        let dist_json = serde_json::to_string(&dist).unwrap();
        let dist_parsed: sender_keys::SenderKeyDistributionMessage =
            serde_json::from_str(&dist_json).unwrap();
        let (_, state) = sender_keys::parse_distribution_message(&dist_parsed).unwrap();
        bob_store.set_peer_key(channel, "alice", state);

        // Alice encrypts a message.
        let envelope =
            sender_keys::encrypt_channel_message(&mut alice_store, channel, "Hello everyone!")
                .unwrap();

        // Bob decrypts it.
        let plain =
            sender_keys::decrypt_channel_message(&mut bob_store, channel, "alice", &envelope)
                .unwrap();
        assert_eq!(plain, "Hello everyone!");
    }

    #[test]
    fn sender_key_decrypt_without_peer_key_errors() {
        let mut store = SenderKeyStore::new();
        // Attempting to decrypt without having the sender's key should fail.
        let fake_envelope = r#"{"v":1,"sk":"xxx","i":0,"iv":"AAAA","ct":"BBBB","sig":"CCCC"}"#;
        let result = sender_keys::decrypt_channel_message(
            &mut store,
            "ch1",
            "unknown_sender",
            fake_envelope,
        );
        assert!(result.is_err());
    }

    #[test]
    fn sender_key_distribution_message_json_round_trip() {
        let mut store = SenderKeyStore::new();
        let sk = store.get_or_create_my_key("ch1").clone();
        let dist = sender_keys::build_distribution_message("ch1", &sk, None);

        // Serialize to JSON (same as JNI layer does with serde_json::to_string).
        let json = serde_json::to_string(&dist).unwrap();
        let restored: sender_keys::SenderKeyDistributionMessage =
            serde_json::from_str(&json).unwrap();

        assert_eq!(restored.msg_type, "skdm");
        assert_eq!(restored.ch, "ch1");

        // Parse should succeed.
        let result = sender_keys::parse_distribution_message(&restored);
        assert!(result.is_ok());
    }

    #[test]
    fn sender_key_multiple_messages_iterate() {
        let mut alice_store = SenderKeyStore::new();
        let mut bob_store = SenderKeyStore::new();
        let channel = "ch1";

        // Distribute key.
        let sk = alice_store.get_or_create_my_key(channel).clone();
        let dist = sender_keys::build_distribution_message(channel, &sk, None);
        let dist_json = serde_json::to_string(&dist).unwrap();
        let dist_parsed: sender_keys::SenderKeyDistributionMessage =
            serde_json::from_str(&dist_json).unwrap();
        let (_, state) = sender_keys::parse_distribution_message(&dist_parsed).unwrap();
        bob_store.set_peer_key(channel, "alice", state);

        // Send multiple messages.
        for i in 0..5 {
            let msg = format!("Message {i}");
            let envelope =
                sender_keys::encrypt_channel_message(&mut alice_store, channel, &msg).unwrap();
            let plain =
                sender_keys::decrypt_channel_message(&mut bob_store, channel, "alice", &envelope)
                    .unwrap();
            assert_eq!(plain, msg);
        }
    }

    // ─── BackgroundVoiceSession ─────────────────────────────────────────

    #[test]
    fn background_voice_create_and_active() {
        let session = BackgroundVoiceSession::new(BackgroundVoiceConfig::default());
        assert!(session.is_active());
        assert_eq!(session.state(), VoiceLifecycleState::Active);
    }

    #[test]
    fn background_voice_enter_background_and_foreground() {
        let session = BackgroundVoiceSession::new(BackgroundVoiceConfig::default());

        let state = session.enter_background(1000);
        assert_eq!(state, Some(VoiceLifecycleState::Backgrounded));
        // is_active() returns true for everything except Suspended.
        assert!(session.is_active());
        assert_eq!(session.state(), VoiceLifecycleState::Backgrounded);

        let state = session.enter_foreground(2000);
        assert_eq!(state, Some(VoiceLifecycleState::Active));
        assert!(session.is_active());
        assert_eq!(session.state(), VoiceLifecycleState::Active);
    }

    #[test]
    fn background_voice_stats_initial() {
        let session = BackgroundVoiceSession::new(BackgroundVoiceConfig::default());
        let stats = session.stats();
        assert_eq!(stats.total_background_ms, 0);
        assert_eq!(stats.packets_received_in_background, 0);
        assert_eq!(stats.keepalives_sent, 0);
        assert_eq!(stats.reconnection_count, 0);
        assert_eq!(stats.failed_reconnections, 0);
        assert_eq!(stats.frames_dropped, 0);
    }

    #[test]
    fn background_voice_stats_track_background_time() {
        let session = BackgroundVoiceSession::new(BackgroundVoiceConfig::default());
        session.enter_background(1000);
        session.enter_foreground(3500);

        let stats = session.stats();
        assert_eq!(stats.total_background_ms, 2500);
    }

    #[test]
    fn background_voice_stats_current_state() {
        let session = BackgroundVoiceSession::new(BackgroundVoiceConfig::default());
        let stats = session.stats();
        assert_eq!(stats.current_state, Some(VoiceLifecycleState::Active));

        session.enter_background(1000);
        let stats = session.stats();
        assert_eq!(stats.current_state, Some(VoiceLifecycleState::Backgrounded));
    }

    #[test]
    fn background_voice_shared_session() {
        let session =
            crate::background_voice::create_shared_session(BackgroundVoiceConfig::default());
        assert!(session.is_active());
        // Arc clone should reference the same session.
        let clone = session.clone();
        session.enter_background(100);
        // Both Arc references should see the same Backgrounded state.
        assert_eq!(clone.state(), VoiceLifecycleState::Backgrounded);
        assert_eq!(session.state(), VoiceLifecycleState::Backgrounded);
    }

    #[test]
    fn background_voice_stats_json_format() {
        // Verify the JSON format used in the JNI nativeVoiceGetStats function.
        let session = BackgroundVoiceSession::new(BackgroundVoiceConfig::default());
        let stats = session.stats();

        let json = format!(
            r#"{{"total_background_ms":{},"packets_received_in_background":{},"keepalives_sent":{},"reconnection_count":{},"failed_reconnections":{},"frames_dropped":{},"current_state":"{}"}}"#,
            stats.total_background_ms,
            stats.packets_received_in_background,
            stats.keepalives_sent,
            stats.reconnection_count,
            stats.failed_reconnections,
            stats.frames_dropped,
            match stats.current_state {
                Some(VoiceLifecycleState::Active) => "active",
                Some(VoiceLifecycleState::Backgrounded) => "backgrounded",
                Some(VoiceLifecycleState::Reconnecting) => "reconnecting",
                Some(VoiceLifecycleState::Suspended) => "suspended",
                None => "unknown",
            }
        );

        // The JSON should be valid.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["current_state"], "active");
        assert_eq!(parsed["total_background_ms"], 0);
    }

    #[test]
    fn background_voice_double_background_is_noop() {
        let session = BackgroundVoiceSession::new(BackgroundVoiceConfig::default());
        let s1 = session.enter_background(1000);
        assert_eq!(s1, Some(VoiceLifecycleState::Backgrounded));

        // Second enter_background while already backgrounded.
        let s2 = session.enter_background(2000);
        assert_eq!(s2, None);
    }

    #[test]
    fn background_voice_foreground_while_active_is_noop() {
        let session = BackgroundVoiceSession::new(BackgroundVoiceConfig::default());
        // Already active, enter_foreground should be a no-op.
        let s = session.enter_foreground(1000);
        assert_eq!(s, None);
    }

    // ─── SessionId edge cases ───────────────────────────────────────────

    #[test]
    fn session_id_equality() {
        let a = SessionId {
            peer_user_id: "user-1".into(),
            channel_id: "ch-1".into(),
        };
        let b = SessionId {
            peer_user_id: "user-1".into(),
            channel_id: "ch-1".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn session_id_inequality() {
        let a = SessionId {
            peer_user_id: "user-1".into(),
            channel_id: "ch-1".into(),
        };
        let b = SessionId {
            peer_user_id: "user-1".into(),
            channel_id: "ch-2".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn session_id_hash_consistency() {
        use std::collections::HashSet;
        let sid = SessionId {
            peer_user_id: "u1".into(),
            channel_id: "c1".into(),
        };
        let mut set = HashSet::new();
        set.insert(sid.clone());
        assert!(set.contains(&sid));
    }
}
