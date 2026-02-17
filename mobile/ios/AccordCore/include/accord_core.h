// accord_core.h — C header for accord-core FFI
// Auto-generated conceptually from core/src/ffi.rs
// This header must stay in sync with the Rust FFI.

#ifndef ACCORD_CORE_H
#define ACCORD_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ─── Result codes ────────────────────────────────────────────────────────────

typedef int32_t AccordResult;

#define ACCORD_OK              0
#define ACCORD_ERR_NULL_PTR   -1
#define ACCORD_ERR_INVALID_UTF8 -2
#define ACCORD_ERR_CRYPTO     -3
#define ACCORD_ERR_SERIALIZATION -4
#define ACCORD_ERR_NO_SESSION -5

// ─── Byte buffer ─────────────────────────────────────────────────────────────

typedef struct {
    uint8_t *data;
    size_t len;
} AccordBuffer;

void accord_buffer_free(AccordBuffer *buf);

// ─── Key Material ────────────────────────────────────────────────────────────

typedef struct AccordKeyMaterial AccordKeyMaterial;

AccordKeyMaterial *accord_keymaterial_generate(uint32_t num_one_time_prekeys);
void accord_keymaterial_free(AccordKeyMaterial *km);
AccordBuffer *accord_keymaterial_identity_key(const AccordKeyMaterial *km);
AccordBuffer *accord_keymaterial_signed_prekey(const AccordKeyMaterial *km);
AccordBuffer *accord_keymaterial_publishable_bundle(const AccordKeyMaterial *km);

// ─── Session Manager ─────────────────────────────────────────────────────────

typedef struct AccordSessionManager AccordSessionManager;

AccordSessionManager *accord_session_manager_new(void);
void accord_session_manager_free(AccordSessionManager *mgr);

int32_t accord_session_manager_has_session(
    const AccordSessionManager *mgr,
    const char *peer_user_id,
    const char *channel_id
);

AccordBuffer *accord_session_manager_initiate(
    AccordSessionManager *mgr,
    const AccordKeyMaterial *km,
    const char *peer_user_id,
    const char *channel_id,
    const uint8_t *their_bundle_data,
    size_t their_bundle_len,
    const uint8_t *first_message,
    size_t first_message_len
);

AccordBuffer *accord_session_manager_receive_initial(
    AccordSessionManager *mgr,
    AccordKeyMaterial *km,
    const char *peer_user_id,
    const char *channel_id,
    const uint8_t *initial_msg_data,
    size_t initial_msg_len
);

AccordBuffer *accord_session_manager_encrypt(
    AccordSessionManager *mgr,
    const char *peer_user_id,
    const char *channel_id,
    const uint8_t *plaintext,
    size_t plaintext_len
);

AccordBuffer *accord_session_manager_decrypt(
    AccordSessionManager *mgr,
    const char *peer_user_id,
    const char *channel_id,
    const uint8_t *ciphertext,
    size_t ciphertext_len
);

// ─── PreKeyBundle serialization ──────────────────────────────────────────────

AccordBuffer *accord_prekey_bundle_serialize(
    const uint8_t *identity_key,    // 32 bytes
    const uint8_t *signed_prekey,   // 32 bytes
    const uint8_t *one_time_prekey  // 32 bytes or NULL
);

#ifdef __cplusplus
}
#endif

#endif // ACCORD_CORE_H
