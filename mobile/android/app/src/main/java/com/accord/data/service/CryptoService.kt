package com.accord.data.service

import android.util.Base64
import com.accord.core.KeyMaterial
import com.accord.core.SessionManager
import com.accord.core.serializePreKeyBundle
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Wraps AccordCore JNI bridge for E2EE operations.
 * All DM crypto runs in Rust via native calls — no Java crypto for DMs.
 * Channel (group) messages use symmetric AES-256-GCM with a shared channel key.
 */
class CryptoService : AutoCloseable {
    private var keyMaterial: KeyMaterial? = null
    private val sessionManager = SessionManager()
    private val random = SecureRandom()

    /** Derived symmetric keys for group channels: channelId → 32-byte AES key */
    private val channelKeys = mutableMapOf<String, ByteArray>()

    // ── Key Generation ────────────────────────────────────────────────

    /** Generate fresh key material. Call once on first launch or key rotation. */
    fun generateKeys(oneTimePrekeys: Int = 10) {
        keyMaterial?.close()
        keyMaterial = KeyMaterial(oneTimePrekeys)
    }

    val isInitialized: Boolean get() = keyMaterial != null

    /** Get the publishable pre-key bundle to upload to the relay. */
    fun getPublishableBundle(): ByteArray {
        return requireKeyMaterial().publishableBundle
    }

    fun getIdentityKey(): ByteArray {
        return requireKeyMaterial().identityKey
    }

    fun getSignedPrekey(): ByteArray {
        return requireKeyMaterial().signedPrekey
    }

    /**
     * Build a KeyBundleRequest suitable for the REST API.
     * Returns identity key, signed prekey as base64 strings.
     */
    fun buildKeyBundleForApi(): KeyBundleRequest {
        val km = requireKeyMaterial()
        val bundle = km.publishableBundle
        // publishableBundle encodes: identityKey(32) + signedPrekey(32) + N*oneTimePrekey(32)
        val identityB64 = Base64.encodeToString(km.identityKey, Base64.NO_WRAP)
        val signedB64 = Base64.encodeToString(km.signedPrekey, Base64.NO_WRAP)
        // Extract one-time prekeys from the bundle (after the first 64 bytes)
        val otpks = mutableListOf<String>()
        if (bundle.size > 64) {
            var offset = 64
            while (offset + 32 <= bundle.size) {
                val key = bundle.copyOfRange(offset, offset + 32)
                otpks.add(Base64.encodeToString(key, Base64.NO_WRAP))
                offset += 32
            }
        }
        return KeyBundleRequest(
            identityKey = identityB64,
            signedPrekey = signedB64,
            oneTimePrekeys = otpks,
        )
    }

    // ── DM Sessions (X3DH + Double Ratchet via JNI) ──────────────────

    /** Initiate an encrypted session with a peer. Returns the initial encrypted message. */
    fun initiateSession(
        peerUserId: String,
        channelId: String,
        theirBundle: ByteArray,
        firstMessage: ByteArray,
    ): ByteArray {
        return sessionManager.initiateSession(
            requireKeyMaterial(), peerUserId, channelId, theirBundle, firstMessage
        )
    }

    /**
     * Initiate a session from a KeyBundleResponse (base64 encoded keys).
     */
    fun initiateSessionFromBundle(
        peerUserId: String,
        channelId: String,
        bundleResponse: KeyBundleResponse,
        firstMessage: ByteArray,
    ): ByteArray {
        val identityKey = Base64.decode(bundleResponse.identityKey, Base64.NO_WRAP)
        val signedPrekey = Base64.decode(bundleResponse.signedPrekey, Base64.NO_WRAP)
        val oneTimePrekey = bundleResponse.oneTimePrekey?.let {
            Base64.decode(it, Base64.NO_WRAP)
        }
        val theirBundle = serializePreKeyBundle(identityKey, signedPrekey, oneTimePrekey)
        return initiateSession(peerUserId, channelId, theirBundle, firstMessage)
    }

    /** Process an incoming initial message that establishes a session. */
    fun receiveInitialMessage(
        peerUserId: String,
        channelId: String,
        initialMessage: ByteArray,
    ): ByteArray {
        return sessionManager.receiveInitialMessage(
            requireKeyMaterial(), peerUserId, channelId, initialMessage
        )
    }

    fun hasSession(peerUserId: String, channelId: String): Boolean {
        return sessionManager.hasSession(peerUserId, channelId)
    }

    fun encryptDm(peerUserId: String, channelId: String, plaintext: ByteArray): ByteArray {
        return sessionManager.encrypt(peerUserId, channelId, plaintext)
    }

    fun decryptDm(peerUserId: String, channelId: String, ciphertext: ByteArray): ByteArray {
        return sessionManager.decrypt(peerUserId, channelId, ciphertext)
    }

    // Legacy compat
    fun encrypt(peerUserId: String, channelId: String, plaintext: ByteArray): ByteArray =
        encryptDm(peerUserId, channelId, plaintext)
    fun decrypt(peerUserId: String, channelId: String, ciphertext: ByteArray): ByteArray =
        decryptDm(peerUserId, channelId, ciphertext)

    // ── Channel (Group) Encryption — Symmetric AES-256-GCM ───────────

    /**
     * Derive and store a channel key. Uses HKDF-style derivation:
     * SHA-256(identityKey || channelId bytes) truncated to 32 bytes.
     *
     * This matches the desktop approach where all members of a channel
     * derive the same symmetric key from their shared context.
     */
    fun deriveChannelKey(channelId: String) {
        val identity = getIdentityKey()
        val channelBytes = channelId.toByteArray(Charsets.UTF_8)
        val input = identity + channelBytes
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(input)
        channelKeys[channelId] = digest
    }

    /**
     * Set a pre-shared channel key directly (e.g., received from key exchange).
     */
    fun setChannelKey(channelId: String, key: ByteArray) {
        require(key.size == 32) { "Channel key must be 32 bytes" }
        channelKeys[channelId] = key.copyOf()
    }

    fun hasChannelKey(channelId: String): Boolean = channelKeys.containsKey(channelId)

    /**
     * Encrypt a plaintext message for a group channel using AES-256-GCM.
     * Returns base64-encoded JSON: {"iv":"...","ct":"..."}
     */
    fun encryptChannel(channelId: String, plaintext: String): String {
        val key = channelKeys[channelId]
            ?: error("No channel key for $channelId. Call deriveChannelKey() first.")
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val json = JSONObject().apply {
            put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
            put("ct", Base64.encodeToString(ct, Base64.NO_WRAP))
        }
        return json.toString()
    }

    /**
     * Decrypt a channel message. Input is the JSON string from encryptChannel.
     */
    fun decryptChannel(channelId: String, encryptedData: String): String {
        val key = channelKeys[channelId]
            ?: error("No channel key for $channelId. Call deriveChannelKey() first.")
        val json = JSONObject(encryptedData)
        val iv = Base64.decode(json.getString("iv"), Base64.NO_WRAP)
        val ct = Base64.decode(json.getString("ct"), Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        val pt = cipher.doFinal(ct)
        return String(pt, Charsets.UTF_8)
    }

    // ── Cleanup ───────────────────────────────────────────────────────

    override fun close() {
        sessionManager.close()
        keyMaterial?.close()
        keyMaterial = null
        // Zeroize channel keys
        channelKeys.values.forEach { it.fill(0) }
        channelKeys.clear()
    }

    private fun requireKeyMaterial(): KeyMaterial {
        return keyMaterial ?: error("Keys not generated. Call generateKeys() first.")
    }
}
