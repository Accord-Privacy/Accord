package com.accord.data.service

import com.accord.core.KeyMaterial
import com.accord.core.SessionManager
import com.accord.core.serializePreKeyBundle

/**
 * Wraps AccordCore JNI bridge for E2EE operations.
 * All crypto runs in Rust via native calls — no Java crypto.
 */
class CryptoService : AutoCloseable {
    private var keyMaterial: KeyMaterial? = null
    private val sessionManager = SessionManager()

    /** Generate fresh key material. Call once on first launch or key rotation. */
    fun generateKeys(oneTimePrekeys: Int = 10) {
        keyMaterial?.close()
        keyMaterial = KeyMaterial(oneTimePrekeys)
    }

    /** Get the publishable pre-key bundle to upload to the relay. */
    fun getPublishableBundle(): ByteArray {
        val km = requireKeyMaterial()
        return km.publishableBundle
    }

    fun getIdentityKey(): ByteArray {
        return requireKeyMaterial().identityKey
    }

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

    fun encrypt(peerUserId: String, channelId: String, plaintext: ByteArray): ByteArray {
        return sessionManager.encrypt(peerUserId, channelId, plaintext)
    }

    fun decrypt(peerUserId: String, channelId: String, ciphertext: ByteArray): ByteArray {
        return sessionManager.decrypt(peerUserId, channelId, ciphertext)
    }

    override fun close() {
        sessionManager.close()
        keyMaterial?.close()
        keyMaterial = null
    }

    private fun requireKeyMaterial(): KeyMaterial {
        return keyMaterial ?: error("Keys not generated. Call generateKeys() first.")
    }
}
