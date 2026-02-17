package com.accord.core

/**
 * Kotlin wrapper around the accord-core native library (JNI).
 *
 * Mirrors the iOS AccordCore.swift API. All crypto operations happen in Rust;
 * this class provides safe Kotlin abstractions with proper resource management.
 *
 * ## Memory Management
 * [KeyMaterial] and [SessionManager] hold native pointers. Call [KeyMaterial.close]
 * and [SessionManager.close] when done, or use Kotlin's `use {}` extension.
 */
object AccordCore {
    init {
        System.loadLibrary("accord_core")
    }

    // ── Key Material ─────────────────────────────────────────────────────

    @JvmStatic external fun nativeKeyMaterialGenerate(numOneTimePrekeys: Int): Long
    @JvmStatic external fun nativeKeyMaterialFree(ptr: Long)
    @JvmStatic external fun nativeKeyMaterialIdentityKey(ptr: Long): ByteArray
    @JvmStatic external fun nativeKeyMaterialSignedPrekey(ptr: Long): ByteArray
    @JvmStatic external fun nativeKeyMaterialPublishableBundle(ptr: Long): ByteArray

    // ── Session Manager ──────────────────────────────────────────────────

    @JvmStatic external fun nativeSessionManagerNew(): Long
    @JvmStatic external fun nativeSessionManagerFree(ptr: Long)
    @JvmStatic external fun nativeSessionManagerHasSession(
        mgrPtr: Long, peerUserId: String, channelId: String
    ): Boolean

    @JvmStatic external fun nativeSessionManagerInitiate(
        mgrPtr: Long, kmPtr: Long,
        peerUserId: String, channelId: String,
        theirBundle: ByteArray, firstMessage: ByteArray
    ): ByteArray

    @JvmStatic external fun nativeSessionManagerReceiveInitial(
        mgrPtr: Long, kmPtr: Long,
        peerUserId: String, channelId: String,
        initialMsgData: ByteArray
    ): ByteArray

    @JvmStatic external fun nativeSessionManagerEncrypt(
        mgrPtr: Long,
        peerUserId: String, channelId: String,
        plaintext: ByteArray
    ): ByteArray

    @JvmStatic external fun nativeSessionManagerDecrypt(
        mgrPtr: Long,
        peerUserId: String, channelId: String,
        ciphertext: ByteArray
    ): ByteArray

    // ── PreKeyBundle ─────────────────────────────────────────────────────

    @JvmStatic external fun nativePreKeyBundleSerialize(
        identityKey: ByteArray, signedPrekey: ByteArray, oneTimePrekey: ByteArray?
    ): ByteArray
}

/**
 * Local cryptographic key material. Wraps a native Rust pointer.
 *
 * Usage:
 * ```kotlin
 * KeyMaterial(oneTimePrekeys = 10).use { keys ->
 *     val identity = keys.identityKey
 *     val bundle = keys.publishableBundle
 * }
 * ```
 */
class KeyMaterial(oneTimePrekeys: Int = 10) : AutoCloseable {
    internal var ptr: Long = AccordCore.nativeKeyMaterialGenerate(oneTimePrekeys)
        private set

    val identityKey: ByteArray
        get() {
            check(ptr != 0L) { "KeyMaterial already closed" }
            return AccordCore.nativeKeyMaterialIdentityKey(ptr)
        }

    val signedPrekey: ByteArray
        get() {
            check(ptr != 0L) { "KeyMaterial already closed" }
            return AccordCore.nativeKeyMaterialSignedPrekey(ptr)
        }

    val publishableBundle: ByteArray
        get() {
            check(ptr != 0L) { "KeyMaterial already closed" }
            return AccordCore.nativeKeyMaterialPublishableBundle(ptr)
        }

    override fun close() {
        if (ptr != 0L) {
            AccordCore.nativeKeyMaterialFree(ptr)
            ptr = 0
        }
    }

    protected fun finalize() {
        close()
    }
}

/**
 * Manages encrypted sessions with peers. Wraps a native Rust pointer.
 *
 * Usage:
 * ```kotlin
 * SessionManager().use { session ->
 *     val initialMsg = session.initiateSession(keys, "bob", "general", bundle, "Hello!".toByteArray())
 *     val encrypted = session.encrypt("bob", "general", "How are you?".toByteArray())
 *     val decrypted = session.decrypt("bob", "general", receivedData)
 * }
 * ```
 */
class SessionManager : AutoCloseable {
    private var ptr: Long = AccordCore.nativeSessionManagerNew()

    fun hasSession(peerUserId: String, channelId: String): Boolean {
        check(ptr != 0L) { "SessionManager already closed" }
        return AccordCore.nativeSessionManagerHasSession(ptr, peerUserId, channelId)
    }

    fun initiateSession(
        keyMaterial: KeyMaterial,
        peerUserId: String,
        channelId: String,
        theirBundle: ByteArray,
        firstMessage: ByteArray
    ): ByteArray {
        check(ptr != 0L) { "SessionManager already closed" }
        check(keyMaterial.ptr != 0L) { "KeyMaterial already closed" }
        return AccordCore.nativeSessionManagerInitiate(
            ptr, keyMaterial.ptr, peerUserId, channelId, theirBundle, firstMessage
        )
    }

    fun receiveInitialMessage(
        keyMaterial: KeyMaterial,
        peerUserId: String,
        channelId: String,
        initialMessage: ByteArray
    ): ByteArray {
        check(ptr != 0L) { "SessionManager already closed" }
        check(keyMaterial.ptr != 0L) { "KeyMaterial already closed" }
        return AccordCore.nativeSessionManagerReceiveInitial(
            ptr, keyMaterial.ptr, peerUserId, channelId, initialMessage
        )
    }

    fun encrypt(peerUserId: String, channelId: String, plaintext: ByteArray): ByteArray {
        check(ptr != 0L) { "SessionManager already closed" }
        return AccordCore.nativeSessionManagerEncrypt(ptr, peerUserId, channelId, plaintext)
    }

    fun decrypt(peerUserId: String, channelId: String, ciphertext: ByteArray): ByteArray {
        check(ptr != 0L) { "SessionManager already closed" }
        return AccordCore.nativeSessionManagerDecrypt(ptr, peerUserId, channelId, ciphertext)
    }

    override fun close() {
        if (ptr != 0L) {
            AccordCore.nativeSessionManagerFree(ptr)
            ptr = 0
        }
    }

    protected fun finalize() {
        close()
    }
}

/**
 * Serialize a PreKeyBundle from component keys.
 */
fun serializePreKeyBundle(
    identityKey: ByteArray,
    signedPrekey: ByteArray,
    oneTimePrekey: ByteArray? = null
): ByteArray {
    require(identityKey.size == 32) { "Identity key must be 32 bytes" }
    require(signedPrekey.size == 32) { "Signed prekey must be 32 bytes" }
    oneTimePrekey?.let { require(it.size == 32) { "One-time prekey must be 32 bytes" } }
    return AccordCore.nativePreKeyBundleSerialize(identityKey, signedPrekey, oneTimePrekey)
}
