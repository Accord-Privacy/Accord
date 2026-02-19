package com.accord.data.service

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.accord.MainActivity
import com.accord.R
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ── Privacy Level ────────────────────────────────────────────────────

enum class PushPrivacyLevel(val value: String, val displayName: String, val description: String) {
    FULL("full", "Full", "Show sender name and message preview"),
    SENDER_ONLY("sender_only", "Sender Only", "Show \"Message from [name]\" only"),
    MINIMAL("minimal", "Minimal", "Show \"New message\" with no details");

    companion object {
        fun fromValue(value: String): PushPrivacyLevel =
            entries.find { it.value == value } ?: MINIMAL
    }
}

// ── Push Metadata (decrypted from encrypted_metadata) ────────────────

@JsonClass(generateAdapter = true)
data class PushMetadata(
    @Json(name = "sender_name") val senderName: String? = null,
    @Json(name = "channel_name") val channelName: String? = null,
    val preview: String? = null,
)

// ── FCM Push Service ─────────────────────────────────────────────────

class PushService : FirebaseMessagingService() {

    companion object {
        private const val TAG = "PushService"
        const val CHANNEL_ID = "accord_messages"
        private const val PREFS_NAME = "accord_push"
        private const val KEY_PRIVACY_LEVEL = "privacy_level"
        private const val KEY_DEVICE_TOKEN = "device_token"
        private var notificationIdCounter = 0

        private val moshi = Moshi.Builder().addLast(KotlinJsonAdapterFactory()).build()

        fun createNotificationChannel(context: Context) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Messages",
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "Accord message notifications"
                enableVibration(true)
                enableLights(true)
            }
            val manager = context.getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }

        fun getPrivacyLevel(context: Context): PushPrivacyLevel {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val value = prefs.getString(KEY_PRIVACY_LEVEL, "minimal") ?: "minimal"
            return PushPrivacyLevel.fromValue(value)
        }

        fun setPrivacyLevel(context: Context, level: PushPrivacyLevel) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putString(KEY_PRIVACY_LEVEL, level.value).apply()
        }

        fun getSavedToken(context: Context): String? {
            return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_DEVICE_TOKEN, null)
        }

        /** Register FCM token with the server. Call after login. */
        suspend fun registerWithServer(api: AccordApi, context: Context) {
            try {
                val token = FirebaseMessaging.getInstance().token.await()
                saveToken(context, token)
                val level = getPrivacyLevel(context)
                api.registerPushToken(
                    mapOf(
                        "platform" to "android",
                        "token" to token,
                        "privacy_level" to level.value,
                    )
                )
                Log.d(TAG, "Push token registered with server")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to register push token", e)
            }
        }

        /** Deregister on logout */
        suspend fun deregisterFromServer(api: AccordApi, context: Context) {
            val token = getSavedToken(context) ?: return
            try {
                api.deregisterPushToken(mapOf("token" to token))
                context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit().remove(KEY_DEVICE_TOKEN).apply()
                Log.d(TAG, "Push token deregistered")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to deregister push token", e)
            }
        }

        /** Update privacy level on server */
        suspend fun updatePrivacyOnServer(api: AccordApi, context: Context, level: PushPrivacyLevel) {
            setPrivacyLevel(context, level)
            try {
                api.registerPushToken(
                    mapOf(
                        "platform" to "android",
                        "token" to (getSavedToken(context) ?: return),
                        "privacy_level" to level.value,
                    )
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to update privacy level", e)
            }
        }

        private fun saveToken(context: Context, token: String) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putString(KEY_DEVICE_TOKEN, token).apply()
        }

        // Kotlin coroutine bridge for Firebase Task
        private suspend fun <T> com.google.android.gms.tasks.Task<T>.await(): T {
            return kotlinx.coroutines.tasks.await()
        }
    }

    override fun onNewToken(token: String) {
        Log.d(TAG, "New FCM token received")
        saveToken(applicationContext, token)
        // Re-register will happen on next app launch or via WorkManager
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val data = message.data
        if (data.isEmpty()) return

        val privacyLevel = getPrivacyLevel(applicationContext)

        // Try to decrypt metadata
        var metadata: PushMetadata? = null
        data["encrypted_metadata"]?.let { encrypted ->
            metadata = decryptMetadata(encrypted)
        }

        val senderName = metadata?.senderName ?: data["sender_name"]
        val channelName = metadata?.channelName
        val preview = metadata?.preview
        val channelId = data["channel_id"]
        val event = data["event"] ?: "new_message"

        val (title, body) = when (privacyLevel) {
            PushPrivacyLevel.FULL -> {
                val sender = senderName ?: "Someone"
                val msg = preview ?: "sent a message"
                val t = channelName?.let { "#$it" } ?: "Accord"
                t to "$sender: $msg"
            }
            PushPrivacyLevel.SENDER_ONLY -> {
                val sender = senderName ?: "Someone"
                "Accord" to "Message from $sender"
            }
            PushPrivacyLevel.MINIMAL -> {
                "Accord" to "New message"
            }
        }

        showNotification(title, body, channelId)
    }

    private fun showNotification(title: String, body: String, channelId: String?) {
        // Check permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        // Deep link intent
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            channelId?.let { putExtra("channel_id", it) }
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(body)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        NotificationManagerCompat.from(this).notify(notificationIdCounter++, notification)
    }

    // MARK: - Crypto (matches core/src/push_crypto.rs)

    private fun decryptMetadata(base64Encoded: String): PushMetadata? {
        return try {
            val data = Base64.decode(base64Encoded, Base64.DEFAULT)
            if (data.size <= 44) return null

            val ephemeralPublic = data.sliceArray(0 until 32)
            val nonce = data.sliceArray(32 until 44)
            val ciphertext = data.sliceArray(44 until data.size)

            val privateKey = getIdentityPrivateKey() ?: return null

            // X25519 ECDH + HKDF + AES-256-GCM
            // Note: In production, use a proper X25519 library (e.g., libsodium via Lazysodium)
            // This is a placeholder showing the interface — actual ECDH needs native crypto
            val sharedSecret = performX25519(privateKey, ephemeralPublic) ?: return null
            val aesKey = hkdfDerive(sharedSecret, "accord-push-metadata-v1".toByteArray(), 32)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(128, nonce))
            val plaintext = cipher.doFinal(ciphertext)

            moshi.adapter(PushMetadata::class.java).fromJson(String(plaintext))
        } catch (e: Exception) {
            Log.e(TAG, "Metadata decryption failed", e)
            null
        }
    }

    private fun getIdentityPrivateKey(): ByteArray? {
        // Retrieve from Android Keystore or encrypted SharedPreferences
        // Must match whatever key storage the app's E2EE layer uses
        val prefs = applicationContext.getSharedPreferences("accord_keys", Context.MODE_PRIVATE)
        val encoded = prefs.getString("identity_private_key", null) ?: return null
        return Base64.decode(encoded, Base64.DEFAULT)
    }

    /** X25519 Diffie-Hellman key agreement. Requires a native crypto library. */
    private fun performX25519(privateKey: ByteArray, publicKey: ByteArray): ByteArray? {
        // TODO: Implement via Lazysodium or BouncyCastle X25519
        // For now this is a stub — the actual app must wire in a real implementation
        return try {
            val keyAgreement = javax.crypto.KeyAgreement.getInstance("XDH")
            val privKeySpec = java.security.spec.PKCS8EncodedKeySpec(privateKey)
            val pubKeySpec = java.security.spec.X509EncodedKeySpec(publicKey)
            val kf = java.security.KeyFactory.getInstance("XDH")
            keyAgreement.init(kf.generatePrivate(privKeySpec))
            keyAgreement.doPhase(kf.generatePublic(pubKeySpec), true)
            keyAgreement.generateSecret()
        } catch (e: Exception) {
            Log.w(TAG, "X25519 not available on this platform, encrypted metadata won't decrypt", e)
            null
        }
    }

    /** HKDF-SHA256 key derivation */
    private fun hkdfDerive(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        // Extract
        mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        // Expand
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info)
        mac.update(byteArrayOf(1))
        return mac.doFinal().sliceArray(0 until length)
    }
}
