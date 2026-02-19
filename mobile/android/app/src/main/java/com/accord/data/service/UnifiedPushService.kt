package com.accord.data.service

import android.content.Context
import android.util.Log
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import org.unifiedpush.android.connector.MessagingReceiver

/**
 * UnifiedPush receiver — FCM-free push transport for degoogled Android.
 *
 * Users on LineageOS, CalyxOS, GrapheneOS etc. can use any UnifiedPush
 * distributor (ntfy, NextPush, etc.) instead of Google's FCM.
 *
 * The push payload format and notification handling is identical to FCM;
 * only the transport differs.
 *
 * Setup:
 * 1. User installs a UnifiedPush distributor (e.g. ntfy from F-Droid)
 * 2. Accord registers with the distributor via UnifiedPush connector
 * 3. Distributor provides an endpoint URL
 * 4. Accord sends endpoint to server via POST /push/register with platform="unified_push"
 * 5. Server sends push payloads to the endpoint URL
 * 6. Distributor delivers to this receiver
 */
class UnifiedPushService : MessagingReceiver() {

    companion object {
        private const val TAG = "UnifiedPushService"
        private const val PREFS_NAME = "accord_push"
        private const val KEY_UP_ENDPOINT = "unified_push_endpoint"

        private val moshi = Moshi.Builder().addLast(KotlinJsonAdapterFactory()).build()

        fun getSavedEndpoint(context: Context): String? {
            return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_UP_ENDPOINT, null)
        }

        private fun saveEndpoint(context: Context, endpoint: String) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putString(KEY_UP_ENDPOINT, endpoint).apply()
        }

        private fun clearEndpoint(context: Context) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().remove(KEY_UP_ENDPOINT).apply()
        }
    }

    override fun onNewEndpoint(context: Context, endpoint: String, instance: String) {
        Log.d(TAG, "New UnifiedPush endpoint received")
        saveEndpoint(context, endpoint)

        // Register endpoint with Accord server
        // The server will POST push payloads directly to this URL
        // Registration happens asynchronously — the app must call this on next API interaction
        // Store for the app to pick up and register via POST /push/register
    }

    override fun onRegistrationFailed(context: Context, instance: String) {
        Log.e(TAG, "UnifiedPush registration failed")
        clearEndpoint(context)
    }

    override fun onUnregistered(context: Context, instance: String) {
        Log.d(TAG, "UnifiedPush unregistered")
        clearEndpoint(context)
    }

    override fun onMessage(context: Context, message: ByteArray, instance: String) {
        val payload = String(message, Charsets.UTF_8)
        Log.d(TAG, "UnifiedPush message received")

        try {
            val data: Map<String, String> = moshi.adapter<Map<String, String>>(
                Map::class.java
            ).fromJson(payload) ?: return

            handlePushData(context, data)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse UnifiedPush message", e)
        }
    }

    /**
     * Handle push data — same logic as FCM PushService.onMessageReceived.
     * Shared implementation to keep behavior identical across transports.
     */
    private fun handlePushData(context: Context, data: Map<String, String>) {
        val privacyLevel = PushService.getPrivacyLevel(context)

        // Try decrypt metadata
        var metadata: PushMetadata? = null
        data["encrypted_metadata"]?.let { encrypted ->
            metadata = tryDecryptMetadata(encrypted)
        }

        val senderName = metadata?.senderName ?: data["sender_name"]
        val channelName = metadata?.channelName
        val preview = metadata?.preview
        val channelId = data["channel_id"]

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

        showNotification(context, title, body, channelId)
    }

    private fun showNotification(context: Context, title: String, body: String, channelId: String?) {
        PushService.createNotificationChannel(context)

        val intent = android.content.Intent(context, com.accord.MainActivity::class.java).apply {
            flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                    android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP
            channelId?.let { putExtra("channel_id", it) }
        }
        val pendingIntent = android.app.PendingIntent.getActivity(
            context, 0, intent,
            android.app.PendingIntent.FLAG_ONE_SHOT or android.app.PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = androidx.core.app.NotificationCompat.Builder(context, PushService.CHANNEL_ID)
            .setSmallIcon(com.accord.R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(body)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU &&
            androidx.core.content.ContextCompat.checkSelfPermission(
                context, android.Manifest.permission.POST_NOTIFICATIONS
            ) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        androidx.core.app.NotificationManagerCompat.from(context).notify(
            System.currentTimeMillis().toInt(), notification
        )
    }

    private fun tryDecryptMetadata(base64Encoded: String): PushMetadata? {
        // Reuse PushService's crypto — in production, extract to shared utility
        return try {
            val data = android.util.Base64.decode(base64Encoded, android.util.Base64.DEFAULT)
            if (data.size <= 44) return null
            // Same decryption as PushService — delegate in production
            null // Stub: requires shared crypto module
        } catch (e: Exception) {
            null
        }
    }
}
