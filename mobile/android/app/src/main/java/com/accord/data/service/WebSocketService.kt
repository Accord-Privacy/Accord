package com.accord.data.service

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Connection state for the WebSocket.
 */
enum class ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

/**
 * Sealed hierarchy of messages received from the relay server.
 */
sealed class WsIncoming {
    /** Server confirmed authentication. */
    data class Authenticated(val userId: String) : WsIncoming()

    /** Server hello with version info. */
    data class Hello(
        val serverVersion: String,
        val serverBuildHash: String,
        val protocolVersion: Int,
    ) : WsIncoming()

    /** A channel (or DM) chat message. */
    data class ChannelMessage(
        val from: String,
        val channelId: String,
        val encryptedData: String,
        val messageId: String,
        val timestamp: Long,
        val replyTo: String? = null,
        val senderDisplayName: String? = null,
        val isDm: Boolean = false,
    ) : WsIncoming()

    /** A message was edited. */
    data class MessageEdit(
        val messageId: String,
        val channelId: String,
        val encryptedData: String,
        val editedAt: Long,
    ) : WsIncoming()

    /** A message was deleted. */
    data class MessageDelete(val messageId: String) : WsIncoming()

    /** Presence update for a user. */
    data class PresenceUpdate(val userId: String, val status: String) : WsIncoming()

    /** Bulk presence on connect. */
    data class PresenceBulk(val members: List<Pair<String, String>>) : WsIncoming()

    /** Someone started typing. */
    data class TypingStart(val channelId: String, val userId: String) : WsIncoming()

    /** Reaction added. */
    data class ReactionAdd(
        val messageId: String,
        val reactions: List<Map<String, Any>>,
    ) : WsIncoming()

    /** Reaction removed. */
    data class ReactionRemove(
        val messageId: String,
        val reactions: List<Map<String, Any>>,
    ) : WsIncoming()

    /** Message pinned. */
    data class MessagePin(val messageId: String, val pinnedBy: String, val timestamp: Long) : WsIncoming()

    /** Message unpinned. */
    data class MessageUnpin(val messageId: String) : WsIncoming()

    /** Read receipt. */
    data class ReadReceipt(val channelId: String, val userId: String, val messageId: String, val timestamp: Long) : WsIncoming()

    /** Voice peer joined. */
    data class VoicePeerJoined(val channelId: String, val userId: String) : WsIncoming()

    /** Voice peer left. */
    data class VoicePeerLeft(val channelId: String, val userId: String) : WsIncoming()

    /** Voice signaling (offer/answer/ice). */
    data class VoiceSignaling(val channelId: String, val fromUserId: String, val signalType: String, val data: String) : WsIncoming()

    /** Node created/joined/left confirmations. */
    data class NodeEvent(val type: String, val raw: JSONObject) : WsIncoming()

    /** Channel created. */
    data class ChannelCreated(val raw: JSONObject) : WsIncoming()

    /** Server error. */
    data class Error(val message: String, val code: String? = null) : WsIncoming()

    /** Pong response. */
    data class Pong(val timestamp: Long) : WsIncoming()

    /** Key bundle response. */
    data class KeyBundleResponse(val identityKey: String, val signedPrekey: String, val oneTimePrekey: String?) : WsIncoming()

    /** Prekey messages retrieved. */
    data class PrekeyMessages(val messages: List<JSONObject>) : WsIncoming()

    /** Any unrecognized message — raw JSON. */
    data class Unknown(val raw: JSONObject) : WsIncoming()
}

/**
 * Manages the WebSocket connection to an Accord relay server.
 *
 * Uses post-upgrade authentication (send `{"Authenticate":{"token":"..."}}` within 5s).
 * Auto-reconnects with exponential backoff (1s → 30s max).
 * Exposes connection state as [StateFlow] and incoming messages as [SharedFlow].
 */
class WebSocketService(
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
) {
    private val client = OkHttpClient.Builder()
        .pingInterval(30, TimeUnit.SECONDS)
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MINUTES) // no read timeout for WS
        .build()

    private var webSocket: WebSocket? = null
    private var authToken: String? = null
    private var relayUrl: String? = null

    // ── Public state ──────────────────────────────────────────────────

    private val _connectionState = MutableStateFlow(ConnectionState.Disconnected)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _incoming = MutableSharedFlow<WsIncoming>(
        replay = 0,
        extraBufferCapacity = 256,
    )
    /** Flow of parsed incoming messages from the relay. */
    val incoming: SharedFlow<WsIncoming> = _incoming.asSharedFlow()

    // ── Reconnect state ───────────────────────────────────────────────

    private val reconnectAttempt = AtomicInteger(0)
    private var reconnectJob: Job? = null

    companion object {
        private const val INITIAL_BACKOFF_MS = 1_000L
        private const val MAX_BACKOFF_MS = 30_000L
    }

    // ── Public API ────────────────────────────────────────────────────

    /** Connect to a relay WebSocket endpoint. */
    fun connect(relayUrl: String, authToken: String) {
        disconnect()
        this.authToken = authToken
        this.relayUrl = relayUrl
        reconnectAttempt.set(0)
        doConnect()
    }

    /** Send a typed WS message matching the server's WsMessage envelope. */
    fun sendMessage(messageType: Any): Boolean {
        val envelope = JSONObject().apply {
            put("message_type", when (messageType) {
                is JSONObject -> messageType
                else -> messageType // caller can pass JSONObject directly
            })
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        return send(envelope.toString())
    }

    /** Send a raw JSON string. */
    fun send(json: String): Boolean {
        return webSocket?.send(json) ?: false
    }

    fun disconnect() {
        reconnectJob?.cancel()
        reconnectJob = null
        webSocket?.close(1000, "Client disconnect")
        webSocket = null
        _connectionState.value = ConnectionState.Disconnected
    }

    // ── Convenience send helpers ──────────────────────────────────────

    fun sendChannelMessage(channelId: String, encryptedData: String, replyTo: String? = null) {
        val type = JSONObject().apply {
            put("ChannelMessage", JSONObject().apply {
                put("channel_id", channelId)
                put("encrypted_data", encryptedData)
                if (replyTo != null) put("reply_to", replyTo)
            })
        }
        sendEnvelope(type)
    }

    fun sendDirectMessage(toUser: String, encryptedData: String) {
        val type = JSONObject().apply {
            put("DirectMessage", JSONObject().apply {
                put("to_user", toUser)
                put("encrypted_data", encryptedData)
            })
        }
        sendEnvelope(type)
    }

    fun sendTypingStart(channelId: String) {
        val type = JSONObject().apply {
            put("TypingStart", JSONObject().apply {
                put("channel_id", channelId)
            })
        }
        sendEnvelope(type)
    }

    fun sendEditMessage(messageId: String, encryptedData: String) {
        val type = JSONObject().apply {
            put("EditMessage", JSONObject().apply {
                put("message_id", messageId)
                put("encrypted_data", encryptedData)
            })
        }
        sendEnvelope(type)
    }

    fun sendDeleteMessage(messageId: String) {
        val type = JSONObject().apply {
            put("DeleteMessage", JSONObject().apply {
                put("message_id", messageId)
            })
        }
        sendEnvelope(type)
    }

    fun sendAddReaction(messageId: String, emoji: String) {
        val type = JSONObject().apply {
            put("AddReaction", JSONObject().apply {
                put("message_id", messageId)
                put("emoji", emoji)
            })
        }
        sendEnvelope(type)
    }

    fun sendRemoveReaction(messageId: String, emoji: String) {
        val type = JSONObject().apply {
            put("RemoveReaction", JSONObject().apply {
                put("message_id", messageId)
                put("emoji", emoji)
            })
        }
        sendEnvelope(type)
    }

    fun sendPing() {
        val type = JSONObject().apply { put("Ping", JSONObject()) }
        sendEnvelope(type)
    }

    fun joinChannel(channelId: String) {
        val type = JSONObject().apply {
            put("JoinChannel", JSONObject().apply {
                put("channel_id", channelId)
            })
        }
        sendEnvelope(type)
    }

    fun leaveChannel(channelId: String) {
        val type = JSONObject().apply {
            put("LeaveChannel", JSONObject().apply {
                put("channel_id", channelId)
            })
        }
        sendEnvelope(type)
    }

    fun joinVoiceChannel(channelId: String) {
        val type = JSONObject().apply {
            put("JoinVoiceChannel", JSONObject().apply {
                put("channel_id", channelId)
            })
        }
        sendEnvelope(type)
    }

    fun leaveVoiceChannel(channelId: String) {
        val type = JSONObject().apply {
            put("LeaveVoiceChannel", JSONObject().apply {
                put("channel_id", channelId)
            })
        }
        sendEnvelope(type)
    }

    fun publishKeyBundle(identityKey: String, signedPrekey: String, oneTimePrekeys: List<String>) {
        val type = JSONObject().apply {
            put("PublishKeyBundle", JSONObject().apply {
                put("identity_key", identityKey)
                put("signed_prekey", signedPrekey)
                put("one_time_prekeys", org.json.JSONArray(oneTimePrekeys))
            })
        }
        sendEnvelope(type)
    }

    fun fetchKeyBundle(targetUserId: String) {
        val type = JSONObject().apply {
            put("FetchKeyBundle", JSONObject().apply {
                put("target_user_id", targetUserId)
            })
        }
        sendEnvelope(type)
    }

    // ── Internal ──────────────────────────────────────────────────────

    private fun sendEnvelope(messageTypeObj: JSONObject) {
        val envelope = JSONObject().apply {
            put("message_type", messageTypeObj)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        send(envelope.toString())
    }

    private fun doConnect() {
        val url = relayUrl ?: return
        val wsUrl = url.replace(Regex("^http"), "ws").trimEnd('/') + "/ws"

        _connectionState.value = if (reconnectAttempt.get() > 0) {
            ConnectionState.Reconnecting
        } else {
            ConnectionState.Connecting
        }

        val request = Request.Builder()
            .url(wsUrl)
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                // Post-upgrade auth: send Authenticate message within 5s
                val authMsg = JSONObject().apply {
                    put("Authenticate", JSONObject().apply {
                        put("token", authToken)
                    })
                }
                webSocket.send(authMsg.toString())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                handleMessage(text)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                _connectionState.value = ConnectionState.Disconnected
                scope.launch { _incoming.emit(WsIncoming.Error(t.message ?: "Connection failed")) }
                scheduleReconnect()
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                _connectionState.value = ConnectionState.Disconnected
                // Don't reconnect on intentional close or auth failure
                if (code != 1000 && code != 4401 && code != 4403) {
                    scheduleReconnect()
                }
            }
        })
    }

    private fun handleMessage(text: String) {
        val json = try { JSONObject(text) } catch (_: Exception) { return }
        val type = json.optString("type", "")

        val msg: WsIncoming = when (type) {
            "authenticated" -> {
                _connectionState.value = ConnectionState.Connected
                reconnectAttempt.set(0)
                WsIncoming.Authenticated(json.optString("user_id"))
            }

            "hello" -> WsIncoming.Hello(
                serverVersion = json.optString("server_version"),
                serverBuildHash = json.optString("server_build_hash"),
                protocolVersion = json.optInt("protocol_version", 0),
            )

            "channel_message" -> WsIncoming.ChannelMessage(
                from = json.optString("from"),
                channelId = json.optString("channel_id"),
                encryptedData = json.optString("encrypted_data"),
                messageId = json.optString("message_id"),
                timestamp = json.optLong("timestamp"),
                replyTo = json.optString("reply_to").takeIf { it.isNotEmpty() },
                senderDisplayName = json.optString("sender_display_name").takeIf { it.isNotEmpty() },
                isDm = json.optBoolean("is_dm", false),
            )

            "message_edit" -> WsIncoming.MessageEdit(
                messageId = json.optString("message_id"),
                channelId = json.optString("channel_id"),
                encryptedData = json.optString("encrypted_data"),
                editedAt = json.optLong("edited_at"),
            )

            "message_delete" -> WsIncoming.MessageDelete(json.optString("message_id"))

            "presence_update" -> WsIncoming.PresenceUpdate(
                userId = json.optString("user_id"),
                status = json.optString("status"),
            )

            "presence_bulk" -> {
                val arr = json.optJSONArray("members")
                val members = mutableListOf<Pair<String, String>>()
                if (arr != null) {
                    for (i in 0 until arr.length()) {
                        val m = arr.optJSONObject(i) ?: continue
                        members.add(m.optString("user_id") to m.optString("status"))
                    }
                }
                WsIncoming.PresenceBulk(members)
            }

            "typing_start" -> WsIncoming.TypingStart(
                channelId = json.optString("channel_id"),
                userId = json.optString("user_id"),
            )

            "reaction_add" -> WsIncoming.ReactionAdd(
                messageId = json.optString("message_id"),
                reactions = parseReactions(json),
            )

            "reaction_remove" -> WsIncoming.ReactionRemove(
                messageId = json.optString("message_id"),
                reactions = parseReactions(json),
            )

            "message_pin" -> WsIncoming.MessagePin(
                messageId = json.optString("message_id"),
                pinnedBy = json.optString("pinned_by"),
                timestamp = json.optLong("timestamp"),
            )

            "message_unpin" -> WsIncoming.MessageUnpin(json.optString("message_id"))

            "read_receipt" -> WsIncoming.ReadReceipt(
                channelId = json.optString("channel_id"),
                userId = json.optString("user_id"),
                messageId = json.optString("message_id"),
                timestamp = json.optLong("timestamp"),
            )

            "voice_peer_joined" -> WsIncoming.VoicePeerJoined(
                channelId = json.optString("channel_id"),
                userId = json.optString("user_id"),
            )

            "voice_peer_left" -> WsIncoming.VoicePeerLeft(
                channelId = json.optString("channel_id"),
                userId = json.optString("user_id"),
            )

            "voice_offer", "voice_answer", "voice_ice_candidate", "p2p_signal" -> WsIncoming.VoiceSignaling(
                channelId = json.optString("channel_id"),
                fromUserId = json.optString("from_user_id", json.optString("user_id")),
                signalType = type,
                data = text,
            )

            "node_created", "node_joined", "node_left", "node_info" -> WsIncoming.NodeEvent(type, json)

            "channel_created" -> WsIncoming.ChannelCreated(json)

            "key_bundle_response" -> WsIncoming.KeyBundleResponse(
                identityKey = json.optString("identity_key"),
                signedPrekey = json.optString("signed_prekey"),
                oneTimePrekey = json.optString("one_time_prekey").takeIf { it.isNotEmpty() },
            )

            "prekey_messages" -> {
                val arr = json.optJSONArray("messages")
                val msgs = mutableListOf<JSONObject>()
                if (arr != null) {
                    for (i in 0 until arr.length()) {
                        arr.optJSONObject(i)?.let { msgs.add(it) }
                    }
                }
                WsIncoming.PrekeyMessages(msgs)
            }

            "pong" -> WsIncoming.Pong(json.optLong("timestamp"))

            "error" -> WsIncoming.Error(
                message = json.optString("message", json.optString("error", "Unknown error")),
                code = json.optString("code").takeIf { it.isNotEmpty() },
            )

            else -> WsIncoming.Unknown(json)
        }

        scope.launch { _incoming.emit(msg) }
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseReactions(json: JSONObject): List<Map<String, Any>> {
        val arr = json.optJSONArray("reactions") ?: return emptyList()
        val result = mutableListOf<Map<String, Any>>()
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val map = mutableMapOf<String, Any>()
            for (key in obj.keys()) {
                map[key] = obj.get(key)
            }
            result.add(map)
        }
        return result
    }

    private fun scheduleReconnect() {
        reconnectJob?.cancel()
        val attempt = reconnectAttempt.incrementAndGet()
        val delay = (INITIAL_BACKOFF_MS * (1L shl (attempt - 1).coerceAtMost(5)))
            .coerceAtMost(MAX_BACKOFF_MS)

        reconnectJob = scope.launch {
            delay(delay)
            if (isActive) {
                _connectionState.value = ConnectionState.Reconnecting
                doConnect()
            }
        }
    }
}
