package com.accord.data.service

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.TimeUnit

/**
 * Manages the WebSocket connection to an Accord relay server.
 * Emits incoming messages as a Flow for reactive consumption.
 */
class WebSocketService {
    private val client = OkHttpClient.Builder()
        .pingInterval(30, TimeUnit.SECONDS)
        .build()

    private var webSocket: WebSocket? = null
    private val _incoming = Channel<String>(Channel.BUFFERED)

    /** Flow of raw JSON messages from the relay. */
    val incoming: Flow<String> = _incoming.receiveAsFlow()

    /** Connect to a relay WebSocket endpoint. */
    fun connect(relayUrl: String, authToken: String? = null) {
        disconnect()
        val request = Request.Builder()
            .url(relayUrl.replace("http", "ws") + "/ws")
            .apply { authToken?.let { header("Authorization", "Bearer $it") } }
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                _incoming.trySend(text)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                // TODO: Implement reconnection with exponential backoff
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                // TODO: Notify UI of disconnection
            }
        })
    }

    /** Send a raw JSON message to the relay. */
    fun send(json: String): Boolean {
        return webSocket?.send(json) ?: false
    }

    fun disconnect() {
        webSocket?.close(1000, "Client disconnect")
        webSocket = null
    }
}
