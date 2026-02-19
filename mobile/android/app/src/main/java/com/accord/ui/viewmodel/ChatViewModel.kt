package com.accord.ui.viewmodel

import android.util.Base64
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.accord.AccordAppState
import com.accord.data.model.Message
import com.accord.data.service.WsIncoming
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

class ChatViewModel(
    private val channelId: String,
    private val isDm: Boolean = false,
    private val peerUserId: String? = null, // required for DMs
) : ViewModel() {
    private val _messages = MutableStateFlow<List<Message>>(emptyList())
    val messages: StateFlow<List<Message>> = _messages.asStateFlow()

    private val _channelName = MutableStateFlow("#channel")
    val channelName: StateFlow<String> = _channelName.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private var hasMore = true
    private var nextCursor: String? = null

    init {
        loadHistory()
        observeWs()
    }

    fun loadHistory() {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            try {
                val api = AccordAppState.requireApi()
                val response = api.getChannelMessages(channelId, limit = 50, before = nextCursor)
                hasMore = response.hasMore
                nextCursor = response.nextCursor

                val decrypted = response.messages.map { mr ->
                    val content = decryptMessage(mr.senderId, mr.encryptedPayload ?: mr.content ?: "")
                    Message(
                        id = mr.id,
                        channelId = channelId,
                        authorId = mr.displayName ?: mr.senderId,
                        content = content,
                        timestamp = if (mr.timestamp > 0) mr.timestamp else mr.createdAt,
                        edited = mr.editedAt != null,
                    )
                }

                _messages.value = (_messages.value + decrypted)
                    .distinctBy { it.id }
                    .sortedByDescending { it.timestamp }
            } catch (e: Exception) {
                _error.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun loadMore() {
        if (hasMore && !_isLoading.value) loadHistory()
    }

    fun sendMessage(text: String) {
        if (text.isBlank()) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val crypto = AccordAppState.crypto
                val ws = AccordAppState.webSocket

                if (isDm && peerUserId != null) {
                    // DM: encrypt with Double Ratchet
                    val encrypted = if (crypto.hasSession(peerUserId, channelId)) {
                        crypto.encryptDm(peerUserId, channelId, text.toByteArray())
                    } else {
                        // Need to establish session first — fetch their bundle
                        val api = AccordAppState.requireApi()
                        val bundle = api.fetchKeyBundle(peerUserId)
                        crypto.initiateSessionFromBundle(
                            peerUserId, channelId, bundle, text.toByteArray()
                        )
                    }
                    val b64 = Base64.encodeToString(encrypted, Base64.NO_WRAP)
                    ws.sendDirectMessage(peerUserId, b64)
                } else {
                    // Channel: encrypt with symmetric AES-GCM
                    if (!crypto.hasChannelKey(channelId)) {
                        crypto.deriveChannelKey(channelId)
                    }
                    val encryptedData = crypto.encryptChannel(channelId, text)
                    ws.sendChannelMessage(channelId, encryptedData)
                }
            } catch (e: Exception) {
                _error.value = "Send failed: ${e.message}"
            }
        }
    }

    fun sendTyping() {
        AccordAppState.webSocket.sendTypingStart(channelId)
    }

    private fun observeWs() {
        viewModelScope.launch {
            AccordAppState.webSocket.incoming.collect { msg ->
                when (msg) {
                    is WsIncoming.ChannelMessage -> {
                        if (msg.channelId == channelId) {
                            val content = decryptMessage(msg.from, msg.encryptedData)
                            val message = Message(
                                id = msg.messageId,
                                channelId = channelId,
                                authorId = msg.senderDisplayName ?: msg.from,
                                content = content,
                                timestamp = msg.timestamp,
                            )
                            _messages.value = listOf(message) + _messages.value
                        }
                    }
                    is WsIncoming.MessageEdit -> {
                        if (msg.channelId == channelId) {
                            val content = decryptMessage("", msg.encryptedData)
                            _messages.value = _messages.value.map {
                                if (it.id == msg.messageId) it.copy(content = content, edited = true) else it
                            }
                        }
                    }
                    is WsIncoming.MessageDelete -> {
                        _messages.value = _messages.value.filter { it.id != msg.messageId }
                    }
                    else -> {}
                }
            }
        }
    }

    private fun decryptMessage(senderId: String, encryptedData: String): String {
        if (encryptedData.isBlank()) return ""
        val crypto = AccordAppState.crypto
        return try {
            if (isDm && senderId.isNotBlank()) {
                // Try Double Ratchet
                val bytes = Base64.decode(encryptedData, Base64.NO_WRAP)
                String(crypto.decryptDm(senderId, channelId, bytes), Charsets.UTF_8)
            } else {
                // Try channel symmetric decrypt
                crypto.decryptChannel(channelId, encryptedData)
            }
        } catch (_: Exception) {
            // Fallback: might be plaintext or unrecognized format
            try {
                // Try channel decrypt as fallback
                crypto.decryptChannel(channelId, encryptedData)
            } catch (_: Exception) {
                encryptedData // Return raw if we can't decrypt
            }
        }
    }

    class Factory(
        private val channelId: String,
        private val isDm: Boolean = false,
        private val peerUserId: String? = null,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return ChatViewModel(channelId, isDm, peerUserId) as T
        }
    }
}
