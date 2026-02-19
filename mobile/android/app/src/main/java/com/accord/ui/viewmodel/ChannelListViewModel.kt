package com.accord.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.accord.AccordAppState
import com.accord.data.model.Channel
import com.accord.data.model.ChannelType
import com.accord.data.service.WsIncoming
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

data class ChannelGroup(
    val categoryId: String?,
    val categoryName: String,
    val channels: List<Channel>,
)

class ChannelListViewModel(private val nodeId: String) : ViewModel() {
    private val _channels = MutableStateFlow<List<Channel>>(emptyList())
    val channels: StateFlow<List<Channel>> = _channels.asStateFlow()

    private val _grouped = MutableStateFlow<List<ChannelGroup>>(emptyList())
    val grouped: StateFlow<List<ChannelGroup>> = _grouped.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _nodeName = MutableStateFlow("")
    val nodeName: StateFlow<String> = _nodeName.asStateFlow()

    init {
        loadChannels()
        observeWs()
    }

    fun loadChannels() {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            try {
                val api = AccordAppState.requireApi()

                // Fetch node name
                try {
                    val node = api.getNode(nodeId)
                    _nodeName.value = node.name
                } catch (_: Exception) {}

                val response = api.getNodeChannels(nodeId)
                val mapped = response.map { cr ->
                    Channel(
                        id = cr.id,
                        name = cr.name,
                        type = when (cr.channelType) {
                            "voice" -> ChannelType.VOICE
                            "dm" -> ChannelType.DM
                            else -> ChannelType.TEXT
                        },
                        nodeId = cr.nodeId,
                        categoryId = cr.categoryId,
                        position = cr.position,
                        topic = cr.topic ?: "",
                    )
                }.sortedBy { it.position }
                _channels.value = mapped

                // Group by category
                val groups = mapped.groupBy { it.categoryId }.map { (catId, chs) ->
                    ChannelGroup(
                        categoryId = catId,
                        categoryName = catId ?: "Channels",
                        channels = chs,
                    )
                }
                _grouped.value = groups

                // Derive channel keys for all text channels
                mapped.filter { it.type == ChannelType.TEXT }.forEach { ch ->
                    if (!AccordAppState.crypto.hasChannelKey(ch.id)) {
                        AccordAppState.crypto.deriveChannelKey(ch.id)
                    }
                }
            } catch (e: Exception) {
                // TODO: expose error
            } finally {
                _isLoading.value = false
            }
        }
    }

    private fun observeWs() {
        viewModelScope.launch {
            AccordAppState.webSocket.incoming.collect { msg ->
                when (msg) {
                    is WsIncoming.ChannelCreated -> loadChannels()
                    else -> {}
                }
            }
        }
    }

    class Factory(private val nodeId: String) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return ChannelListViewModel(nodeId) as T
        }
    }
}
