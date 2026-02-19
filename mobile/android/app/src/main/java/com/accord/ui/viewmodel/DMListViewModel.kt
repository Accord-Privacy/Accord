package com.accord.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.accord.AccordAppState
import com.accord.data.model.Channel
import com.accord.data.model.ChannelType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

data class DmConversation(
    val channelId: String,
    val peerUserId: String,
    val peerDisplayName: String,
)

class DMListViewModel : ViewModel() {
    private val _conversations = MutableStateFlow<List<DmConversation>>(emptyList())
    val conversations: StateFlow<List<DmConversation>> = _conversations.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    init {
        loadDms()
    }

    fun loadDms() {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            try {
                val api = AccordAppState.requireApi()
                val myId = AccordAppState.requireUserId()
                val response = api.getDmChannels()

                val convos = response.channels.map { dm ->
                    val peerId = if (dm.user1Id == myId) dm.user2Id else dm.user1Id
                    val peerName = try {
                        api.getUserProfile(peerId).displayName ?: peerId.take(8)
                    } catch (_: Exception) {
                        peerId.take(8)
                    }
                    DmConversation(
                        channelId = dm.id,
                        peerUserId = peerId,
                        peerDisplayName = peerName,
                    )
                }
                _conversations.value = convos
            } catch (_: Exception) {
                // silently fail for now
            } finally {
                _isLoading.value = false
            }
        }
    }
}
