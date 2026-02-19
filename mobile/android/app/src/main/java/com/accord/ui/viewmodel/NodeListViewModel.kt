package com.accord.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.accord.AccordAppState
import com.accord.data.model.Node
import com.accord.data.service.WsIncoming
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

class NodeListViewModel : ViewModel() {
    private val _nodes = MutableStateFlow<List<Node>>(emptyList())
    val nodes: StateFlow<List<Node>> = _nodes.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    init {
        loadNodes()
        observeWs()
    }

    fun loadNodes() {
        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            try {
                val api = AccordAppState.requireApi()
                val response = api.getNodes()
                _nodes.value = response.map { nr ->
                    Node(
                        id = nr.id,
                        name = nr.name,
                        description = nr.description ?: "",
                        ownerId = nr.ownerId ?: "",
                        iconUrl = nr.iconHash,
                    )
                }
                _error.value = null
            } catch (e: Exception) {
                _error.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }

    private fun observeWs() {
        viewModelScope.launch {
            AccordAppState.webSocket.incoming.collect { msg ->
                when (msg) {
                    is WsIncoming.NodeEvent -> loadNodes() // Refresh on node changes
                    else -> {}
                }
            }
        }
    }

    fun joinNodeByInvite(inviteCode: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                AccordAppState.requireApi().useInvite(inviteCode)
                loadNodes()
            } catch (e: Exception) {
                _error.value = e.message
            }
        }
    }
}
