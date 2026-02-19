package com.accord

import com.accord.data.service.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Application-level singleton holding shared services and auth state.
 * Manual DI — no Hilt/Dagger needed for this scale.
 */
object AccordAppState {
    val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    // ── Auth ──────────────────────────────────────────────────────────
    private val _authToken = MutableStateFlow<String?>(null)
    val authToken: StateFlow<String?> = _authToken.asStateFlow()

    private val _userId = MutableStateFlow<String?>(null)
    val userId: StateFlow<String?> = _userId.asStateFlow()

    private val _relayUrl = MutableStateFlow<String?>(null)
    val relayUrl: StateFlow<String?> = _relayUrl.asStateFlow()

    private val _displayName = MutableStateFlow<String?>(null)
    val displayName: StateFlow<String?> = _displayName.asStateFlow()

    // ── Services (lazy-initialized after login) ───────────────────────
    var api: AccordApi? = null
        private set
    var authInterceptor: AuthInterceptor? = null
        private set
    val webSocket = WebSocketService()
    val crypto = CryptoService()

    val isLoggedIn: Boolean get() = _authToken.value != null

    /**
     * Called after successful register/login.
     * Sets up API client, stores auth, connects WebSocket.
     */
    fun onAuthenticated(
        relayUrl: String,
        token: String,
        userId: String,
        displayName: String? = null,
    ) {
        _relayUrl.value = relayUrl
        _authToken.value = token
        _userId.value = userId
        _displayName.value = displayName

        // Create API client
        val (apiInstance, interceptor) = ApiService.create(
            baseUrl = relayUrl,
            trustAllCerts = true, // TODO: make configurable
        )
        interceptor.updateToken(token)
        api = apiInstance
        authInterceptor = interceptor

        // Connect WebSocket
        webSocket.connect(relayUrl, token)
    }

    fun logout() {
        webSocket.disconnect()
        crypto.close()
        api = null
        authInterceptor = null
        _authToken.value = null
        _userId.value = null
        _relayUrl.value = null
        _displayName.value = null
    }

    fun requireApi(): AccordApi = api ?: error("Not authenticated. Call onAuthenticated() first.")
    fun requireUserId(): String = _userId.value ?: error("Not authenticated.")
}
