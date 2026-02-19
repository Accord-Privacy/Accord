package com.accord.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.accord.AccordAppState
import com.accord.data.service.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class LoginUiState(
    val isLoading: Boolean = false,
    val error: String? = null,
    val isAuthenticated: Boolean = false,
)

class LoginViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(LoginUiState())
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    /**
     * Register a new account: generate keys, register with relay, publish bundle, connect WS.
     */
    fun register(relayUrl: String, displayName: String, password: String) {
        if (_uiState.value.isLoading) return
        _uiState.value = LoginUiState(isLoading = true)

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val url = normalizeUrl(relayUrl)

                // 1. Generate crypto keys
                val crypto = AccordAppState.crypto
                crypto.generateKeys()

                // 2. Create temporary API client for registration
                val (tempApi, tempInterceptor) = ApiService.create(baseUrl = url, trustAllCerts = true)

                // 3. Register with public key
                val identityKeyB64 = android.util.Base64.encodeToString(
                    crypto.getIdentityKey(), android.util.Base64.NO_WRAP
                )
                val response = tempApi.register(
                    RegisterRequest(
                        publicKey = identityKeyB64,
                        password = password,
                        displayName = displayName.ifBlank { null },
                    )
                )

                // 4. Set up app state with auth
                AccordAppState.onAuthenticated(
                    relayUrl = url,
                    token = response.token,
                    userId = response.userId,
                    displayName = displayName.ifBlank { null },
                )

                // 5. Publish key bundle via REST API
                val bundleReq = crypto.buildKeyBundleForApi()
                AccordAppState.requireApi().publishKeyBundle(bundleReq)

                _uiState.value = LoginUiState(isAuthenticated = true)
            } catch (e: Exception) {
                _uiState.value = LoginUiState(error = e.message ?: "Registration failed")
            }
        }
    }

    /**
     * Login with existing credentials.
     */
    fun login(relayUrl: String, password: String) {
        if (_uiState.value.isLoading) return
        _uiState.value = LoginUiState(isLoading = true)

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val url = normalizeUrl(relayUrl)

                // Generate keys (or restore — for now, fresh keys each login)
                val crypto = AccordAppState.crypto
                crypto.generateKeys()

                val identityKeyB64 = android.util.Base64.encodeToString(
                    crypto.getIdentityKey(), android.util.Base64.NO_WRAP
                )

                // Create temporary API for auth
                val (tempApi, _) = ApiService.create(baseUrl = url, trustAllCerts = true)
                val response = tempApi.login(
                    AuthRequest(publicKey = identityKeyB64, password = password)
                )

                AccordAppState.onAuthenticated(
                    relayUrl = url,
                    token = response.token,
                    userId = response.userId,
                )

                // Re-publish bundle
                val bundleReq = crypto.buildKeyBundleForApi()
                AccordAppState.requireApi().publishKeyBundle(bundleReq)

                _uiState.value = LoginUiState(isAuthenticated = true)
            } catch (e: Exception) {
                _uiState.value = LoginUiState(error = e.message ?: "Login failed")
            }
        }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    private fun normalizeUrl(url: String): String {
        var u = url.trim().trimEnd('/')
        if (!u.startsWith("http://") && !u.startsWith("https://")) {
            u = "https://$u"
        }
        return u
    }
}
