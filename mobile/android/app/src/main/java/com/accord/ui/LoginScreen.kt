package com.accord.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoginScreen(onLoginComplete: () -> Unit) {
    var relayUrl by remember { mutableStateOf("") }
    var importMode by remember { mutableStateOf(false) }
    var privateKeyHex by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Accord") })
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                "Privacy-first communication",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onBackground,
            )

            Spacer(Modifier.height(32.dp))

            OutlinedTextField(
                value = relayUrl,
                onValueChange = { relayUrl = it },
                label = { Text("Relay URL") },
                placeholder = { Text("wss://relay.example.com") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )

            Spacer(Modifier.height(16.dp))

            if (importMode) {
                OutlinedTextField(
                    value = privateKeyHex,
                    onValueChange = { privateKeyHex = it },
                    label = { Text("Private key (hex)") },
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                )
                Spacer(Modifier.height(16.dp))
            }

            Button(
                onClick = {
                    isLoading = true
                    // TODO: If importMode, restore keys from hex
                    // TODO: Else, call CryptoService.generateKeys()
                    // TODO: Upload pre-key bundle to relay
                    // TODO: Save relay URL + keys to secure storage
                    onLoginComplete()
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = relayUrl.isNotBlank() && !isLoading,
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp))
                } else {
                    Text(if (importMode) "Import & Connect" else "Generate Keys & Connect")
                }
            }

            Spacer(Modifier.height(8.dp))

            TextButton(onClick = { importMode = !importMode }) {
                Text(if (importMode) "Generate new keypair instead" else "Import existing keypair")
            }
        }
    }
}
