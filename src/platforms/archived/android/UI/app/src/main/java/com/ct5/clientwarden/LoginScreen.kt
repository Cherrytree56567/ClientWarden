package com.ct5.clientwarden

import android.annotation.SuppressLint
import android.content.res.Configuration
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonColors
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.composables.icons.lucide.ArrowRight
import com.composables.icons.lucide.FingerprintPattern
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.X
import com.ct5.clientwarden.ui.theme.ClientwardenTheme
import kotlinx.coroutines.delay
import java.util.UUID
import kotlin.time.Duration.Companion.milliseconds

enum class LoginScreenType {
    Generic,
    TOTP,
    DeviceVerify,
    Passkey
}

object LoginScreen {
    var email = mutableStateOf("")
    var password = mutableStateOf("")
    var code = mutableStateOf("")
    var s_type = mutableStateOf(LoginScreenType.Generic)

    var vaultURL = mutableStateOf("https://vault.bitwarden.com")
    var mainURL = mutableStateOf("https://vault.bitwarden.com")
    var apiURL = mutableStateOf("https://api.bitwarden.com")
    var iconURL = mutableStateOf("https://icons.bitwarden.net")
    var wssURL = mutableStateOf("wss://notifications.bitwarden.com")
    var selectedTab = mutableStateOf(0)

    private var mainChanged = false
    private var apiChanged = false
    private var wssChanged = false

    private fun removeProt(url: String): String {
        val idx = url.indexOf("://")
        return if (idx != -1) url.substring(idx + 3) else url
    }

    fun setVaultURL(newURL: String) {
        vaultURL.value = newURL
        if (!mainChanged) {
            mainURL.value = newURL
        }
        if (!apiChanged) {
            apiURL.value = newURL
        }
        if (!wssChanged) {
            wssURL.value = "wss://" + removeProt(newURL) + "/notifications"
        }
    }

    fun setMainURL(newURL: String) {
        mainURL.value = newURL
        mainChanged = true
    }

    fun setApiURL(newURL: String) {
        apiURL.value = newURL
        apiChanged = true
    }

    fun setWssURL(newURL: String) {
        wssURL.value = newURL
        wssChanged = true
    }

    fun switchTab(newTab: Int) {
        selectedTab.value = newTab
        if (newTab == 0) {
            vaultURL.value = "https://vault.bitwarden.com"
            mainURL.value = "https://vault.bitwarden.com"
            apiURL.value = "https://api.bitwarden.com"
            iconURL.value = "https://icons.bitwarden.net"
            wssURL.value = "wss://notifications.bitwarden.com"
            mainChanged = true
            apiChanged = true
            wssChanged = true
        } else if (newTab == 1) {
            vaultURL.value = "https://someVault.com"
            mainURL.value = "https://someVault.com"
            apiURL.value = "https://someVault.com"
            iconURL.value = "https://icons.bitwarden.net"
            wssURL.value = "wss://someVault.com/notifications"
            mainChanged = false
            apiChanged = false
            wssChanged = false
        }
    }

    //              Email   Passwd  Vault   Main    API     Icon    WSS
    var cb_login: ((String, String, String, String, String, String, String) -> Boolean)? = null
    var cb_loginCode: ((String) -> Boolean)? = null

    fun setScreenType(ordinal: Int) {
        s_type.value = LoginScreenType.entries[ordinal]
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun view() {
        var e_dialog by remember { mutableStateOf(false) }
        Column(modifier = Modifier.fillMaxSize().padding(64.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center) {
            /*
             * Main Header
             * I wanted the header to have an easter egg bc
             * why not
             */
            ClientwardenEasterText()

            Spacer(modifier = Modifier.height(12.dp))

            if (s_type.value == LoginScreenType.Generic) {
                /*
                 * Email Field
                 */
                 OutlinedTextField(
                    value = email.value,
                    onValueChange = { email.value = it },
                    label = { Text("Email") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                    shape = RoundedCornerShape(64.dp),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                /*
                 * Password Field
                 */
                OutlinedTextField(
                    value = password.value,
                    onValueChange = { password.value = it },
                    label = { Text("Password") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    shape = RoundedCornerShape(64.dp),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            } else if (s_type.value == LoginScreenType.TOTP ||
                s_type.value == LoginScreenType.DeviceVerify) {
                /*
                 * TOTP/Device Verify Field
                 */
                OutlinedTextField(
                    value = code.value,
                    onValueChange = { code.value = it },
                    label = {
                        Text(if (s_type.value == LoginScreenType.TOTP) "TOTP Code"
                            else "Device Verification Code"
                        )
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    shape = RoundedCornerShape(64.dp),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            } else if (s_type.value == LoginScreenType.Passkey) {
                Spacer(modifier = Modifier.height(12.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    FilledIconButton(
                        onClick = {
                            /*
                             * TODO: Passkey Support
                             */
                        }
                    ) {
                        Icon(Lucide.KeyRound,
                            contentDescription = "Passkey")
                    }

                    Spacer(modifier = Modifier.width(8.dp))

                    Button(
                        onClick = {

                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Cancel")
                    }
                }
            }

            if (s_type.value != LoginScreenType.Passkey) {
                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = {
                        if (s_type.value == LoginScreenType.Generic) {
                            if (cb_login?.invoke(email.value, password.value, vaultURL.value, mainURL.value, apiURL.value, iconURL.value, wssURL.value) == true) {
                                email.value = ""
                            }
                            password.value = ""
                        } else if (s_type.value == LoginScreenType.TOTP ||
                            s_type.value == LoginScreenType.DeviceVerify) {
                            cb_loginCode?.invoke(code.value)
                            code.value = ""
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Log In")
                }

                Spacer(modifier = Modifier.height(12.dp))

                Text("Custom Environment",
                    modifier = Modifier.clickable {
                        e_dialog = true
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary)
            }

            if (e_dialog) {
                Dialog(
                    onDismissRequest = { e_dialog = false },
                    properties = DialogProperties(
                        usePlatformDefaultWidth = false
                    )) {
                    Scaffold(
                        topBar = {
                            TopAppBar(
                                title = { Text("Custom Environment") },
                                navigationIcon = {
                                    IconButton(onClick = { e_dialog = false }) {
                                        Icon(Lucide.X, contentDescription = "Close")
                                    }
                                },
                                colors = TopAppBarDefaults.topAppBarColors()
                            )
                        }
                    ) { padding ->
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(padding)
                                .padding(24.dp)
                                .verticalScroll(rememberScrollState())
                        ) {
                            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                                SegmentedButton(
                                    selected = selectedTab.value == 0,
                                    onClick = { switchTab(0) },
                                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
                                ) {
                                    Text("Bitwarden")
                                }
                                SegmentedButton(
                                    selected = selectedTab.value == 1,
                                    onClick = { switchTab(1) },
                                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
                                ) {
                                    Text("Custom")
                                }
                            }

                            Spacer(modifier = Modifier.height(12.dp))
                            OutlinedTextField(
                                value = vaultURL.value,
                                onValueChange = { setVaultURL(it) },
                                label = {
                                    Text("Vault URL")
                                },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                                shape = RoundedCornerShape(64.dp),
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = mainURL.value,
                                onValueChange = { setMainURL(it) },
                                label = {
                                    Text("Main URL")
                                },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                                shape = RoundedCornerShape(64.dp),
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = apiURL.value,
                                onValueChange = { setApiURL(it) },
                                label = {
                                    Text("API URL")
                                },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                                shape = RoundedCornerShape(64.dp),
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = iconURL.value,
                                onValueChange = { iconURL.value = it },
                                label = {
                                    Text("Icon URL")
                                },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                                shape = RoundedCornerShape(64.dp),
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = wssURL.value,
                                onValueChange = { setWssURL(it) },
                                label = {
                                    Text("WebSocket URL")
                                },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                                shape = RoundedCornerShape(64.dp),
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    }
                }
            }
        }
    }
}

@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
@Preview(
    showBackground = true,
    showSystemUi = true,
    device = Devices.PIXEL_9,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
fun PreviewLogin() {
    ClientwardenTheme {
        Scaffold() {
            LoginScreen.view()
        }
    }
}