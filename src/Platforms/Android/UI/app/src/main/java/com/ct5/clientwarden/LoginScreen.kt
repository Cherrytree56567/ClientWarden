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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.composables.icons.lucide.ArrowRight
import com.composables.icons.lucide.FingerprintPattern
import com.composables.icons.lucide.Lucide
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

    var cb_login: ((String, String) -> Boolean)? = null
    var cb_loginCode: ((String) -> Boolean)? = null

    @Composable
    fun view() {
        var t_clicked by remember { mutableStateOf(false) }

        val textColor by animateColorAsState(
            targetValue = if (t_clicked) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.inverseSurface,
            animationSpec = tween(durationMillis = 800),
            label = "textColor"
        )

        LaunchedEffect(t_clicked) {
            if (t_clicked) {
                delay(5000.milliseconds)
                t_clicked = false
            }
        }

        Column(modifier = Modifier.fillMaxSize().padding(64.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center) {
            /*
             * Main Header
             * I wanted the header to have an easter egg bc
             * why not
             */
            Text("Clientwarden", style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.Bold,
                color = textColor,
                modifier = Modifier.clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null
                ) { t_clicked = true }
            )

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
                        Icon(Lucide.FingerprintPattern,
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
                            if (cb_login?.invoke(email.value, password.value) == true) {
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