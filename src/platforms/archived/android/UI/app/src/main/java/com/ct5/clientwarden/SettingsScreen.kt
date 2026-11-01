package com.ct5.clientwarden

import android.content.res.Configuration
import android.widget.Space
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.Popup
import com.composables.icons.lucide.AArrowDown
import com.composables.icons.lucide.ArrowDown
import com.composables.icons.lucide.ArrowRight
import com.composables.icons.lucide.BadgeCheck
import com.composables.icons.lucide.Check
import com.composables.icons.lucide.ChevronDown
import com.composables.icons.lucide.EllipsisVertical
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Shield
import com.ct5.clientwarden.NavScreen.c_item
import com.ct5.clientwarden.NavScreen.cb_DeleteFolder
import com.ct5.clientwarden.NavScreen.cb_RenameFolder
import com.ct5.clientwarden.ui.theme.ClientwardenTheme
import java.util.UUID
import android.net.Uri
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.clickable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.core.net.toUri
import kotlinx.coroutines.launch

enum class SettingsSelection {
    Security,
    AutoFill,
    About,
    NONE
}
object SettingsScreen {
    var c_item = mutableStateOf(SettingsSelection.NONE)

    @Composable
    fun SettingButton(text: String, icon: ImageVector = Lucide.AArrowDown, onClick: () -> Unit = {},
                      start: Boolean = false, end: Boolean = false) {
        /*
         * A Mat You Button with a custom BG Color
         */
        FilledTonalButton(onClick = { onClick() },
            modifier = Modifier.fillMaxWidth()
                .height(52.dp)
                .drawWithContent {
                    drawContent()
                },
            shape = RoundedCornerShape(
                topStart = if (start) 12.dp else 0.dp,
                topEnd = if (start) 12.dp else 0.dp,
                bottomStart = if (end) 12.dp else 0.dp,
                bottomEnd = if (end) 12.dp else 0.dp
            ),
            contentPadding = PaddingValues(16.dp, 0.dp, 0.dp, 0.dp),
            colors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                contentColor = MaterialTheme.colorScheme.surfaceContainerHigh
            )) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (icon != Lucide.AArrowDown) {
                    /*
                     * Nav Item Icon
                     */
                    Icon(
                        icon,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.size(20.dp)
                    )

                    Spacer(Modifier.width(8.dp))
                }

                /*
                 * Nav Item Name
                 */
                Text(text,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    overflow = TextOverflow.Ellipsis,
                    maxLines = 1)

                Spacer(Modifier.weight(1f).fillMaxWidth())
            }
        }
    }

    @Composable
    fun SettingsSwitch(text: String, onClick: () -> Unit = {},
                      start: Boolean = false, end: Boolean = false) {
        /*
         * A Mat You Button with a custom BG Color
         */
        FilledTonalButton(onClick = { },
            modifier = Modifier.fillMaxWidth()
                .height(52.dp)
                .drawWithContent {
                    drawContent()
                },
            shape = RoundedCornerShape(
                topStart = if (start) 12.dp else 0.dp,
                topEnd = if (start) 12.dp else 0.dp,
                bottomStart = if (end) 12.dp else 0.dp,
                bottomEnd = if (end) 12.dp else 0.dp
            ),
            contentPadding = PaddingValues(16.dp, 0.dp, 0.dp, 0.dp),
            colors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                contentColor = MaterialTheme.colorScheme.surfaceContainerHigh
            )) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                /*
                 * Item Name
                 */
                Text(text,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    overflow = TextOverflow.Ellipsis,
                    maxLines = 1)

                Spacer(Modifier.weight(1f).fillMaxWidth())

                var checked by remember { mutableStateOf(false) }

                Switch(
                    checked = checked,
                    onCheckedChange = { checked = it },
                    modifier = Modifier.scale(0.75f)
                )

                Spacer(Modifier.width(8.dp))
            }
        }
    }

    @Composable
    fun SettingsDropdown(text: String, options: List<String>, selected: String,
        onSelectedChange: (String) -> Unit, start: Boolean = false,
        end: Boolean = false) {
        var m_expanded by remember { mutableStateOf(false) }

        FilledTonalButton(
            onClick = { m_expanded = true },
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            shape = RoundedCornerShape(
                topStart = if (start) 12.dp else 0.dp,
                topEnd = if (start) 12.dp else 0.dp,
                bottomStart = if (end) 12.dp else 0.dp,
                bottomEnd = if (end) 12.dp else 0.dp
            ),
            contentPadding = PaddingValues(16.dp, 0.dp, 0.dp, 0.dp),
            colors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                contentColor = MaterialTheme.colorScheme.surfaceContainerHigh
            )
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column() {
                    Text(
                        text,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall
                    )

                    Text(
                        selected,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        overflow = TextOverflow.Ellipsis,
                        maxLines = 1
                    )
                }

                Spacer(Modifier.weight(1f).fillMaxWidth())

                Icon(
                    Lucide.ChevronDown,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.size(24.dp)
                )

                Spacer(Modifier.width(16.dp))
            }

            if (m_expanded) {
                AlertDialog(
                    onDismissRequest = { m_expanded = false },
                    title = { Text("Select an option") },
                    text = {
                        Column {
                            options.forEach { option ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            onSelectedChange(option)
                                            m_expanded = false
                                        }
                                        .padding(vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(option, modifier = Modifier.weight(1f))
                                    if (option == selected) {
                                        Icon(
                                            Lucide.Check,
                                            contentDescription = null,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                }
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = { m_expanded = false }) {
                            Text("Cancel")
                        }
                    }
                )
            }
        }
    }

    @Composable
    fun view(modifier: Modifier = Modifier) {
        var context = LocalContext.current
        var scope = rememberCoroutineScope()
        var rotation = remember { Animatable(0f) }
        var c_count by remember { mutableStateOf(0) }
        var l_time by remember { mutableStateOf(0L) }

        BackHandler(enabled = c_item.value != SettingsSelection.NONE) {
            c_item.value = SettingsSelection.NONE
        }

        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.TopStart
        ) {
            AnimatedContent(
                targetState = c_item.value,
                transitionSpec = {
                    if (targetState == SettingsSelection.NONE) {
                        slideInHorizontally(
                            initialOffsetX = { -it },
                            animationSpec = tween(250)
                        ) + fadeIn(
                            animationSpec = tween(250)
                        ) togetherWith
                                slideOutHorizontally(
                                    targetOffsetX = { it },
                                    animationSpec = tween(250)
                                ) + fadeOut(
                            animationSpec = tween(150)
                        )
                    } else {
                        slideInHorizontally(
                            initialOffsetX = { it },
                            animationSpec = tween(250)
                        ) + fadeIn(
                            animationSpec = tween(250)
                        ) togetherWith
                                slideOutHorizontally(
                                    targetOffsetX = { -it },
                                    animationSpec = tween(250)
                                ) + fadeOut(
                            animationSpec = tween(150)
                        )
                    }
                },
                label = "settings_nav"
            ) { item ->
                Column(modifier = Modifier.padding(16.dp)) {
                    if (item == SettingsSelection.NONE) {
                        SettingButton("Security", Lucide.Shield, {
                            c_item.value = SettingsSelection.Security
                        }, true)

                        SettingButton("AutoFill", Lucide.Check, {
                            c_item.value = SettingsSelection.AutoFill
                        })

                        SettingButton("About", Lucide.BadgeCheck, {
                            c_item.value = SettingsSelection.About
                        }, false, true)
                    } else if (item == SettingsSelection.Security) {
                        SettingsSwitch("Unlock with Biometrics", {

                        }, true)

                        var selected by remember { mutableStateOf("Immediate") }

                        SettingsDropdown(
                            text = "Session Timeout",
                            options = listOf(
                                "Immediate",
                                "1 minute",
                                "5 minutes",
                                "15 minutes",
                                "30 minutes",
                                "1 hour",
                                "4 hours",
                                "Never"
                            ),
                            selected = selected,
                            onSelectedChange = { selected = it }
                        )

                        SettingButton("Lock", onClick = {

                        })

                        SettingButton("Log Out", onClick = {

                        }, end = true)
                    } else if (item == SettingsSelection.AutoFill) {
                        SettingsSwitch("AutoFill", {

                        }, true, true)
                    } else if (item == SettingsSelection.About) {
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(top = 32.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(128.dp)
                                    .clip(RoundedCornerShape(30))
                                    .clickable {
                                        val now = System.currentTimeMillis()
                                        if (now - l_time > 500) {
                                            c_count = 1
                                        } else {
                                            c_count++
                                        }
                                        l_time = now

                                        if (c_count == 3) {
                                            c_count = 0
                                            if (!rotation.isRunning) {
                                                scope.launch {
                                                    rotation.animateTo(
                                                        targetValue = rotation.value + 360f,
                                                        animationSpec = tween(
                                                            durationMillis = 600,
                                                            easing = FastOutSlowInEasing
                                                        )
                                                    )

                                                    rotation.snapTo(rotation.value % 360f)
                                                }
                                            }
                                        }
                                    }
                                    .graphicsLayer { rotationZ = rotation.value }
                            ) {
                                Image(
                                    painter = painterResource(id = R.mipmap.ic_launcher_background),
                                    contentDescription = null,
                                    modifier = Modifier.fillMaxSize()
                                        .scale(1.5f)
                                )
                                Image(
                                    painter = painterResource(id = R.mipmap.ic_launcher_foreground),
                                    contentDescription = "App icon",
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .scale(1.5f)
                                )
                            }

                            Spacer(modifier = Modifier.height(32.dp))

                            ClientwardenEasterText()

                            Spacer(modifier = Modifier.height(2.dp))

                            Text(
                                "Version 0482A1A Release",
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                style = MaterialTheme.typography.bodyMedium
                            )

                            Spacer(modifier = Modifier.weight(1f).fillMaxHeight())

                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    "Github",
                                    color = MaterialTheme.colorScheme.primary,
                                    style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.clickable {
                                        val intent = Intent(
                                            Intent.ACTION_VIEW,
                                            "https://github.com/Cherrytree56567/ClientWarden".toUri()
                                        )
                                        context.startActivity(intent)
                                    })

                                Spacer(modifier = Modifier.weight(1f).fillMaxWidth())

                                Text(
                                    "Made By CT5",
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    style = MaterialTheme.typography.bodyMedium
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Preview(
    showBackground = true,
    showSystemUi = true,
    device = Devices.PIXEL_9,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
fun PreviewSettings() {
    ClientwardenTheme {
        VaultUI()
    }
}