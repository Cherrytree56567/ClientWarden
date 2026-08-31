package com.ct5.clientwarden

import android.content.res.Configuration
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.DpOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Popup
import com.composables.icons.lucide.Archive
import com.composables.icons.lucide.CreditCard
import com.composables.icons.lucide.EllipsisVertical
import com.composables.icons.lucide.Expand
import com.composables.icons.lucide.Folder
import com.composables.icons.lucide.FunnelPlus
import com.composables.icons.lucide.Globe
import com.composables.icons.lucide.House
import com.composables.icons.lucide.IdCard
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.SquareAsterisk
import com.composables.icons.lucide.Star
import com.composables.icons.lucide.StickyNote
import com.composables.icons.lucide.Trash2
import com.ct5.clientwarden.NavScreen.NavButton
import com.ct5.clientwarden.NavScreen.folders
import java.util.UUID
import kotlin.math.floor

/*
 * f_items = Filtered Items
 */
object ItemsScreen {
    var items = mutableListOf<ItemElement>()
    var f_items = mutableListOf<ItemElement>(
        ItemElement(
            UUID.randomUUID(),
            "Google",
            ItemType.Login,
            Lucide.Globe
        ),
        ItemElement(
            UUID.randomUUID(),
            "GitHub",
            ItemType.Login,
            Lucide.Globe
        ),
        ItemElement(
            UUID.randomUUID(),
            "Amazon",
            ItemType.Login,
            Lucide.Globe
        ),
        ItemElement(
            UUID.randomUUID(),
            "Netflix",
            ItemType.Login,
            Lucide.Globe
        ),
        ItemElement(
            UUID.randomUUID(),
            "Visa",
            ItemType.Card,
            Lucide.CreditCard
        ),
        ItemElement(
            UUID.randomUUID(),
            "Mastercard",
            ItemType.Card,
            Lucide.CreditCard
        ),
        ItemElement(
            UUID.randomUUID(),
            "American Express",
            ItemType.Card,
            Lucide.CreditCard
        ),
        ItemElement(
            UUID.randomUUID(),
            "Driver Licence",
            ItemType.Identity,
            Lucide.IdCard
        ),
        ItemElement(
            UUID.randomUUID(),
            "Passport",
            ItemType.Identity,
            Lucide.IdCard
        ),
        ItemElement(
            UUID.randomUUID(),
            "Personal Notes",
            ItemType.Note,
            Lucide.StickyNote
        ),
        ItemElement(
            UUID.randomUUID(),
            "Server Credentials",
            ItemType.SSHKey,
            Lucide.KeyRound
        ),
        ItemElement(
            UUID.randomUUID(),
            "Production Server",
            ItemType.SSHKey,
            Lucide.KeyRound
        )
    )

    var cb_bin: (() -> Boolean)? = null
    var cb_delete: (() -> Boolean)? = null
    var cb_restore: (() -> Boolean)? = null
    var cb_archive: (() -> Boolean)? = null
    var cb_unarchive: (() -> Boolean)? = null

    fun SetItems(l_items: List<ItemElement>) {
        items = mutableListOf<ItemElement>()
        items.addAll(l_items)
        f_items = items
    }

    @Composable
    fun Item(item: ItemElement, start: Boolean = false, end: Boolean = false) {
        var m_expanded by remember { mutableStateOf(false) }
        FilledTonalButton(onClick = { },
            modifier = Modifier.fillMaxWidth()
                .height(64.dp),
            shape = RoundedCornerShape(
                topStart = if (start) 12.dp else 0.dp,
                topEnd = if (start) 12.dp else 0.dp,
                bottomStart = if (end) 12.dp else 0.dp,
                bottomEnd = if (end) 12.dp else 0.dp
            ),
            contentPadding = PaddingValues(start = 16.dp, end = 4.dp),
            colors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                contentColor = MaterialTheme.colorScheme.surfaceContainerHigh
            )) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(item.icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Column(modifier = Modifier.padding(horizontal = 4.dp)) {
                    Text(item.name,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        lineHeight = 16.sp,
                        modifier = Modifier.padding(top = 2.dp),
                        overflow = TextOverflow.Ellipsis,
                        maxLines = 1)
                    Text(item.type.desc,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        lineHeight = 16.sp)
                }
                Spacer(Modifier.weight(1f).fillMaxWidth())
                Box {
                    IconButton(
                        onClick = { m_expanded = true }
                    ) {
                        Icon(
                            Lucide.EllipsisVertical,
                            contentDescription = "More",
                            tint = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    val transitionState = remember { MutableTransitionState(false) }
                    transitionState.targetState = m_expanded

                    /*
                     * Thanks to claude for the Animated Visibility,
                     * the Popup stuff was mine
                     */
                    if (transitionState.currentState || transitionState.targetState) {
                        Popup(
                            alignment = Alignment.TopEnd,
                            onDismissRequest = { m_expanded = false }
                        ) {
                            androidx.compose.animation.AnimatedVisibility(
                                visibleState = transitionState,
                                enter = fadeIn(tween(120)) + scaleIn(
                                    initialScale = 0.85f,
                                    animationSpec = tween(120),
                                    transformOrigin = androidx.compose.ui.graphics.TransformOrigin(1f, 0f) // top-end anchor
                                ),
                                exit = fadeOut(tween(100)) + scaleOut(
                                    targetScale = 0.85f,
                                    animationSpec = tween(280),
                                    transformOrigin = androidx.compose.ui.graphics.TransformOrigin(1f, 0f)
                                )
                            ) {
                                Surface(
                                    shape = RoundedCornerShape(8.dp),
                                    color = MaterialTheme.colorScheme.surfaceContainerHighest,
                                    tonalElevation = 3.dp,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 0.dp)
                                ) {
                                    /*
                                 * Use NavScreen.c_item to show or hide restore/delete
                                 */
                                    Column(
                                        modifier = Modifier.padding(
                                            horizontal = 0.dp,
                                            vertical = 0.dp
                                        )
                                    ) {
                                        if (NavScreen.c_item == NavItem.Trash) {
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    cb_restore?.invoke()
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 8.dp,
                                                    topEnd = 8.dp,
                                                    bottomStart = 8.dp,
                                                    bottomEnd = 8.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Restore",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    cb_delete?.invoke()
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 8.dp,
                                                    topEnd = 8.dp,
                                                    bottomStart = 8.dp,
                                                    bottomEnd = 8.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Permanently Delete",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }
                                        } else if (NavScreen.c_item == NavItem.Archived) {
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    cb_unarchive?.invoke()
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 8.dp,
                                                    topEnd = 8.dp,
                                                    bottomStart = 0.dp,
                                                    bottomEnd = 0.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Unarchive",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }

                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    cb_bin?.invoke()
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 0.dp,
                                                    topEnd = 0.dp,
                                                    bottomStart = 8.dp,
                                                    bottomEnd = 8.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Bin",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }
                                        } else {
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    cb_bin?.invoke()
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 8.dp,
                                                    topEnd = 8.dp,
                                                    bottomStart = 0.dp,
                                                    bottomEnd = 0.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Bin",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }

                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    cb_archive?.invoke()
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 0.dp,
                                                    topEnd = 0.dp,
                                                    bottomStart = 8.dp,
                                                    bottomEnd = 8.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Archive",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!end) {
            Column(modifier = Modifier.fillMaxWidth()
                                      .background(color = MaterialTheme.colorScheme.surfaceContainerHigh)) {
                HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp))
            }
        }
    }

    @Composable
    fun view() {
        Column(
            modifier = Modifier.fillMaxWidth()
                               .padding(16.dp)
                               .clip(RoundedCornerShape(16.dp))
                               .verticalScroll(rememberScrollState())
        ) {
            for ((i, item) in f_items.withIndex()) {
                Item(item, start = i == 0, end = i == f_items.lastIndex)
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
fun PreviewItems() {
    MainScreen()
}