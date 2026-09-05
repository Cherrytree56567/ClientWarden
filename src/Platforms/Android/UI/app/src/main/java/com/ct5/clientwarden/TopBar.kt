package com.ct5.clientwarden

import android.content.res.Configuration
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.TextField
import androidx.compose.material3.SearchBar
import androidx.compose.material3.SearchBarDefaults
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.VerticalAlignmentLine
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Popup
import com.composables.icons.lucide.Archive
import com.composables.icons.lucide.CreditCard
import com.composables.icons.lucide.EllipsisVertical
import com.composables.icons.lucide.Globe
import com.composables.icons.lucide.IdCard
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Pen
import com.composables.icons.lucide.Plus
import com.composables.icons.lucide.ScreenShare
import com.composables.icons.lucide.Search
import com.composables.icons.lucide.SearchX
import com.composables.icons.lucide.StickyNote
import com.composables.icons.lucide.Trash2
import com.composables.icons.lucide.X
import com.ct5.clientwarden.ItemsScreen.cb_archive
import com.ct5.clientwarden.ItemsScreen.cb_bin
import com.ct5.clientwarden.ItemsScreen.cb_delete
import com.ct5.clientwarden.ItemsScreen.cb_restore
import com.ct5.clientwarden.ItemsScreen.cb_unarchive

object TopBar {
    var query: String = ""
    var m_expanded by mutableStateOf(false)
    var cb_query: ((String) -> Unit)? = null
    var cb_new: ((ItemType) -> Boolean)? = null

    @Composable
    @OptIn(ExperimentalMaterial3Api::class)
    fun view() {
        if (HomeScreen.c_panel == HomeScreenPanel.DetailsScreen) {
            Row(
                modifier = Modifier.padding(top = 8.dp, start = 16.dp, end = 16.dp, bottom = 16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                FilledIconButton(
                    onClick = { },
                    modifier = Modifier.size(48.dp)
                ) {
                    Icon(
                        Lucide.X,
                        contentDescription = "Close Item",
                        modifier = Modifier.size(20.dp)
                    )
                }

                Spacer(modifier = Modifier.weight(1f).fillMaxWidth())

                FilledIconButton(
                    onClick = { },
                    modifier = Modifier.height(48.dp)
                        .width(48.dp)
                ) {
                    Icon(
                        Lucide.Trash2,
                        contentDescription = "Bin",
                        modifier = Modifier.size(20.dp)
                    )
                }

                Spacer(modifier = Modifier.width(16.dp))

                FilledIconButton(
                    onClick = { },
                    modifier = Modifier.height(48.dp)
                        .width(48.dp)
                ) {
                    Icon(
                        Lucide.Archive,
                        contentDescription = "Archive",
                        modifier = Modifier.size(20.dp)
                    )
                }

                Spacer(modifier = Modifier.width(16.dp))

                FilledIconButton(
                    onClick = { },
                    modifier = Modifier.height(48.dp)
                        .width(48.dp)
                ) {
                    Icon(
                        Lucide.Pen,
                        contentDescription = "Edit Item",
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        } else {
            Row(
                modifier = Modifier.padding(top = 8.dp, start = 16.dp, end = 16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextField(
                    value = query,
                    onValueChange = { newValue -> cb_query?.invoke(newValue) },
                    modifier = Modifier.weight(1f),
                    placeholder = {
                        Text("Search")
                    },
                    leadingIcon = {
                        Icon(
                            Lucide.Search,
                            contentDescription = "Search",
                            modifier = Modifier.size(20.dp)
                        )
                    },
                    singleLine = true,
                    shape = RoundedCornerShape(32.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                        focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                        focusedBorderColor = Color.Transparent,
                        unfocusedBorderColor = Color.Transparent
                    )
                )

                Spacer(modifier = Modifier.width(16.dp))

                Surface(
                    modifier = Modifier
                        .height(48.dp)
                        .wrapContentWidth()
                        .animateContentSize(animationSpec = tween(0)),
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.primary,
                    onClick = { if (!m_expanded) m_expanded = true }
                ) {
                    AnimatedContent(
                        targetState = m_expanded,
                        transitionSpec = {
                            fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                        },
                        label = "plusToPill"
                    ) { i_expanded ->
                        if (!i_expanded) {
                            Row(
                                modifier = Modifier.width(48.dp).height(48.dp),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    Lucide.Plus,
                                    contentDescription = "Add Item",
                                    tint = MaterialTheme.colorScheme.onPrimary,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        } else {
                            Row(
                                modifier = Modifier
                                    .height(48.dp)
                                    .padding(horizontal = 12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                IconButton(
                                    onClick = {
                                        m_expanded = false
                                        cb_new?.invoke(ItemType.Login)
                                    },
                                    modifier = Modifier.size(36.dp)
                                ) {
                                    Icon(
                                        Lucide.Globe,
                                        contentDescription = "Login",
                                        tint = MaterialTheme.colorScheme.onPrimary,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }

                                IconButton(
                                    onClick = {
                                        m_expanded = false
                                        cb_new?.invoke(ItemType.Card)
                                    },
                                    modifier = Modifier.size(40.dp)
                                ) {
                                    Icon(
                                        Lucide.CreditCard,
                                        contentDescription = "Card",
                                        tint = MaterialTheme.colorScheme.onPrimary,
                                        modifier = Modifier.size(22.dp)
                                    )
                                }

                                IconButton(
                                    onClick = {
                                        m_expanded = false
                                        cb_new?.invoke(ItemType.Identity)
                                    },
                                    modifier = Modifier.size(40.dp)
                                ) {
                                    Icon(
                                        Lucide.IdCard,
                                        contentDescription = "Identity",
                                        tint = MaterialTheme.colorScheme.onPrimary,
                                        modifier = Modifier.size(22.dp)
                                    )
                                }

                                IconButton(
                                    onClick = {
                                        m_expanded = false
                                        cb_new?.invoke(ItemType.Note)
                                    },
                                    modifier = Modifier.size(36.dp)
                                ) {
                                    Icon(
                                        Lucide.StickyNote,
                                        contentDescription = "Note",
                                        tint = MaterialTheme.colorScheme.onPrimary,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }

                                IconButton(
                                    onClick = {
                                        m_expanded = false
                                        cb_new?.invoke(ItemType.SSHKey)
                                    },
                                    modifier = Modifier.size(36.dp)
                                ) {
                                    Icon(
                                        Lucide.KeyRound,
                                        contentDescription = "SSH Key",
                                        tint = MaterialTheme.colorScheme.onPrimary,
                                        modifier = Modifier.size(18.dp)
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

@Preview(
    showBackground = true,
    showSystemUi = true,
    device = Devices.PIXEL_9,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
fun PreviewTopBar() {
    MainScreen()
}