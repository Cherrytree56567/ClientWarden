package com.ct5.clientwarden

import android.content.res.Configuration
import android.graphics.fonts.Font
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.Popup
import com.composables.icons.lucide.Archive
import com.composables.icons.lucide.ArrowRight
import com.composables.icons.lucide.CreditCard
import com.composables.icons.lucide.EllipsisVertical
import com.composables.icons.lucide.Folder
import com.composables.icons.lucide.House
import com.composables.icons.lucide.IdCard
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Plus
import com.composables.icons.lucide.SquareAsterisk
import com.composables.icons.lucide.Star
import com.composables.icons.lucide.StickyNote
import com.composables.icons.lucide.Trash2
import com.composables.icons.lucide.X
import com.ct5.clientwarden.ItemsScreen.cb_archive
import com.ct5.clientwarden.ItemsScreen.cb_bin
import com.ct5.clientwarden.ItemsScreen.cb_delete
import com.ct5.clientwarden.ItemsScreen.cb_restore
import com.ct5.clientwarden.ItemsScreen.cb_unarchive
import java.util.UUID

sealed interface NavItem {
    data object AllItems : NavItem
    data object Favorites : NavItem
    data object Trash : NavItem
    data object Archived : NavItem
    data object Login : NavItem
    data object Card : NavItem
    data object Identity : NavItem
    data object Note : NavItem
    data object SshKey : NavItem
    data class Folder(val id: UUID) : NavItem
    data object None : NavItem
}

object NavScreen {
    var folders = mutableListOf<ClientwardenFolder>(
        ClientwardenFolder(uuid = UUID(0L, 0L), "New Fol")
    )
    var c_item: NavItem = NavItem.AllItems

    /*
     * Tons of callbacks
     */
    var cb_AllItems: (() -> List<ItemElement>)? = null
    var cb_Favorites: (() -> List<ItemElement>)? = null
    var cb_Trash: (() -> List<ItemElement>)? = null
    var cb_Archived: (() -> List<ItemElement>)? = null

    var cb_Login: (() -> List<ItemElement>)? = null
    var cb_Card: (() -> List<ItemElement>)? = null
    var cb_Identity: (() -> List<ItemElement>)? = null
    var cb_Note: (() -> List<ItemElement>)? = null
    var cb_SSHKey: (() -> List<ItemElement>)? = null

    var cb_Folder: ((uuid: UUID) -> List<ItemElement>)? = null
    var cb_NewFolder: ((name: String) -> Unit)? = null
    var cb_RenameFolder: ((uuid: UUID, name: String) -> Unit)? = null
    var cb_DeleteFolder: ((uuid: UUID) -> Unit)? = null

    @Composable
    fun NavButton(text: String, icon: ImageVector, item: NavItem,
                  onClick: () -> Unit = {}, start: Boolean = false,
                  end: Boolean = false, addEllipses: Boolean = false,
                  folder: ClientwardenFolder = ClientwardenFolder(uuid = UUID(0L, 0L), name = "Fol")) {
        var m_expanded by remember { mutableStateOf(false) }
        var m_renameExpanded by remember { mutableStateOf(false) }
        var m_deleteExpanded by remember { mutableStateOf(false) }
        /*
         * A Mat You Button with a custom BG Color
         */
        FilledTonalButton(onClick = {
            if (item != NavItem.None) {
                c_item = item
            }
            onClick()
        },
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
                 * Nav Item Icon
                 */
                Icon(icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.size(20.dp))

                Spacer(Modifier.width(8.dp))

                /*
                 * Nav Item Name
                 */
                Text(text,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    overflow = TextOverflow.Ellipsis,
                    maxLines = 1)

                Spacer(Modifier.weight(1f).fillMaxWidth())

                /*
                 * Ellipses Box
                 * Stores the Ellipses Button and Dropdown
                 */
                if (addEllipses) {
                    Box {
                        /*
                         * Ellipses Button
                         */
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
                         * Thanks to Claude for the Animated Visibility,
                         * although the Popup stuff was mine
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
                                        transformOrigin = androidx.compose.ui.graphics.TransformOrigin(
                                            1f,
                                            0f
                                        )
                                    ),
                                    exit = fadeOut(tween(100)) + scaleOut(
                                        targetScale = 0.85f,
                                        animationSpec = tween(280),
                                        transformOrigin = androidx.compose.ui.graphics.TransformOrigin(
                                            1f,
                                            0f
                                        )
                                    )
                                ) {
                                    Surface(
                                        shape = RoundedCornerShape(8.dp),
                                        color = MaterialTheme.colorScheme.surfaceContainerHighest,
                                        tonalElevation = 3.dp,
                                        modifier = Modifier.padding(
                                            horizontal = 8.dp,
                                            vertical = 0.dp
                                        )
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(
                                                horizontal = 0.dp,
                                                vertical = 0.dp
                                            )
                                        ) {
                                            /*
                                             * Rename Folder Button
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    m_renameExpanded = true
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
                                                    "Rename",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }

                                            /*
                                             * Delete Folder Button
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    m_deleteExpanded = true
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
                                                    "Delete",
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

        var s_folderName by remember { mutableStateOf("") }

        /*
         * Prompt to ask for New Folder Name
         */
        if (m_renameExpanded) {
            s_folderName = text
            Dialog(
                onDismissRequest = {
                    m_renameExpanded = false
                },
                properties = DialogProperties(
                    usePlatformDefaultWidth = false
                ),
            ) {
                Surface(color = MaterialTheme.colorScheme.surfaceContainer, shape = RoundedCornerShape(32.dp)) {
                    Column(
                        modifier = Modifier
                            .padding(24.dp)
                            .width(300.dp),
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Rename Folder",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(Modifier.height(24.dp))

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            /*
                             * Custom Text Field
                             * We are using a custom text field here
                             * bc the mat you one has to be thicc, but
                             * I need it to be thin
                             */
                            BasicTextField(
                                value = s_folderName,
                                onValueChange = {
                                    s_folderName = it
                                },
                                modifier = Modifier.weight(1f)
                                    .height(34.dp)
                                    .background(
                                        color = MaterialTheme.colorScheme.surfaceContainerHighest,
                                        shape = RoundedCornerShape(32.dp)
                                    )
                                    .padding(horizontal = 14.dp, vertical = 8.dp),
                                singleLine = true,
                                textStyle = MaterialTheme.typography.bodyMedium.copy(
                                    color = MaterialTheme.colorScheme.onSurface
                                ),
                                cursorBrush = SolidColor(
                                    MaterialTheme.colorScheme.primary
                                )
                            )

                            Spacer(Modifier.width(12.dp))

                            FilledIconButton(
                                onClick = {
                                    m_renameExpanded = false
                                    cb_RenameFolder?.invoke(folder.uuid, s_folderName)
                                },
                                modifier = Modifier.size(32.dp)
                            ) {
                                Icon(
                                    Lucide.ArrowRight,
                                    contentDescription = "More",
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                    }
                }
            }
        }

        /*
         * Prompt to Ask for Folder Deletion
         * Confirmation
         */
        if (m_deleteExpanded) {
            Dialog(
                onDismissRequest = {
                    m_deleteExpanded = false
                },
                properties = DialogProperties(
                    usePlatformDefaultWidth = false
                ),
            ) {
                Surface(color = MaterialTheme.colorScheme.surfaceContainer, shape = RoundedCornerShape(32.dp)) {
                    Column(
                        modifier = Modifier
                            .padding(24.dp)
                            .width(300.dp),
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Delete Folder",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(Modifier.height(8.dp))

                        Text(
                            text = "Are you sure you would like to delete this folder? This is an irreversable action!",
                            style = MaterialTheme.typography.bodyMedium
                        )

                        Spacer(Modifier.height(8.dp))

                        TextButton(
                            onClick = {
                                m_deleteExpanded = false
                                cb_DeleteFolder?.invoke(folder.uuid)
                            },
                            colors = ButtonDefaults.textButtonColors(
                                containerColor = MaterialTheme.colorScheme.primary,
                                contentColor = MaterialTheme.colorScheme.onPrimary
                            )
                        ) {
                            Text("Continue")
                        }
                    }
                }
            }
        }
    }

    @Composable
    fun view() {
        var addFolder_expanded by remember { mutableStateOf(false) }
        var s_folderName by remember { mutableStateOf("New Folder") }
        Column(
            modifier = Modifier.fillMaxSize()
                               .verticalScroll(rememberScrollState())
                               .padding(16.dp)
        ) {
            /*
             * Main Nav Items
             */
            NavButton("All Items", Lucide.House, NavItem.AllItems,
                start = true, onClick = { ItemsScreen.SetItems(cb_AllItems?.invoke() ?: emptyList()) })
            NavButton("Favorites", Lucide.Star, NavItem.Favorites,
                onClick = { ItemsScreen.SetItems(cb_Favorites?.invoke() ?: emptyList()) })
            NavButton("Trash", Lucide.Trash2, NavItem.Trash,
                onClick = { ItemsScreen.SetItems(cb_Trash?.invoke() ?: emptyList()) })
            NavButton("Archived", Lucide.Archive, NavItem.Archived,
                end = true, onClick = { ItemsScreen.SetItems(cb_Archived?.invoke() ?: emptyList()) })

            Spacer(modifier = Modifier.height(16.dp))

            /*
             * Item Type Nav Items
             */
            NavButton("Login", Lucide.SquareAsterisk, NavItem.Login,
                start = true, onClick = { ItemsScreen.SetItems(cb_Login?.invoke() ?: emptyList()) })
            NavButton("Card", Lucide.CreditCard, NavItem.Card,
                onClick = { ItemsScreen.SetItems(cb_Card?.invoke() ?: emptyList()) })
            NavButton("Identity", Lucide.IdCard, NavItem.Identity,
                onClick = { ItemsScreen.SetItems(cb_Identity?.invoke() ?: emptyList()) })
            NavButton("Note", Lucide.StickyNote, NavItem.Note,
                onClick = { ItemsScreen.SetItems(cb_Note?.invoke() ?: emptyList()) })
            NavButton("SSH Key", Lucide.KeyRound, NavItem.SshKey, end = true,
                onClick = { ItemsScreen.SetItems(cb_SSHKey?.invoke() ?: emptyList()) })

            Spacer(modifier = Modifier.height(16.dp))

            /*
             * Folder Nav Items
             */
            for ((i, folder) in folders.withIndex()) {
                NavButton(folder.name, Lucide.Folder,
                    NavItem.Folder(folder.uuid), start = i == 0,
                    onClick = {
                        ItemsScreen.SetItems(cb_Folder?.invoke(folder.uuid) ?: emptyList())
                    }, addEllipses = true, folder = folder
                )
            }

            /*
             * Add Folder Button
             */
            NavButton("Add Folder", Lucide.Plus, NavItem.None,
                start = if (folders.size == 0) true else false, end = true,
                onClick = {
                    addFolder_expanded = true
                }
            )
        }

        /*
         * Prompt to ask for New Folder Name
         */
        if (addFolder_expanded) {
            Dialog(
                onDismissRequest = {
                    addFolder_expanded = false
                },
                properties = DialogProperties(
                    usePlatformDefaultWidth = false
                ),
            ) {
                Surface(color = MaterialTheme.colorScheme.surfaceContainer, shape = RoundedCornerShape(32.dp)) {
                    Column(
                        modifier = Modifier
                            .padding(24.dp)
                            .width(300.dp),
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Create Folder",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(Modifier.height(24.dp))

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            /*
                             * Custom Text Field
                             * We are using a custom text field here
                             * bc the mat you one has to be thicc, but
                             * I need it to be thin
                             */
                            BasicTextField(
                                value = s_folderName,
                                onValueChange = {
                                    s_folderName = it
                                },
                                modifier = Modifier.weight(1f)
                                    .height(34.dp)
                                    .background(
                                        color = MaterialTheme.colorScheme.surfaceContainerHighest,
                                        shape = RoundedCornerShape(32.dp)
                                    )
                                    .padding(horizontal = 14.dp, vertical = 6.dp),
                                singleLine = true,
                                textStyle = MaterialTheme.typography.bodyMedium.copy(
                                    color = MaterialTheme.colorScheme.onSurface
                                ),
                                cursorBrush = SolidColor(
                                    MaterialTheme.colorScheme.primary
                                )
                            )

                            Spacer(Modifier.width(12.dp))

                            FilledIconButton(
                                onClick = {
                                    addFolder_expanded = false
                                    cb_NewFolder?.invoke(s_folderName)
                                },
                                modifier = Modifier.size(32.dp)
                            ) {
                                Icon(
                                    Lucide.ArrowRight,
                                    contentDescription = "More",
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

@Preview(
    showBackground = true,
    showSystemUi = true,
    device = Devices.PIXEL_9,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
fun PreviewNav() {
    MainScreen()
}