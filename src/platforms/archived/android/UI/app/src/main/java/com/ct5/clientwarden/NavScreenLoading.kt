package com.ct5.clientwarden

import android.content.res.Configuration
import android.graphics.fonts.Font
import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.TransformOrigin
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
import java.util.UUID

object NavScreenLoading {
    var folders = mutableListOf<ClientwardenFolder>()
    var c_item: NavItem = NavItem.AllItems

    @Composable
    fun NavButton(text: String, icon: ImageVector, item: NavItem,
                  onClick: () -> Unit = {}, start: Boolean = false,
                  end: Boolean = false, addEllipses: Boolean = true,
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
                Box(modifier = Modifier.size(20.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .shimmerEffect())

                Spacer(Modifier.width(8.dp))

                /*
                 * Nav Item Name
                 */
                Text(text,
                    color = Color.Transparent,
                    overflow = TextOverflow.Ellipsis,
                    maxLines = 1,
                    modifier = Modifier.weight(1f)
                        .clip(RoundedCornerShape(8.dp))
                        .fillMaxWidth()
                        .shimmerEffect()
                        .padding(end = 8.dp))

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
                        Box(modifier = Modifier.padding(end = 16.dp)
                            .size(20.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .shimmerEffect())

                        val transitionState = remember { MutableTransitionState(false) }
                        transitionState.targetState = m_expanded
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
                               .padding(16.dp, 0.dp, 16.dp, 16.dp)
        ) {
            /*
             * Main Nav Items
             */
            NavButton("All Items", Lucide.House, NavItem.AllItems,
                start = true, onClick = {})
            NavButton("Favorites", Lucide.Star, NavItem.Favorites,
                onClick = {})
            NavButton("Trash", Lucide.Trash2, NavItem.Trash,
                onClick = {})
            NavButton("Archived", Lucide.Archive, NavItem.Archived,
                end = true, onClick = {})

            Spacer(modifier = Modifier.height(16.dp))

            /*
             * Item Type Nav Items
             */
            NavButton("Login", Lucide.SquareAsterisk, NavItem.Login,
                start = true, onClick = {})
            NavButton("Card", Lucide.CreditCard, NavItem.Card,
                onClick = {})
            NavButton("Identity", Lucide.IdCard, NavItem.Identity,
                onClick = {})
            NavButton("Note", Lucide.StickyNote, NavItem.Note,
                onClick = {})
            NavButton("SSH Key", Lucide.KeyRound, NavItem.SshKey, end = true,
                onClick = {})

            Spacer(modifier = Modifier.height(16.dp))

            /*
             * Folder Nav Items
             */
            for ((i, folder) in folders.withIndex()) {
                NavButton(folder.name, Lucide.Folder,
                    NavItem.Folder(folder.uuid), start = i == 0,
                    onClick = {
                    }, addEllipses = true, folder = folder
                )
            }

            /*
             * Add Folder Button
             */
            NavButton("Add Folder", Lucide.Plus, NavItem.None,
                start = if (folders.size == 0) true else false, end = true,
                onClick = {
                }, addEllipses = false
            )
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
fun PreviewNavLoading() {
    VaultUI()
}