package com.ct5.clientwarden

import android.content.res.Configuration
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.composables.icons.lucide.Archive
import com.composables.icons.lucide.CreditCard
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

/*
 * TODO: Create Add Folder Popup
 */
object NavScreen {
    var folders = mutableListOf<ClientwardenFolder>()
    var c_item: NavItem = NavItem.AllItems

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

    @Composable
    fun NavButton(text: String, icon: ImageVector, item: NavItem, onClick: () -> Unit = {}, start: Boolean = false, end: Boolean = false) {
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
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 0.dp),
            colors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                contentColor = MaterialTheme.colorScheme.surfaceContainerHigh
            )) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text(text,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    overflow = TextOverflow.Ellipsis,
                    maxLines = 1)
            }
        }
    }
    @Composable
    fun view() {
        Column(
            modifier = Modifier.fillMaxSize()
                               .verticalScroll(rememberScrollState())
                               .padding(16.dp)
        ) {
            NavButton("All Items", Lucide.House, NavItem.AllItems,
                start = true, onClick = { ItemsScreen.SetItems(cb_AllItems?.invoke() ?: emptyList()) })
            NavButton("Favorites", Lucide.Star, NavItem.Favorites,
                onClick = { ItemsScreen.SetItems(cb_Favorites?.invoke() ?: emptyList()) })
            NavButton("Trash", Lucide.Trash2, NavItem.Trash,
                onClick = { ItemsScreen.SetItems(cb_Trash?.invoke() ?: emptyList()) })
            NavButton("Archived", Lucide.Archive, NavItem.Archived,
                end = true, onClick = { ItemsScreen.SetItems(cb_Archived?.invoke() ?: emptyList()) })

            Spacer(modifier = Modifier.height(16.dp))

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

            for ((i, folder) in folders.withIndex()) {
                NavButton(folder.name, Lucide.Folder,
                    NavItem.Folder(folder.uuid), start = i == 0,
                    onClick = { ItemsScreen.SetItems(cb_Folder?.invoke(folder.uuid) ?: emptyList()) })
            }


            NavButton("Add Folder", Lucide.Plus, NavItem.None,
                start = if (folders.size == 0) true else false, end = true)
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