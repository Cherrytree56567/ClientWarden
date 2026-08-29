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
}

object NavScreen {
    val folders = mutableListOf<ClientwardenFolder>()

    //var cb_AllItems: (() -> List<ItemElement>)? = null
    @Composable
    fun NavButton(text: String, icon: ImageVector, start: Boolean = false, end: Boolean = false) {
        val o_color = MaterialTheme.colorScheme.outline
        FilledTonalButton(onClick = { },
            modifier = Modifier.fillMaxWidth()
                .height(52.dp)
                .drawWithContent {
                    drawContent()
                    if (false) {
                        drawLine(
                            color = o_color,
                            start = androidx.compose.ui.geometry.Offset(
                                10.dp.toPx(),
                                kotlin.math.floor(size.height - 1.dp.toPx() / 2) + 0.5f
                            ),
                            end = androidx.compose.ui.geometry.Offset(
                                size.width - 10.dp.toPx(),
                                kotlin.math.floor(size.height - 1.dp.toPx() / 2) + 0.5f
                            ),
                            strokeWidth = 2.dp.toPx()
                        )
                    }
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
                    color = MaterialTheme.colorScheme.onSecondaryContainer)
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
            NavButton("All Items", Lucide.House, start = true)
            NavButton("Favorites", Lucide.Star)
            NavButton("Trash", Lucide.Trash2)
            NavButton("Archived", Lucide.Archive, end = true)

            Spacer(modifier = Modifier.height(16.dp))

            NavButton("Login", Lucide.SquareAsterisk, start = true)
            NavButton("Card", Lucide.CreditCard)
            NavButton("Identity", Lucide.IdCard)
            NavButton("Note", Lucide.StickyNote)
            NavButton("SSH Key", Lucide.KeyRound, end = true)

            Spacer(modifier = Modifier.height(16.dp))

            for ((i, folder) in folders.withIndex()) {
                NavButton(folder.name, Lucide.Folder, start = i == 0, end = i == folders.lastIndex)
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