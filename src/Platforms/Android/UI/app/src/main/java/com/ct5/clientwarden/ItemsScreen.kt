package com.ct5.clientwarden

import android.content.res.Configuration
import androidx.compose.foundation.background
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
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
    var f_items = mutableListOf<ItemElement>()

    @Composable
    fun Item(item: ItemElement, start: Boolean = false, end: Boolean = false) {
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
                IconButton(onClick = {}) {
                    Icon(
                        Lucide.EllipsisVertical,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.size(20.dp)
                    )
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
            modifier = Modifier.fillMaxSize()
                               .verticalScroll(rememberScrollState())
                               .padding(16.dp)
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