package com.ct5.clientwarden

import android.content.res.Configuration
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.composables.icons.lucide.Download
import com.composables.icons.lucide.File
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Trash

data class AttachmentItemData(
    var id: String,
    var name: String,
    var progress: Double
) {
    constructor(id: String, name: String) : this(
        id = id,
        name = name,
        progress = 0.0
    )
}

class AttachmentItem(var data: AttachmentItemData, var editable: Boolean) {
    @Composable
    fun view() {
        Column(
            modifier = Modifier.fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .padding(4.dp)
        ) {
            Text(
                "Attachment",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall
            )

            HorizontalDivider(modifier = Modifier.padding(0.dp, 4.dp, 0.dp, 8.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Lucide.File, contentDescription = "Attachment",
                    modifier = Modifier.size(18.dp))

                Spacer(modifier = Modifier.width(8.dp))

                if (!editable) {
                    /*
                     * Attachment File Name
                     */
                    Text(
                        data.name,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall
                    )

                    Spacer(modifier = Modifier.weight(1f).fillMaxWidth())

                    /*
                     * Attachment Button (Download)
                     */
                    IconButton(onClick = {
                        DetailsScreen.cb_downloadAttachment?.invoke(data.id)
                    }, modifier = Modifier.size(22.dp)) {
                        Icon(Lucide.Download, contentDescription = "Download",
                            modifier = Modifier.size(18.dp))
                    }
                } else {
                    /*
                     * Editable Attachment File Name
                     */
                    BasicTextView(
                        data.name,
                        cb_data = { data.name = it },
                        modifier = Modifier.weight(1f).fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.width(8.dp))

                    /*
                     * Attachment Button (Delete)
                     */
                    IconButton(onClick = {
                        DetailsScreen.cb_removeAttachment?.invoke(data.id)
                    }, modifier = Modifier.size(22.dp)) {
                        Icon(Lucide.Trash, contentDescription = "Delete",
                            modifier = Modifier.size(18.dp))
                    }
                }
            }

            /*
             * Progress Bar
             */
            AnimatedVisibility(
                visible = data.progress > 0.0 && data.progress < 1.0,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                Column {
                    Spacer(modifier = Modifier.height(6.dp))
                    LinearProgressIndicator(
                        progress = { data.progress.toFloat() },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(4.dp)
                            .clip(RoundedCornerShape(2.dp)),
                        trackColor = MaterialTheme.colorScheme.surfaceContainerHigh
                    )
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
fun PreviewAttachment() {
    MainScreen()
}