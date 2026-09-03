package com.ct5.clientwarden

import android.content.res.Configuration
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.composables.icons.lucide.Eye
import com.composables.icons.lucide.EyeOff
import com.composables.icons.lucide.Lucide
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import com.composables.icons.lucide.GripVertical
import sh.calvin.reorderable.ReorderableItem
import sh.calvin.reorderable.rememberReorderableLazyListState

/*
 * Special Cases (editable):
 *  - Generic4
 *  - Website
 *  - Date
 */
enum class GenericItemType {
    Generic,
    Generic4,
    Password,
    TOTP,
    Website,
    ML_Generic,
    ML_Password,
    Date
}

data class TOTPResult(
    val refreshDate: Long,
    val maxTimer: Int,
    val value: String
)

data class GenericItemData(
    var title: String,
    var value: String,
    var value2: String,
    var value3: String,
    var value4: String,
    var type: GenericItemType,
    var cb_getTOTP: (() -> TOTPResult)?
) {
    constructor(title: String, value: String, type: GenericItemType) : this(
        title = title,
        value = value,
        type = type,
        value2 = "",
        value3 = "",
        value4 = "",
        cb_getTOTP = null
    )

    constructor(title: String, value: String, type: GenericItemType, cb_getTOTP: (() -> TOTPResult)?) : this(
        title = title,
        value = value,
        type = type,
        value2 = "",
        value3 = "",
        value4 = "",
        cb_getTOTP = cb_getTOTP
    )

    constructor(title: String, value: String, value2: String, value3: String, value4: String) : this(
        title = title,
        value = value,
        value2 = value2,
        value3 = value3,
        value4 = value4,
        type = GenericItemType.Generic4,
        cb_getTOTP = null
    )
}

/*
 * TODO: Add Editable + Add TOTP Support + Add Date Support
 */
class GenericItem(var data: GenericItemData, var editable: Boolean) {
    @Composable
    fun BasicTextView(data: String, cb_data: (String) -> Unit, modifier: Modifier = Modifier) {
        var m_data by remember(data) { mutableStateOf(data) }
        BasicTextField(
            value = m_data,
            onValueChange = {
                m_data = it
                cb_data(it)
            },
            modifier = modifier
                .height(34.dp)
                .background(
                    color = MaterialTheme.colorScheme.surfaceBright,
                    shape = RoundedCornerShape(8.dp)
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
    }

    @Composable
    fun view() {
        var p_visible by remember { mutableStateOf(false) }
        Column(modifier = Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .padding(12.dp)) {
            Text(data.title,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall)

            HorizontalDivider(modifier = Modifier.padding(0.dp, 4.dp, 0.dp, 8.dp))

            if (!editable) {
                if (data.type == GenericItemType.Generic4) {
                    Text(
                        "${data.value} ${data.value2} ${data.value3} ${data.value4}",
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                } else if (data.type == GenericItemType.Password || data.type == GenericItemType.ML_Password) {
                    /*
                     * btw: im using this dot bc it looks good
                     * You might notice its a bit bigger, but thats
                     * bc its a bigger dot
                     * U+25CF
                     */
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            if (p_visible) data.value else "●".repeat(data.value.length),
                            maxLines = if (data.type == GenericItemType.ML_Password) 30 else 1,
                            overflow = TextOverflow.Ellipsis
                        )

                        Spacer(modifier = Modifier.weight(1f).fillMaxWidth())

                        IconButton(
                            onClick = { p_visible = !p_visible },
                            colors = IconButtonDefaults.iconButtonColors(
                                containerColor = Color.Transparent
                            ),
                            modifier = Modifier.size(18.dp)
                        ) {
                            Icon(
                                if (p_visible) Lucide.Eye else Lucide.EyeOff,
                                contentDescription = "Show"
                            )
                        }
                    }
                } else {
                    /*
                     * Generic, ML_Generic, Website
                     */
                    Text(
                        data.value,
                        maxLines = if (data.type == GenericItemType.ML_Generic ||
                            data.type == GenericItemType.Website) 30 else 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            } else {
                if (data.type == GenericItemType.Generic4) {
                    Row {
                        BasicTextView(data.value, {
                            data.value = it
                        }, Modifier.weight(1f))

                        Spacer(modifier = Modifier.width(8.dp))

                        BasicTextView(data.value2, {
                            data.value2 = it
                        }, Modifier.weight(1f))

                        Spacer(modifier = Modifier.width(8.dp))

                        BasicTextView(data.value3, {
                            data.value3 = it
                        }, Modifier.weight(1f))

                        Spacer(modifier = Modifier.width(8.dp))

                        BasicTextView(data.value4, {
                            data.value4 = it
                        }, Modifier.weight(1f))
                    }
                } else if (data.type == GenericItemType.Website) {
                    var websites by remember { mutableStateOf(data.value.lines()) }

                    val l_state = rememberLazyListState()
                    val r_state = rememberReorderableLazyListState(l_state) { from, to ->
                        websites = websites.toMutableList().apply {
                            add(to.index, removeAt(from.index))
                        }
                        data.value = websites.joinToString("\n")
                    }

                    LazyColumn(state = l_state) {
                        items(
                            items = websites,
                            key = { it }
                        ) { line ->
                            ReorderableItem(r_state, key = line) { dragging ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clip(RoundedCornerShape(8.dp))
                                        .background(if (dragging) MaterialTheme.colorScheme.surfaceBright else Color.Transparent)
                                        .padding(8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    /*
                                     * Text Input
                                     */
                                    BasicTextView(line, { value ->
                                        val index = websites.indexOf(line)
                                        if (index != -1) {
                                            websites = websites.toMutableList().apply {
                                                this[index] = value
                                            }
                                            data.value = websites.joinToString("\n")
                                        }
                                    }, Modifier.weight(1f))

                                    Spacer(modifier = Modifier.width(8.dp))

                                    /*
                                     * The actual icon that allows it to move
                                     */
                                    Icon(
                                        imageVector = Lucide.GripVertical,
                                        contentDescription = "Drag to Reorder",
                                        modifier = Modifier.draggableHandle().size(16.dp)
                                    )
                                }
                            }
                        }
                    }
                } else {
                    /*
                     * Generic, ML_Generic, Password, ML_Password, TOTP
                     */
                    Text(
                        data.value,
                        maxLines = if (data.type == GenericItemType.ML_Generic ||
                            data.type == GenericItemType.ML_Password) 30 else 1,
                        overflow = TextOverflow.Ellipsis
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
fun PreviewGeneric() {
    MainScreen()
}