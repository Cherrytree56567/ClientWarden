package com.ct5.clientwarden

import android.content.res.Configuration
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableDoubleStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.composables.icons.lucide.Eye
import com.composables.icons.lucide.EyeOff
import com.composables.icons.lucide.Folder
import com.composables.icons.lucide.Globe
import com.composables.icons.lucide.GripVertical
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Star
import com.composables.icons.lucide.StarOff
import com.ct5.clientwarden.AttachmentItem
import com.ct5.clientwarden.FieldItem
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import sh.calvin.reorderable.ReorderableItem
import sh.calvin.reorderable.rememberReorderableLazyListState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import kotlin.time.Duration.Companion.milliseconds

object DetailsScreen {
    var cb_removeAttachment: ((String) -> Boolean)? = null
    var cb_downloadAttachment: ((String) -> Boolean)? = null
    var cb_favorite: ((Boolean) -> Boolean)? = null
    var cb_folder: ((UUID) -> Boolean)? = null

    var name by mutableStateOf("")

    var uuid by mutableStateOf(UUID(0L, 0L))
    var folderUUID by mutableStateOf(UUID(0L, 0L))
    var type by mutableStateOf(ItemType.Login)
    var icon by mutableStateOf<ClientwardenImage>(ClientwardenImage.ImageIcon(Lucide.Globe))
    var editable by mutableStateOf(false)
    var favorite by mutableStateOf(false)

    var itemHistory = mutableStateListOf<String>()
    var passwordHistory = mutableStateListOf<PasswordHistoryItem>(
        PasswordHistoryItem("dat", "pw@@"),
        PasswordHistoryItem("d3at", "pw@@"),
        PasswordHistoryItem("d4at", "pw@@"),
        PasswordHistoryItem("da5t", "pw@@"),
        PasswordHistoryItem("da6t", "pw@@"),
        PasswordHistoryItem("daft", "pw@@"),
        PasswordHistoryItem("daydt", "pw@@"),
        PasswordHistoryItem("dat", "pw@@"),
        PasswordHistoryItem("dat", "pw@@")
    )
    var notes: String = ""

    var genericItems = mutableStateListOf<GenericItemData>()
    var fieldItems = mutableStateListOf<FieldItemData>()
    var attachmentItems = mutableStateListOf<AttachmentItemData>()

    var s_name: String = ""
    var s_favorite: Boolean = false
    var s_folderUUID: UUID = UUID(0L, 0L)
    var s_notes: String = ""
    var s_genericItems = mutableStateListOf<GenericItemData>()
    var s_fieldItems = mutableStateListOf<FieldItemData>()
    var s_attachmentItems = mutableStateListOf<AttachmentItemData>()

    fun takeSnapshot() {
        DetailsScreen.s_name = DetailsScreen.name
        DetailsScreen.s_favorite = DetailsScreen.favorite
        DetailsScreen.s_folderUUID = DetailsScreen.folderUUID
        DetailsScreen.s_notes = DetailsScreen.notes
        DetailsScreen.s_genericItems = DetailsScreen.genericItems
        DetailsScreen.s_fieldItems = DetailsScreen.fieldItems
        DetailsScreen.s_attachmentItems = DetailsScreen.attachmentItems
    }

    fun releaseSnapshot() {
        DetailsScreen.name = DetailsScreen.s_name
        DetailsScreen.favorite = DetailsScreen.s_favorite
        DetailsScreen.folderUUID = DetailsScreen.s_folderUUID
        DetailsScreen.notes = DetailsScreen.s_notes
        DetailsScreen.genericItems = DetailsScreen.s_genericItems
        DetailsScreen.fieldItems = DetailsScreen.s_fieldItems
        DetailsScreen.attachmentItems = DetailsScreen.s_attachmentItems
    }

    @Composable
    fun folderButton(e_change: (Boolean) -> Unit, option: ClientwardenFolder) {
        TextButton(
            onClick = {
                if (cb_folder?.invoke(option.uuid) == true) {
                    folderUUID = option.uuid
                    e_change(false)
                }
            },
            modifier = Modifier.fillMaxWidth(),
            shape = RectangleShape
        ) {
            Row(
                modifier = Modifier.fillMaxWidth()
                    .padding(start = 6.dp),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Lucide.Folder,
                    contentDescription = null,
                    modifier = Modifier.size(ButtonDefaults.IconSize)
                )
                Spacer(modifier = Modifier.size(ButtonDefaults.IconSpacing))
                Text(
                    option.name
                )
            }
        }
    }
    
    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun view() {
        var f_expanded by remember { mutableStateOf(false) }
        var pw_expanded by remember { mutableStateOf(false) }

        Column(modifier = Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp, 0.dp, 16.dp, 16.dp), horizontalAlignment = Alignment.Start) {
            /*
             * First Row - Item Detail
             * This contains the Item's Icon, Name/Type, Favorite
             */
            Row(modifier = Modifier.fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .background(MaterialTheme.colorScheme.surfaceContainerHigh),
                verticalAlignment = Alignment.CenterVertically) {
                Column {
                    /*
                     * Details Row
                     */
                    Row(modifier = Modifier.padding(top = 16.dp, start = 16.dp, end = 16.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(38.dp)
                                .background(
                                    color = MaterialTheme.colorScheme.primary,
                                    shape = CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            icon.view(contentDesc = "Item Icon")
                        }

                        /*
                         * Item Name/Type
                         */
                        Column(modifier = Modifier.padding(start = 12.dp)) {
                            AnimatedContent(
                                targetState = editable,
                                transitionSpec = {
                                    fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                                },
                                label = "nameEditable"
                            ) { i_editable ->
                                if (i_editable) {
                                    BasicTextView(name, { name = it },
                                        modifier = Modifier.size(200.dp, 32.dp).padding(bottom = 4.dp),
                                        textStyle = MaterialTheme.typography.bodySmall)
                                } else {
                                    Text(name, fontSize = 20.sp, lineHeight = 20.sp)
                                }
                            }
                            Text(type.desc, fontSize = 12.sp, lineHeight = 12.sp)
                        }

                        Spacer(modifier = Modifier.weight(1f).fillMaxWidth())

                        /*
                         * Favorite Button
                         *
                         * Here, we are using Button instead of Icon Button,
                         * because I want to use a more transparent ripple
                         * effect.
                         */
                        Button(
                            onClick = {
                                if (cb_favorite?.invoke(!favorite) == true) {
                                    favorite = !favorite
                                }
                            },
                            modifier = Modifier.size(42.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.Transparent
                            ),
                            contentPadding = PaddingValues(0.dp),
                            elevation = null
                        ) {
                            Icon(
                                if (favorite) Lucide.Star else Lucide.StarOff,
                                contentDescription = "Favorite",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(22.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp))

                    /*
                     * Folder Row
                     */
                    Row(modifier = Modifier.fillMaxWidth()) {
                        ExposedDropdownMenuBox(
                            expanded = f_expanded,
                            onExpandedChange = { f_expanded = it },
                            modifier = Modifier.fillMaxWidth().height(48.dp)
                        ) {
                            TextButton(onClick = { },
                                modifier = Modifier.fillMaxWidth()
                                    .weight(1f)
                                    .fillMaxHeight()
                                    .menuAnchor(MenuAnchorType.PrimaryNotEditable, true),
                                shape = RectangleShape) {
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(start = 6.dp),
                                    horizontalArrangement = Arrangement.Start,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Lucide.Folder,
                                        contentDescription = null,
                                        modifier = Modifier.size(ButtonDefaults.IconSize)
                                    )
                                    Spacer(modifier = Modifier.size(ButtonDefaults.IconSpacing))

                                    val l_folder = NavScreen.folders.firstOrNull { it.uuid == folderUUID }
                                        ?: ClientwardenFolder(uuid = UUID(0L, 0L), name = "No Folder")

                                    Text(
                                        l_folder.name
                                    )
                                }
                            }
                        }
                    }

                    if (f_expanded) {
                        /*
                         * I've decided to move the divider outside
                         * bc otherwise it gets lost when the user
                         * scrolls down
                         */
                        HorizontalDivider(
                            modifier = Modifier.padding(
                                horizontal = 12.dp,
                                vertical = 0.dp
                            )
                        )
                    }

                    /*
                     * Animated Folder View thing
                     */
                    AnimatedVisibility(
                        visible = f_expanded,
                        enter = expandVertically() + fadeIn(),
                        exit = shrinkVertically() + fadeOut()
                    ) {
                        Column(modifier = Modifier.heightIn(max = 200.dp)
                            .verticalScroll(rememberScrollState())) {
                            folderButton(e_change = { f_expanded = it }, ClientwardenFolder(uuid = UUID(0L, 0L), name = "No Folder"))

                            NavScreen.folders.forEach { option ->
                                folderButton(e_change = { f_expanded = it }, option)
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.padding(vertical = 8.dp))

            HorizontalDivider()

            Spacer(modifier = Modifier.padding(vertical = 8.dp))

            for (genericItem in genericItems) {
                AnimatedContent(
                    targetState = editable,
                    transitionSpec = {
                        fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                    },
                    label = "genericItemEditable"
                ) { i_editable ->
                    GenericItem(genericItem, i_editable).view()
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            AnimatedContent(
                targetState = editable,
                transitionSpec = {
                    fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                },
                label = "genericItemNotesEditable"
            ) { i_editable ->
                GenericItem(GenericItemData("Notes", notes,
                    GenericItemType.ML_Generic), i_editable).view()
            }

            Spacer(modifier = Modifier.padding(vertical = 8.dp))

            HorizontalDivider()

            Spacer(modifier = Modifier.padding(vertical = 8.dp))

            for (fieldItem in fieldItems) {
                AnimatedContent(
                    targetState = editable,
                    transitionSpec = {
                        fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                    },
                    label = "genericItemEditable"
                ) { i_editable ->
                    FieldItem(fieldItem, i_editable).view()
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            if (fieldItems.isNotEmpty()) {
                HorizontalDivider()

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            for (attachmentItems in attachmentItems) {
                AnimatedContent(
                    targetState = editable,
                    transitionSpec = {
                        fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                    },
                    label = "genericItemEditable"
                ) { i_editable ->
                    AttachmentItem(attachmentItems, i_editable).view()
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            if (attachmentItems.isNotEmpty()) {
                HorizontalDivider()

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            for (item in itemHistory) {
                Text(item, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Text("View Password History", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.clickable {
                    pw_expanded = true
                }
            )
        }

        if (pw_expanded) {
            AlertDialog(
                onDismissRequest = { pw_expanded = false }, title = { Text("Password History") },
                text = {
                    Column(
                        modifier = Modifier
                            .heightIn(max = 400.dp)
                            .verticalScroll(rememberScrollState())
                    ) {
                        for (pwHist in passwordHistory) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(MaterialTheme.colorScheme.surfaceContainerHighest)
                                    .padding(12.dp)
                            ) {
                                /*
                                 * Date Text
                                 */
                                Text(
                                    pwHist.date,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    style = MaterialTheme.typography.bodySmall
                                )

                                HorizontalDivider(
                                    modifier = Modifier.padding(
                                        0.dp,
                                        4.dp,
                                        0.dp,
                                        8.dp
                                    )
                                )

                                /*
                                 * Password
                                 */
                                Text(
                                    pwHist.password,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
                                )
                            }

                            Spacer(modifier = Modifier.padding(vertical = 8.dp))
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { pw_expanded = false }) {
                        Text("Done")
                    }
                }
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
fun PreviewDetails() {
    MainScreen()
}