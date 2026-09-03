package com.ct5.clientwarden

import android.content.res.Configuration
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.composables.icons.lucide.Folder
import com.composables.icons.lucide.Globe
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Star
import java.util.UUID

object DetailsScreen {
    var s_folder: ClientwardenFolder = ClientwardenFolder(uuid = UUID(0L, 0L), name = "No Folder")

    @Composable
    fun folderButton(e_change: (Boolean) -> Unit, option: ClientwardenFolder) {
        TextButton(
            onClick = {
                s_folder = option
                e_change(false)
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

        Column(modifier = Modifier.fillMaxSize().padding(16.dp), horizontalAlignment = Alignment.Start) {
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
                        /*
                         * Item Icon
                         *
                         * TODO: This should be changed to a separate type
                         *  which can handle Icon's, Images, etc.
                         */
                        Box(
                            modifier = Modifier
                                .size(38.dp)
                                .background(
                                    color = MaterialTheme.colorScheme.primary,
                                    shape = CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Lucide.Globe,
                                contentDescription = "Item Icon",
                                tint = MaterialTheme.colorScheme.onPrimary
                            )
                        }

                        /*
                         * Item Name/Type
                         */
                        Column(modifier = Modifier.padding(start = 12.dp)) {
                            Text("Item 1", fontSize = 20.sp, lineHeight = 20.sp)
                            Text("Login", fontSize = 12.sp, lineHeight = 12.sp)
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
                            onClick = { },
                            modifier = Modifier.size(42.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.Transparent
                            ),
                            contentPadding = PaddingValues(0.dp),
                            elevation = null
                        ) {
                            Icon(
                                Lucide.Star,
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
                                    Text(
                                        if (s_folder.uuid == UUID(0L, 0L)) "No Folder" else s_folder.name
                                    )
                                }
                            }
                        }
                    }

                    /*
                     * Animated Folder View thing
                     */
                    AnimatedVisibility(
                        visible = f_expanded,
                        enter = expandVertically() + fadeIn(),
                        exit = shrinkVertically() + fadeOut()
                    ) {
                        Column {
                            HorizontalDivider(
                                modifier = Modifier.padding(
                                    horizontal = 12.dp,
                                    vertical = 0.dp
                                )
                            )

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

            GenericItem(GenericItemData(title = "Email", value = "a@a.comfbweysfg", type = GenericItemType.Generic), false).view()
            GenericItem(GenericItemData(title = "Email", value = "a@a.comfbweysfg", "4", "5", "6"), true).view()
            GenericItem(GenericItemData(title = "Email", value = "a@a.comfbweysfg", type = GenericItemType.Password), false).view()
            GenericItem(GenericItemData(title = "Email", value = "goog.com\na.com", type = GenericItemType.Website), true).view()
            GenericItem(GenericItemData(title = "Email", value = "a@a.comfbweysfg", type = GenericItemType.Generic), false).view()
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