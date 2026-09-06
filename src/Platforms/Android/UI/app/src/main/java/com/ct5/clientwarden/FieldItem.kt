package com.ct5.clientwarden

import android.content.res.Configuration
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.composables.icons.lucide.Check
import com.composables.icons.lucide.Eye
import com.composables.icons.lucide.EyeOff
import com.composables.icons.lucide.Lucide
import com.ct5.clientwarden.GenericItemData

enum class FieldItemType {
    Text,
    Hidden,
    Checkbox,
    Linked
}

data class FieldItemData(
    var title: String,
    var value: String,
    var type: FieldItemType,
    var itemType: ItemType
) {
    constructor(title: String, value: String, type: FieldItemType) : this(
        title = title,
        value = value,
        type = type,
        itemType = ItemType.Note
    )
}

interface LinkedID {
    val id: Int
    val description: String
}

enum class LoginLinkedIDs(override val id: Int, override val description: String) : LinkedID {
    Username(100, "Username"),
    Password(101, "Password")
}

enum class CardLinkedIDs(override val id: Int, override val description: String) : LinkedID {
    CardholderName(300, "Cardholder Name"),
    ExpMonth(301, "Expiration Month"),
    ExpYear(302, "Expiration Year"),
    Code(303, "Code"),
    Brand(304, "Brand"),
    Number(305, "Number")
}

enum class IdentityLinkedIDs(override val id: Int, override val description: String) : LinkedID {
    Title(400, "Title"),
    MiddleName(401, "Middle Name"),
    Address1(402, "Address 1"),
    Address2(403, "Address 2"),
    Address3(404, "Address 3"),
    City(405, "City"),
    State(406, "State"),
    PostalCode(407, "Postal Code"),
    Country(408, "Country"),
    Company(409, "Company"),
    Email(410, "Email"),
    Phone(411, "Phone"),
    SSN(412, "Social Security Number"),
    Username(413, "Username"),
    PassportNumber(414, "Passport Number"),
    LicenseNumber(415, "License Number"),
    FirstName(416, "First Name"),
    LastName(417, "Last Name"),
    FullName(418, "Full Name")
}

class FieldItem(var data: FieldItemData, var editable: Boolean) {
    @Composable
    fun view() {
        var p_visible by remember { mutableStateOf(false) }
        Column(
            modifier = Modifier.fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .padding(4.dp)
        ) {
            if (data.type != FieldItemType.Checkbox) {
                if (editable) {
                    BasicTextView(
                        data.title,
                        { data.title = it },
                        modifier = Modifier.fillMaxWidth()
                    )
                } else {
                    Text(
                        data.title,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                HorizontalDivider(modifier = Modifier.padding(0.dp, 4.dp, 0.dp, 8.dp))
            }

            if (!editable) {
                if (data.type == FieldItemType.Hidden) {
                    /*
                     * From GenericItem
                     */
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            if (p_visible) data.value else "●".repeat(data.value.length),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
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
                } else if (data.type == FieldItemType.Checkbox) {
                    var m_value by remember { mutableStateOf(data.value) }

                    /*
                     * We are using a custom checkbox here bc I can make it rounded
                     * and the default material you one isnt rounded
                     */
                    Row(verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(0.dp)) {
                        Box(modifier = Modifier.size(24.dp)
                            .clip(RoundedCornerShape(6.dp))
                            .background(
                                if (m_value.toBoolean()) MaterialTheme.colorScheme.primary
                                else Color.Transparent
                            )
                            .border(
                                width = 2.dp,
                                color = if (m_value.toBoolean()) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.outline,
                                shape = RoundedCornerShape(6.dp)
                            ),
                            contentAlignment = Alignment.Center
                        ) {
                            if (m_value.toBoolean()) {
                                Icon(
                                    imageVector = Lucide.Check,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onPrimary,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(
                            data.title,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                } else if (data.type == FieldItemType.Linked) {
                    val options: List<LinkedID> = when (data.itemType) {
                        ItemType.Login -> LoginLinkedIDs.entries
                        ItemType.Card -> CardLinkedIDs.entries
                        ItemType.Identity -> IdentityLinkedIDs.entries
                        else -> emptyList()
                    }
                    Text(
                        options.firstOrNull { it.id == data.value.toIntOrNull() }?.description ?: "",
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                } else {
                    /*
                     * Text
                     */
                    Text(
                        data.value,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            } else {
                if (data.type == FieldItemType.Checkbox) {
                    var m_value by remember { mutableStateOf(data.value) }

                    /*
                     * We are using a custom checkbox here bc I can make it rounded
                     * and the default material you one isnt rounded
                     */
                    Row(verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(0.dp)) {
                        Box(modifier = Modifier.size(24.dp)
                            .clip(RoundedCornerShape(6.dp))
                            .background(
                                if (m_value.toBoolean()) MaterialTheme.colorScheme.primary
                                else Color.Transparent
                            )
                            .border(
                                width = 2.dp,
                                color = if (m_value.toBoolean()) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.outline,
                                shape = RoundedCornerShape(6.dp)
                            )
                            .toggleable(
                                value = m_value.toBoolean(),
                                onValueChange = { checked ->
                                    m_value = checked.toString()
                                    data.value = m_value
                                }
                            ),
                            contentAlignment = Alignment.Center
                        ) {
                            if (m_value.toBoolean()) {
                                Icon(
                                    imageVector = Lucide.Check,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onPrimary,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(
                            data.title,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                } else if (data.type == FieldItemType.Linked) {
                    var m_expanded by remember { mutableStateOf(false) }

                    val options: List<Pair<Int, String>> = when (data.itemType) {
                        ItemType.Login -> LoginLinkedIDs.entries.map {
                            it.id to it.description
                        }
                        ItemType.Card -> CardLinkedIDs.entries.map {
                            it.id to it.description
                        }
                        ItemType.Identity -> IdentityLinkedIDs.entries.map {
                            it.id to it.description
                        }
                        else -> emptyList()
                    }

                    val selectedLabel = options.firstOrNull {
                        it.first == data.value.toIntOrNull()
                    }?.second ?: ""

                    Box {
                        Row(
                            modifier = Modifier
                                .height(34.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                                .clickable(enabled = options.isNotEmpty()) { m_expanded = true }
                                .padding(horizontal = 14.dp, vertical = 6.dp)
                                .width(160.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                selectedLabel,
                                style = MaterialTheme.typography.bodyMedium.copy(
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                            )
                        }

                        DropdownMenu(expanded = m_expanded, onDismissRequest = { m_expanded = false }) {
                            options.forEach { (id, label) ->
                                DropdownMenuItem(
                                    text = { Text(label) },
                                    onClick = {
                                        data.value = id.toString()
                                        m_expanded = false
                                    }
                                )
                            }
                        }
                    }
                } else {
                    BasicTextView(data.value, { data.value = it },
                        modifier = Modifier.fillMaxWidth())
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
fun PreviewField() {
    MainScreen()
}