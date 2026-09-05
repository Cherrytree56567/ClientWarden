package com.ct5.clientwarden

import androidx.compose.ui.graphics.vector.ImageVector
import java.util.UUID

enum class ItemType(val desc: String) {
    Login("Login"),
    Card("Card"),
    Identity("Identity"),
    Note("Note"),
    SSHKey("SSH Key")
}

data class ClientwardenFolder(val uuid: UUID, var name: String)
data class ItemElement(val uuid: UUID, var name: String, var type: ItemType, var icon: ImageVector)
data class PasswordHistoryItem(val date: String, var password: String)