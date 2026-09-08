package com.ct5.clientwarden

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import java.util.UUID
import kotlin.time.Duration.Companion.milliseconds

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

/*
 * We are using our own BasicTextView here because
 * the mat you one is really annoying bc of the internal padding
 * so I decided to make my own which can easily be reused
 */
@Composable
fun BasicTextView(data: String, cb_data: (String) -> Unit, modifier: Modifier = Modifier, multiLine: Boolean = false,
                  textStyle: TextStyle = MaterialTheme.typography.bodyMedium) {
    var m_data by remember(data) { mutableStateOf(data) }
    BasicTextField(
        value = m_data,
        onValueChange = {
            m_data = it
            cb_data(it)
        },
        modifier = modifier
            .then(
                if (multiLine) Modifier.heightIn(min = 34.dp)
                else Modifier.height(34.dp)
            )
            .background(
                color = MaterialTheme.colorScheme.surfaceBright,
                shape = RoundedCornerShape(8.dp)
            )
            .padding(horizontal = 14.dp, vertical = 6.dp),
        singleLine = !multiLine,
        textStyle = textStyle.copy(
            color = MaterialTheme.colorScheme.onSurface
        ),
        cursorBrush = SolidColor(
            MaterialTheme.colorScheme.primary
        )
    )
}

@Composable
fun ClientwardenEasterText() {
    var t_clicked by remember { mutableStateOf(false) }

    val textColor by animateColorAsState(
        targetValue = if (t_clicked) MaterialTheme.colorScheme.primary
        else MaterialTheme.colorScheme.inverseSurface,
        animationSpec = tween(durationMillis = 800),
        label = "textColor"
    )

    LaunchedEffect(t_clicked) {
        if (t_clicked) {
            delay(5000.milliseconds)
            t_clicked = false
        }
    }

    Text("Clientwarden", style = MaterialTheme.typography.headlineLarge,
        fontWeight = FontWeight.Bold,
        color = textColor,
        modifier = Modifier.clickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null
        ) { t_clicked = true }
    )
}