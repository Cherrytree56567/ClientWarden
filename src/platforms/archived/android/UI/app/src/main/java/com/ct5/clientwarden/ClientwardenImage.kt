package com.ct5.clientwarden

import androidx.compose.foundation.Image
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import coil.compose.AsyncImage

sealed class ClientwardenImage {
    data class ImageIcon(val vector: ImageVector) : ClientwardenImage()
    data class Bundle(val resId: Int) : ClientwardenImage()
    data class Uri(val path: String) : ClientwardenImage()

    @Composable
    fun view(
        modifier: Modifier = Modifier,
        tint: Color = MaterialTheme.colorScheme.onPrimary,
        contentDesc: String = "Item"
    ) {
        when (this) {
            is ImageIcon -> Icon(
                imageVector = vector,
                contentDescription = contentDesc,
                tint = tint,
                modifier = modifier
            )

            is Bundle -> Image(
                painter = painterResource(id = resId),
                contentDescription = contentDesc,
                modifier = modifier,
                contentScale = ContentScale.Crop
            )

            is Uri -> AsyncImage(
                model = path,
                contentDescription = contentDesc,
                modifier = modifier,
                contentScale = ContentScale.Crop
            )
        }
    }
}