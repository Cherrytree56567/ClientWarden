package com.ct5.clientwarden

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.ct5.clientwarden.LoginScreen.s_type

enum class HomeScreenPanel {
    NavPanel,
    ItemsPanel,
    DetailsScreen,
    NavPanelLoading
}

object HomeScreen {
    var c_panel = mutableStateOf(HomeScreenPanel.NavPanelLoading)

    @Composable
    fun view(modifier: Modifier = Modifier) {
        Column(modifier = modifier.fillMaxSize()) {
            /*
             * Top Bar
             * Shows the Search Bar/Add Button or
             * Details Panel Buttons
             */
            TopBar.view()

            /*
             * Displays current screen
             */
            Box(
                modifier = modifier.fillMaxSize()
                    .padding(top = 16.dp),
                contentAlignment = Alignment.Center
            ) {
                when (c_panel.value) {
                    HomeScreenPanel.NavPanel -> NavScreen.view()
                    HomeScreenPanel.ItemsPanel -> ItemsScreen.view()
                    HomeScreenPanel.DetailsScreen -> DetailsScreen.view()
                    HomeScreenPanel.NavPanelLoading -> NavScreenLoading.view()
                    else -> Spacer(modifier = modifier)
                }
            }
        }
    }
}