package com.ct5.clientwarden

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier

enum class HomeScreenPanel {
    NavPanel,
    ItemsPanel,
    DetailsScreen
}

object HomeScreen {
    var c_panel: HomeScreenPanel = HomeScreenPanel.DetailsScreen
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
                modifier = modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                when (c_panel) {
                    HomeScreenPanel.NavPanel -> NavScreen.view()
                    HomeScreenPanel.ItemsPanel -> ItemsScreen.view()
                    HomeScreenPanel.DetailsScreen -> DetailsScreen.view()
                    else -> Spacer(modifier = modifier)
                }
            }
        }
    }
}