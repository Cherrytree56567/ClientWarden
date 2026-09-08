package com.ct5.clientwarden

import android.annotation.SuppressLint
import android.content.res.Configuration
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.navigation.compose.rememberNavController
import com.ct5.clientwarden.ui.theme.ClientwardenTheme

enum class MainViews {
    LoginUI,
    UnlockUI,
    VaultUI
}

class MainActivity : ComponentActivity() {
    var c_view = mutableStateOf(MainViews.VaultUI)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ClientwardenTheme {
                if (c_view.value == MainViews.VaultUI) {
                    VaultUI()
                } else if (c_view.value == MainViews.LoginUI) {
                    LoginScreen.view()
                } else if (c_view.value == MainViews.UnlockUI) {
                    UnlockScreen.view()
                }
            }
        }
    }
}

@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
@Composable
fun VaultUI() {
    val navController = rememberNavController()

    Scaffold(
        bottomBar = {
            NavBar(navController = navController)
        }
    ) { innerPadding ->
        Column(modifier = Modifier.fillMaxSize()
            .padding(innerPadding)
        ) {
            AppNavHost(
                navController = navController,
                startDestination = NavTabs.SETTINGS,
                modifier = Modifier.weight(1f)
            )
        }

        /*
         * This allows the Add pill in the top panel
         * to close if we click somewhere else on the screen
         */
        if (TopBar.m_expanded) {
            Box(modifier = Modifier.fillMaxSize()
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null
                ) {
                    TopBar.m_expanded = false
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
fun Preview() {
    ClientwardenTheme {
        VaultUI()
    }
}