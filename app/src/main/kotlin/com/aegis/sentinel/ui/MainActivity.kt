package com.aegis.sentinel.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel

/**
 * Single activity host.
 *
 * Android 16 notes handled here:
 *  - edge-to-edge is mandatory for targetSdk 36, so we opt in explicitly and the composables
 *    consume window insets rather than assuming fixed system bar heights.
 *  - predictive back is enabled in the manifest; we use no custom onBackPressed override.
 *  - no orientation lock is declared, so the adaptive-layout changes on large screens are a
 *    non-issue and the UI simply reflows.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent { AegisApp() }
    }
}

@Composable
private fun AegisApp() {
    MaterialTheme {
        Surface(
            modifier = Modifier,
            color = MaterialTheme.colorScheme.background,
        ) {
            val vm: DashboardViewModel = viewModel()
            DashboardScreen(viewModel = vm, modifier = Modifier)
        }
    }
}
