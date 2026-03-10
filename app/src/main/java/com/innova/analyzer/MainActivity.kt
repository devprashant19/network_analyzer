package com.innova.analyzer

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Scaffold
import androidx.compose.ui.Modifier
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.rememberNavController
import com.innova.analyzer.core.vpn.TrafficCaptureService
import com.innova.analyzer.data.local.TrafficDatabase
import com.innova.analyzer.ui.dashboard.DashboardViewModel
import com.innova.analyzer.ui.navigation.BottomNavBar
import com.innova.analyzer.ui.navigation.MainNavGraph
import com.innova.analyzer.ui.theme.InnovaTheme

class MainActivity : ComponentActivity() {

    // 1. The Modern Activity Result Launcher (VPN Permission)
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            Log.d("MainActivity", "VPN Permission GRANTED by user.")
            startTrafficCaptureService()
        } else {
            Log.e("MainActivity", "VPN Permission DENIED by user.")
            Toast.makeText(this, "VPN permission is required.", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // 2. Initialize the Database
        val db = TrafficDatabase.getDatabase(this)
        val dao = db.trafficDao()

        // 3. The Modern Compose Navigation UI
        setContent {
            var isDarkTheme by remember { mutableStateOf(true) }

            // 🟢 CRITICAL ARCHITECTURE FIX:
            // We create the ViewModel HERE at the Activity level so it survives tab switches!
            val sharedViewModel: DashboardViewModel = viewModel()

            InnovaTheme(darkTheme = isDarkTheme) {
                val navController = rememberNavController()

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    bottomBar = { BottomNavBar(navController, isDarkTheme = isDarkTheme) }
                ) { innerPadding ->

                    // Pass the shared ViewModel into the NavGraph
                    MainNavGraph(
                        navController = navController,
                        innerPadding = innerPadding,
                        isDarkTheme = isDarkTheme,
                        onThemeToggle = { isDarkTheme = !isDarkTheme },
                        sharedViewModel = sharedViewModel // 🟢 Injecting the brain!
                    )
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // KEEPING THESE FOR LATER: Triggered from the Dashboard
    // ------------------------------------------------------------------

    fun requestVpnPermission() {
        Log.d("MainActivity", "Checking VPN permissions...")
        val vpnIntent = VpnService.prepare(this)

        if (vpnIntent != null) {
            Log.d("MainActivity", "Launching OS VPN Permission Dialog...")
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            Log.d("MainActivity", "VPN Permission already granted.")
            startTrafficCaptureService()
        }
    }

    private fun startTrafficCaptureService() {
        Log.d("MainActivity", "Starting TrafficCaptureService...")
        val intent = Intent(this, TrafficCaptureService::class.java)
        startService(intent)
        Toast.makeText(this, "Traffic Interception Started!", Toast.LENGTH_SHORT).show()
    }
}