package com.innova.analyzer.ui.navigation

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import com.innova.analyzer.ui.alerts.AlertsScreen
import com.innova.analyzer.ui.dashboard.DashboardScreen
import com.innova.analyzer.ui.dashboard.DashboardViewModel // 🟢 ADDED IMPORT
import com.innova.analyzer.ui.report.ReportScreen

@Composable
fun MainNavGraph(
    navController: NavHostController,
    innerPadding: PaddingValues,
    isDarkTheme: Boolean,
    onThemeToggle: () -> Unit,
    sharedViewModel: DashboardViewModel // 🟢 1. INJECT THE SHARED BRAIN HERE
) {
    NavHost(
        navController = navController,
        startDestination = BottomNavItem.Dashboard.route,
        modifier = Modifier.padding(innerPadding) // Crucial: Respects the bottom bar height
    ) {
        composable(BottomNavItem.Dashboard.route) {
            DashboardScreen(
                viewModel = sharedViewModel, // 🟢 2. FEED IT TO THE DASHBOARD
                isDarkTheme = isDarkTheme,
                onThemeToggle = onThemeToggle
            )
        }
        composable(BottomNavItem.Alerts.route) {
            // 🟢 FIX: Passed the sharedViewModel so AlertsScreen can filter the threats!
            AlertsScreen(viewModel = sharedViewModel)
        }
        composable(BottomNavItem.Report.route) {
            ReportScreen(viewModel = sharedViewModel) // 🟢 3. FEED IT TO THE REPORT SCREEN
        }
    }
}