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
import com.innova.analyzer.ui.report.ReportScreen

@Composable
fun MainNavGraph(navController: NavHostController, innerPadding: PaddingValues) {
    NavHost(
        navController = navController,
        startDestination = BottomNavItem.Dashboard.route,
        modifier = Modifier.padding(innerPadding) // Crucial: Respects the bottom bar height
    ) {
        composable(BottomNavItem.Dashboard.route) { DashboardScreen() }
        composable(BottomNavItem.Alerts.route) { AlertsScreen() }
        composable(BottomNavItem.Report.route) { ReportScreen() }
    }
}