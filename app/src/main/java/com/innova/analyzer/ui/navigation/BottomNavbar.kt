package com.innova.analyzer.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar 
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import androidx.navigation.compose.currentBackStackEntryAsState

// 1. Define the Routes
sealed class BottomNavItem(val route: String, val title: String, val icon: ImageVector) {
    object Dashboard : BottomNavItem("dashboard", "Dashboard", Icons.Default.Shield)
    object Alerts : BottomNavItem("alerts", "Alerts", Icons.Default.Warning)
    object Report : BottomNavItem("report", "Report", Icons.Default.List)
}

// 2. The UI Component
@Composable
fun BottomNavBar(navController: NavHostController, isDarkTheme: Boolean) {
    val items = listOf(
        BottomNavItem.Dashboard,
        BottomNavItem.Alerts,
        BottomNavItem.Report
    )

    // Select the best contrasting highlight color based on the theme
    val highlightColor = if (isDarkTheme) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondary
    val unselectedColor = MaterialTheme.colorScheme.onSurfaceVariant
    val backgroundColor = MaterialTheme.colorScheme.surface

    NavigationBar(
        containerColor = backgroundColor,
        contentColor = unselectedColor,
        tonalElevation = 8.dp
    ) {
        val navBackStackEntry by navController.currentBackStackEntryAsState()
        val currentRoute = navBackStackEntry?.destination?.route

        items.forEach { item ->
            val selected = currentRoute == item.route
            NavigationBarItem(
                icon = {
                    Icon(
                        imageVector = item.icon,
                        contentDescription = item.title,
                        tint = if (selected) highlightColor else unselectedColor
                    )
                },
                label = {
                    Text(
                        text = item.title,
                        color = if (selected) highlightColor else unselectedColor,
                        fontWeight = if (selected) androidx.compose.ui.text.font.FontWeight.Bold else androidx.compose.ui.text.font.FontWeight.Normal
                    )
                },
                selected = selected,
                colors = androidx.compose.material3.NavigationBarItemDefaults.colors(
                    indicatorColor = highlightColor.copy(alpha = 0.15f)
                ),
                onClick = {
                    navController.navigate(item.route) {
                        navController.graph.startDestinationRoute?.let { route ->
                            popUpTo(route) { saveState = true }
                        }
                        launchSingleTop = true
                        restoreState = true
                    }
                }
            )
        }
    }
}
