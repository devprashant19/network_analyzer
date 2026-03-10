package com.innova.analyzer.ui.dashboard

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    // 1. The Live Feed (In-Memory)
    private val _trafficLogs = MutableStateFlow<List<NetworkEvent>>(emptyList())
    val trafficLogs: StateFlow<List<NetworkEvent>> = _trafficLogs.asStateFlow()

    // 2. The VPN Status
    private val _isVpnActive = MutableStateFlow(false)
    val isVpnActive: StateFlow<Boolean> = _isVpnActive.asStateFlow()

    init {
        // 🚨 THE SWAP: Connect directly to the live SharedFlow instead of the Database!
        viewModelScope.launch {
            TrafficStream.trafficFlow.collect { realEvent ->
                // Grab the current list and add the new packet to the TOP (index 0)
                val currentList = _trafficLogs.value.toMutableList()
                currentList.add(0, realEvent)

                // PERFORMANCE FIX: Cap the list at 150 items.
                // If a background app spams 10,000 packets, this prevents the Jetpack Compose UI from crashing!
                if (currentList.size > 150) {
                    currentList.removeLast()
                }

                // Push the updated list to the UI
                _trafficLogs.value = currentList
            }
        }
    }

    fun setVpnActive(active: Boolean) {
        _isVpnActive.value = active

        // Optional Polish: Clear the dashboard every time you start a fresh Audit
        if (active) {
            _trafficLogs.value = emptyList()
        }
    }
}