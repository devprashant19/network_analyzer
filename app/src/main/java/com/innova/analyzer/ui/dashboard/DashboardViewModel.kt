package com.innova.analyzer.ui.dashboard

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentLinkedDeque

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    // 1. The Live Feed (In-Memory) UI State
    private val _trafficLogs = MutableStateFlow<List<NetworkEvent>>(emptyList())
    val trafficLogs: StateFlow<List<NetworkEvent>> = _trafficLogs.asStateFlow()

    // 2. The VPN Status UI State
    private val _isVpnActive = MutableStateFlow(false)
    val isVpnActive: StateFlow<Boolean> = _isVpnActive.asStateFlow()

    // 🟢 NEW: Thread-safe memory buffer to catch the firehose without slowing down the VPN
    private val rawPacketBuffer = ConcurrentLinkedDeque<NetworkEvent>()

    init {
        // --- THREAD 1: The Firehose Catcher (The Producer) ---
        // This runs as fast as possible in the background. No UI updates happen here!
        viewModelScope.launch {
            TrafficStream.trafficFlow.collect { realEvent ->
                rawPacketBuffer.addFirst(realEvent) // Add to the top of the list

                // Keep memory clean: Only hold the last 150 packets
                if (rawPacketBuffer.size > 150) {
                    rawPacketBuffer.removeLast()
                }
            }
        }

        // --- THREAD 2: The UI Throttle (The Consumer) ---
        // This wakes up twice a second, grabs a snapshot of the buffer, and paints the screen.
        viewModelScope.launch {
            while (true) {
                if (rawPacketBuffer.isNotEmpty()) {
                    // Push the safe snapshot to Jetpack Compose!
                    _trafficLogs.value = rawPacketBuffer.toList()
                }
                delay(500L) // 500ms throttle = perfectly smooth UI that never crashes
            }
        }
    }

    fun setVpnActive(active: Boolean) {
        _isVpnActive.value = active

        // Clear the dashboard every time you start a fresh Audit
        if (active) {
            rawPacketBuffer.clear()
            _trafficLogs.value = emptyList()
        }
    }
}