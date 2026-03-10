package com.innova.analyzer.ui.dashboard

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.data.local.TrafficDatabase
import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.Dispatchers
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

    // 🟢 Thread-safe memory buffer to catch the firehose
    private val rawPacketBuffer = ConcurrentLinkedDeque<NetworkEvent>()

    init {
        // 🟢 BOOT SEQUENCE: Load historical data from permanent storage instantly!
        viewModelScope.launch(Dispatchers.IO) {
            val dao = TrafficDatabase.getDatabase(getApplication()).trafficDao()
            val history = dao.getRecentLogs() // Grabs the last 1000 packets

            if (history.isNotEmpty()) {
                // Load history into our high-speed buffer
                rawPacketBuffer.addAll(history)
                // Immediately paint the UI so it doesn't look empty
                _trafficLogs.value = history
            }
        }

        // --- THREAD 1: The Firehose Catcher (The Producer) ---
        // This runs as fast as possible in the background. No UI updates happen here!
        viewModelScope.launch(Dispatchers.IO) {
            TrafficStream.trafficFlow.collect { realEvent ->
                rawPacketBuffer.addFirst(realEvent) // Add to the top of the list

                // 🟢 Keep memory clean: Expanded to hold the last 1000 packets!
                if (rawPacketBuffer.size > 1000) {
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
        // 🟢 Removed the auto-wipe logic here!
        // Now, pausing the VPN won't accidentally delete your beautiful report data.
    }

    // The End Session feature called from your ReportScreen
    fun clearSessionData() {
        viewModelScope.launch(Dispatchers.IO) {
            // 1. Wipe the Room Database to save user storage space
            val dao = TrafficDatabase.getDatabase(getApplication()).trafficDao()
            dao.clearAll()

            // 2. Clear the live UI memory buffers
            rawPacketBuffer.clear()
            _trafficLogs.value = emptyList()
        }
    }
}