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

    // 1. The Live Feed (In-Memory) UI State (Capped at 1,000 to prevent lag)
    private val _trafficLogs = MutableStateFlow<List<NetworkEvent>>(emptyList())
    val trafficLogs: StateFlow<List<NetworkEvent>> = _trafficLogs.asStateFlow()

    // 2. The Lifetime Counter (Counts forever, regardless of UI limits)
    private val _totalPacketCount = MutableStateFlow(0)
    val totalPacketCount: StateFlow<Int> = _totalPacketCount.asStateFlow()

    // 3. The VPN Status UI State
    private val _isVpnActive = MutableStateFlow(false)
    val isVpnActive: StateFlow<Boolean> = _isVpnActive.asStateFlow()

    // Thread-safe memory buffer to catch the firehose
    private val rawPacketBuffer = ConcurrentLinkedDeque<NetworkEvent>()

    init {
        // 🟢 BOOT SEQUENCE: Load historical data from permanent storage instantly!
        viewModelScope.launch(Dispatchers.IO) {
            val dao = TrafficDatabase.getDatabase(getApplication()).trafficDao()
            val history = dao.getRecentLogs()

            if (history.isNotEmpty()) {
                // Load history into our high-speed buffer
                rawPacketBuffer.addAll(history)
                // Instantly paint the screen
                _trafficLogs.value = history

                // 🟢 FIX: Fetch the TRUE lifetime count from the database, not just the 1000 limit!
                _totalPacketCount.value = dao.getTotalCount()
            }
        }

        // --- THREAD 1: The Firehose Catcher (The Producer) ---
        // This runs as fast as possible in the background. No UI updates happen here!
        viewModelScope.launch(Dispatchers.IO) {
            TrafficStream.trafficFlow.collect { realEvent ->
                // Increment the massive counter
                _totalPacketCount.value += 1

                // Add the new packet to the top of the UI list
                rawPacketBuffer.addFirst(realEvent)

                // Keep memory clean: Limit UI list to 1000 items so the screen doesn't lag
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
    }

    // The End Session feature called from your ReportScreen
    fun clearSessionData() {
        viewModelScope.launch(Dispatchers.IO) {
            // 1. Wipe the Room Database to save user storage space
            val dao = TrafficDatabase.getDatabase(getApplication()).trafficDao()
            dao.clearAll()

            // 2. Clear the live UI memory buffers and the counter!
            rawPacketBuffer.clear()
            _trafficLogs.value = emptyList()
            _totalPacketCount.value = 0
        }
    }
}