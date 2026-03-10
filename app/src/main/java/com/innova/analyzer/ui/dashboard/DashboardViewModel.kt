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

    init {
        val dao = TrafficDatabase.getDatabase(getApplication()).trafficDao()

        // 1. Observe the Live Aggregated Connections directly from the Database!
        // Room auto-emits a new list every time a connection is UPSERTED.
        viewModelScope.launch(Dispatchers.IO) {
            dao.getLiveTraffic().collect { history ->
                // Keep the UI fast: only hold the top 1000 connections in memory
                _trafficLogs.value = history.take(1000)
                
                // Keep the lifetime packet count accurate based on the true database count
                _totalPacketCount.value = dao.getTotalCount()
            }
        }

        // 2. The Firehose Catcher (The Producer)
        // We still listen to the raw TrafficStream purely to make the Total Packet Counter
        // spin up instantly in real-time, giving that "hacking" feel to the UI!
        viewModelScope.launch(Dispatchers.IO) {
            TrafficStream.trafficFlow.collect {
                _totalPacketCount.value += 1
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
            _trafficLogs.value = emptyList()
            _totalPacketCount.value = 0
        }
    }
}