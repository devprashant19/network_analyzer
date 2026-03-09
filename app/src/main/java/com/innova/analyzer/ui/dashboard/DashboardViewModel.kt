package com.innova.analyzer.ui.dashboard

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.innova.analyzer.data.local.TrafficDatabase
import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    private val dao = TrafficDatabase.getDatabase(application).trafficDao()

    val trafficLogs: StateFlow<List<NetworkEvent>> = dao.getLiveTraffic()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    // NEW: Track the VPN status
    private val _isVpnActive = MutableStateFlow(false)
    val isVpnActive: StateFlow<Boolean> = _isVpnActive

    fun setVpnActive(active: Boolean) {
        _isVpnActive.value = active
    }
}