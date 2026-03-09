package com.innova.analyzer.ui.dashboard

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.innova.analyzer.data.local.TrafficDatabase
import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn

// 1. Change to AndroidViewModel so it automatically receives the Application context
class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    // 2. The ViewModel grabs its own DAO directly from the context!
    private val dao = TrafficDatabase.getDatabase(application).trafficDao()

    // 3. The Flow remains exactly the same
    val trafficLogs: StateFlow<List<NetworkEvent>> = dao.getLiveTraffic()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
}