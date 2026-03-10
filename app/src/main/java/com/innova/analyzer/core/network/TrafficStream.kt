package com.innova.analyzer.core.network

import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow

object TrafficStream {
    // extraBufferCapacity ensures we don't drop packets if the UI lags for a millisecond
    private val _trafficFlow = MutableSharedFlow<NetworkEvent>(extraBufferCapacity = 100)

    // The public, read-only version for the UI to observe
    val trafficFlow = _trafficFlow.asSharedFlow()

    // The VPN Service calls this every time it parses a packet
    suspend fun emitEvent(event: NetworkEvent) {
        _trafficFlow.emit(event)
    }
}