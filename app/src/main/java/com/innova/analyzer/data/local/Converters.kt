package com.innova.analyzer.data.local

import androidx.room.TypeConverter
import com.innova.analyzer.data.models.ConnectionProtocol

class Converters {
    @TypeConverter
    fun fromProtocol(protocol: ConnectionProtocol): String {
        return protocol.name
    }

    @TypeConverter
    fun toProtocol(name: String): ConnectionProtocol {
        return try {
            ConnectionProtocol.valueOf(name)
        } catch (e: IllegalArgumentException) {
            ConnectionProtocol.UNKNOWN
        }
    }
}