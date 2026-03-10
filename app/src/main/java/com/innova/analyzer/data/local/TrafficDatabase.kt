package com.innova.analyzer.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.innova.analyzer.data.models.NetworkEvent

@Database(entities = [NetworkEvent::class], version = 2, exportSchema = false)
abstract class TrafficDatabase : RoomDatabase() {

    abstract fun trafficDao(): TrafficDao

    companion object {
        @Volatile
        private var INSTANCE: TrafficDatabase? = null

        fun getDatabase(context: Context): TrafficDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    TrafficDatabase::class.java,
                    "traffic_database"
                )
                    .fallbackToDestructiveMigration()
                    .build()

                INSTANCE = instance
                instance
            }
        }
    }
}