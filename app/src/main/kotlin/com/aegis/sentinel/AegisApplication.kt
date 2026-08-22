package com.aegis.sentinel

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import androidx.core.content.ContextCompat
import com.aegis.sentinel.platform.AegisRuntime

class AegisApplication : Application() {

    lateinit var runtime: AegisRuntime
        private set

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        runtime = AegisRuntime.create(this)
    }

    private fun createNotificationChannels() {
        val nm = ContextCompat.getSystemService(this, NotificationManager::class.java) ?: return

        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_MONITORING,
                getString(R.string.channel_monitoring),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.channel_monitoring_desc)
                setShowBadge(false)
            }
        )

        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ALERTS,
                getString(R.string.channel_alerts),
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = getString(R.string.channel_alerts_desc)
            }
        )
    }

    companion object {
        const val CHANNEL_MONITORING = "aegis.monitoring"
        const val CHANNEL_ALERTS = "aegis.alerts"
    }
}
