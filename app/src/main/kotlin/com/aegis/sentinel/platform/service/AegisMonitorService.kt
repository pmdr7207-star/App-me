package com.aegis.sentinel.platform.service

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.BatteryManager
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.aegis.sentinel.AegisApplication
import com.aegis.sentinel.R
import com.aegis.sentinel.core.perf.DeviceState
import com.aegis.sentinel.core.perf.OperatingMode
import com.aegis.sentinel.platform.AegisRuntime
import com.aegis.sentinel.platform.telemetry.AppInventory
import com.aegis.sentinel.ui.MainActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Foreground monitoring service.
 *
 * Foreground service type is `specialUse`: continuous security monitoring does not fit `dataSync`,
 * which since Android 15 is capped at 6 hours per 24 and would silently stop protecting the user.
 *
 * The loop is adaptive rather than a fixed poll: the resource governor decides the cadence from
 * real battery, memory and thermal state, and the service backs off automatically under pressure.
 */
class AegisMonitorService : LifecycleService() {

    private val runtime: AegisRuntime? get() = AegisRuntime.get()

    override fun onCreate() {
        super.onCreate()
        startForegroundSafely(OperatingMode.FULL)
        startMonitoringLoop()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        // Restart if the system kills us; monitoring should survive memory pressure.
        return START_STICKY
    }

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null
    }

    private fun startMonitoringLoop() {
        lifecycleScope.launch {
            val rt = runtime ?: return@launch
            val inventory = AppInventory(applicationContext)

            while (isActive) {
                val state = readDeviceState()
                val decision = rt.governor.decide(state)

                if (decision.mode != lastMode) {
                    lastMode = decision.mode
                    updateNotification(decision.mode)
                }

                // Static posture sweep. Cheap, event-light, and the highest-value signal set
                // available without special access.
                withContext(Dispatchers.Default) {
                    val now = System.currentTimeMillis()
                    val records = inventory.enumerate()
                    records.forEach { record ->
                        inventory.analyze(record, now).forEach { evidence ->
                            rt.pipeline.threatGraph().ingestEvidence(evidence)
                        }
                    }
                }

                delay(sweepIntervalMs(decision.mode))
            }
        }
    }

    private fun sweepIntervalMs(mode: OperatingMode): Long = when (mode) {
        OperatingMode.FULL -> 15 * 60_000L
        OperatingMode.REDUCED -> 30 * 60_000L
        OperatingMode.CONSERVATIVE -> 60 * 60_000L
        OperatingMode.SURVIVAL -> 180 * 60_000L
    }

    private fun readDeviceState(): DeviceState {
        val bm = ContextCompat.getSystemService(this, BatteryManager::class.java)
        val pm = ContextCompat.getSystemService(this, PowerManager::class.java)
        val am = ContextCompat.getSystemService(this, android.app.ActivityManager::class.java)
        val mi = android.app.ActivityManager.MemoryInfo().also { am?.getMemoryInfo(it) }

        val battery = bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) ?: 100
        val charging = bm?.isCharging ?: false
        val thermal = (pm?.currentThermalStatus ?: PowerManager.THERMAL_STATUS_NONE) >=
            PowerManager.THERMAL_STATUS_MODERATE

        return DeviceState(
            batteryPercent = battery.coerceIn(0, 100),
            charging = charging,
            availableRamMb = (mi.availMem / (1024 * 1024)).toInt(),
            thermalThrottled = thermal,
            eventsPerSecond = 0.0,
            powerSaveMode = pm?.isPowerSaveMode ?: false,
        )
    }

    private fun startForegroundSafely(mode: OperatingMode) {
        val notification = buildNotification(mode)
        runCatching {
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        }.onFailure {
            // If the system refuses the foreground start we stop rather than pretend to run.
            stopSelf()
        }
    }

    private fun updateNotification(mode: OperatingMode) {
        val nm = ContextCompat.getSystemService(this, android.app.NotificationManager::class.java)
        runCatching { nm?.notify(NOTIFICATION_ID, buildNotification(mode)) }
    }

    private fun buildNotification(mode: OperatingMode): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val text = when (mode) {
            OperatingMode.FULL -> getString(R.string.monitor_full)
            OperatingMode.REDUCED -> getString(R.string.monitor_reduced)
            OperatingMode.CONSERVATIVE -> getString(R.string.monitor_conservative)
            OperatingMode.SURVIVAL -> getString(R.string.monitor_survival)
        }
        return NotificationCompat.Builder(this, AegisApplication.CHANNEL_MONITORING)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setContentIntent(open)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private var lastMode: OperatingMode? = null

    companion object {
        private const val NOTIFICATION_ID = 1001

        fun start(context: Context) {
            val intent = Intent(context, AegisMonitorService::class.java)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, AegisMonitorService::class.java))
        }
    }
}

/** Thin indirection so the foreground-start call site stays readable and testable. */
private object ServiceCompat {
    fun startForeground(
        service: android.app.Service,
        id: Int,
        notification: Notification,
        type: Int,
    ) {
        androidx.core.app.ServiceCompat.startForeground(service, id, notification, type)
    }
}
