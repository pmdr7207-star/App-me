package com.aegis.sentinel.platform.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.aegis.sentinel.platform.AegisRuntime
import com.aegis.sentinel.platform.prefs.AegisPreferences
import com.aegis.sentinel.platform.service.AegisMonitorService

/**
 * Restores monitoring after a reboot or an app update.
 *
 * Note on Android 15+ restrictions: a BOOT_COMPLETED receiver may not launch dataSync, camera,
 * mediaPlayback, phoneCall, mediaProjection or microphone foreground services. Our monitoring
 * service uses the `specialUse` type, which is not on that list, so this start is permitted.
 * We still guard the call and record failure rather than assuming success.
 */
class BootCompletedReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }

        // Only resume if the user had monitoring enabled; never start protection they did not ask
        // for, and never claim it started when it did not.
        if (!AegisPreferences(context).monitoringEnabled) return

        AegisRuntime.create(context)
        runCatching { AegisMonitorService.start(context) }
            .onFailure { AegisPreferences(context).recordBootStartFailure(it.javaClass.simpleName) }
    }
}
