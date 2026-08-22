package com.aegis.sentinel.platform.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.EventType
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.platform.AegisRuntime
import com.aegis.sentinel.platform.telemetry.AppInventory

/**
 * Reacts to package lifecycle changes. These are protected system broadcasts, so the receiver is
 * not exported and the sender cannot be spoofed by another app.
 */
class PackageEventReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.data?.schemeSpecificPart ?: return
        val runtime = AegisRuntime.get() ?: AegisRuntime.create(context)
        val now = System.currentTimeMillis()

        val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
        val type = when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED -> if (replacing) EventType.APP_UPDATED else EventType.APP_INSTALLED
            Intent.ACTION_PACKAGE_REPLACED -> EventType.APP_UPDATED
            Intent.ACTION_PACKAGE_FULLY_REMOVED -> EventType.APP_REMOVED
            else -> return
        }

        // Determine install provenance at the moment of installation, which is when it is most
        // reliable. Failure here is reported as unknown rather than assumed trusted.
        val installer = runCatching {
            context.packageManager.getInstallSourceInfo(pkg).installingPackageName
        }.getOrNull()
        val trusted = installer in AppInventory.TRUSTED_INSTALLERS

        runtime.pipeline.ingest(
            Event(
                id = "pkg-$pkg-$now",
                type = type,
                timestamp = now,
                packageName = pkg,
                observability = Observability.PLATFORM_DIRECT,
                attributes = mapOf(
                    "installer" to (installer ?: "unknown"),
                    "installer_trusted" to trusted.toString(),
                ),
            )
        )
    }
}
