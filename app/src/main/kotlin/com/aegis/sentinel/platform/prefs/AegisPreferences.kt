package com.aegis.sentinel.platform.prefs

import android.content.Context

/**
 * Small settings store.
 *
 * Only non-sensitive operational flags live here. Evidence and any security-relevant record go to
 * the encrypted, integrity-chained [com.aegis.sentinel.platform.evidence.EvidenceStore] instead.
 */
class AegisPreferences(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences(NAME, Context.MODE_PRIVATE)

    var monitoringEnabled: Boolean
        get() = prefs.getBoolean(KEY_MONITORING, false)
        set(value) = prefs.edit().putBoolean(KEY_MONITORING, value).apply()

    var flowObservationEnabled: Boolean
        get() = prefs.getBoolean(KEY_FLOW, false)
        set(value) = prefs.edit().putBoolean(KEY_FLOW, value).apply()

    val lastBootStartFailure: String?
        get() = prefs.getString(KEY_BOOT_FAILURE, null)

    fun recordBootStartFailure(reason: String) {
        prefs.edit().putString(KEY_BOOT_FAILURE, reason).apply()
    }

    fun clearBootStartFailure() {
        prefs.edit().remove(KEY_BOOT_FAILURE).apply()
    }

    private companion object {
        const val NAME = "aegis.prefs"
        const val KEY_MONITORING = "monitoring_enabled"
        const val KEY_FLOW = "flow_observation_enabled"
        const val KEY_BOOT_FAILURE = "boot_start_failure"
    }
}
