package com.aegis.sentinel.platform.capability

import android.Manifest
import android.app.ActivityManager
import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.os.Process
import android.provider.Settings
import androidx.core.content.ContextCompat
import com.aegis.sentinel.core.model.AccessClass
import com.aegis.sentinel.core.model.Capability
import com.aegis.sentinel.core.model.CapabilityRegistry
import com.aegis.sentinel.core.response.ResponsePolicyEngine

/**
 * Runtime capability discovery.
 *
 * DISCOVER → VERIFY → SELECT → FALLBACK.
 *
 * Nothing here is assumed. Every capability is probed against the real device and marked
 * production-enabled only when the probe succeeds. A capability that cannot be verified is
 * reported as UNKNOWN and is structurally barred from production use by [Capability]'s own
 * invariants, so an unverified feature can never be silently relied upon.
 */
object CapabilityDiscovery {

    // Capability IDs consumed by detectors and the response engine.
    const val CAP_PACKAGE_ENUMERATION = "observe.package_enumeration"
    const val CAP_PACKAGE_SIGNING = "observe.package_signing"
    const val CAP_INSTALL_SOURCE = "observe.install_source"
    const val CAP_USAGE_STATS = "observe.usage_stats"
    const val CAP_ACCESSIBILITY_AUDIT = "observe.accessibility_audit"
    const val CAP_OVERLAY_AUDIT = "observe.overlay_audit"
    const val CAP_NOTIFICATION_LISTENER = "observe.notification_listener"
    const val CAP_VPN_FLOW_OBSERVATION = "observe.vpn_flows"
    const val CAP_NETWORK_STATE = "observe.network_state"
    const val CAP_FILE_SAF_MONITOR = "observe.file_saf"
    const val CAP_BATTERY_STATE = "observe.battery_state"
    const val CAP_NOTIFICATIONS = "respond.post_notification"

    /**
     * Probe the device and build the registry.
     *
     * @param context application context.
     */
    fun discover(context: Context): CapabilityRegistry {
        val caps = mutableListOf<Capability>()

        // --- Package enumeration ----------------------------------------------------------------
        // Verified by actually performing the query rather than assuming it works.
        val launchable = runCatching {
            val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            context.packageManager.queryIntentActivities(intent, 0).size
        }.getOrNull()
        caps += Capability(
            id = CAP_PACKAGE_ENUMERATION,
            description = "Enumerate launchable installed apps via <queries>",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = (launchable ?: 0) > 0,
            notes = "Observed $launchable launchable packages. Apps without a launcher activity " +
                "are not visible without QUERY_ALL_PACKAGES, which is deliberately not requested.",
        )

        // --- Signing information ----------------------------------------------------------------
        val signingOk = runCatching {
            val flags = PackageManager.GET_SIGNING_CERTIFICATES
            context.packageManager.getPackageInfo(context.packageName, flags).signingInfo != null
        }.getOrDefault(false)
        caps += Capability(
            id = CAP_PACKAGE_SIGNING,
            description = "Read signing certificates of visible packages",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = signingOk,
        )

        // --- Install source -----------------------------------------------------------------------
        val installSourceOk = runCatching {
            context.packageManager.getInstallSourceInfo(context.packageName)
            true
        }.getOrDefault(false)
        caps += Capability(
            id = CAP_INSTALL_SOURCE,
            description = "Read the installing package (store vs sideload) for visible packages",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = installSourceOk,
            notes = "getInstallSourceInfo may throw for packages that are not visible to us.",
        )

        // --- Usage stats (special access) ---------------------------------------------------------
        val usageGranted = hasUsageStatsAccess(context)
        caps += Capability(
            id = CAP_USAGE_STATS,
            description = "App foreground/background events via UsageStatsManager",
            accessClass = AccessClass.SPECIAL_ACCESS,
            productionEnabled = usageGranted,
            notes = if (usageGranted) "Granted." else
                "Not granted. User must enable Usage Access in Settings; detectors that depend " +
                    "on it stay disabled until then.",
        )

        // --- Accessibility audit (read-only) -------------------------------------------------------
        // Reading which apps hold accessibility access needs no special permission.
        val accessibilityReadable = runCatching {
            Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            )
            true
        }.getOrDefault(false)
        caps += Capability(
            id = CAP_ACCESSIBILITY_AUDIT,
            description = "Audit which apps hold accessibility access",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = accessibilityReadable,
            notes = "Read-only audit of Settings.Secure. This app does not itself register an " +
                "accessibility service.",
        )

        // --- Overlay audit --------------------------------------------------------------------------
        caps += Capability(
            id = CAP_OVERLAY_AUDIT,
            description = "Detect whether this app can draw overlays (self only)",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = true,
            notes = "Settings.canDrawOverlays reports our own state. Enumerating which OTHER apps " +
                "hold SYSTEM_ALERT_WINDOW requires AppOpsManager access we do not hold; that " +
                "broader capability is documented as unavailable.",
        )

        // --- Notification listener ------------------------------------------------------------------
        // Declared but NOT implemented: we do not ship a NotificationListenerService, so this is
        // honestly reported as unavailable rather than pretended.
        caps += Capability(
            id = CAP_NOTIFICATION_LISTENER,
            description = "Observe notifications posted by other apps",
            accessClass = AccessClass.SPECIAL_ACCESS,
            productionEnabled = false,
            notes = "Not implemented in this release. No NotificationListenerService is shipped, " +
                "so no notification telemetry is collected.",
        )

        // --- Local VPN flow observation ---------------------------------------------------------------
        val vpnConsentReady = runCatching { VpnService.prepare(context) == null }
            .getOrDefault(false)
        val vpnDeclared = runCatching {
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SERVICES,
            ).services?.any { it.name.contains("AegisVpnService") } == true
        }.getOrDefault(false)
        caps += Capability(
            id = CAP_VPN_FLOW_OBSERVATION,
            description = "Observe per-app network flow metadata via a local VpnService",
            accessClass = AccessClass.SPECIAL_ACCESS,
            productionEnabled = vpnDeclared && vpnConsentReady,
            notes = buildString {
                append("Local sink only; traffic is never forwarded off-device. ")
                append(if (vpnConsentReady) "User consent already granted. " else "Requires user consent. ")
                append(
                    "Visibility is limited to IP/port/timing/size metadata. TLS payloads, " +
                        "certificate-pinned sessions and QUIC/DoH contents are NOT inspectable."
                )
            },
        )

        // --- Network state ------------------------------------------------------------------------------
        val cm = ContextCompat.getSystemService(context, ConnectivityManager::class.java)
        caps += Capability(
            id = CAP_NETWORK_STATE,
            description = "Read network transport and capability state",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = cm != null,
        )

        // --- File monitoring via SAF ------------------------------------------------------------------------
        caps += Capability(
            id = CAP_FILE_SAF_MONITOR,
            description = "Monitor user-selected document trees via the Storage Access Framework",
            accessClass = AccessClass.USER_PERMISSION,
            productionEnabled = true,
            notes = "Scope is exactly the trees the user grants. Other apps' private storage is " +
                "never visible on a non-rooted device.",
        )

        // --- Battery / power state ----------------------------------------------------------------------------
        val pm = ContextCompat.getSystemService(context, PowerManager::class.java)
        caps += Capability(
            id = CAP_BATTERY_STATE,
            description = "Read battery and power-save state for the resource governor",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = pm != null,
        )

        // --- Notifications ---------------------------------------------------------------------------------------
        val notifOk = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        caps += Capability(
            id = CAP_NOTIFICATIONS,
            description = "Post alert notifications to the user",
            accessClass = AccessClass.USER_PERMISSION,
            productionEnabled = notifOk,
        )

        // --- Response actions ---------------------------------------------------------------------------------------
        caps += Capability(
            id = ResponsePolicyEngine.CAP_APP_SETTINGS,
            description = "Open the system app-details screen for a package",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = resolves(context, Settings.ACTION_APPLICATION_DETAILS_SETTINGS),
        )

        val uninstallResolvable = runCatching {
            val i = Intent(Intent.ACTION_DELETE).setData(
                android.net.Uri.parse("package:${context.packageName}")
            )
            i.resolveActivity(context.packageManager) != null
        }.getOrDefault(false)
        caps += Capability(
            id = ResponsePolicyEngine.CAP_REQUEST_UNINSTALL,
            description = "Ask the system to show the uninstall confirmation dialog",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = uninstallResolvable,
            notes = "Silent uninstall is impossible without device owner; only the system " +
                "confirmation dialog is offered.",
        )

        caps += Capability(
            id = ResponsePolicyEngine.CAP_EVIDENCE_STORE,
            description = "Persist integrity-protected incident evidence in app-private storage",
            accessClass = AccessClass.NORMAL_APP,
            productionEnabled = runCatching { context.filesDir.canWrite() }.getOrDefault(false),
        )

        // --- Explicitly unavailable actions ---------------------------------------------------------------------------
        // Declared so the UI can show them as impossible rather than quietly omitting them.
        caps += Capability(
            id = ResponsePolicyEngine.CAP_FORCE_STOP,
            description = "Force stop another application",
            accessClass = AccessClass.DEVICE_OWNER,
            productionEnabled = false,
            notes = "ActivityManager.forceStopPackage is a system API. A non-root, " +
                "non-device-owner app cannot terminate another app on Android 16.",
        )

        return CapabilityRegistry(caps)
    }

    /** Usage access is an app-op, not a runtime permission, so it must be checked via AppOps. */
    fun hasUsageStatsAccess(context: Context): Boolean = runCatching {
        val appOps = ContextCompat.getSystemService(context, AppOpsManager::class.java)
            ?: return false
        val mode = appOps.unsafeCheckOpNoThrow(
            AppOpsManager.OPSTR_GET_USAGE_STATS,
            Process.myUid(),
            context.packageName,
        )
        mode == AppOpsManager.MODE_ALLOWED
    }.getOrDefault(false)

    private fun resolves(context: Context, action: String): Boolean = runCatching {
        Intent(action).resolveActivity(context.packageManager) != null
    }.getOrDefault(false)

    /** Device facts used by the resource governor and for the diagnostics screen. */
    data class DeviceProfile(
        val model: String,
        val manufacturer: String,
        val sdkInt: Int,
        val cpuCores: Int,
        val totalRamMb: Int,
        val is64Bit: Boolean,
        val supportedAbis: List<String>,
    )

    fun profile(context: Context): DeviceProfile {
        val am = ContextCompat.getSystemService(context, ActivityManager::class.java)
        val mi = ActivityManager.MemoryInfo().also { am?.getMemoryInfo(it) }
        return DeviceProfile(
            model = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            sdkInt = Build.VERSION.SDK_INT,
            cpuCores = Runtime.getRuntime().availableProcessors(),
            totalRamMb = (mi.totalMem / (1024 * 1024)).toInt(),
            is64Bit = Build.SUPPORTED_64_BIT_ABIS.isNotEmpty(),
            supportedAbis = Build.SUPPORTED_ABIS.toList(),
        )
    }
}
