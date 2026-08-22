package com.aegis.sentinel.platform.telemetry

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.provider.Settings
import com.aegis.sentinel.core.model.Confidence
import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Reliability
import com.aegis.sentinel.core.model.Severity
import com.aegis.sentinel.core.safety.Sanitizer
import java.security.MessageDigest

/**
 * Static inventory and posture analysis of visible applications.
 *
 * Scope honesty: only packages visible under our <queries> declaration are analysed. We do not
 * request QUERY_ALL_PACKAGES, so packages without a launcher activity are invisible; the UI
 * reports the count it actually saw rather than implying completeness.
 */
class AppInventory(private val context: Context) {

    private val pm: PackageManager get() = context.packageManager

    val detectorId = "inventory.static"

    data class AppRecord(
        val packageName: String,
        val label: String,
        val versionName: String?,
        val installerPackage: String?,
        val installedFromTrustedStore: Boolean,
        val isSystemApp: Boolean,
        val debuggable: Boolean,
        val signatureSha256: String?,
        val dangerousPermissions: List<String>,
        val targetSdk: Int,
        val firstInstallTime: Long,
        val lastUpdateTime: Long,
        val hasAccessibilityAccess: Boolean,
    )

    /** Enumerate the launchable apps we can actually see. */
    fun enumerate(): List<AppRecord> {
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = runCatching { pm.queryIntentActivities(intent, 0) }.getOrDefault(emptyList())
        val accessibilityHolders = accessibilityPackages()

        return resolved.mapNotNull { ri ->
            val pkg = ri.activityInfo?.packageName ?: return@mapNotNull null
            runCatching { record(pkg, accessibilityHolders) }.getOrNull()
        }.distinctBy { it.packageName }
    }

    private fun record(pkg: String, accessibilityHolders: Set<String>): AppRecord {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        val info = pm.getPackageInfo(pkg, flags)
        val appInfo = info.applicationInfo

        val installer = runCatching {
            pm.getInstallSourceInfo(pkg).installingPackageName
        }.getOrNull()

        val requested = info.requestedPermissions?.toList().orEmpty()
        val dangerous = requested.filter { isDangerous(it) }

        return AppRecord(
            packageName = pkg,
            label = Sanitizer.sanitize(
                runCatching { appInfo?.loadLabel(pm)?.toString() }.getOrNull() ?: pkg,
                80,
            ).text,
            versionName = Sanitizer.sanitize(info.versionName, 40).text.ifBlank { null },
            installerPackage = installer,
            installedFromTrustedStore = installer in TRUSTED_INSTALLERS,
            isSystemApp = appInfo != null &&
                (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            debuggable = appInfo != null &&
                (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
            signatureSha256 = signatureDigest(info.signingInfo?.apkContentsSigners),
            dangerousPermissions = dangerous,
            targetSdk = appInfo?.targetSdkVersion ?: 0,
            firstInstallTime = info.firstInstallTime,
            lastUpdateTime = info.lastUpdateTime,
            hasAccessibilityAccess = pkg in accessibilityHolders,
        )
    }

    /**
     * Turn a record into evidence. Each signal is deliberately modest on its own — a sideloaded
     * app is not malware. Only fusion across detectors can escalate.
     */
    fun analyze(record: AppRecord, now: Long): List<Evidence> {
        val out = mutableListOf<Evidence>()

        if (!record.isSystemApp && !record.installedFromTrustedStore) {
            out += Evidence(
                id = "$detectorId:sideload:${record.packageName}",
                detector = detectorId,
                packageName = record.packageName,
                timestamp = now,
                severity = Severity.LOW,
                confidence = Confidence(0.6),
                reliability = Reliability(0.9),
                observability = Observability.PLATFORM_DIRECT,
                summary = "Installed from ${record.installerPackage ?: "an unknown source"} " +
                    "rather than a recognised app store.",
                attributes = mapOf("installer" to (record.installerPackage ?: "unknown")),
            )
        }

        if (record.hasAccessibilityAccess && !record.isSystemApp) {
            out += Evidence(
                id = "$detectorId:accessibility:${record.packageName}",
                detector = detectorId,
                packageName = record.packageName,
                timestamp = now,
                severity = Severity.MEDIUM,
                confidence = Confidence(0.7),
                reliability = Reliability(0.95),
                observability = Observability.PLATFORM_DIRECT,
                summary = "Holds accessibility access, which permits reading screen content " +
                    "and performing actions on the user's behalf.",
            )
        }

        val highRisk = record.dangerousPermissions.filter { it in HIGH_RISK_PERMISSIONS }
        if (highRisk.size >= 3 && !record.isSystemApp) {
            out += Evidence(
                id = "$detectorId:permcluster:${record.packageName}",
                detector = detectorId,
                packageName = record.packageName,
                timestamp = now,
                severity = Severity.LOW,
                confidence = Confidence(0.5),
                reliability = Reliability(0.85),
                observability = Observability.PLATFORM_DIRECT,
                summary = "Requests ${highRisk.size} high-risk permissions: " +
                    highRisk.joinToString(", ") { it.substringAfterLast('.') },
                attributes = mapOf("permissions" to highRisk.joinToString(",")),
            )
        }

        if (record.debuggable && !record.isSystemApp) {
            out += Evidence(
                id = "$detectorId:debuggable:${record.packageName}",
                detector = detectorId,
                packageName = record.packageName,
                timestamp = now,
                severity = Severity.LOW,
                confidence = Confidence(0.5),
                reliability = Reliability(0.9),
                observability = Observability.PLATFORM_DIRECT,
                summary = "Ships with the debuggable flag enabled, which is unusual for a " +
                    "production release.",
            )
        }

        // Exculpatory: a well-signed store app with a long history argues against suspicion.
        if (record.installedFromTrustedStore && record.isSystemApp.not() &&
            now - record.firstInstallTime > NINETY_DAYS
        ) {
            out += Evidence(
                id = "$detectorId:established:${record.packageName}",
                detector = detectorId,
                packageName = record.packageName,
                timestamp = now,
                severity = Severity.INFO,
                confidence = Confidence(0.6),
                reliability = Reliability(0.9),
                observability = Observability.PLATFORM_DIRECT,
                summary = "Installed from a recognised store and present for over 90 days.",
                supportsMalicious = false,
            )
        }

        return out
    }

    private fun accessibilityPackages(): Set<String> = runCatching {
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ).orEmpty()
        enabled.split(':')
            .mapNotNull { it.substringBefore('/').takeIf(String::isNotBlank) }
            .toSet()
    }.getOrDefault(emptySet())

    private fun signatureDigest(signatures: Array<Signature>?): String? {
        val first = signatures?.firstOrNull() ?: return null
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(first.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    private fun isDangerous(permission: String): Boolean = runCatching {
        val info = pm.getPermissionInfo(permission, 0)
        val protection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.protection
        } else {
            @Suppress("DEPRECATION")
            info.protectionLevel and android.content.pm.PermissionInfo.PROTECTION_MASK_BASE
        }
        protection == android.content.pm.PermissionInfo.PROTECTION_DANGEROUS
    }.getOrDefault(false)

    companion object {
        private const val NINETY_DAYS = 90L * 24 * 60 * 60 * 1000

        val TRUSTED_INSTALLERS = setOf(
            "com.android.vending",
            "com.google.android.packageinstaller",
            "com.sec.android.app.samsungapps",
            "com.samsung.android.app.updatecenter",
        )

        val HIGH_RISK_PERMISSIONS = setOf(
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        )
    }
}
