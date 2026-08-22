package com.aegis.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.sentinel.core.model.AccessClass
import com.aegis.sentinel.core.response.ResponsePolicyEngine
import com.aegis.sentinel.platform.capability.CapabilityDiscovery
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs on a real Android 16 (API 36) emulator in CI.
 *
 * This is the test that verifies our capability claims against the actual platform instead of
 * trusting documentation.
 */
@RunWith(AndroidJUnit4::class)
class CapabilityDiscoveryInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun capabilityDiscoveryRunsAndProducesARegistry() {
        val registry = CapabilityDiscovery.discover(context)
        assertTrue("registry should not be empty", registry.all.isNotEmpty())
    }

    /** The core invariant: nothing unverified may be production enabled. */
    @Test
    fun noUnknownCapabilityIsProductionEnabled() {
        val registry = CapabilityDiscovery.discover(context)
        registry.all.forEach { c ->
            if (c.accessClass == AccessClass.UNKNOWN) {
                assertFalse("UNKNOWN capability ${c.id} must not be enabled", c.productionEnabled)
            }
            if (c.accessClass == AccessClass.ROOT_ONLY || c.accessClass == AccessClass.UNAVAILABLE) {
                assertFalse("${c.id} is unreachable and must not be enabled", c.productionEnabled)
            }
        }
    }

    /** Force stop genuinely is not available to a normal app; assert we report it that way. */
    @Test
    fun forceStopIsReportedUnavailable() {
        val registry = CapabilityDiscovery.discover(context)
        val forceStop = registry[ResponsePolicyEngine.CAP_FORCE_STOP]
        assertNotNull(forceStop)
        assertFalse(forceStop!!.productionEnabled)
        assertEquals(AccessClass.DEVICE_OWNER, forceStop.accessClass)
    }

    /** Package enumeration must genuinely work through the <queries> declaration. */
    @Test
    fun packageEnumerationWorksWithoutQueryAllPackages() {
        val registry = CapabilityDiscovery.discover(context)
        val cap = registry[CapabilityDiscovery.CAP_PACKAGE_ENUMERATION]
        assertNotNull(cap)
        assertTrue("expected at least one launchable app on the device", cap!!.productionEnabled)
    }

    @Test
    fun weDoNotHoldQueryAllPackages() {
        val pm = context.packageManager
        val info = pm.getPackageInfo(context.packageName, android.content.pm.PackageManager.GET_PERMISSIONS)
        val requested = info.requestedPermissions?.toList().orEmpty()
        assertFalse(
            "QUERY_ALL_PACKAGES must not be requested",
            requested.contains("android.permission.QUERY_ALL_PACKAGES"),
        )
    }

    @Test
    fun deviceProfileIsPopulated() {
        val p = CapabilityDiscovery.profile(context)
        assertTrue(p.sdkInt >= 31)
        assertTrue(p.cpuCores > 0)
        assertTrue(p.totalRamMb > 0)
    }

    /** Usage stats access is special access; without a grant it must read as false, not assumed. */
    @Test
    fun usageStatsReportsHonestly() {
        val granted = CapabilityDiscovery.hasUsageStatsAccess(context)
        val cap = CapabilityDiscovery.discover(context)[CapabilityDiscovery.CAP_USAGE_STATS]
        assertEquals(granted, cap!!.productionEnabled)
    }
}
