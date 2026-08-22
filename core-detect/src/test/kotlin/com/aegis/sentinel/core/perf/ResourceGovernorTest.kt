package com.aegis.sentinel.core.perf

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResourceGovernorTest {

    private val nominal = DeviceState(
        batteryPercent = 85, charging = false, availableRamMb = 2000,
        thermalThrottled = false, eventsPerSecond = 5.0,
    )

    @Test
    fun `nominal device runs at full capability`() {
        val d = ResourceGovernor().decide(nominal)
        assertEquals(OperatingMode.FULL, d.mode)
        assertEquals(1.0, d.samplingRate, 1e-9)
        assertTrue(d.mlEnabled)
        assertTrue(d.llmEnabled)
    }

    @Test
    fun `low battery reduces the operating mode`() {
        val d = ResourceGovernor().decide(nominal.copy(batteryPercent = 15))
        assertTrue(d.mode != OperatingMode.FULL)
        assertFalse("LLM must not run on low battery", d.llmEnabled)
    }

    @Test
    fun `low memory reduces the operating mode`() {
        val d = ResourceGovernor().decide(nominal.copy(availableRamMb = 150))
        assertTrue(d.mode == OperatingMode.CONSERVATIVE || d.mode == OperatingMode.SURVIVAL)
    }

    @Test
    fun `combined pressure reaches survival mode`() {
        val d = ResourceGovernor().decide(
            DeviceState(
                batteryPercent = 5, charging = false, availableRamMb = 150,
                thermalThrottled = true, eventsPerSecond = 800.0, powerSaveMode = true,
            )
        )
        assertEquals(OperatingMode.SURVIVAL, d.mode)
        assertFalse(d.mlEnabled)
        assertFalse(d.llmEnabled)
    }

    /** The core safety property: monitoring degrades but never stops. */
    @Test
    fun `sampling never reaches zero under any pressure combination`() {
        val g = ResourceGovernor()
        for (battery in listOf(0, 5, 15, 50, 100)) {
            for (ram in listOf(50, 150, 300, 2000)) {
                for (thermal in listOf(true, false)) {
                    for (rate in listOf(0.0, 150.0, 5000.0)) {
                        for (save in listOf(true, false)) {
                            for (charging in listOf(true, false)) {
                                val d = g.decide(
                                    DeviceState(battery, charging, ram, thermal, rate, save)
                                )
                                assertTrue(
                                    "sampling collapsed to ${d.samplingRate}",
                                    d.samplingRate > 0.0,
                                )
                                assertTrue(d.reasons.isNotEmpty())
                            }
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `critical event kinds always bypass sampling`() {
        val g = ResourceGovernor()
        assertTrue(g.isCriticalAlways("APP_INSTALLED"))
        assertTrue(g.isCriticalAlways("PERMISSION_GRANTED"))
        assertTrue(g.isCriticalAlways("SPECIAL_ACCESS_CHANGED"))
        assertFalse(g.isCriticalAlways("APP_FOREGROUND"))
    }

    @Test
    fun `charging relieves some pressure`() {
        val g = ResourceGovernor()
        val onBattery = g.decide(nominal.copy(batteryPercent = 15, charging = false))
        val charging = g.decide(nominal.copy(batteryPercent = 15, charging = true))
        assertTrue(charging.mode.ordinal <= onBattery.mode.ordinal)
    }

    @Test
    fun `batch window grows as pressure grows`() {
        val g = ResourceGovernor()
        val full = g.decide(nominal)
        val survival = g.decide(
            DeviceState(3, false, 100, true, 900.0, true)
        )
        assertTrue(survival.batchWindowMs > full.batchWindowMs)
    }
}
