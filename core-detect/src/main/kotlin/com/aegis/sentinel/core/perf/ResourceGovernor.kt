package com.aegis.sentinel.core.perf

import kotlin.math.max
import kotlin.math.min

/**
 * Adaptive resource governor.
 *
 * Under pressure the system reduces analysis cost while preserving the monitoring that matters.
 * The invariant enforced here and covered by tests: critical monitoring is never fully disabled,
 * whatever the pressure — degradation is graceful, not a silent shutdown.
 */
data class DeviceState(
    val batteryPercent: Int,
    val charging: Boolean,
    val availableRamMb: Int,
    val thermalThrottled: Boolean,
    val eventsPerSecond: Double,
    val powerSaveMode: Boolean = false,
)

enum class OperatingMode {
    /** Everything on: full sampling, ML enabled, richest telemetry. */
    FULL,

    /** Reduced sampling and deferred heavy analysis. */
    REDUCED,

    /** Only high-value, low-cost detectors. */
    CONSERVATIVE,

    /** Bare minimum: critical detectors only, everything else deferred. */
    SURVIVAL,
}

data class GovernorDecision(
    val mode: OperatingMode,
    /** Fraction of non-critical events to sample, in (0,1]. */
    val samplingRate: Double,
    val mlEnabled: Boolean,
    val llmEnabled: Boolean,
    val batchWindowMs: Long,
    val reasons: List<String>,
) {
    init {
        require(samplingRate > 0.0 && samplingRate <= 1.0) {
            "sampling must remain strictly positive: monitoring may degrade but never stop"
        }
    }
}

class ResourceGovernor(private val config: Config = Config()) {

    data class Config(
        val lowBatteryPercent: Int = 20,
        val criticalBatteryPercent: Int = 10,
        val lowRamMb: Int = 400,
        val criticalRamMb: Int = 200,
        val highEventRate: Double = 120.0,
        val extremeEventRate: Double = 400.0,
        val minSamplingRate: Double = 0.05,
    )

    fun decide(state: DeviceState): GovernorDecision {
        val reasons = mutableListOf<String>()
        var pressure = 0

        if (!state.charging && state.batteryPercent <= config.criticalBatteryPercent) {
            pressure += 3
            reasons += "Battery critically low (${state.batteryPercent}%)."
        } else if (!state.charging && state.batteryPercent <= config.lowBatteryPercent) {
            pressure += 2
            reasons += "Battery low (${state.batteryPercent}%)."
        }

        if (state.availableRamMb <= config.criticalRamMb) {
            pressure += 3
            reasons += "Available memory critically low (${state.availableRamMb} MB)."
        } else if (state.availableRamMb <= config.lowRamMb) {
            pressure += 2
            reasons += "Available memory low (${state.availableRamMb} MB)."
        }

        if (state.thermalThrottled) {
            pressure += 2
            reasons += "Device is thermally throttled."
        }

        if (state.powerSaveMode) {
            pressure += 1
            reasons += "System power save mode is active."
        }

        if (state.eventsPerSecond >= config.extremeEventRate) {
            pressure += 3
            reasons += "Extreme event rate (${state.eventsPerSecond.toInt()}/s)."
        } else if (state.eventsPerSecond >= config.highEventRate) {
            pressure += 1
            reasons += "Elevated event rate (${state.eventsPerSecond.toInt()}/s)."
        }

        // Charging on mains relieves the energy budget but not memory or thermal pressure.
        if (state.charging) pressure = max(0, pressure - 1)

        val mode = when {
            pressure >= 6 -> OperatingMode.SURVIVAL
            pressure >= 4 -> OperatingMode.CONSERVATIVE
            pressure >= 2 -> OperatingMode.REDUCED
            else -> OperatingMode.FULL
        }

        val samplingRate = when (mode) {
            OperatingMode.FULL -> 1.0
            OperatingMode.REDUCED -> 0.6
            OperatingMode.CONSERVATIVE -> 0.3
            OperatingMode.SURVIVAL -> max(config.minSamplingRate, 0.1)
        }

        if (reasons.isEmpty()) reasons += "Device resources nominal."

        return GovernorDecision(
            mode = mode,
            samplingRate = min(1.0, samplingRate),
            // Local ML is affordable except under real pressure.
            mlEnabled = mode == OperatingMode.FULL || mode == OperatingMode.REDUCED,
            // The LLM is the most expensive component; it is opportunistic by design.
            llmEnabled = mode == OperatingMode.FULL && !state.powerSaveMode,
            batchWindowMs = when (mode) {
                OperatingMode.FULL -> 2_000
                OperatingMode.REDUCED -> 5_000
                OperatingMode.CONSERVATIVE -> 15_000
                OperatingMode.SURVIVAL -> 60_000
            },
            reasons = reasons,
        )
    }

    /**
     * Critical events bypass sampling entirely. This is what guarantees that degradation never
     * blinds the product to the things that matter most.
     */
    fun isCriticalAlways(eventKind: String): Boolean = eventKind in CRITICAL_KINDS

    companion object {
        val CRITICAL_KINDS = setOf(
            "APP_INSTALLED",
            "PERMISSION_GRANTED",
            "SPECIAL_ACCESS_CHANGED",
            "DOWNLOAD_COMPLETED",
        )
    }
}
