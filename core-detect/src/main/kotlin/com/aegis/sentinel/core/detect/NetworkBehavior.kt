package com.aegis.sentinel.core.detect

import com.aegis.sentinel.core.model.Confidence
import com.aegis.sentinel.core.model.EpochMillis
import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.EventType
import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Reliability
import com.aegis.sentinel.core.model.Severity
import com.aegis.sentinel.core.safety.Sanitizer
import com.aegis.sentinel.core.stats.BoundedSample
import kotlin.math.abs
import kotlin.math.ln
import kotlin.math.min

/**
 * Network behaviour analysis over *observable* metadata only.
 *
 * Explicitly NOT claimed anywhere in this product: payload inspection of TLS, certificate pinning
 * bypass, decryption of QUIC/DoH, or kernel-level visibility. With a local VpnService the app can
 * observe IP/port/timing/volume and plaintext DNS it is asked to resolve. Everything below is
 * derived from that metadata alone.
 */
class NetworkBehaviorDetector(private val config: Config = Config()) {

    data class Config(
        val minSamplesForBeacon: Int = 8,
        /** Coefficient of variation below this means suspiciously regular intervals. */
        val beaconCvThreshold: Double = 0.15,
        val minBeaconIntervalMs: Long = 5_000,
        val historyPerEndpoint: Int = 48,
        val maxEndpoints: Int = 512,
        val highEntropyLabelBits: Double = 3.6,
        val minLabelLengthForDga: Int = 10,
    )

    private data class EndpointState(
        val sample: BoundedSample,
        var lastSeen: EpochMillis,
        var count: Long,
    )

    private val endpoints = LinkedHashMap<String, EndpointState>()

    val detectorId = "network.behavior"

    fun onEvent(event: Event): List<Evidence> = when (event.type) {
        EventType.NETWORK_FLOW -> onFlow(event)
        EventType.DNS_QUERY -> onDns(event)
        else -> emptyList()
    }

    private fun onFlow(event: Event): List<Evidence> {
        val endpoint = event.attr("endpoint") ?: return emptyList()
        val key = "${event.packageName ?: "?"}|$endpoint"

        val state = endpoints.getOrPut(key) {
            EndpointState(BoundedSample(config.historyPerEndpoint), event.timestamp, 0)
        }
        if (state.count > 0) {
            val interval = event.timestamp - state.lastSeen
            if (interval >= config.minBeaconIntervalMs) {
                state.sample.add(interval.toDouble())
            }
        }
        state.lastSeen = event.timestamp
        state.count++
        trimEndpoints()

        val out = mutableListOf<Evidence>()

        // --- Beaconing: highly regular intervals to a single endpoint. ------------------------
        if (state.sample.size >= config.minSamplesForBeacon) {
            val cv = state.sample.coefficientOfVariation()
            if (cv <= config.beaconCvThreshold) {
                val medianMs = state.sample.median()
                out += Evidence(
                    id = "$detectorId:beacon:$key:${event.timestamp}",
                    detector = detectorId,
                    packageName = event.packageName,
                    timestamp = event.timestamp,
                    severity = Severity.MEDIUM,
                    confidence = Confidence(min(1.0, 1.0 - (cv / config.beaconCvThreshold) * 0.5)),
                    reliability = Reliability(0.8),
                    observability = Observability.DERIVED,
                    summary = "Regular contact with ${redact(endpoint)} every ~${medianMs.toLong() / 1000}s " +
                        "(variation ${"%.2f".format(cv)}), consistent with automated beaconing.",
                    sourceEventIds = listOf(event.id),
                    attributes = mapOf(
                        "endpoint" to redact(endpoint),
                        "cv" to cv.toString(),
                        "median_interval_ms" to medianMs.toString(),
                        "samples" to state.sample.size.toString(),
                    ),
                )
            }
        }
        return out
    }

    private fun onDns(event: Event): List<Evidence> {
        val host = event.attr("hostname")?.lowercase() ?: return emptyList()
        val out = mutableListOf<Evidence>()

        // --- DGA-like domain: high-entropy long label. ----------------------------------------
        val label = host.substringBefore('.')
        if (label.length >= config.minLabelLengthForDga) {
            val bits = labelEntropyBits(label)
            if (bits >= config.highEntropyLabelBits) {
                out += Evidence(
                    id = "$detectorId:dga:${event.id}",
                    detector = detectorId,
                    packageName = event.packageName,
                    timestamp = event.timestamp,
                    severity = Severity.LOW,
                    confidence = Confidence(min(1.0, (bits - config.highEntropyLabelBits) / 1.0 + 0.4)),
                    reliability = Reliability(0.6),
                    // The hostname is attacker-chosen text.
                    observability = Observability.UNTRUSTED_CONTENT,
                    summary = "Lookup of high-entropy hostname ${redact(host)} " +
                        "(${"%.2f".format(bits)} bits/char), consistent with algorithmic generation.",
                    sourceEventIds = listOf(event.id),
                    attributes = mapOf("hostname" to redact(host), "entropy_bits" to bits.toString()),
                )
            }
        }

        // --- Answer/target inconsistency, only where genuinely observable. --------------------
        val answered = event.attr("resolved_ip")
        val expected = event.attr("expected_ip")
        if (!answered.isNullOrBlank() && !expected.isNullOrBlank() && answered != expected) {
            out += Evidence(
                id = "$detectorId:dnsinconsistency:${event.id}",
                detector = detectorId,
                packageName = event.packageName,
                timestamp = event.timestamp,
                severity = Severity.MEDIUM,
                confidence = Confidence(0.55),
                reliability = Reliability(0.6),
                observability = Observability.DERIVED,
                summary = "Resolution for ${redact(host)} differs from the previously observed address.",
                sourceEventIds = listOf(event.id),
                attributes = mapOf("hostname" to redact(host)),
            )
        }
        return out
    }

    /** Shannon entropy per character of a domain label. */
    internal fun labelEntropyBits(label: String): Double {
        if (label.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>()
        for (c in label) counts[c] = (counts[c] ?: 0) + 1
        var h = 0.0
        for (c in counts.values) {
            val p = c.toDouble() / label.length
            h -= p * (ln(p) / LN2)
        }
        return h
    }

    private fun trimEndpoints() {
        if (endpoints.size <= config.maxEndpoints) return
        val victims = endpoints.entries.sortedBy { it.value.lastSeen }
            .take(endpoints.size - config.maxEndpoints)
            .map { it.key }
        victims.forEach { endpoints.remove(it) }
    }

    private fun redact(s: String): String = Sanitizer.sanitize(s, 120).text

    fun trackedEndpoints(): Int = endpoints.size

    private companion object {
        const val LN2 = 0.6931471805599453
    }
}

/** Small helper so callers can compare doubles in tests without importing kotlin.math. */
internal fun near(a: Double, b: Double, eps: Double = 1e-6) = abs(a - b) < eps
