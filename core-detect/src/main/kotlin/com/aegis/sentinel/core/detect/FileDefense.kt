package com.aegis.sentinel.core.detect

import com.aegis.sentinel.core.model.Confidence
import com.aegis.sentinel.core.model.EpochMillis
import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.EventType
import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Reliability
import com.aegis.sentinel.core.model.Severity
import kotlin.math.min

/**
 * Detects encryption-like mass file transformation from *observable* file activity.
 *
 * Honest scope: a non-root app sees the directory trees it has access to (its own storage, plus
 * user-selected trees via SAF and media via MediaStore). It does not see other apps' private data.
 * The Android layer is responsible for only feeding events it genuinely observed; this detector
 * reasons about whatever it is given.
 *
 * Signal model — no single one of these is conclusive, so the detector emits separate evidence
 * items and lets fusion combine them:
 *   - write burst rate (files/second within a sliding window)
 *   - directory concentration (a single tree being rewritten)
 *   - extension churn (files acquiring a new/unknown extension)
 *   - entropy rise (post-write content looks like ciphertext)
 *   - type/magic mismatch (extension says JPEG, header says otherwise)
 */
class FileDefenseDetector(
    private val config: Config = Config(),
) {
    data class Config(
        val windowMs: Long = 60_000,
        val burstFileThreshold: Int = 25,
        val highBurstFileThreshold: Int = 80,
        val concentrationThreshold: Double = 0.7,
        val entropyCiphertextBits: Double = 7.5,
        val entropyMinSamples: Int = 5,
        val maxTrackedEvents: Int = 2000,
    )

    private data class Write(
        val timestamp: EpochMillis,
        val path: String,
        val directory: String,
        val newExtension: String?,
        val extensionChanged: Boolean,
        val entropy: Double?,
        val typeMismatch: Boolean,
    )

    private val writes = ArrayDeque<Write>()

    val detectorId = "file.transformation"

    /**
     * Feed one file event and receive any evidence it triggers.
     * Returns an empty list for events that are not file writes or that do not cross a threshold.
     */
    fun onEvent(event: Event, now: EpochMillis = event.timestamp): List<Evidence> {
        if (event.type != EventType.FILE_WRITE &&
            event.type != EventType.FILE_RENAME
        ) {
            return emptyList()
        }
        val path = event.attr("path") ?: return emptyList()

        writes.addLast(
            Write(
                timestamp = event.timestamp,
                path = path,
                directory = path.substringBeforeLast('/', ""),
                newExtension = path.substringAfterLast('.', "").lowercase().ifBlank { null },
                extensionChanged = event.attr("extension_changed")?.toBoolean() ?: false,
                entropy = event.num("entropy"),
                typeMismatch = event.attr("type_mismatch")?.toBoolean() ?: false,
            )
        )
        while (writes.size > config.maxTrackedEvents) writes.removeFirst()
        evict(now)

        return evaluate(event.packageName, now)
    }

    private fun evict(now: EpochMillis) {
        while (writes.isNotEmpty() && now - writes.first().timestamp > config.windowMs) {
            writes.removeFirst()
        }
    }

    private fun evaluate(pkg: String?, now: EpochMillis): List<Evidence> {
        val window = writes.toList()
        if (window.size < config.burstFileThreshold) return emptyList()

        val out = mutableListOf<Evidence>()
        val distinctFiles = window.map { it.path }.distinct().size

        // --- 1. Write burst -------------------------------------------------------------------
        val severity = if (distinctFiles >= config.highBurstFileThreshold) {
            Severity.HIGH
        } else {
            Severity.MEDIUM
        }
        out += Evidence(
            id = "$detectorId:burst:${now}",
            detector = detectorId,
            packageName = pkg,
            timestamp = now,
            severity = severity,
            confidence = Confidence(min(1.0, distinctFiles.toDouble() / config.highBurstFileThreshold)),
            reliability = Reliability(0.9),
            observability = Observability.PLATFORM_DIRECT,
            summary = "$distinctFiles files modified within ${config.windowMs / 1000}s.",
            attributes = mapOf(
                "distinct_files" to distinctFiles.toString(),
                "window_ms" to config.windowMs.toString(),
            ),
        )

        // --- 2. Directory concentration -------------------------------------------------------
        val byDir = window.groupingBy { it.directory }.eachCount()
        val topDir = byDir.maxByOrNull { it.value }
        if (topDir != null) {
            val concentration = topDir.value.toDouble() / window.size
            if (concentration >= config.concentrationThreshold) {
                out += Evidence(
                    id = "$detectorId:concentration:${now}",
                    detector = detectorId,
                    packageName = pkg,
                    timestamp = now,
                    severity = Severity.MEDIUM,
                    confidence = Confidence(min(1.0, concentration)),
                    reliability = Reliability(0.85),
                    observability = Observability.DERIVED,
                    summary = "${(concentration * 100).toInt()}% of writes concentrated in one directory.",
                    attributes = mapOf("concentration" to concentration.toString()),
                )
            }
        }

        // --- 3. Extension churn ---------------------------------------------------------------
        val changed = window.count { it.extensionChanged }
        if (changed >= config.burstFileThreshold / 2) {
            val distinctNewExt = window.filter { it.extensionChanged }
                .mapNotNull { it.newExtension }.distinct()
            // A single new extension applied en masse is the classic ransomware pattern.
            val uniform = distinctNewExt.size == 1
            out += Evidence(
                id = "$detectorId:extchurn:${now}",
                detector = detectorId,
                packageName = pkg,
                timestamp = now,
                severity = if (uniform) Severity.HIGH else Severity.MEDIUM,
                confidence = Confidence(min(1.0, changed.toDouble() / window.size)),
                reliability = Reliability(0.85),
                observability = Observability.DERIVED,
                summary = if (uniform) {
                    "$changed files renamed to a single new extension '.${distinctNewExt.first()}'."
                } else {
                    "$changed files changed extension."
                },
                attributes = mapOf(
                    "changed" to changed.toString(),
                    "uniform_extension" to uniform.toString(),
                ),
            )
        }

        // --- 4. Entropy rise ------------------------------------------------------------------
        val entropies = window.mapNotNull { it.entropy }
        if (entropies.size >= config.entropyMinSamples) {
            val high = entropies.count { it >= config.entropyCiphertextBits }
            val ratio = high.toDouble() / entropies.size
            if (ratio >= 0.6) {
                out += Evidence(
                    id = "$detectorId:entropy:${now}",
                    detector = detectorId,
                    packageName = pkg,
                    timestamp = now,
                    severity = Severity.HIGH,
                    confidence = Confidence(min(1.0, ratio)),
                    reliability = Reliability(0.8),
                    observability = Observability.DERIVED,
                    summary = "$high of ${entropies.size} written files have ciphertext-like entropy " +
                        "(>= ${config.entropyCiphertextBits} bits/byte).",
                    attributes = mapOf("high_entropy_ratio" to ratio.toString()),
                )
            }
        }

        // --- 5. Declared-type mismatch --------------------------------------------------------
        val mismatches = window.count { it.typeMismatch }
        if (mismatches >= config.entropyMinSamples) {
            out += Evidence(
                id = "$detectorId:typemismatch:${now}",
                detector = detectorId,
                packageName = pkg,
                timestamp = now,
                severity = Severity.MEDIUM,
                confidence = Confidence(min(1.0, mismatches.toDouble() / window.size)),
                reliability = Reliability(0.75),
                observability = Observability.DERIVED,
                summary = "$mismatches files whose content no longer matches their extension.",
                attributes = mapOf("mismatches" to mismatches.toString()),
            )
        }

        return out
    }

    /** Current number of tracked writes; used by the resource governor and by tests. */
    fun trackedCount(): Int = writes.size

    fun reset() = writes.clear()
}
