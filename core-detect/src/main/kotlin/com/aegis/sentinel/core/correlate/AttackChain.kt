package com.aegis.sentinel.core.correlate

import com.aegis.sentinel.core.model.Confidence
import com.aegis.sentinel.core.model.EpochMillis
import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.EventType
import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Reliability
import com.aegis.sentinel.core.model.Severity

/**
 * Correlates ordered events into recognized attack chains.
 *
 * A chain is a sequence of stages that must occur in order, attributable to the same subject,
 * within a bounded time window. Chains produce stronger evidence than their individual stages
 * because the *ordering* itself is informative — but a chain is still only one detector, and the
 * fusion layer caps how much any single detector can contribute.
 */
class AttackChainCorrelator(private val chains: List<ChainDefinition> = DEFAULT_CHAINS) {

    val detectorId = "correlate.attackchain"

    /** One stage of a chain: a predicate over a normalized event. */
    data class Stage(
        val name: String,
        val matches: (Event) -> Boolean,
    )

    data class ChainDefinition(
        val id: String,
        val title: String,
        val stages: List<Stage>,
        val windowMs: Long,
        val severity: Severity,
        /** Chains built only from weak/untrusted signals must not claim high confidence. */
        val baseConfidence: Double = 0.6,
    ) {
        init {
            require(stages.size >= 2) { "a chain needs at least two stages" }
        }
    }

    data class ChainMatch(
        val definition: ChainDefinition,
        val subject: String,
        val events: List<Event>,
        val startedAt: EpochMillis,
        val completedAt: EpochMillis,
    )

    private data class Progress(var stageIndex: Int, val events: MutableList<Event>, var startedAt: EpochMillis)

    // subject -> chainId -> progress
    private val progress = HashMap<String, HashMap<String, Progress>>()

    /**
     * Feed an event. Returns evidence for any chain that completed on this event.
     * Events must be supplied in non-decreasing timestamp order per subject.
     */
    fun onEvent(event: Event): List<Evidence> {
        val subject = event.packageName ?: return emptyList()
        val perChain = progress.getOrPut(subject) { HashMap() }
        val completed = mutableListOf<Evidence>()

        for (def in chains) {
            val p = perChain.getOrPut(def.id) { Progress(0, mutableListOf(), event.timestamp) }

            // Expire a partially matched chain that has gone stale.
            if (p.stageIndex > 0 && event.timestamp - p.startedAt > def.windowMs) {
                p.stageIndex = 0
                p.events.clear()
            }

            val stage = def.stages[p.stageIndex]
            if (stage.matches(event)) {
                if (p.stageIndex == 0) {
                    p.startedAt = event.timestamp
                    p.events.clear()
                }
                p.events.add(event)
                p.stageIndex++

                if (p.stageIndex == def.stages.size) {
                    val match = ChainMatch(
                        definition = def,
                        subject = subject,
                        events = p.events.toList(),
                        startedAt = p.startedAt,
                        completedAt = event.timestamp,
                    )
                    completed += toEvidence(match)
                    p.stageIndex = 0
                    p.events.clear()
                }
            }
        }
        return completed
    }

    private fun toEvidence(m: ChainMatch): Evidence {
        // A chain is only as trustworthy as its weakest observation.
        val weakest = m.events.minOf { observabilityRank(it.observability) }
        val observability = when (weakest) {
            0 -> Observability.UNTRUSTED_CONTENT
            1 -> Observability.DERIVED
            else -> Observability.PLATFORM_DIRECT
        }
        val stageNames = m.definition.stages.joinToString(" → ") { it.name }
        return Evidence(
            id = "$detectorId:${m.definition.id}:${m.subject}:${m.completedAt}",
            detector = detectorId,
            packageName = m.subject,
            timestamp = m.completedAt,
            severity = m.definition.severity,
            confidence = Confidence(m.definition.baseConfidence),
            reliability = Reliability(0.85),
            observability = observability,
            summary = "${m.definition.title}: $stageNames " +
                "(completed in ${(m.completedAt - m.startedAt) / 1000}s).",
            sourceEventIds = m.events.map { it.id },
            attributes = mapOf(
                "chain_id" to m.definition.id,
                "stages" to m.definition.stages.size.toString(),
                "duration_ms" to (m.completedAt - m.startedAt).toString(),
            ),
        )
    }

    private fun observabilityRank(o: Observability): Int = when (o) {
        Observability.UNTRUSTED_CONTENT -> 0
        Observability.DERIVED -> 1
        Observability.PLATFORM_DIRECT -> 2
    }

    fun reset() = progress.clear()

    companion object {
        private const val HOUR = 60L * 60 * 1000

        /**
         * Default chains. Each one describes a sequence that is meaningfully more suspicious than
         * the sum of its parts.
         */
        val DEFAULT_CHAINS: List<ChainDefinition> = listOf(
            ChainDefinition(
                id = "sideload_to_exfil",
                title = "Sideloaded install followed by sensitive access and upload",
                stages = listOf(
                    Stage("install from non-store source") { e ->
                        e.type == EventType.APP_INSTALLED &&
                            e.attr("installer_trusted")?.toBoolean() == false
                    },
                    Stage("sensitive permission granted") { e ->
                        e.type == EventType.PERMISSION_GRANTED &&
                            e.attr("dangerous")?.toBoolean() == true
                    },
                    Stage("outbound transfer") { e ->
                        e.type == EventType.NETWORK_FLOW &&
                            (e.num("bytes_out") ?: 0.0) > 512_000
                    },
                ),
                windowMs = 24 * HOUR,
                severity = Severity.HIGH,
                baseConfidence = 0.65,
            ),
            ChainDefinition(
                id = "download_install_persist",
                title = "Download → install → accessibility abuse",
                stages = listOf(
                    Stage("APK downloaded") { e ->
                        e.type == EventType.DOWNLOAD_COMPLETED &&
                            e.attr("mime")?.contains("android.package-archive") == true
                    },
                    Stage("package installed") { e -> e.type == EventType.APP_INSTALLED },
                    Stage("accessibility service enabled") { e ->
                        e.type == EventType.SPECIAL_ACCESS_CHANGED &&
                            e.attr("access") == "accessibility" &&
                            e.attr("enabled")?.toBoolean() == true
                    },
                ),
                windowMs = 6 * HOUR,
                severity = Severity.CRITICAL,
                baseConfidence = 0.7,
            ),
            ChainDefinition(
                id = "mass_encrypt_then_contact",
                title = "Mass file rewrite followed by outbound contact",
                stages = listOf(
                    Stage("bulk file modification") { e ->
                        e.type == EventType.FILE_WRITE &&
                            e.attr("extension_changed")?.toBoolean() == true
                    },
                    Stage("high-entropy write") { e ->
                        e.type == EventType.FILE_WRITE && (e.num("entropy") ?: 0.0) >= 7.5
                    },
                    Stage("outbound contact") { e -> e.type == EventType.NETWORK_FLOW },
                ),
                windowMs = 2 * HOUR,
                severity = Severity.CRITICAL,
                baseConfidence = 0.7,
            ),
        )
    }
}
