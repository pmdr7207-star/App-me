package com.aegis.sentinel.core.pipeline

import com.aegis.sentinel.core.correlate.AttackChainCorrelator
import com.aegis.sentinel.core.detect.FileDefenseDetector
import com.aegis.sentinel.core.detect.NetworkBehaviorDetector
import com.aegis.sentinel.core.fusion.EvidenceFusion
import com.aegis.sentinel.core.graph.ThreatGraph
import com.aegis.sentinel.core.memory.AdaptiveMemory
import com.aegis.sentinel.core.memory.BehaviorBaseline
import com.aegis.sentinel.core.model.Assessment
import com.aegis.sentinel.core.model.EpochMillis
import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Verdict
import com.aegis.sentinel.core.stats.TokenBucket

/**
 * EVENT → NORMALIZE → FEATURES → TEMPORAL CONTEXT → BASELINE → ANOMALY →
 * CROSS-SIGNAL CORRELATION → CONFIDENCE → THREAT SCORE → POLICY
 *
 * This class owns the ordering and the backpressure. It is intentionally free of Android types so
 * the whole decision path is unit-testable on the JVM.
 */
class DetectionPipeline(
    private val fileDefense: FileDefenseDetector = FileDefenseDetector(),
    private val network: NetworkBehaviorDetector = NetworkBehaviorDetector(),
    private val correlator: AttackChainCorrelator = AttackChainCorrelator(),
    private val fusion: EvidenceFusion = EvidenceFusion(),
    private val memory: AdaptiveMemory = AdaptiveMemory(),
    private val baseline: BehaviorBaseline = BehaviorBaseline(),
    private val graph: ThreatGraph = ThreatGraph(),
    private val config: Config = Config(),
) {
    data class Config(
        /** Hard ceiling on events processed per second before adaptive sampling kicks in. */
        val maxEventsPerSecond: Double = 200.0,
        val burstCapacity: Double = 400.0,
        val maxEvidencePerSubject: Int = 200,
        val sessionId: Int = 0,
    )

    private val bucket = TokenBucket(config.burstCapacity, config.maxEventsPerSecond)
    private val evidenceBySubject = LinkedHashMap<String, ArrayDeque<Evidence>>()

    var droppedEvents: Long = 0L
        private set

    var processedEvents: Long = 0L
        private set

    /**
     * Ingest one normalized event.
     *
     * Under backpressure, events are dropped rather than queued without bound — but the drop is
     * counted and reported, never hidden.
     */
    fun ingest(event: Event, now: EpochMillis = event.timestamp): List<Evidence> {
        if (!bucket.tryConsume(now)) {
            droppedEvents++
            return emptyList()
        }
        processedEvents++

        val produced = buildList {
            addAll(fileDefense.onEvent(event, now))
            addAll(network.onEvent(event))
            addAll(correlator.onEvent(event))
        }

        // Behavioural memory: a behaviour seen alongside evidence is never allowed to become
        // "normal". This is the anti-poisoning gate on baseline updates.
        val suspicious = produced.any { it.supportsMalicious }
        event.packageName?.let { pkg ->
            memory.observe(
                key = memoryKey(pkg, event),
                now = now,
                sessionId = config.sessionId,
                suspicious = suspicious,
            )
            event.numeric.forEach { (feature, value) ->
                baseline.update("$pkg:$feature", value, suspicious = suspicious)
            }
        }

        produced.forEach { e ->
            graph.ingestEvidence(e)
            val subject = e.packageName ?: "system"
            val q = evidenceBySubject.getOrPut(subject) { ArrayDeque() }
            q.addLast(e)
            while (q.size > config.maxEvidencePerSubject) q.removeFirst()
        }
        return produced
    }

    /** Fuse everything currently known about a subject into an auditable assessment. */
    fun assess(subject: String, now: EpochMillis): Assessment {
        val evidence = evidenceBySubject[subject]?.toList().orEmpty()
        return fusion.assess(subject, evidence, now)
    }

    fun subjects(): Set<String> = evidenceBySubject.keys.toSet()

    fun evidenceFor(subject: String): List<Evidence> =
        evidenceBySubject[subject]?.toList().orEmpty()

    fun threatGraph(): ThreatGraph = graph

    fun adaptiveMemory(): AdaptiveMemory = memory

    fun behaviorBaseline(): BehaviorBaseline = baseline

    /** Assess every known subject; used for the dashboard. */
    fun assessAll(now: EpochMillis): List<Assessment> =
        subjects().map { assess(it, now) }
            .sortedByDescending { it.score }

    fun highestVerdict(now: EpochMillis): Verdict =
        assessAll(now).maxByOrNull { it.verdict.ordinal }?.verdict ?: Verdict.UNKNOWN

    private fun memoryKey(pkg: String, event: Event): String {
        val discriminator = event.attr("endpoint")
            ?: event.attr("hostname")
            ?: event.attr("permission")
            ?: event.type.name
        return "$pkg|${event.type.name}|$discriminator"
    }
}
