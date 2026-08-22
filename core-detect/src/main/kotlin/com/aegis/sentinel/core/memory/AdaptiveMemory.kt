package com.aegis.sentinel.core.memory

import com.aegis.sentinel.core.model.EpochMillis
import com.aegis.sentinel.core.stats.BoundedSample

/**
 * Adaptive behavioural memory with an explicit promotion lifecycle.
 *
 * Design rule enforced here: an observation that is itself suspicious must never be able to widen
 * the baseline that decides what "normal" means. Promotion requires (a) repeated corroboration,
 * (b) elapsed time, and (c) the absence of a suspicion mark. This is what makes the baseline
 * resistant to gradual poisoning.
 */
enum class MemoryStage {
    /** Seen once. Carries no weight in any decision. */
    OBSERVED,

    /** Seen repeatedly. Weak weight, may be revoked freely. */
    PROVISIONAL,

    /** Corroborated over time and over distinct sessions. Moderate weight. */
    VALIDATED,

    /** Long-lived, stable, never associated with a suspicious episode. Full weight. */
    TRUSTED,
}

data class MemoryEntry(
    val key: String,
    val stage: MemoryStage,
    val observations: Int,
    val firstSeen: EpochMillis,
    val lastSeen: EpochMillis,
    val distinctSessions: Int,
    /** Set when this behaviour co-occurred with a suspicious episode. Blocks promotion. */
    val suspicionMarks: Int = 0,
) {
    /** Weight this entry contributes when suppressing an anomaly as "known normal". */
    fun trustWeight(): Double = when (stage) {
        MemoryStage.OBSERVED -> 0.0
        MemoryStage.PROVISIONAL -> 0.25
        MemoryStage.VALIDATED -> 0.6
        MemoryStage.TRUSTED -> 1.0
    }
}

/** Tunables for promotion. Deliberately conservative: promotion is slow, demotion is immediate. */
data class MemoryPolicy(
    val provisionalAfterObservations: Int = 3,
    val validatedAfterObservations: Int = 8,
    val validatedMinAgeMs: Long = 24L * 60 * 60 * 1000,
    val validatedMinSessions: Int = 3,
    val trustedAfterObservations: Int = 20,
    val trustedMinAgeMs: Long = 7L * 24 * 60 * 60 * 1000,
    val trustedMinSessions: Int = 7,
    /** Any suspicion mark at or above this count permanently blocks TRUSTED. */
    val suspicionBlockThreshold: Int = 1,
    val maxEntries: Int = 4000,
)

/** An immutable, restorable snapshot of the whole memory state. */
data class MemorySnapshot(
    val version: Long,
    val createdAt: EpochMillis,
    val entries: Map<String, MemoryEntry>,
)

/**
 * Versioned adaptive memory.
 *
 * All mutating operations bump [version]. [snapshot] / [rollbackTo] give the controlled-adaptation
 * and rollback guarantees required of learned state.
 */
class AdaptiveMemory(
    private val policy: MemoryPolicy = MemoryPolicy(),
) {
    private val entries = LinkedHashMap<String, MemoryEntry>()
    private val snapshots = ArrayDeque<MemorySnapshot>()

    var version: Long = 0L
        private set

    val size: Int get() = entries.size

    fun get(key: String): MemoryEntry? = entries[key]

    fun all(): Map<String, MemoryEntry> = entries.toMap()

    /**
     * Record an observation of a behaviour.
     *
     * @param suspicious when true the observation is recorded but marked; it can never promote the
     *   entry, and it demotes an already promoted entry back to PROVISIONAL.
     */
    fun observe(
        key: String,
        now: EpochMillis,
        sessionId: Int,
        suspicious: Boolean = false,
    ): MemoryEntry {
        val existing = entries[key]
        val updated = if (existing == null) {
            MemoryEntry(
                key = key,
                stage = MemoryStage.OBSERVED,
                observations = 1,
                firstSeen = now,
                lastSeen = now,
                distinctSessions = 1,
                suspicionMarks = if (suspicious) 1 else 0,
            )
        } else {
            val newSessions =
                if (sessionId != lastSessionFor(key)) existing.distinctSessions + 1
                else existing.distinctSessions
            existing.copy(
                observations = existing.observations + 1,
                lastSeen = now,
                distinctSessions = newSessions,
                suspicionMarks = existing.suspicionMarks + if (suspicious) 1 else 0,
            )
        }
        sessionOf[key] = sessionId

        val staged = if (suspicious) demote(updated) else promote(updated, now)
        entries[key] = staged
        evictIfNeeded()
        version++
        return staged
    }

    /**
     * Mark a behaviour as having co-occurred with a suspicious episode. Demotes immediately.
     * This is the anti-poisoning hook: retroactive suspicion removes previously granted trust.
     */
    fun markSuspicious(key: String): MemoryEntry? {
        val e = entries[key] ?: return null
        val marked = demote(e.copy(suspicionMarks = e.suspicionMarks + 1))
        entries[key] = marked
        version++
        return marked
    }

    private fun promote(e: MemoryEntry, now: EpochMillis): MemoryEntry {
        if (e.suspicionMarks >= policy.suspicionBlockThreshold) {
            // Corroboration cannot overcome a suspicion mark; cap at PROVISIONAL.
            val capped =
                if (e.observations >= policy.provisionalAfterObservations) MemoryStage.PROVISIONAL
                else MemoryStage.OBSERVED
            return e.copy(stage = capped)
        }
        val age = now - e.firstSeen
        val stage = when {
            e.observations >= policy.trustedAfterObservations &&
                age >= policy.trustedMinAgeMs &&
                e.distinctSessions >= policy.trustedMinSessions -> MemoryStage.TRUSTED

            e.observations >= policy.validatedAfterObservations &&
                age >= policy.validatedMinAgeMs &&
                e.distinctSessions >= policy.validatedMinSessions -> MemoryStage.VALIDATED

            e.observations >= policy.provisionalAfterObservations -> MemoryStage.PROVISIONAL

            else -> MemoryStage.OBSERVED
        }
        return e.copy(stage = stage)
    }

    private fun demote(e: MemoryEntry): MemoryEntry {
        val stage = when (e.stage) {
            MemoryStage.TRUSTED, MemoryStage.VALIDATED -> MemoryStage.PROVISIONAL
            else -> e.stage
        }
        return e.copy(stage = stage)
    }

    /** Trust weight for a behaviour; 0.0 when unknown. */
    fun trustWeight(key: String): Double = entries[key]?.trustWeight() ?: 0.0

    fun snapshot(now: EpochMillis): MemorySnapshot {
        val snap = MemorySnapshot(version = version, createdAt = now, entries = entries.toMap())
        snapshots.addLast(snap)
        while (snapshots.size > MAX_SNAPSHOTS) snapshots.removeFirst()
        return snap
    }

    fun snapshots(): List<MemorySnapshot> = snapshots.toList()

    /** Restore a previously captured snapshot. Bumps the version (rollback is itself a change). */
    fun rollbackTo(snapshot: MemorySnapshot) {
        entries.clear()
        entries.putAll(snapshot.entries)
        version++
    }

    private val sessionOf = HashMap<String, Int>()

    private fun lastSessionFor(key: String): Int = sessionOf[key] ?: -1

    /** LRU-ish eviction by last seen; keeps memory bounded under event floods. */
    private fun evictIfNeeded() {
        if (entries.size <= policy.maxEntries) return
        val victims = entries.values
            .sortedBy { it.lastSeen }
            .take(entries.size - policy.maxEntries)
        for (v in victims) {
            entries.remove(v.key)
            sessionOf.remove(v.key)
        }
    }

    companion object {
        const val MAX_SNAPSHOTS = 8
    }
}

/**
 * Per-app numeric baseline over named features, using robust statistics.
 *
 * Updates are gated: [update] refuses to fold a sample into the baseline when the caller flags the
 * sample as suspicious, so a burst of malicious activity cannot become the new normal.
 */
class BehaviorBaseline(
    private val sampleCapacity: Int = 64,
    private val maxSeries: Int = 512,
) {
    private val series = LinkedHashMap<String, BoundedSample>()

    fun update(feature: String, value: Double, suspicious: Boolean = false): Boolean {
        if (suspicious) return false
        val s = series.getOrPut(feature) { BoundedSample(sampleCapacity) }
        s.add(value)
        if (series.size > maxSeries) {
            val oldest = series.keys.first()
            series.remove(oldest)
        }
        return true
    }

    fun sample(feature: String): BoundedSample? = series[feature]

    fun robustZ(feature: String, value: Double): Double =
        series[feature]?.robustZ(value) ?: 0.0

    /** A baseline needs enough history before its verdicts are meaningful. */
    fun isEstablished(feature: String, minSamples: Int = 8): Boolean =
        (series[feature]?.size ?: 0) >= minSamples

    fun featureCount(): Int = series.size
}
