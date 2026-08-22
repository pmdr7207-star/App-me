package com.aegis.sentinel.core.stats

import kotlin.math.abs
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

/**
 * Bounded streaming statistics. Every structure here has a hard memory ceiling so that a hostile
 * event flood cannot grow the process heap.
 */

/** Exponentially weighted moving average/variance (West's incremental form). */
class Ewma(private val alpha: Double, initialMean: Double = 0.0) {
    init {
        require(alpha > 0.0 && alpha <= 1.0) { "alpha must be in (0,1]" }
    }

    var mean: Double = initialMean
        private set

    var variance: Double = 0.0
        private set

    var count: Long = 0L
        private set

    fun update(x: Double) {
        count++
        if (count == 1L) {
            mean = x
            variance = 0.0
            return
        }
        val delta = x - mean
        mean += alpha * delta
        variance = (1 - alpha) * (variance + alpha * delta * delta)
    }

    fun stdDev(): Double = sqrt(max(0.0, variance))

    /** Z-score guarded against a degenerate (zero variance) baseline. */
    fun zScore(x: Double, floor: Double = 1e-9): Double {
        val sd = stdDev()
        if (sd < floor) return if (abs(x - mean) < floor) 0.0 else DEGENERATE_Z
        return (x - mean) / sd
    }

    companion object {
        /** Returned when the baseline has no spread yet but the sample differs. */
        const val DEGENERATE_Z = 6.0
    }
}

/**
 * Fixed-capacity ring buffer of doubles supporting robust order statistics.
 * Robust statistics (median/MAD) are used instead of mean/sd wherever a single extreme sample
 * could otherwise poison the baseline.
 */
class BoundedSample(val capacity: Int) {
    init {
        require(capacity > 0) { "capacity must be positive" }
    }

    private val buf = DoubleArray(capacity)
    private var writeIndex = 0
    var size: Int = 0
        private set

    fun add(x: Double) {
        buf[writeIndex] = x
        writeIndex = (writeIndex + 1) % capacity
        if (size < capacity) size++
    }

    fun isFull(): Boolean = size == capacity

    fun values(): DoubleArray = DoubleArray(size) { i ->
        val start = if (size < capacity) 0 else writeIndex
        buf[(start + i) % capacity]
    }

    fun median(): Double = medianOf(values())

    /**
     * Median absolute deviation, scaled to be a consistent estimator of sigma for normal data.
     */
    fun mad(): Double {
        if (size == 0) return 0.0
        val v = values()
        val med = medianOf(v)
        val dev = DoubleArray(v.size) { abs(v[it] - med) }
        return 1.4826 * medianOf(dev)
    }

    /** Robust z-score. Falls back to a bounded value when the sample has no spread. */
    fun robustZ(x: Double, floor: Double = 1e-9): Double {
        if (size == 0) return 0.0
        val med = median()
        val mad = mad()
        if (mad < floor) return if (abs(x - med) < floor) 0.0 else Ewma.DEGENERATE_Z
        return (x - med) / mad
    }

    fun mean(): Double {
        if (size == 0) return 0.0
        var s = 0.0
        for (v in values()) s += v
        return s / size
    }

    fun stdDev(): Double {
        if (size < 2) return 0.0
        val m = mean()
        var s = 0.0
        for (v in values()) {
            val d = v - m
            s += d * d
        }
        return sqrt(s / (size - 1))
    }

    /** Coefficient of variation; the standard beaconing regularity measure. */
    fun coefficientOfVariation(): Double {
        val m = mean()
        if (abs(m) < 1e-12) return 0.0
        return stdDev() / m
    }

    companion object {
        fun medianOf(input: DoubleArray): Double {
            if (input.isEmpty()) return 0.0
            val v = input.copyOf()
            v.sort()
            val mid = v.size / 2
            return if (v.size % 2 == 1) v[mid] else (v[mid - 1] + v[mid]) / 2.0
        }
    }
}

/**
 * Page-Hinkley concept drift test.
 *
 * Detects a persistent shift in the mean of a stream while tolerating noise. Used to notice that an
 * app's behaviour has genuinely changed (a real drift signal) rather than reacting to one outlier.
 */
class PageHinkley(
    private val delta: Double = 0.005,
    private val lambda: Double = 12.0,
    private val alpha: Double = 0.9999,
) {
    private var mean = 0.0
    private var n = 0L
    private var cumulative = 0.0
    private var minCumulative = 0.0
    private var maxCumulative = 0.0

    var lastMagnitude: Double = 0.0
        private set

    /** @return true when a drift point is detected; the detector auto-resets on detection. */
    fun update(x: Double): Boolean {
        n++
        mean += (x - mean) / n
        cumulative = cumulative * alpha + (x - mean - delta)
        minCumulative = min(minCumulative, cumulative)
        maxCumulative = max(maxCumulative, cumulative)

        val increase = cumulative - minCumulative
        val decrease = maxCumulative - cumulative
        lastMagnitude = max(increase, decrease)
        if (lastMagnitude > lambda) {
            reset()
            return true
        }
        return false
    }

    fun reset() {
        mean = 0.0
        n = 0
        cumulative = 0.0
        minCumulative = 0.0
        maxCumulative = 0.0
    }
}

/** Shannon entropy in bits per byte over a byte histogram. */
object Entropy {
    fun shannonBitsPerByte(histogram: IntArray, total: Long): Double {
        if (total <= 0L) return 0.0
        var h = 0.0
        for (c in histogram) {
            if (c <= 0) continue
            val p = c.toDouble() / total.toDouble()
            h -= p * (ln(p) / LN2)
        }
        return h
    }

    fun ofBytes(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val hist = IntArray(256)
        for (b in bytes) hist[b.toInt() and 0xFF]++
        return shannonBitsPerByte(hist, bytes.size.toLong())
    }

    private const val LN2 = 0.6931471805599453
}

/** Token-bucket rate limiter used to bound work and to blunt event-flood poisoning. */
class TokenBucket(
    private val capacity: Double,
    private val refillPerSecond: Double,
    nowMs: Long = 0L,
) {
    private var tokens = capacity
    private var lastRefillMs = nowMs

    fun tryConsume(nowMs: Long, amount: Double = 1.0): Boolean {
        refill(nowMs)
        if (tokens >= amount) {
            tokens -= amount
            return true
        }
        return false
    }

    fun available(nowMs: Long): Double {
        refill(nowMs)
        return tokens
    }

    private fun refill(nowMs: Long) {
        if (nowMs <= lastRefillMs) return
        val elapsedSec = (nowMs - lastRefillMs) / 1000.0
        tokens = min(capacity, tokens + elapsedSec * refillPerSecond)
        lastRefillMs = nowMs
    }
}
