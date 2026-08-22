package com.aegis.sentinel.platform

import android.content.Context
import com.aegis.sentinel.core.model.CapabilityRegistry
import com.aegis.sentinel.core.perf.ResourceGovernor
import com.aegis.sentinel.core.pipeline.DetectionPipeline
import com.aegis.sentinel.core.response.ResponsePolicyEngine
import com.aegis.sentinel.platform.capability.CapabilityDiscovery
import com.aegis.sentinel.platform.evidence.EvidenceStore
import java.util.concurrent.atomic.AtomicInteger

/**
 * Process-wide singletons, wired once at startup.
 *
 * Capability discovery runs first: every downstream component receives a registry describing what
 * this specific device can actually do, so nothing operates on an assumption.
 */
class AegisRuntime private constructor(
    val capabilities: CapabilityRegistry,
    val pipeline: DetectionPipeline,
    val governor: ResourceGovernor,
    val responsePolicy: ResponsePolicyEngine,
    val evidenceStore: EvidenceStore,
    val deviceProfile: CapabilityDiscovery.DeviceProfile,
) {
    companion object {
        private val sessionCounter = AtomicInteger(0)

        @Volatile
        private var instance: AegisRuntime? = null

        fun create(context: Context): AegisRuntime {
            instance?.let { return it }
            synchronized(this) {
                instance?.let { return it }

                val appContext = context.applicationContext
                val capabilities = CapabilityDiscovery.discover(appContext)
                val runtime = AegisRuntime(
                    capabilities = capabilities,
                    pipeline = DetectionPipeline(
                        config = DetectionPipeline.Config(
                            sessionId = sessionCounter.incrementAndGet(),
                        ),
                    ),
                    governor = ResourceGovernor(),
                    responsePolicy = ResponsePolicyEngine(capabilities),
                    evidenceStore = EvidenceStore(appContext),
                    deviceProfile = CapabilityDiscovery.profile(appContext),
                )
                instance = runtime
                return runtime
            }
        }

        fun get(): AegisRuntime? = instance
    }
}
