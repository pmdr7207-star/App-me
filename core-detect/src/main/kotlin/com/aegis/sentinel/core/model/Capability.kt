package com.aegis.sentinel.core.model

/**
 * Access class required for a capability. This is the single source of truth that keeps the
 * product honest about what a non-root app can actually do on Android 16.
 */
enum class AccessClass {
    /** Works with no permission beyond a normal install. */
    NORMAL_APP,

    /** Requires a runtime permission the user can grant in a dialog. */
    USER_PERMISSION,

    /** Requires a Settings-mediated special access grant (usage access, accessibility, VPN...). */
    SPECIAL_ACCESS,

    /** Requires device owner / profile owner provisioning. */
    DEVICE_OWNER,

    /** Requires platform signature or OEM privilege. */
    SYSTEM_OEM,

    /** Requires root. Out of scope for this product. */
    ROOT_ONLY,

    /** Verified as not achievable on the target platform. */
    UNAVAILABLE,

    /** Not yet verified. MUST NOT be relied upon on a production path. */
    UNKNOWN,
}

/**
 * A capability the product may want to use, with its verified access class.
 *
 * [productionEnabled] is false for anything that is not verified-supported. The pipeline refuses to
 * consume a capability that is not production enabled, which structurally prevents imaginary
 * features from reaching users.
 */
data class Capability(
    val id: String,
    val description: String,
    val accessClass: AccessClass,
    val productionEnabled: Boolean,
    val notes: String = "",
) {
    init {
        require(!(productionEnabled && accessClass == AccessClass.UNKNOWN)) {
            "capability $id is UNKNOWN and cannot be production enabled"
        }
        require(
            !(
                productionEnabled &&
                    (
                        accessClass == AccessClass.ROOT_ONLY ||
                            accessClass == AccessClass.UNAVAILABLE
                        )
                )
        ) {
            "capability $id is not achievable on a non-root device and cannot be production enabled"
        }
    }
}

/**
 * Registry of capabilities. Detectors ask this before running, so a detector whose data source is
 * unavailable degrades to "not run" instead of fabricating a result.
 */
class CapabilityRegistry(capabilities: List<Capability>) {
    private val byId: Map<String, Capability> = capabilities.associateBy { it.id }

    val all: List<Capability> = capabilities.sortedBy { it.id }

    operator fun get(id: String): Capability? = byId[id]

    /** True only when the capability is known, achievable and enabled for production use. */
    fun isUsable(id: String): Boolean {
        val c = byId[id] ?: return false
        return c.productionEnabled
    }

    fun requireUsable(id: String): Capability {
        val c = byId[id] ?: error("unknown capability: $id")
        check(c.productionEnabled) { "capability $id is not usable on this device" }
        return c
    }
}
