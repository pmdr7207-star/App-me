# Capability Matrix — Android 16 (API 36), non-root, Samsung Galaxy A54 5G (SM-A546E)

This is the authoritative statement of what Aegis Sentinel X **can** and **cannot** do. Anything
not verified here is disabled on the production path by `Capability`'s own constructor invariants
(`core-detect/.../model/Capability.kt`), which throw if an `UNKNOWN`, `ROOT_ONLY` or `UNAVAILABLE`
capability is marked production-enabled.

Access classes: `NORMAL_APP`, `USER_PERMISSION`, `SPECIAL_ACCESS`, `DEVICE_OWNER`, `SYSTEM_OEM`,
`ROOT_ONLY`, `UNAVAILABLE`, `UNKNOWN`.

## Implemented and enabled

| Capability | Access class | How it is verified at runtime | Real limits |
|---|---|---|---|
| Enumerate installed apps | `NORMAL_APP` | `queryIntentActivities` for `MAIN`/`LAUNCHER` returns > 0 | **Only launchable apps.** `QUERY_ALL_PACKAGES` is deliberately *not* requested (Play-restricted), so apps without a launcher activity are invisible. The UI states the count observed rather than implying completeness. |
| Read signing certificates | `NORMAL_APP` | `GET_SIGNING_CERTIFICATES` returns non-null `signingInfo` | Only for visible packages. |
| Read install source (store vs sideload) | `NORMAL_APP` | `getInstallSourceInfo` succeeds | Throws for non-visible packages; treated as "unknown", never as "trusted". |
| Audit which apps hold accessibility access | `NORMAL_APP` | `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES` readable | Read-only audit. This app ships **no** accessibility service of its own. |
| Detect own overlay permission | `NORMAL_APP` | `Settings.canDrawOverlays` | Self only. Enumerating *other* apps' `SYSTEM_ALERT_WINDOW` state is not available to us. |
| Network transport/capability state | `NORMAL_APP` | `ConnectivityManager` non-null | Metadata only. |
| File monitoring in user-granted trees | `USER_PERMISSION` | SAF tree grant | **Exactly** the trees the user picks. Other apps' private storage is never visible without root. |
| Battery / thermal / power-save state | `NORMAL_APP` | `PowerManager`, `BatteryManager` non-null | Drives the resource governor. |
| Post notifications | `USER_PERMISSION` | `POST_NOTIFICATIONS` granted | Runtime permission since Android 13. |
| App usage events | `SPECIAL_ACCESS` | `AppOpsManager.OPSTR_GET_USAGE_STATS == MODE_ALLOWED` | Requires the user to enable Usage Access in Settings. Detectors depending on it stay off until granted. |
| Local flow observation (VpnService) | `SPECIAL_ACCESS` | Service declared **and** `VpnService.prepare() == null` | See the network section below — metadata only. |
| Open system app-details screen | `NORMAL_APP` | Intent resolves | The supported hand-off for permission revocation. |
| Request uninstall | `NORMAL_APP` | `ACTION_DELETE` resolves | Shows the **system confirmation dialog**. Silent uninstall is impossible. |
| Persist encrypted evidence | `NORMAL_APP` | `filesDir.canWrite()` | AES-256-GCM via Android Keystore + chained HMAC. |

## Declared but disabled (honest gaps)

| Capability | Access class | Why it is off |
|---|---|---|
| Observe other apps' notifications | `SPECIAL_ACCESS` | **Not implemented.** No `NotificationListenerService` is shipped, so no notification telemetry is collected. Declared so the UI can say so explicitly. |
| Force-stop another app | `DEVICE_OWNER` | `forceStopPackage` is a system API. A non-root, non-device-owner app cannot terminate another app. Surfaced in the UI as `SPECIAL_PRIVILEGE`, never silently omitted. |

## Verified impossible (and therefore never claimed)

These are stated because a security product that overstates coverage is itself a hazard.

- **TLS/HTTPS payload inspection** — impossible without a user-installed CA *and* the target app
  trusting user CAs. Since Android 7, apps do not trust user CAs by default. Not attempted.
- **Certificate-pinning bypass** — out of scope; would be offensive tooling.
- **QUIC / DoH / DoT content** — encrypted; only endpoint and timing metadata is observable.
- **Kernel or syscall visibility** — requires root/eBPF. Not available.
- **Other apps' private data directories** — blocked by the SELinux sandbox.
- **Traffic of other VPN apps** — only one VPN can hold the tunnel at a time.
- **Inbound connections** — a non-root local VPN sees egress only.
- **Silent uninstall / silent permission revocation** — device owner only.
- **Universal decryption of ransomware-encrypted files** — cryptographically impossible. The
  product targets *early detection*, alerting and evidence preservation, never recovery promises.

## Network visibility, precisely

With the local `VpnService` enabled for a user-selected app, Aegis observes per packet:
protocol (TCP/UDP/ICMP), destination address and port, packet size, and timing. From that it
derives: beaconing regularity (coefficient of variation of inter-arrival times), endpoint
cardinality, and volume anomalies.

Two honest caveats implemented in code:

1. **No forwarding.** Packets are read from the TUN device and dropped. Nothing is proxied
   off-device. Consequently, enabling observation interrupts connectivity for the selected app,
   so it is opt-in, per-app and never device-wide by default (`AegisVpnService.establish` stops
   the service when no package is selected).
2. **Attribution honesty.** Per-app attribution is only recorded when exactly **one** app is in
   scope. With several allowed apps the tunnel cannot distinguish them, so the flow is recorded
   without a package rather than guessed.

## Android 16 behaviour changes accounted for

| Change | Handling |
|---|---|
| Edge-to-edge enforced for `targetSdk 36` | `enableEdgeToEdge()`; Compose consumes insets. No fixed system-bar assumptions. |
| Predictive back mandatory | `android:enableOnBackInvokedCallback="true"`; no `onBackPressed` override anywhere. |
| Large-screen orientation/resizability overrides | No `screenOrientation` or aspect-ratio lock is declared, so the adaptive behaviour is a non-issue. |
| `dataSync` FGS 6-hour/24h cap (Android 15+) | Monitoring uses `specialUse`, **not** `dataSync`, so continuous protection is not silently killed. Subtype property declared for review. |
| `BOOT_COMPLETED` cannot start certain FGS types | `specialUse` is not on the restricted list; the boot start is additionally wrapped in `runCatching` and records failure instead of assuming success. |
| Job runtime quotas tightened | Analysis is event-driven; the governor lengthens batch windows instead of holding long jobs. |
| Ordered-broadcast priority no longer global | No cross-process broadcast ordering is relied upon. |
| Local Network Permission (phased) | No LAN scanning, mDNS or NSD is performed, so the app is unaffected. |
| Safer intents | All internal broadcasts are explicit and non-exported. |

## Device profile (discovered, never assumed)

`CapabilityDiscovery.profile()` reads model, manufacturer, SDK level, CPU core count, total RAM
and supported ABIs at runtime. Nothing about the A54's NPU/GPU is assumed; no ML delegate is
claimed. The current release uses deterministic rules plus classical streaming statistics
(EWMA, median/MAD, Page-Hinkley, Shannon entropy, token-bucket), which is why it needs no
accelerator and no model file — see `docs/ARCHITECTURE.md` for why an LLM is not bundled.
