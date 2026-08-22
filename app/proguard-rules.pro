# Aegis Sentinel X — R8 configuration.
#
# The detection core is plain Kotlin with no reflection, so it shrinks and obfuscates safely.
# Only the entries the Android framework instantiates by name need to be kept.

-keep class com.aegis.sentinel.platform.service.AegisMonitorService { *; }
-keep class com.aegis.sentinel.platform.service.AegisVpnService { *; }
-keep class com.aegis.sentinel.platform.receiver.BootCompletedReceiver { *; }
-keep class com.aegis.sentinel.platform.receiver.PackageEventReceiver { *; }

# Keep line numbers so crash reports from an obfuscated release remain investigable.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
