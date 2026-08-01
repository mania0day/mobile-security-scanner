"""
Pipeline definitions for the Mobile Security Scanner (Android & iOS).

Pipelines structure execution order for both platforms and scan modes.
"""

# ─────────────────────────────────────────────
# ANDROID PIPELINES
# ─────────────────────────────────────────────
ANDROID_MINIMAL_PIPELINE: list[str] = [
    "adb",               # 1. Detect device & collect hardware info
    "apk_inventory",     # 2. List all installed packages
    "apk_extractor",     # 3. Pull APK files from device
    "apkid",             # 4. Detect packers/obfuscators
    "androguard",        # 5. Parse manifests, permissions, components
    "certificate",       # 6. Analyze signing certificates
    "permission_analyzer",  # 7. Classify permissions by risk
    "root_detection",    # 8. Check for root/tamper indicators
    "cve_checker",       # 9. Check known CVEs vs security patch level
    "hash_lookup",       # 10. Generate SHA256 (no VT in minimal mode)
    "yara",              # 11. Scan with local YARA rules
    "risk_engine",       # 12. Aggregate and score everything
    "report_generator",  # 13. Generate reports
]

ANDROID_DEEP_PIPELINE: list[str] = [
    "adb",
    "apk_inventory",
    "apk_extractor",
    "apkid",
    "androguard",
    "certificate",
    "permission_analyzer",
    "root_detection",
    "cve_checker",       # CVE vulnerability scan
    "hash_lookup",       # Runs VT lookup when VT_API_KEY is present
    "yara",
    "mobsf",             # Deep static analysis via REST API
    "mvt",               # MVT Android spyware IOC check
    "risk_engine",       # Aggregate including CVE data
    "report_generator",
]

# Legacy alias
MINIMAL_PIPELINE = ANDROID_MINIMAL_PIPELINE
DEEP_PIPELINE = ANDROID_DEEP_PIPELINE

# ─────────────────────────────────────────────
# iOS PIPELINES
# ─────────────────────────────────────────────
IOS_MINIMAL_PIPELINE: list[str] = [
    "ios_device",           # 1. Detect iPhone/iPad over USB
    "plist_analyzer",       # 2. Parse Info.plist, permissions & entitlements
    "macho_analyzer",       # 3. Binary mitigations check (PIE, ARC, Canaries)
    "ios_certificate",      # 4. Provisioning profile & Developer Cert analysis
    "jailbreak_detection",  # 5. Jailbreak & tampering detection
    "risk_engine",          # 6. Unified risk scoring
    "report_generator",     # 7. Generate reports
]

IOS_DEEP_PIPELINE: list[str] = [
    "ios_device",
    "plist_analyzer",
    "macho_analyzer",
    "ios_certificate",
    "jailbreak_detection",
    "yara",                 # YARA malware scan
    "mvt",                  # mvt-ios check
    "mobsf",                # MobSF iOS static analysis
    "risk_engine",
    "report_generator",
]
