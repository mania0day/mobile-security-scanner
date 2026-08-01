"""
Risk Weights and Scoring Logic for the Mobile Security Scanner.

Why weights?
Not all security findings are equal. A rooted device is a critical
finding regardless of what apps are installed. A debug certificate
is worth noting but isn't a crisis. These weights encode Android
security domain knowledge into the scoring engine.

Score scale:
  0-25    LOW      — informational findings only
  26-50   MEDIUM   — some concerning signals
  51-75   HIGH     — clear security issues present
  76-100  CRITICAL — serious security compromise indicated
"""

# Device-level weights (out of 100 for device score)
DEVICE_WEIGHTS = {
    "rooted": 25,              # su binary or Magisk found
    "bootloader_unlocked": 15, # Unlocked bootloader / verified boot not enforcing
    "debuggable_build": 8,     # ro.debuggable=1
    "selinux_permissive": 10,  # SELinux not enforcing
    "test_keys": 6,            # Not production-signed ROM
    "ro_secure": 10,           # ro.secure=0 — unrestricted ADB root shell
}

# Per-app risk weights (out of 100, then averaged across all apps)
APP_WEIGHTS = {
    # YARA rule hits
    "yara_critical": 20,       # Matches a critical malware rule
    "yara_high": 12,           # Matches high-severity rule
    "yara_medium": 5,          # Matches medium-severity rule

    # Certificate issues
    "cert_expired": 8,
    "cert_weak_algorithm": 5,  # MD5/SHA1 signing

    # Permission risk
    "permission_critical": 10, # BIND_ACCESSIBILITY, BIND_DEVICE_ADMIN, etc.
    "permission_high": 5,
    "permission_medium": 2,

    # Obfuscation/packing (suspicious, not necessarily malicious)
    "apkid_obfuscator": 4,
    "apkid_packer": 6,
    "apkid_anti_debug": 8,
    "apkid_anti_vm": 8,

    # MobSF (deep scan)
    "mobsf_security_score_low": 8,   # MobSF score < 60
    "mobsf_high_severity": 6,        # Each high-severity finding
}

# Risk level thresholds
RISK_LEVELS = {
    "critical": 76,
    "high": 51,
    "medium": 26,
    "low": 0,
}


def score_to_level(score: int) -> str:
    """Convert a numeric risk score to a named level."""
    if score >= RISK_LEVELS["critical"]:
        return "CRITICAL"
    elif score >= RISK_LEVELS["high"]:
        return "HIGH"
    elif score >= RISK_LEVELS["medium"]:
        return "MEDIUM"
    else:
        return "LOW"
