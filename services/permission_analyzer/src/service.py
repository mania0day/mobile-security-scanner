import sys
import os

from shared.logger import get_logger
from shared.json_writer import read_json, write_json
from config import INPUT_FILE, OUTPUT_FILE

logger = get_logger("PermissionAnalyzer")

DANGEROUS_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION": {"category": "location", "risk": "high"},
    "android.permission.ACCESS_COARSE_LOCATION": {"category": "location", "risk": "medium"},
    "android.permission.ACCESS_BACKGROUND_LOCATION": {"category": "location", "risk": "high"},
    "android.permission.READ_CONTACTS": {"category": "contacts", "risk": "high"},
    "android.permission.WRITE_CONTACTS": {"category": "contacts", "risk": "high"},
    "android.permission.READ_EXTERNAL_STORAGE": {"category": "storage", "risk": "medium"},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"category": "storage", "risk": "medium"},
    "android.permission.MANAGE_EXTERNAL_STORAGE": {"category": "storage", "risk": "high"},
    "android.permission.CAMERA": {"category": "camera", "risk": "high"},
    "android.permission.RECORD_AUDIO": {"category": "microphone", "risk": "high"},
    "android.permission.READ_PHONE_STATE": {"category": "phone", "risk": "medium"},
    "android.permission.CALL_PHONE": {"category": "phone", "risk": "high"},
    "android.permission.READ_CALL_LOG": {"category": "phone", "risk": "high"},
    "android.permission.PROCESS_OUTGOING_CALLS": {"category": "phone", "risk": "high"},
    "android.permission.SEND_SMS": {"category": "sms", "risk": "high"},
    "android.permission.RECEIVE_SMS": {"category": "sms", "risk": "high"},
    "android.permission.READ_SMS": {"category": "sms", "risk": "high"},
    "android.permission.READ_CALENDAR": {"category": "calendar", "risk": "medium"},
    "android.permission.WRITE_CALENDAR": {"category": "calendar", "risk": "medium"},
    "android.permission.BLUETOOTH_SCAN": {"category": "bluetooth", "risk": "medium"},
    "android.permission.BLUETOOTH_CONNECT": {"category": "bluetooth", "risk": "medium"},
    "android.permission.REQUEST_INSTALL_PACKAGES": {"category": "install", "risk": "critical"},
    "android.permission.SYSTEM_ALERT_WINDOW": {"category": "overlay", "risk": "critical"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"category": "accessibility", "risk": "critical"},
    "android.permission.BIND_DEVICE_ADMIN": {"category": "admin", "risk": "critical"},
    "android.permission.RECEIVE_BOOT_COMPLETED": {"category": "persistence", "risk": "medium"},
    "android.permission.FOREGROUND_SERVICE": {"category": "background", "risk": "low"},
}


class PermissionAnalyzerService:
    """
    Reads Androguard results and classifies each app's permissions by risk.

    Reads:  backend/output/androguard/results.json
    Writes: backend/output/permission_analyzer/results.json
    """

    def __init__(self):
        self.logger = get_logger("PermissionAnalyzer")

    def run(self) -> None:
        self.logger.info("Starting Permission Analyzer")

        if not os.path.exists(INPUT_FILE):
            self.logger.error(f"Input not found: {INPUT_FILE}")
            sys.exit(1)

        data = read_json(INPUT_FILE)
        apps = data.get("results", [])

        results = []
        critical_app_count = 0

        for app in apps:
            pkg = app.get("package_name", "unknown")
            manifest = app.get("manifest") or {}

            # Androguard stores permissions under manifest.permissions
            # Fall back to top-level permissions key for compatibility
            perms = manifest.get("permissions", app.get("permissions", []))
            if perms is None:
                perms = []

            dangerous = []
            risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            for p in perms:
                if p in DANGEROUS_PERMISSIONS:
                    info = DANGEROUS_PERMISSIONS[p]
                    dangerous.append({
                        "permission": p,
                        "category": info["category"],
                        "risk": info["risk"],
                    })
                    risk_counts[info["risk"]] += 1

            if risk_counts["critical"] > 0:
                critical_app_count += 1

            results.append({
                "package_name": pkg,
                "total_permissions": len(perms),
                "dangerous_count": len(dangerous),
                "risk_summary": risk_counts,
                "dangerous_permissions": dangerous,
                "all_permissions": perms,
            })

        output = {
            "total_analyzed": len(results),
            "apps_with_critical_permissions": critical_app_count,
            "results": results,
        }

        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        write_json(OUTPUT_FILE, output)
        self.logger.info(f"Saved → {OUTPUT_FILE}")
