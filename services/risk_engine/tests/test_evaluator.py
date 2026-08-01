import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from evaluator import ChecklistEvaluator


def test_bootloader_unlock_is_warned_instead_of_failed():
    evaluator = ChecklistEvaluator()
    verdict, checklist = evaluator.evaluate(
        device_info={
            "serial": "test-device",
            "model": "Pixel 8",
            "manufacturer": "Google",
            "android_version": "14",
            "security_patch": "2024-01-01",
            "screen_lock_enabled": True,
            "encryption_enabled": True,
        },
        root_data={
            "is_rooted": False,
            "checks": {
                "bootloader_unlocked": True,
                "adb_enabled": False,
                "developer_options_enabled": False,
                "is_test_keys": False,
            },
        },
        jailbreak_data=None,
        cert_data=None,
        perm_data=None,
        yara_data=None,
        apkid_data=None,
        app_risks=[{"package_name": "com.example.app", "critical_permissions": [], "yara_matches": 0, "yara_severities": {}}],
        platform="android",
    )

    bootloader_check = next(
        item for item in checklist if item["check_name"] == "Bootloader lock status"
    )

    assert bootloader_check["priority"] == "Should"
    assert bootloader_check["status"] == "WARNING"
    assert verdict != "FAIL"
