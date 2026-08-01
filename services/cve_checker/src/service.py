import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from shared.logger import get_logger
from shared.json_writer import read_json, write_json

from cve_data import get_cves_for_patch

logger = get_logger("CVEChecker")

ADB_OUTPUT = os.environ.get("ADB_OUTPUT", "/app/backend/output/adb")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/backend/output/cve_checker")


def run():
    logger.info("Starting CVE checker")

    device_path = Path(ADB_OUTPUT) / "device.json"
    if not device_path.exists():
        logger.warning("No device.json found — skipping CVE check")
        return

    device = read_json(str(device_path))
    if not device:
        logger.warning("Empty device info — skipping CVE check")
        return

    android_version = device.get("android_version", "")
    security_patch = device.get("security_patch", "")
    fingerprint = device.get("fingerprint", "")
    sdk = device.get("sdk", "")

    logger.info(f"Checking CVEs for Android {android_version}, patch {security_patch}")

    # Get unpatched CVEs
    cve_result = get_cves_for_patch(security_patch)

    # Determine OS end-of-life status
    eol = False
    eol_details = ""
    try:
        major = int(str(android_version).split(".")[0]) if android_version else 0
        if major < 12:
            eol = True
            eol_details = f"Android {android_version} is EOL — no longer receives security updates"
    except (ValueError, IndexError):
        pass

    # Calculate overall vulnerability level
    if eol:
        overall_level = "CRITICAL"
    elif cve_result.get("critical_count", 0) > 0:
        overall_level = "HIGH"
    elif cve_result.get("high_count", 0) > 0:
        overall_level = "MEDIUM"
    elif cve_result.get("total_unpatched", 0) > 0:
        overall_level = "LOW"
    else:
        overall_level = "NONE"

    result = {
        "scanned_at": datetime.utcnow().isoformat(),
        "android_version": android_version,
        "security_patch": security_patch,
        "sdk": sdk,
        "fingerprint": fingerprint,
        "os_eol": eol,
        "os_eol_details": eol_details,
        "overall_level": overall_level,
        **cve_result,
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "results.json")
    write_json(output_path, result)
    logger.info(
        f"Found {cve_result['total_unpatched']} unpatched CVEs "
        f"({cve_result['critical_count']} critical, {cve_result['high_count']} high) "
        f"— overall level: {overall_level}"
    )


if __name__ == "__main__":
    run()
