import os
import glob
import json
from config import MVT_ENABLED, ADB_TIMEOUT, IOCS_DIR
from shared.logger import get_logger
from shared.command import run_command

logger = get_logger("MVT")


def run_mvt_scan(serial: str):
    if not MVT_ENABLED:
        return {
            "scan_mode": "minimal",
            "mvt_enabled": False,
            "skipped": True,
            "skip_reason": "MVT_ENABLED not set — deep scan only",
            "ioc_matches": [],
            "total_ioc_matches": 0,
            "error": ""
        }

    tmp_out = "/tmp/mvt_out"
    os.makedirs(tmp_out, exist_ok=True)

    logger.info(f"Running MVT on device {serial}")
    cmd = ["mvt-android", "check-adb", "--output", tmp_out, "--serial", serial]
    if os.path.exists(IOCS_DIR) and os.listdir(IOCS_DIR):
        cmd.extend(["--iocs", IOCS_DIR])

    error = ""
    try:
        run_command(cmd, timeout=ADB_TIMEOUT)
    except Exception as e:
        logger.error(f"MVT command failed: {e}")
        error = str(e)

    ioc_matches = []

    # Check output json files
    for filepath in glob.glob(os.path.join(tmp_out, "*.json")):
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item.get("detections"):
                            ioc_matches.append(item)
                elif isinstance(data, dict):
                    if data.get("detections"):
                        ioc_matches.append(data)
        except Exception as e:
            logger.error(f"Failed to read MVT output file {filepath}: {e}")

    return {
        "scan_mode": "deep",
        "mvt_enabled": True,
        "skipped": False,
        "skip_reason": "",
        "ioc_matches": ioc_matches,
        "total_ioc_matches": len(ioc_matches),
        "error": error
    }
