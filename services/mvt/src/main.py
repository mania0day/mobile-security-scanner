import os
from config import ADB_OUTPUT_DIR, OUTPUT_DIR, MVT_ENABLED
from service import run_mvt_scan
from shared.logger import get_logger
from shared.json_writer import read_json, write_json

logger = get_logger("MVT")


def main():
    logger.info("Starting MVT service...")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    results_path = os.path.join(OUTPUT_DIR, "results.json")

    if not MVT_ENABLED:
        logger.info("MVT_ENABLED is not set, skipping scan")
        write_json(results_path, {
            "scan_mode": "minimal",
            "mvt_enabled": False,
            "skipped": True,
            "skip_reason": "MVT_ENABLED not set — deep scan only",
            "ioc_matches": [],
            "total_ioc_matches": 0,
            "error": ""
        })
        return

    device_file = os.path.join(ADB_OUTPUT_DIR, "device.json")
    if not os.path.exists(device_file):
        logger.error(f"Device file not found: {device_file}")
        write_json(results_path, {
            "scan_mode": "deep",
            "mvt_enabled": True,
            "skipped": False,
            "skip_reason": "",
            "ioc_matches": [],
            "total_ioc_matches": 0,
            "error": "Device info not found"
        })
        return

    device_info = read_json(device_file)
    serial = device_info.get("serial") if isinstance(device_info, dict) else None

    if not serial:
        logger.error("No serial found in device info")
        write_json(results_path, {
            "scan_mode": "deep",
            "mvt_enabled": True,
            "skipped": False,
            "skip_reason": "",
            "ioc_matches": [],
            "total_ioc_matches": 0,
            "error": "No device serial"
        })
        return

    res = run_mvt_scan(serial)
    write_json(results_path, res)
    logger.info("MVT service complete.")


if __name__ == "__main__":
    main()
