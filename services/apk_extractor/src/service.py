import os
import json
import dataclasses
from typing import Dict, Any, List

from shared.logger import get_logger
from shared.command import run_command
from shared.json_writer import read_json, write_json
from shared.exceptions import CommandError

from config import (
    ADB_OUTPUT_DIR,
    INVENTORY_OUTPUT_DIR,
    APKS_OUTPUT_DIR,
    ADB_TIMEOUT,
    EXTRACT_SYSTEM_APPS
)
from models import ExtractionStatus, ExtractionResult

logger = get_logger("ApkExtractor")


def get_device_serial() -> str:
    """Read the device serial from adb output directory."""
    device_file = os.path.join(ADB_OUTPUT_DIR, "device.json")
    try:
        device_data = read_json(device_file)
        return device_data["serial"]
    except Exception as e:
        logger.error(f"Failed to read device serial from {device_file}: {e}")
        raise


def get_inventory_apps() -> List[Dict[str, Any]]:
    """Read the apps inventory."""
    inventory_file = os.path.join(INVENTORY_OUTPUT_DIR, "apps.json")
    try:
        inventory_data = read_json(inventory_file)
        return inventory_data.get("apps", [])
    except Exception as e:
        logger.error(f"Failed to read apps inventory from {inventory_file}: {e}")
        raise


def save_extraction_results(serial: str, results: List[ExtractionResult]) -> None:
    """Save the extraction results to json."""
    output_file = os.path.join(INVENTORY_OUTPUT_DIR, "extracted.json")

    total = len(results)
    success = sum(1 for r in results if r.status == ExtractionStatus.SUCCESS)
    failed = sum(1 for r in results if r.status == ExtractionStatus.FAILED)
    skipped = sum(1 for r in results if r.status == ExtractionStatus.SKIPPED)
    no_path = sum(1 for r in results if r.status == ExtractionStatus.NO_PATH)

    data = {
        "device_serial": serial,
        "total_attempted": total,
        "success_count": success,
        "failed_count": failed,
        "skipped_count": skipped,
        "no_path_count": no_path,
        "results": [dataclasses.asdict(r) for r in results]
    }

    write_json(output_file, data)
    logger.info(f"Saved extraction results to {output_file}")


def extract_apk(serial: str, package_name: str, device_path: str) -> bool:
    """Pull the APK from device using ADB."""
    local_path = os.path.join(APKS_OUTPUT_DIR, f"{package_name}.apk")

    os.makedirs(APKS_OUTPUT_DIR, exist_ok=True)

    cmd = ["adb", "-s", serial, "pull", device_path, local_path]
    logger.debug(f"Executing: {' '.join(cmd)}")

    try:
        run_command(cmd, timeout=ADB_TIMEOUT)
        return True
    except Exception as e:
        logger.error(f"Failed to extract {package_name}: {e}")
        return False


def run_extraction() -> None:
    """Main extraction logic."""
    serial = get_device_serial()
    apps = get_inventory_apps()

    results = []

    for app in apps:
        package_name = app.get("package_name")
        is_system = app.get("is_system", False)

        # Skip system apps if not requested
        if is_system and not EXTRACT_SYSTEM_APPS:
            logger.debug(f"Skipping system app: {package_name}")
            results.append(ExtractionResult(
                package_name=package_name,
                status=ExtractionStatus.SKIPPED,
                is_system_app=is_system
            ))
            continue

        apk_paths = app.get("apk_paths", [])
        if not apk_paths:
            logger.warning(f"No APK path found for {package_name}")
            results.append(ExtractionResult(
                package_name=package_name,
                status=ExtractionStatus.NO_PATH,
                is_system_app=is_system
            ))
            continue

        device_path = apk_paths[0]
        local_path = os.path.join(APKS_OUTPUT_DIR, f"{package_name}.apk")

        logger.info(f"Extracting {package_name} from {device_path}")
        success = extract_apk(serial, package_name, device_path)

        if success:
            results.append(ExtractionResult(
                package_name=package_name,
                status=ExtractionStatus.SUCCESS,
                local_path=local_path,
                device_path=device_path,
                is_system_app=is_system
            ))
        else:
            results.append(ExtractionResult(
                package_name=package_name,
                status=ExtractionStatus.FAILED,
                device_path=device_path,
                error="ADB pull failed",
                is_system_app=is_system
            ))

    save_extraction_results(serial, results)
