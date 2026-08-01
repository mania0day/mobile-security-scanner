import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from shared.logger import get_logger
from shared.json_writer import read_json, write_json
from config import INVENTORY_OUTPUT_DIR, OUTPUT_DIR, ANALYSIS_TIMEOUT
from service import AndroguardService

logger = get_logger("Androguard")


def main() -> None:
    logger.info("Starting Androguard service (Fast Parallel Manifest Analysis)")

    inventory_file = os.path.join(INVENTORY_OUTPUT_DIR, "extracted.json")
    output_file = os.path.join(OUTPUT_DIR, "results.json")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if not os.path.exists(inventory_file):
        logger.error(f"Inventory file not found: {inventory_file}")
        sys.exit(1)

    try:
        inventory_data = read_json(inventory_file)
    except Exception as e:
        logger.error(f"Failed to read inventory file: {e}")
        sys.exit(1)

    if isinstance(inventory_data, dict):
        apps = inventory_data.get("results", [])
    else:
        apps = inventory_data

    valid_apps = [
        app for app in apps
        if app.get("status") == "success" and app.get("local_path")
    ]

    svc = AndroguardService(timeout=ANALYSIS_TIMEOUT)
    results = []

    # Parallel Execution Pool (4 Workers)
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_app = {
            executor.submit(svc.analyze_apk, app["local_path"], app.get("package_name", "unknown")): app
            for app in valid_apps
        }
        for future in as_completed(future_to_app):
            try:
                res = future.result()
                results.append(res.to_dict())
            except Exception as exc:
                logger.error(f"Execution generated an exception: {exc}")

    output_data = {
        "total_analyzed": len(results),
        "results": results,
    }

    write_json(output_file, output_data)
    logger.info(f"Androguard completed. Results written to {output_file}")


if __name__ == "__main__":
    main()
