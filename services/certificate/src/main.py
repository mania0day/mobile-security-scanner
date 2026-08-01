import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from shared.logger import get_logger
from shared.json_writer import read_json, write_json
from config import INVENTORY_OUTPUT_DIR, OUTPUT_DIR
from service import CertificateAnalyzer

logger = get_logger("CertificateAnalyzer")


def main():
    logger.info("Starting Certificate Analyzer Service (Parallel)")
    inventory_file = os.path.join(INVENTORY_OUTPUT_DIR, "extracted.json")

    if not os.path.exists(inventory_file):
        logger.error(f"Inventory file not found: {inventory_file}")
        sys.exit(1)

    try:
        inventory_data = read_json(inventory_file)
    except Exception as e:
        logger.error(f"Failed to read inventory: {e}")
        sys.exit(1)

    if isinstance(inventory_data, list):
        apps = inventory_data
    else:
        apps = inventory_data.get("results", inventory_data.get("apps", []))

    valid_apps = [
        app for app in apps
        if app.get("status") == "success" and app.get("local_path") and app.get("package_name")
    ]

    analyzer = CertificateAnalyzer()
    results = []

    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_app = {
            executor.submit(analyzer.analyze, app["package_name"], app["local_path"]): app
            for app in valid_apps
        }
        for future in as_completed(future_to_app):
            try:
                res = future.result()
                results.append(res.to_dict())
            except Exception as exc:
                logger.error(f"Certificate analysis generated exception: {exc}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_file = os.path.join(OUTPUT_DIR, "results.json")

    output_data = {
        "total_analyzed": len(results),
        "results": results
    }

    try:
        write_json(output_file, output_data)
        logger.info(f"Analysis complete. Results written to {output_file}")
    except Exception as e:
        logger.error(f"Failed to write results: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
