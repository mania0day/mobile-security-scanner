import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import INVENTORY_OUTPUT_DIR, OUTPUT_DIR
from service import compile_rules, scan_apk
from shared.logger import get_logger
from shared.json_writer import read_json, write_json

logger = get_logger("Yara")


def main():
    logger.info("Starting Yara service (Parallel)...")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    results_path = os.path.join(OUTPUT_DIR, "results.json")

    inventory_file = os.path.join(INVENTORY_OUTPUT_DIR, "extracted.json")

    if not os.path.exists(inventory_file):
        logger.error(f"Inventory file not found: {inventory_file}")
        write_json(results_path, {"error": "inventory not found", "total_analyzed": 0, "total_with_matches": 0, "results": []})
        return

    inventory = read_json(inventory_file)
    if not inventory:
        logger.error("Empty inventory")
        write_json(results_path, {"error": "inventory is empty", "total_analyzed": 0, "total_with_matches": 0, "results": []})
        return

    rules = compile_rules()
    if not rules:
        write_json(results_path, {"error": "Failed to compile rules", "total_analyzed": 0, "total_with_matches": 0, "results": []})
        return

    apps = inventory.get("results", []) if isinstance(inventory, dict) else inventory
    valid_apps = [
        app for app in apps
        if app.get("status") == "success" and app.get("package_name") and app.get("local_path") and os.path.exists(app.get("local_path"))
    ]

    all_results = []

    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_app = {
            executor.submit(scan_apk, rules, app["local_path"], app["package_name"]): app
            for app in valid_apps
        }
        for future in as_completed(future_to_app):
            try:
                res = future.result()
                all_results.append(res)
            except Exception as exc:
                logger.error(f"YARA scan generated exception: {exc}")

    total_analyzed = len(all_results)
    total_with_matches = len([r for r in all_results if r.get("match_count", 0) > 0])

    final_output = {
        "total_analyzed": total_analyzed,
        "total_with_matches": total_with_matches,
        "results": all_results
    }

    write_json(results_path, final_output)
    logger.info(f"Yara scan complete. Analyzed {total_analyzed} apps.")


if __name__ == "__main__":
    main()
