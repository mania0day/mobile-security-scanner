import os

INVENTORY_OUTPUT_DIR = os.environ.get("INVENTORY_OUTPUT_DIR", "/app/backend/output/apk_inventory")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/backend/output/androguard")
ANALYSIS_TIMEOUT = int(os.environ.get("ANALYSIS_TIMEOUT", "180"))
