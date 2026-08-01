import os

ADB_OUTPUT_DIR = os.environ.get("ADB_OUTPUT_DIR", "/app/backend/output/adb")
INVENTORY_OUTPUT_DIR = os.environ.get("INVENTORY_OUTPUT_DIR", "/app/backend/output/apk_inventory")
APKS_OUTPUT_DIR = os.environ.get("APKS_OUTPUT_DIR", "/app/backend/output/apks")
ADB_TIMEOUT = int(os.environ.get("ADB_TIMEOUT", "60"))
EXTRACT_SYSTEM_APPS = os.environ.get("EXTRACT_SYSTEM_APPS", "false").lower() == "true"
