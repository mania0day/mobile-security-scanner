import os

# Where this service reads device info from (written by ADB service)
ADB_OUTPUT_DIR = os.environ.get("ADB_OUTPUT_DIR", "/app/backend/output/adb")

# Where this service writes its output
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/backend/output/apk_inventory")

# ADB command timeout in seconds
ADB_TIMEOUT = int(os.environ.get("ADB_TIMEOUT", "30"))

# Whether to include system apps in the inventory
INCLUDE_SYSTEM_APPS = os.environ.get("INCLUDE_SYSTEM_APPS", "true").lower() == "true"
