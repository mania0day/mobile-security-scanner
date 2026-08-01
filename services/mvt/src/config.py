import os
ADB_OUTPUT_DIR = os.environ.get("ADB_OUTPUT_DIR", "/app/backend/output/adb")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/backend/output/mvt")
IOCS_DIR = os.environ.get("IOCS_DIR", "/app/mvt/iocs")
MVT_ENABLED = os.environ.get("MVT_ENABLED", "false").lower() == "true"
ADB_TIMEOUT = int(os.environ.get("ADB_TIMEOUT", "300"))
