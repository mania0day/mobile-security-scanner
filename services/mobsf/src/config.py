import os

# MobSF server (runs as a persistent Docker service)
MOBSF_URL = os.environ.get("MOBSF_URL", "http://mobsf:8000")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "")
MOBSF_ENABLED = os.environ.get("MOBSF_ENABLED", "false").lower() == "true"

# Input / output
INVENTORY_OUTPUT_DIR = os.environ.get(
    "INVENTORY_OUTPUT_DIR", "/app/backend/output/apk_inventory"
)
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/backend/output/mobsf")

# Timeouts
UPLOAD_TIMEOUT = int(os.environ.get("MOBSF_UPLOAD_TIMEOUT", "60"))
SCAN_TIMEOUT = int(os.environ.get("MOBSF_SCAN_TIMEOUT", "300"))
REPORT_TIMEOUT = int(os.environ.get("MOBSF_REPORT_TIMEOUT", "60"))
