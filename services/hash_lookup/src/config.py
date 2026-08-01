import os

INVENTORY_OUTPUT_DIR = os.environ.get("INVENTORY_OUTPUT_DIR", "/app/backend/output/apk_inventory")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/backend/output/hash_lookup")
VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_ENABLED = bool(VT_API_KEY) and os.environ.get("VT_ENABLED", "0").lower() in ("1", "true", "yes")
VT_MAX_QUERIES = int(os.environ.get("VT_MAX_QUERIES", "30"))
VT_THROTTLE_SECONDS = float(os.environ.get("VT_THROTTLE_SECONDS", "12"))
VT_TIMEOUT = float(os.environ.get("VT_TIMEOUT", "12"))
