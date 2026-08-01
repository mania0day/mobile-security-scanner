import os

# Where this service writes its output JSON
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/backend/output/adb")

# Maximum seconds to wait for an ADB command to respond
ADB_TIMEOUT = int(os.environ.get("ADB_TIMEOUT", "30"))