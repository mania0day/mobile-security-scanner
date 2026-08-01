import os
INVENTORY_OUTPUT_DIR = os.environ.get("INVENTORY_OUTPUT_DIR", "/app/backend/output/apk_inventory")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/backend/output/yara")
RULES_PATH = os.environ.get("RULES_PATH", "/app/yara/rules/android_malware.yar")
