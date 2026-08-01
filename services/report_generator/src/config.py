import os

OUTPUT_BASE = os.environ.get("OUTPUT_BASE", "/app/backend/output")
RISK_ENGINE_OUTPUT = f"{OUTPUT_BASE}/risk_engine"
ADB_OUTPUT = f"{OUTPUT_BASE}/adb"
INVENTORY_OUTPUT = f"{OUTPUT_BASE}/apk_inventory"
CVE_OUTPUT = f"{OUTPUT_BASE}/cve_checker"
OUTPUT_DIR = os.environ.get("REPORT_OUTPUT_DIR", f"{OUTPUT_BASE}/reports")
