import os

# Where each service wrote its results
OUTPUT_BASE = os.environ.get("OUTPUT_BASE", "/app/backend/output")

ADB_OUTPUT = f"{OUTPUT_BASE}/adb"
APKID_OUTPUT = f"{OUTPUT_BASE}/apkid"
ANDROGUARD_OUTPUT = f"{OUTPUT_BASE}/androguard"
MOBSF_OUTPUT = f"{OUTPUT_BASE}/mobsf"
CERTIFICATE_OUTPUT = f"{OUTPUT_BASE}/certificate"
PERMISSION_OUTPUT = f"{OUTPUT_BASE}/permission_analyzer"
ROOT_OUTPUT = f"{OUTPUT_BASE}/root_detection"
HASH_OUTPUT = f"{OUTPUT_BASE}/hash_lookup"
YARA_OUTPUT = f"{OUTPUT_BASE}/yara"
MVT_OUTPUT = f"{OUTPUT_BASE}/mvt"
CVE_OUTPUT = f"{OUTPUT_BASE}/cve_checker"

OUTPUT_DIR = os.environ.get("RISK_OUTPUT_DIR", f"{OUTPUT_BASE}/risk_engine")
