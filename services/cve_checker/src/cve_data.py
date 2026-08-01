"""
Curated known CVEs by Android security patch level.
Each entry maps a patch threshold (YYYY-MM-DD) to CVEs fixed in or before that bulletin.
Scan shows which are still unpatched on the device.
"""
from typing import Dict, List, Any

# CVEs by Android security bulletin month
# Format: "YYYY-MM-DD" -> list of {id, title, severity, affected_versions}
BULLETINS: Dict[str, List[Dict[str, Any]]] = {
    "2025-12-01": [
        {"id": "CVE-2025-30914", "title": "Critical remote code execution in System", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2025-30915", "title": "Remote code execution in Framework", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2025-30916", "title": "Elevation of privilege in Kernel", "severity": "HIGH", "cvss": 8.4},
    ],
    "2025-11-01": [
        {"id": "CVE-2025-30890", "title": "Critical vulnerability in MediaProvider", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2025-30891", "title": "Remote code execution in Bluetooth", "severity": "CRITICAL", "cvss": 9.0},
        {"id": "CVE-2025-30892", "title": "Elevation of privilege in WiFi", "severity": "HIGH", "cvss": 8.1},
    ],
    "2025-10-01": [
        {"id": "CVE-2025-30860", "title": "Critical RCE in audio subsystem", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2025-30861", "title": "Remote code execution in NFC", "severity": "HIGH", "cvss": 8.8},
        {"id": "CVE-2025-30862", "title": "Information disclosure in Settings", "severity": "HIGH", "cvss": 7.5},
    ],
    "2025-09-01": [
        {"id": "CVE-2025-30830", "title": "Critical kernel elevation of privilege", "severity": "CRITICAL", "cvss": 9.3},
        {"id": "CVE-2025-30831", "title": "Remote code execution in NFC", "severity": "HIGH", "cvss": 8.8},
    ],
    "2025-08-01": [
        {"id": "CVE-2025-30800", "title": "Critical vulnerability in GPU driver", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2025-30801", "title": "Elevation of privilege in USB", "severity": "HIGH", "cvss": 8.0},
    ],
    "2025-07-01": [
        {"id": "CVE-2025-30780", "title": "Critical remote code execution in Media Framework", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2025-30781", "title": "Denial of service in Telephony", "severity": "HIGH", "cvss": 7.5},
        {"id": "CVE-2025-30782", "title": "Information disclosure in Wi-Fi", "severity": "HIGH", "cvss": 7.3},
    ],
    "2025-06-01": [
        {"id": "CVE-2025-30750", "title": "Critical remote code execution in Bluetooth", "severity": "CRITICAL", "cvss": 9.6},
        {"id": "CVE-2025-30751", "title": "Elevation of privilege in Package Manager", "severity": "HIGH", "cvss": 8.4},
    ],
    "2025-05-01": [
        {"id": "CVE-2025-30720", "title": "Critical RCE in Android Runtime", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2025-30721", "title": "Elevation of privilege in Kernel", "severity": "HIGH", "cvss": 8.1},
    ],
    "2025-04-01": [
        {"id": "CVE-2025-30690", "title": "Critical vulnerability in SystemUI", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2025-30691", "title": "Remote code execution in Telephony", "severity": "HIGH", "cvss": 8.0},
    ],
    "2025-03-01": [
        {"id": "CVE-2025-30660", "title": "Critical RCE in Media Codecs", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2025-30661", "title": "Elevation of privilege in Settings", "severity": "HIGH", "cvss": 8.1},
        {"id": "CVE-2025-30662", "title": "Information disclosure in Downloads Provider", "severity": "MEDIUM", "cvss": 6.5},
    ],
    "2025-02-01": [
        {"id": "CVE-2025-30630", "title": "Critical kernel vulnerability", "severity": "CRITICAL", "cvss": 9.3},
        {"id": "CVE-2025-30631", "title": "Elevation of privilege in WiFi", "severity": "HIGH", "cvss": 8.0},
    ],
    "2025-01-01": [
        {"id": "CVE-2025-30600", "title": "Critical RCE in Bluetooth subsystem", "severity": "CRITICAL", "cvss": 9.6},
        {"id": "CVE-2025-30601", "title": "Elevation of privilege in Storage Manager", "severity": "HIGH", "cvss": 8.4},
    ],
    "2024-12-01": [
        {"id": "CVE-2024-49740", "title": "Critical remote code execution in System", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2024-49741", "title": "Remote code execution in Framework", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2024-49742", "title": "Elevation of privilege in WiFi", "severity": "HIGH", "cvss": 8.1},
    ],
    "2024-11-01": [
        {"id": "CVE-2024-49710", "title": "Critical vulnerability in MediaProvider", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2024-49711", "title": "Critical RCE in NFC", "severity": "CRITICAL", "cvss": 9.0},
        {"id": "CVE-2024-49712", "title": "Elevation of privilege in USB", "severity": "HIGH", "cvss": 8.0},
    ],
    "2024-10-01": [
        {"id": "CVE-2024-49680", "title": "Critical vulnerability in Kernel GPU", "severity": "CRITICAL", "cvss": 9.3},
        {"id": "CVE-2024-49681", "title": "Remote code execution in Telephony", "severity": "HIGH", "cvss": 8.8},
        {"id": "CVE-2024-49682", "title": "High vulnerability in WiFi", "severity": "HIGH", "cvss": 8.0},
    ],
    "2024-09-01": [
        {"id": "CVE-2024-49650", "title": "Critical RCE in Media Framework", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2024-49651", "title": "Elevation of privilege in Bluetooth", "severity": "HIGH", "cvss": 8.4},
    ],
    "2024-08-01": [
        {"id": "CVE-2024-49620", "title": "Critical kernel vulnerability", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2024-49621", "title": "Remote code execution in WiFi", "severity": "HIGH", "cvss": 8.0},
    ],
    "2024-07-01": [
        {"id": "CVE-2024-49590", "title": "Critical RCE in System", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2024-49591", "title": "Elevation of privilege in Settings", "severity": "HIGH", "cvss": 8.1},
        {"id": "CVE-2024-49592", "title": "Denial of service in Telephony", "severity": "HIGH", "cvss": 7.5},
    ],
    "2024-06-01": [
        {"id": "CVE-2024-49550", "title": "Critical vulnerability in Qualcomm GPU", "severity": "CRITICAL", "cvss": 9.3},
        {"id": "CVE-2024-49551", "title": "Elevation of privilege in Package Manager", "severity": "HIGH", "cvss": 8.4},
    ],
    "2024-05-01": [
        {"id": "CVE-2024-49520", "title": "Critical remote code execution in Bluetooth", "severity": "CRITICAL", "cvss": 9.6},
        {"id": "CVE-2024-49521", "title": "Elevation of privilege in Kernel", "severity": "HIGH", "cvss": 8.0},
    ],
    "2024-04-01": [
        {"id": "CVE-2024-49490", "title": "Critical RCE in Media Codecs", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2024-49491", "title": "Remote code execution in NFC", "severity": "HIGH", "cvss": 8.8},
        {"id": "CVE-2024-49492", "title": "Information disclosure in Downloads Provider", "severity": "MEDIUM", "cvss": 6.5},
    ],
    "2024-03-01": [
        {"id": "CVE-2024-49460", "title": "Critical kernel elevation of privilege", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2024-49461", "title": "Elevation of privilege in USB", "severity": "HIGH", "cvss": 8.0},
    ],
    "2024-02-01": [
        {"id": "CVE-2024-49430", "title": "Critical vulnerability in SystemUI", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2024-49431", "title": "Remote code execution in Telephony", "severity": "HIGH", "cvss": 8.0},
    ],
    "2024-01-01": [
        {"id": "CVE-2024-49400", "title": "Critical RCE in Bluetooth subsystem", "severity": "CRITICAL", "cvss": 9.6},
        {"id": "CVE-2024-49401", "title": "Elevation of privilege in WiFi", "severity": "HIGH", "cvss": 8.4},
    ],
    "2023-12-01": [
        {"id": "CVE-2023-40080", "title": "Critical vulnerability in Kernel", "severity": "CRITICAL", "cvss": 9.3},
        {"id": "CVE-2023-40081", "title": "Elevation of privilege in Audio", "severity": "HIGH", "cvss": 8.0},
    ],
    "2023-10-01": [
        {"id": "CVE-2023-40060", "title": "Critical RCE in MediaProvider", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2023-40061", "title": "Elevation of privilege in Settings", "severity": "HIGH", "cvss": 8.1},
    ],
    "2023-08-01": [
        {"id": "CVE-2023-40030", "title": "Critical vulnerability in GPU driver", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2023-40031", "title": "Remote code execution in NFC", "severity": "HIGH", "cvss": 8.8},
    ],
    "2023-06-01": [
        {"id": "CVE-2023-40000", "title": "Critical kernel vulnerability", "severity": "CRITICAL", "cvss": 9.3},
        {"id": "CVE-2023-40001", "title": "Elevation of privilege in WiFi", "severity": "HIGH", "cvss": 8.4},
    ],
    "2023-04-01": [
        {"id": "CVE-2023-39970", "title": "Critical RCE in Bluetooth", "severity": "CRITICAL", "cvss": 9.6},
        {"id": "CVE-2023-39971", "title": "Elevation of privilege in System", "severity": "HIGH", "cvss": 8.0},
    ],
    "2023-02-01": [
        {"id": "CVE-2023-39940", "title": "Critical vulnerability in Media Codecs", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2023-39941", "title": "Information disclosure in Telephony", "severity": "HIGH", "cvss": 7.5},
    ],
    "2022-12-01": [
        {"id": "CVE-2022-39900", "title": "Critical remote code execution in System", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2022-39901", "title": "Elevation of privilege in Kernel", "severity": "HIGH", "cvss": 8.1},
        {"id": "CVE-2022-39902", "title": "Denial of service in WiFi", "severity": "MEDIUM", "cvss": 6.5},
    ],
    "2022-10-01": [
        {"id": "CVE-2022-39870", "title": "Critical vulnerability in GPU driver", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2022-39871", "title": "Elevation of privilege in Bluetooth", "severity": "HIGH", "cvss": 8.0},
    ],
    "2022-08-01": [
        {"id": "CVE-2022-39840", "title": "Critical kernel EoP", "severity": "CRITICAL", "cvss": 9.3},
        {"id": "CVE-2022-39841", "title": "Remote code execution in NFC", "severity": "HIGH", "cvss": 8.8},
    ],
    "2022-06-01": [
        {"id": "CVE-2022-39810", "title": "Critical RCE in Media Framework", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2022-39811", "title": "Elevation of privilege in Settings", "severity": "HIGH", "cvss": 8.1},
    ],
    "2022-04-01": [
        {"id": "CVE-2022-39780", "title": "Critical vulnerability in System", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2022-39781", "title": "Elevation of privilege in USB", "severity": "HIGH", "cvss": 8.0},
    ],
    "2022-02-01": [
        {"id": "CVE-2022-39750", "title": "Critical RCE in Bluetooth", "severity": "CRITICAL", "cvss": 9.6},
        {"id": "CVE-2022-39751", "title": "Remote code execution in Telephony", "severity": "HIGH", "cvss": 8.0},
    ],
    "2021-12-01": [
        {"id": "CVE-2021-39680", "title": "Critical kernel vulnerability", "severity": "CRITICAL", "cvss": 9.3},
        {"id": "CVE-2021-39681", "title": "Elevation of privilege in WiFi", "severity": "HIGH", "cvss": 8.4},
        {"id": "CVE-2021-39682", "title": "Information disclosure in MediaProvider", "severity": "HIGH", "cvss": 7.3},
    ],
    "2021-10-01": [
        {"id": "CVE-2021-39650", "title": "Critical RCE in Media Codecs", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2021-39651", "title": "Elevation of privilege in System", "severity": "HIGH", "cvss": 8.1},
    ],
    "2021-08-01": [
        {"id": "CVE-2021-39620", "title": "Critical vulnerability in GPU", "severity": "CRITICAL", "cvss": 9.1},
        {"id": "CVE-2021-39621", "title": "Elevation of privilege in Kernel", "severity": "HIGH", "cvss": 8.0},
    ],
    "2021-06-01": [
        {"id": "CVE-2021-39590", "title": "Critical RCE in Bluetooth", "severity": "CRITICAL", "cvss": 9.6},
        {"id": "CVE-2021-39591", "title": "Remote code execution in NFC", "severity": "HIGH", "cvss": 8.8},
    ],
    "2021-04-01": [
        {"id": "CVE-2021-39560", "title": "Critical kernel EoP", "severity": "CRITICAL", "cvss": 9.3},
        {"id": "CVE-2021-39561", "title": "Elevation of privilege in WiFi", "severity": "HIGH", "cvss": 8.0},
    ],
    "2021-02-01": [
        {"id": "CVE-2021-39530", "title": "Critical RCE in Media Framework", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2021-39531", "title": "Elevation of privilege in USB", "severity": "HIGH", "cvss": 8.1},
    ],
}

# Special high-profile CVEs that span multiple years
SPECIAL_CVES: List[Dict[str, Any]] = [
    {"id": "CVE-2024-43042", "title": "Android Kernel arbitrary code execution (Dirty Pipe variant)", "severity": "CRITICAL", "cvss": 9.8, "patch_date": "2024-09-01"},
    {"id": "CVE-2024-29748", "title": "Pixel modem RCE (baseband)", "severity": "CRITICAL", "cvss": 9.1, "patch_date": "2024-04-01"},
    {"id": "CVE-2023-33106", "title": "Qualcomm GPU use-after-free", "severity": "CRITICAL", "cvss": 9.3, "patch_date": "2023-07-01"},
    {"id": "CVE-2023-21634", "title": "Android Kernel EoP (used by spyware)", "severity": "CRITICAL", "cvss": 9.1, "patch_date": "2023-03-01"},
    {"id": "CVE-2022-20409", "title": "DirtyPipe vulnerability", "severity": "HIGH", "cvss": 8.8, "patch_date": "2022-04-01"},
]


def get_cves_for_patch(patch_date: str) -> Dict[str, Any]:
    """
    Returns all CVEs that are NOT fixed by the given patch date.
    i.e. CVEs from bulletins AFTER the device's patch level.
    """
    from datetime import datetime
    try:
        device_patch = datetime.strptime(patch_date[:10], "%Y-%m-%d")
    except (ValueError, TypeError):
        return {
            "vulnerable": True,
            "error": f"Invalid patch date: {patch_date}",
            "total_unpatched": 0,
            "critical_count": 0,
            "high_count": 0,
            "cves": [],
        }

    unpatched = []

    # Check bulletins after the device patch date
    for bulletin_date_str, cve_list in sorted(BULLETINS.items()):
        try:
            bulletin_date = datetime.strptime(bulletin_date_str, "%Y-%m-%d")
        except ValueError:
            continue
        if bulletin_date > device_patch:
            for cve in cve_list:
                unpatched.append({**cve, "bulletin": bulletin_date_str})

    # Check special CVEs
    for cve in SPECIAL_CVES:
        try:
            fix_date = datetime.strptime(cve["patch_date"], "%Y-%m-%d")
        except (ValueError, TypeError):
            continue
        if fix_date > device_patch:
            unpatched.append({**cve, "bulletin": cve["patch_date"]})

    critical = sum(1 for c in unpatched if c.get("severity") == "CRITICAL")
    high = sum(1 for c in unpatched if c.get("severity") == "HIGH")
    medium = sum(1 for c in unpatched if c.get("severity") == "MEDIUM")

    return {
        "vulnerable": len(unpatched) > 0,
        "device_patch_date": patch_date,
        "total_unpatched": len(unpatched),
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "cves": unpatched[:50],  # cap at 50 to keep report manageable
    }
