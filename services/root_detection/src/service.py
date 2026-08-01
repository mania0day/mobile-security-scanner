import os
import subprocess
from datetime import datetime
from typing import Dict, Any, List

from config import INPUT_FILE, OUTPUT_FILE
from shared.logger import get_logger
from shared.json_writer import read_json, write_json
from shared.command import run_command

logger = get_logger("RootDetection")

# Extra `service call` hex-dump markers for root-indicating packages.
ROOT_MANAGER_PACKAGES = (
    "com.topjohnwu.magisk",
    "io.github.vvb2060.magisk",
    "com.koushikdutta.superuser",
    "eu.chainfire.supersu",
    "com.superuser",
    "me.phh.superuser",
    "com.dimonvideo.layout",
    "ma.rae.supersu",
    "com.kingroot.kinguser",
    "com.king.oem",
    "com.oneplus.superuser",
    "com.qianyu.superuser",
    "com.magisk.manager",
    "com.policija.magisk",
)

SU_PATHS = (
    "/system/bin/su",
    "/system/xbin/su",
    "/system/bin/.su",
    "/su/bin/su",
    "/sbin/su",
    "/vendor/bin/su",
    "/system/sbin/su",
    "/system/app/Superuser.apk",
    "/system/xbin/daemonsu",
    "/system/etc/init.d/99SuperSUDaemon",
)

BOOTLOADER_UNLOCK_INDICATORS = {
    # property           -> values that mean "unlocked / tampered"
    "ro.boot.verifiedbootstate": {"orange", "yellow", "red"},
    "ro.boot.flash.locked": {"0"},
    "ro.boot.vbmeta.device_state": {"unlocked"},
    "ro.boot.warranty_bit": {"0"},
    "ro.boot.warranty_byte": {"0"},
    "ro.boot.secureboot": {"unlocked"},
    "ro.boot.warranty": {"0"},
}


def check_os_vulnerabilities(android_version: str, sdk: str, security_patch: str) -> List[str]:
    """
    Checks Android OS version and security patch date for known EOL and systemic CVE vulnerabilities.
    """
    vulns = []

    # Check Android Version EOL status
    try:
        ver_num = float(android_version) if android_version else 0.0
        if 0 < ver_num < 12:
            vulns.append(f"Outdated & EOL Android OS version ({android_version}). Android <12 no longer receives official security updates (CVE exposure).")
    except ValueError:
        pass

    # Check Security Patch Date
    if security_patch:
        try:
            # Format: YYYY-MM-DD
            patch_date = datetime.strptime(security_patch[:10], "%Y-%m-%d")
            # Calculate patch age relative to 2026
            current_date = datetime(2026, 7, 1)
            days_old = (current_date - patch_date).days
            if days_old > 730:
                vulns.append(f"Outdated Security Patch Level ({security_patch}). Device is missing {days_old // 30} months of security patches (High CVE Risk).")
        except ValueError:
            pass

    return vulns


def _adb(serial: str, *args: str, timeout: int = 30) -> str:
    """Run an adb shell command and return stripped stdout ('' on failure)."""
    try:
        proc = run_command(["adb", "-s", serial, "shell", *args], timeout=timeout)
        return (proc.stdout or "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _detect_bootloader_unlocked(serial: str, device_data: Dict[str, Any]) -> tuple[bool, list[str]]:
    """Check multiple device properties to determine bootloader unlock state.

    Different vendors expose the state via different props, so we probe all of
    them and treat the device as unlocked if ANY reliable indicator says so.
    """
    indicators: list[str] = []
    evidence: list[str] = []

    for prop, unlocked_values in BOOTLOADER_UNLOCK_INDICATORS.items():
        try:
            value = _adb(serial, "getprop", prop, timeout=15)
        except Exception:
            continue
        value = value.strip().lower()
        if not value:
            continue
        if value in unlocked_values:
            indicators.append(prop)
            evidence.append(f"{prop}={value}")
        elif prop == "ro.boot.verifiedbootstate" and value == "green":
            evidence.append("ro.boot.verifiedbootstate=green (locked)")

    # Fallback: the raw `ro.boot.bootloader` string sometimes carries state.
    if not indicators:
        try:
            bootloader_prop = (device_data.get("bootloader") or "").lower()
            if "unlock" in bootloader_prop or "unlocked" in bootloader_prop:
                indicators.append("ro.boot.bootloader")
                evidence.append(f"ro.boot.bootloader contains 'unlock'")
        except Exception:
            pass

    return bool(indicators), evidence


def detect_root(input_path: str, output_path: str):
    logger.info("Starting root detection and OS security audit")

    if not os.path.exists(input_path):
        logger.warning(f"Input file not found: {input_path}")
        return

    device_data = read_json(input_path)
    serial = device_data.get("serial", "")
    if not serial:
        logger.error("No device serial found")
        return

    # Ensure the adb server is running before probing the device.
    try:
        run_command(["adb", "start-server"], timeout=15)
    except Exception as exc:
        logger.warning(f"adb start-server failed: {exc}")

    android_version = device_data.get("android_version", "")
    sdk = device_data.get("sdk", "")
    security_patch = device_data.get("security_patch", "")

    checks = {
        "su_binary_found": False,
        "su_locations_found": [],
        "magisk_detected": False,
        "root_manager_detected": False,
        "is_debuggable_build": False,
        "selinux_status": "Unknown",
        "build_tags": "Unknown",
        "is_test_keys": False,
        "ro_secure": "Unknown",
        "adb_enabled": True,
        "developer_options_enabled": False,
        "bootloader_unlocked": False,
        "bootloader_evidence": [],
        "os_vulnerabilities": []
    }
    risk_factors = []

    # Check OS & CVE vulnerability exposure
    cve_risks = check_os_vulnerabilities(android_version, sdk, security_patch)
    checks["os_vulnerabilities"] = cve_risks
    risk_factors.extend(cve_risks)

    # Check 1: su binary (explicit paths + `which su`)
    for path in SU_PATHS:
        try:
            proc = run_command(["adb", "-s", serial, "shell", "ls", path])
            if proc.returncode == 0:
                checks["su_binary_found"] = True
                checks["su_locations_found"].append(path)
                risk_factors.append(f"su binary found at {path}")
        except Exception:
            pass

    if not checks["su_binary_found"]:
        # `which su` returns 0 + path when su is on PATH
        try:
            proc = run_command(["adb", "-s", serial, "shell", "sh", "-c", "which su"])
            if proc.returncode == 0 and proc.stdout.strip():
                checks["su_binary_found"] = True
                checks["su_locations_found"].append(proc.stdout.strip())
                risk_factors.append(f"su binary found at {proc.stdout.strip()}")
        except Exception:
            pass

    # Check 2: magisk / root manager packages
    try:
        proc = run_command(["adb", "-s", serial, "shell", "pm", "list", "packages"])
        pkg_output = (proc.stdout or "").lower()
        if "magisk" in pkg_output:
            checks["magisk_detected"] = True
            risk_factors.append("Magisk package detected")
        for pkg in ROOT_MANAGER_PACKAGES:
            if pkg in pkg_output:
                checks["root_manager_detected"] = True
                risk_factors.append(f"Root manager package installed: {pkg}")
                break
    except Exception:
        pass

    # Check 3: debuggable
    try:
        proc = run_command(["adb", "-s", serial, "shell", "getprop", "ro.debuggable"])
        if proc.stdout.strip() == "1":
            checks["is_debuggable_build"] = True
            risk_factors.append("Debuggable build detected")
    except Exception:
        pass

    # Check 4: ro.secure (0 means root shell possible over ADB)
    try:
        proc = run_command(["adb", "-s", serial, "shell", "getprop", "ro.secure"])
        checks["ro_secure"] = proc.stdout.strip() or "Unknown"
        if proc.stdout.strip() == "0":
            risk_factors.append("ro.secure=0 — unrestricted ADB root shell")
    except Exception:
        pass

    # Check 5: selinux
    try:
        proc = run_command(["adb", "-s", serial, "shell", "getenforce"])
        status = proc.stdout.strip()
        checks["selinux_status"] = status
        if status and status.lower() != "enforcing":
            risk_factors.append(f"SELinux is {status}")
    except Exception:
        pass

    # Check 6: build tags
    try:
        proc = run_command(["adb", "-s", serial, "shell", "getprop", "ro.build.tags"])
        tags = proc.stdout.strip()
        checks["build_tags"] = tags
        if "test-keys" in tags:
            checks["is_test_keys"] = True
            risk_factors.append("Test-keys build tags detected")
    except Exception:
        pass

    # Check 7: developer options / adb
    try:
        proc = run_command(["adb", "-s", serial, "shell", "settings", "get", "global", "development_settings_enabled"])
        if proc.stdout.strip() == "1":
            checks["developer_options_enabled"] = True
            risk_factors.append("Developer options enabled")
    except Exception:
        pass
    try:
        proc = run_command(["adb", "-s", serial, "shell", "settings", "get", "global", "adb_enabled"])
        checks["adb_enabled"] = proc.stdout.strip() == "1"
    except Exception:
        pass

    # Check 8: bootloader state (multi-prop detection)
    bootloader_unlocked, bootloader_evidence = _detect_bootloader_unlocked(serial, device_data)
    checks["bootloader_unlocked"] = bootloader_unlocked
    checks["bootloader_evidence"] = bootloader_evidence
    if bootloader_unlocked:
        risk_factors.append("Bootloader is unlocked / verified boot not enforcing")

    is_rooted = (
        checks["su_binary_found"]
        or checks["magisk_detected"]
        or checks["root_manager_detected"]
        or (checks["ro_secure"] == "0" and checks["is_debuggable_build"])
    )

    if is_rooted:
        risk_level = "critical"
    elif bootloader_unlocked or checks["is_debuggable_build"] or checks["is_test_keys"] or cve_risks:
        risk_level = "high"
    elif checks["developer_options_enabled"]:
        risk_level = "medium"
    else:
        risk_level = "low"

    out_data = {
        "device_serial": serial,
        "is_rooted": is_rooted,
        "risk_level": risk_level,
        "checks": checks,
        "risk_factors": risk_factors
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    write_json(output_path, out_data)
    logger.info("Finished root detection and OS vulnerability audit")
