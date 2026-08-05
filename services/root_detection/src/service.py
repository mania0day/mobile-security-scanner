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


def _confirm_su_execution(serial: str, timeout: int = 5) -> tuple[bool, str]:
    """Actually exercise su to confirm root, rather than inferring from file presence.

    Modern Magisk (Zygisk/DenyList) can hide the su binary path and the Magisk app
    itself from adb-visible checks, but if su genuinely grants root, running it
    still returns uid=0 — this is the strongest single signal we have.
    """
    try:
        proc = run_command(["adb", "-s", serial, "shell", "su", "-c", "id"], timeout=timeout)
        out = (proc.stdout or "").strip()
        return ("uid=0" in out), out[:200]
    except subprocess.TimeoutExpired:
        return False, "(timed out — su may be waiting on a Magisk grant prompt)"
    except Exception:
        return False, ""


def _check_magisk_indicators(serial: str) -> Dict[str, Any]:
    """Probe for modern Magisk artifacts that a renamed/hidden Magisk app or a
    `pm list packages` substring match would otherwise miss entirely.

    Deliberately excludes bare `/data/adb` and `/debug_ramdisk` existence —
    both are standard AOSP artifacts present on many stock, unrooted devices
    (`/data/adb` holds adb_keys persistence since Android 8; `/debug_ramdisk`
    is a normal GKI mountpoint since Android 11) and false-positive on clean
    phones if treated as root signals. Only Magisk-specific paths count.
    """
    return {
        "which_magisk": _adb(serial, "which", "magisk") or None,
        "magisk_version": (_adb(serial, "magisk", "-v") or _adb(serial, "magisk", "--version")) or None,
        "data_adb_magisk": bool(_adb(serial, "ls", "-d", "/data/adb/magisk")),
        "sbin_magisk": bool(_adb(serial, "ls", "/sbin/.magisk")),
    }


def _check_overlay_mounts(serial: str) -> tuple[bool, List[str]]:
    """Look for a writable OverlayFS mount rooted at /data/adb — the pattern
    Magisk/KernelSU use to layer systemless root modifications on top of
    system partitions (upperdir=/data/adb/...).

    Stock Android (and heavily-customized vendor builds like MIUI/HyperOS)
    mount dozens of *read-only* overlay filesystems for completely unrelated
    reasons — e.g. Xiaomi's mi_ext product-partition layering, APEX modules,
    dynamic partitions. Those are `lowerdir=`-only with no `upperdir=`, so a
    bare "overlay" substring match false-positives on every modern device.
    Only a writable overlay anchored in /data/adb is an actual root signal.
    """
    mounts = _adb(serial, "cat", "/proc/mounts")
    matches = [
        line[:200] for line in mounts.splitlines()
        if "overlay" in line.lower() and "upperdir=" in line and "/data/adb" in line
    ]
    return bool(matches), matches[:5]


def _detect_bootloader_unlocked(serial: str, device_data: Dict[str, Any]) -> tuple[bool, list[str], Any]:
    """Check multiple device properties to determine bootloader unlock state.

    Different vendors expose the state via different props, so we probe all of
    them and treat the device as unlocked if ANY reliable indicator says so.

    Also probes `sys.oem_unlock_allowed` as a separate tri-state signal — this
    only indicates whether OEM unlocking is *permitted* in developer options,
    which is not the same thing as the bootloader actually being unlocked.
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

    oem_unlock_allowed = None
    try:
        v = _adb(serial, "getprop", "sys.oem_unlock_allowed", timeout=15).strip().lower()
        if v in ("1", "true"):
            oem_unlock_allowed = True
        elif v in ("0", "false"):
            oem_unlock_allowed = False
        if v:
            evidence.append(f"sys.oem_unlock_allowed={v}")
    except Exception:
        pass

    return bool(indicators), evidence, oem_unlock_allowed


def _quick_composite_probe(serial: str) -> Dict[str, str]:
    """Gather nearly all root/bootloader signals in a SINGLE adb shell round-trip.

    Used only for Quick mode, whose time budget is ~5 seconds. The exhaustive
    per-check style used by Minimal/Deep issues ~25 separate `adb shell`
    invocations (each costing ~100-300ms in practice just for process spawn +
    protocol handshake) — that alone can cost several real-world seconds.
    Bundling everything into one shell script collapses that to one round-trip;
    only the isolated `su -c id` execution-confirmation call stays separate.
    """
    script = (
        "echo SU:$(which su 2>/dev/null || ls /system/bin/su /system/xbin/su 2>/dev/null | head -1); "
        "echo PKGS:$(pm list packages 2>/dev/null | tr '\\n' ','); "
        "echo DEBUG:$(getprop ro.debuggable); echo SECURE:$(getprop ro.secure); "
        "echo SELINUX:$(getenforce 2>/dev/null); "
        "echo TAGS:$(getprop ro.build.tags); "
        "echo DEVOPTS:$(settings get global development_settings_enabled 2>/dev/null); "
        "echo ADBEN:$(settings get global adb_enabled 2>/dev/null); "
        "echo VBSTATE:$(getprop ro.boot.verifiedbootstate); "
        "echo FLASHLOCK:$(getprop ro.boot.flash.locked); "
        "echo VBMETA:$(getprop ro.boot.vbmeta.device_state); "
        "echo OEMUNLOCK:$(getprop sys.oem_unlock_allowed); "
        "echo MAGISKWHICH:$(which magisk 2>/dev/null); "
        "echo DATAADBMAGISK:$([ -d /data/adb/magisk ] && echo yes); "
        "echo SBINMAGISK:$([ -e /sbin/.magisk ] && echo yes); "
        "echo MOUNTS:$(grep -c 'overlay.*upperdir=.*/data/adb' /proc/mounts 2>/dev/null); "
        "echo MOUNTEV:$(grep -m1 'overlay.*upperdir=.*/data/adb' /proc/mounts 2>/dev/null | cut -c1-200)"
    )
    try:
        proc = run_command(["adb", "-s", serial, "shell", script], timeout=10)
        out = (proc.stdout or "")
    except Exception:
        out = ""
    parsed: Dict[str, str] = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            parsed[k.strip()] = v.strip()
    return parsed


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

    # Quick mode trades exhaustiveness for speed (~5s budget) — see
    # _quick_composite_probe() for the rationale.
    fast_mode = (os.environ.get("SCAN_MODE") or "").strip().lower() == "quick"

    checks = {
        "su_binary_found": False,
        "su_locations_found": [],
        "su_execution_confirmed": False,
        "su_execution_output": "",
        "magisk_detected": False,
        "root_manager_detected": False,
        "magisk_indicators": {},
        "overlay_mounts_found": False,
        "overlay_mounts_evidence": [],
        "is_debuggable_build": False,
        "selinux_status": "Unknown",
        "build_tags": "Unknown",
        "is_test_keys": False,
        "ro_secure": "Unknown",
        "adb_enabled": True,
        "developer_options_enabled": False,
        "bootloader_unlocked": False,
        "bootloader_evidence": [],
        "oem_unlock_allowed": None,
        "os_vulnerabilities": []
    }
    risk_factors = []

    # Check OS & CVE vulnerability exposure
    cve_risks = check_os_vulnerabilities(android_version, sdk, security_patch)
    checks["os_vulnerabilities"] = cve_risks
    risk_factors.extend(cve_risks)

    if fast_mode:
        # ── Quick mode: one composite round-trip instead of ~25 individual calls ──
        p = _quick_composite_probe(serial)

        su_path = p.get("SU", "")
        if su_path:
            checks["su_binary_found"] = True
            checks["su_locations_found"].append(su_path)
            risk_factors.append(f"su binary found at {su_path}")

        pkg_output = (p.get("PKGS", "") or "").lower()
        if "magisk" in pkg_output:
            checks["magisk_detected"] = True
            risk_factors.append("Magisk package detected")
        for pkg in ROOT_MANAGER_PACKAGES:
            if pkg in pkg_output:
                checks["root_manager_detected"] = True
                risk_factors.append(f"Root manager package installed: {pkg}")
                break

        checks["is_debuggable_build"] = p.get("DEBUG", "") == "1"
        if checks["is_debuggable_build"]:
            risk_factors.append("Debuggable build detected")

        checks["ro_secure"] = p.get("SECURE", "") or "Unknown"
        if checks["ro_secure"] == "0":
            risk_factors.append("ro.secure=0 — unrestricted ADB root shell")

        selinux_status = p.get("SELINUX", "")
        checks["selinux_status"] = selinux_status or "Unknown"
        if selinux_status and selinux_status.lower() != "enforcing":
            risk_factors.append(f"SELinux is {selinux_status}")

        tags = p.get("TAGS", "")
        checks["build_tags"] = tags or "Unknown"
        if "test-keys" in tags:
            checks["is_test_keys"] = True
            risk_factors.append("Test-keys build tags detected")

        checks["developer_options_enabled"] = p.get("DEVOPTS", "") == "1"
        if checks["developer_options_enabled"]:
            risk_factors.append("Developer options enabled")
        checks["adb_enabled"] = p.get("ADBEN", "") == "1"

        magisk_indicators = {
            "which_magisk": p.get("MAGISKWHICH") or None,
            "data_adb_magisk": p.get("DATAADBMAGISK", "") == "yes",
            "sbin_magisk": p.get("SBINMAGISK", "") == "yes",
        }
        checks["magisk_indicators"] = magisk_indicators
        fired = [k for k, v in magisk_indicators.items() if v]
        if fired:
            risk_factors.append(f"Modern Magisk artifact(s) detected: {', '.join(fired)}")

        overlay_count = p.get("MOUNTS", "0")
        checks["overlay_mounts_found"] = overlay_count.isdigit() and int(overlay_count) > 0
        if checks["overlay_mounts_found"]:
            evidence = p.get("MOUNTEV", "").strip()
            checks["overlay_mounts_evidence"] = [evidence] if evidence else []
            risk_factors.append("Writable OverlayFS mount under /data/adb detected (systemless root indicator)")

        bootloader_indicators = []
        bootloader_evidence = []
        vbstate = (p.get("VBSTATE", "") or "").lower()
        if vbstate in {"orange", "yellow", "red"}:
            bootloader_indicators.append("ro.boot.verifiedbootstate")
            bootloader_evidence.append(f"ro.boot.verifiedbootstate={vbstate}")
        if (p.get("FLASHLOCK", "") or "").lower() == "0":
            bootloader_indicators.append("ro.boot.flash.locked")
            bootloader_evidence.append("ro.boot.flash.locked=0")
        if (p.get("VBMETA", "") or "").lower() == "unlocked":
            bootloader_indicators.append("ro.boot.vbmeta.device_state")
            bootloader_evidence.append("ro.boot.vbmeta.device_state=unlocked")
        bootloader_unlocked = bool(bootloader_indicators)
        checks["bootloader_unlocked"] = bootloader_unlocked
        checks["bootloader_evidence"] = bootloader_evidence
        if bootloader_unlocked:
            risk_factors.append("Bootloader is unlocked / verified boot not enforcing")

        oem_v = (p.get("OEMUNLOCK", "") or "").lower()
        checks["oem_unlock_allowed"] = True if oem_v in ("1", "true") else (False if oem_v in ("0", "false") else None)

        # su execution confirmation stays an isolated call even in quick mode —
        # it's the strongest signal, but a hung Magisk grant-prompt shouldn't be
        # allowed to dominate the ~5s budget, hence the tighter 3s timeout.
        su_confirmed, su_output = _confirm_su_execution(serial, timeout=3)
        checks["su_execution_confirmed"] = su_confirmed
        checks["su_execution_output"] = su_output
        if su_confirmed:
            risk_factors.append(f"su execution confirmed (uid=0): {su_output}")

    else:
        # ── Minimal/Deep: exhaustive per-check style (time budget is minutes) ──

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

        # Check 2b: actually execute su to confirm root — not gated on su_binary_found,
        # since Magisk can hide the su path/app while root access still works.
        su_confirmed, su_output = _confirm_su_execution(serial)
        checks["su_execution_confirmed"] = su_confirmed
        checks["su_execution_output"] = su_output
        if su_confirmed:
            risk_factors.append(f"su execution confirmed (uid=0): {su_output}")

        # Check 2c: modern Magisk artifacts (data/adb, debug_ramdisk, etc.) that survive
        # a renamed/hidden Magisk app and a plain `pm list packages` substring match.
        magisk_indicators = _check_magisk_indicators(serial)
        checks["magisk_indicators"] = magisk_indicators
        fired = [k for k, v in magisk_indicators.items() if v]
        if fired:
            risk_factors.append(f"Modern Magisk artifact(s) detected: {', '.join(fired)}")

        # Check 2d: OverlayFS mounts — common systemless-root indicator.
        overlay_found, overlay_evidence = _check_overlay_mounts(serial)
        checks["overlay_mounts_found"] = overlay_found
        checks["overlay_mounts_evidence"] = overlay_evidence
        if overlay_found:
            risk_factors.append(f"Writable OverlayFS mount under /data/adb detected (systemless root indicator): {overlay_evidence[0]}")

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
        bootloader_unlocked, bootloader_evidence, oem_unlock_allowed = _detect_bootloader_unlocked(serial, device_data)
        checks["bootloader_unlocked"] = bootloader_unlocked
        checks["bootloader_evidence"] = bootloader_evidence
        checks["oem_unlock_allowed"] = oem_unlock_allowed
        if bootloader_unlocked:
            risk_factors.append("Bootloader is unlocked / verified boot not enforcing")

    is_rooted = (
        checks["su_binary_found"]
        or checks["su_execution_confirmed"]
        or checks["magisk_detected"]
        or checks["root_manager_detected"]
        or any(checks["magisk_indicators"].values())
        or checks["overlay_mounts_found"]
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
