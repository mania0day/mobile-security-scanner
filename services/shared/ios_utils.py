"""
iOS Shared Utilities for Mobile Security Scanner.
Wraps pymobiledevice3 and libimobiledevice CLI commands.
"""
import json
import logging
from typing import Dict, Any, Tuple
from shared.command import run_command

logger = logging.getLogger("iOSUtils")


def get_ios_device_info() -> Tuple[bool, Dict[str, Any], str]:
    """
    Attempts to detect a connected iOS device using pymobiledevice3 or ideviceinfo.
    Returns (success, device_dict, error_message).
    """
    try:
        # Try pymobiledevice3's lockdown info first — `usbmux list` only returns
        # connection identifiers (udid/connection type), never product_version/
        # build_version/device_name, so those fields always stayed empty when
        # this path was taken. `lockdown info` reads the full lockdown record.
        proc = run_command(["pymobiledevice3", "lockdown", "info", "--json"], timeout=10)
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                if isinstance(data, dict) and (data.get("UniqueDeviceID") or data.get("udid")):
                    udid = data.get("UniqueDeviceID", data.get("udid", ""))
                    return True, {
                        "udid": udid,
                        "device_name": data.get("DeviceName", ""),
                        "device_class": data.get("DeviceClass", "iPhone"),
                        "product_type": data.get("ProductType", ""),
                        "product_version": data.get("ProductVersion", ""),
                        "build_version": data.get("BuildVersion", ""),
                        "raw": data,
                    }, ""
            except Exception:
                pass

        # Fallback to ideviceinfo if installed
        proc_idevice = run_command(["ideviceinfo", "-s"], timeout=10)
        if proc_idevice.returncode == 0 and proc_idevice.stdout.strip():
            lines = proc_idevice.stdout.strip().splitlines()
            info = {}
            for line in lines:
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip()] = v.strip()

            udid = info.get("UniqueDeviceID", info.get("udid", ""))
            return True, {
                "udid": udid,
                "device_name": info.get("DeviceName", ""),
                "device_class": info.get("DeviceClass", "iPhone"),
                "product_type": info.get("ProductType", ""),
                "product_version": info.get("ProductVersion", ""),
                "build_version": info.get("BuildVersion", ""),
                "raw": info
            }, ""

        return False, {}, "No iOS device detected via USB"
    except Exception as e:
        logger.error(f"Error detecting iOS device: {e}")
        return False, {}, str(e)


def get_installed_app_bundle_ids() -> list[str]:
    """
    List installed application bundle IDs via pymobiledevice3's installation
    proxy — this works over a standard (non-jailbroken) USB pairing, unlike
    filesystem/SSH-based jailbreak checks which require the device to already
    be jailbroken to reach. Used to spot known jailbreak-tool apps (Cydia,
    Sileo, Zebra, ...) that install as ordinary user-visible apps.
    """
    try:
        proc = run_command(["pymobiledevice3", "apps", "list", "--user", "--system", "--json"], timeout=20)
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                if isinstance(data, dict):
                    return list(data.keys())
                if isinstance(data, list):
                    return [
                        (a.get("CFBundleIdentifier") or a.get("bundle_id") or "")
                        for a in data if isinstance(a, dict)
                    ]
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Could not list installed apps for jailbreak bundle-ID check: {e}")
    return []
