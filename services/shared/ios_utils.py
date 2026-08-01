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
        # Try pymobiledevice3 first
        proc = run_command(["pymobiledevice3", "usbmux", "list"], timeout=10)
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                if data and isinstance(data, list) and len(data) > 0:
                    dev = data[0]
                    udid = dev.get("Identifier", dev.get("udid", ""))
                    return True, {
                        "udid": udid,
                        "connection_type": dev.get("ConnectionType", "USB"),
                        "device_type": dev.get("DeviceClass", "iPhone"),
                        "raw": dev
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
