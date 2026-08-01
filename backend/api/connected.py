"""Detect phones currently attached over USB (Android ADB / iOS usbmux)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List


ADB_CANDIDATES = [
    os.environ.get("ADB_PATH", ""),
    shutil.which("adb") or "",
    str(Path.home() / "Android" / "Sdk" / "platform-tools" / "adb"),
    "/usr/lib/android-sdk/platform-tools/adb",
]


def _adb_bin() -> str | None:
    for path in ADB_CANDIDATES:
        if path and Path(path).exists() and os.access(path, os.X_OK):
            return path
    return None


def _run(cmd: List[str], timeout: float = 8.0) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def _adb_prop(adb: str, serial: str, prop: str) -> str:
    out = _run([adb, "-s", serial, "shell", "getprop", prop], timeout=5.0)
    return out.strip().splitlines()[0].strip() if out.strip() else ""


def list_connected_devices() -> List[Dict[str, Any]]:
    devices: List[Dict[str, Any]] = []

    adb = _adb_bin()
    if adb:
        raw = _run([adb, "devices", "-l"])
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            if state != "device":
                # unauthorized / offline still listed so UI can guide the user
                devices.append({
                    "platform": "android",
                    "serial": serial,
                    "state": state,
                    "manufacturer": "",
                    "model": "",
                    "os_version": "",
                    "label": f"Android ({serial})",
                    "ready": False,
                    "hint": (
                        "Unlock phone and allow USB debugging"
                        if state == "unauthorized"
                        else f"Device state: {state}"
                    ),
                })
                continue

            manufacturer = _adb_prop(adb, serial, "ro.product.manufacturer")
            model = _adb_prop(adb, serial, "ro.product.model")
            version = _adb_prop(adb, serial, "ro.build.version.release")
            label = f"{manufacturer} {model}".strip() or f"Android {serial}"
            devices.append({
                "platform": "android",
                "serial": serial,
                "state": "device",
                "manufacturer": manufacturer,
                "model": model,
                "os_version": version,
                "label": label,
                "ready": True,
                "hint": f"Android {version}" if version else "Ready to scan",
            })

    # iOS via libimobiledevice if present
    idevice = shutil.which("idevice_id") or shutil.which("ideviceinfo")
    if shutil.which("idevice_id"):
        ids = [x.strip() for x in _run(["idevice_id", "-l"]).splitlines() if x.strip()]
        for udid in ids:
            name = ""
            product = ""
            version = ""
            if shutil.which("ideviceinfo"):
                info = _run(["ideviceinfo", "-u", udid])
                for line in info.splitlines():
                    if line.startswith("DeviceName:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("ProductType:"):
                        product = line.split(":", 1)[1].strip()
                    elif line.startswith("ProductVersion:"):
                        version = line.split(":", 1)[1].strip()
            label = name or product or f"iPhone {udid[:8]}"
            devices.append({
                "platform": "ios",
                "serial": udid,
                "state": "device",
                "manufacturer": "Apple",
                "model": name or product,
                "os_version": version,
                "label": label,
                "ready": True,
                "hint": f"iOS {version}" if version else "Ready to scan",
            })
    elif idevice:
        pass

    return devices
