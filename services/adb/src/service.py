import time
from shared.command import run_command
from shared.logger import get_logger
from shared.json_writer import write_json
from shared.exceptions import DeviceNotFoundError

from models import Device
from config import OUTPUT_DIR, ADB_TIMEOUT


class ADBService:
    """
    Detects the connected Android device and collects hardware/software info.

    Pipeline position: FIRST — all other services depend on this output.

    Output: backend/output/adb/device.json
    """

    def __init__(self):
        self.logger = get_logger("ADB")
        self.device: Device | None = None

    def run(self) -> None:
        self.logger.info("Starting ADB service")

        self._start_adb_server()
        self._detect_device()
        self._collect_info()
        self._save()

        self.logger.info("ADB service finished → device.json written")

    def _start_adb_server(self) -> None:
        self.logger.info("Starting ADB server...")
        result = run_command(["adb", "start-server"], timeout=15)
        if result.returncode == 0:
            self.logger.info("ADB server started")
        else:
            self.logger.warning(
                f"ADB server start returned code {result.returncode}: {result.stderr.strip()}"
            )

    def _detect_device(self) -> None:
        """
        Detect the connected USB device with retry loop for authorization.

        Honors ADB_SERIAL to scan a specific device; otherwise uses the first
        authorized device found (like adb's default behavior).
        """
        import os

        target_serial = os.environ.get("ADB_SERIAL", "").strip()
        max_attempts = 10
        delay = 2

        serial = ""
        state = "unknown"

        for attempt in range(1, max_attempts + 1):
            result = run_command(["adb", "devices"], timeout=ADB_TIMEOUT)
            lines = result.stdout.strip().splitlines()

            device_lines = [
                line for line in lines[1:]
                if line.strip() and not line.startswith("*")
            ]

            if not device_lines:
                if attempt == max_attempts:
                    raise DeviceNotFoundError(
                        "No Android device detected over USB.\n"
                        "Check: USB cable connected, USB debugging enabled, "
                        "device is unlocked and trusted."
                    )
                time.sleep(delay)
                continue

            # Choose the requested serial if provided, otherwise the first device
            if target_serial:
                match = next(
                    (line for line in device_lines if line.split()[0] == target_serial),
                    None,
                )
                if not match:
                    raise DeviceNotFoundError(
                        f"Requested serial '{target_serial}' is not connected over USB. "
                        f"Connected: {[l.split()[0] for l in device_lines]}"
                    )
                parts = match.split()
            else:
                parts = device_lines[0].split()

            serial = parts[0]
            state = parts[1] if len(parts) > 1 else "unknown"

            if state == "device":
                break

            if state == "unauthorized":
                self.logger.warning(
                    f"[{attempt}/{max_attempts}] Device {serial} is 'unauthorized'. "
                    f"Please unlock your phone screen and tap 'ALLOW USB DEBUGGING'!"
                )

            time.sleep(delay)

        if state != "device":
            raise DeviceNotFoundError(
                f"Device {serial} is in state '{state}' — expected 'device'.\n"
                f"If state is 'unauthorized': unlock your phone and tap 'Allow'."
            )

        self.logger.info(f"✅ Android Device Detected & Authorized: {serial} (state={state})")

        self.device = Device(
            serial=serial,
            model="",
            manufacturer="",
            android_version="",
            sdk="",
            build_id="",
            fingerprint="",
            security_patch="",
        )

    def _collect_info(self) -> None:
        """Collect hardware, software, and identity properties via ADB."""

        def getprop(prop: str) -> str:
            result = run_command(
                ["adb", "-s", self.device.serial, "shell", "getprop", prop],
                timeout=ADB_TIMEOUT,
            )
            return result.stdout.strip()

        def shell(cmd: str) -> str:
            result = run_command(
                ["adb", "-s", self.device.serial, "shell", cmd],
                timeout=ADB_TIMEOUT,
            )
            return result.stdout.strip()

        # Basic device info
        self.device.model = getprop("ro.product.model")
        self.device.manufacturer = getprop("ro.product.manufacturer")
        self.device.android_version = getprop("ro.build.version.release")
        self.device.sdk = getprop("ro.build.version.sdk")
        self.device.build_id = getprop("ro.build.id")
        self.device.fingerprint = getprop("ro.build.fingerprint")
        self.device.security_patch = getprop("ro.build.version.security_patch")
        self.device.hardware = getprop("ro.hardware")
        self.device.bootloader = getprop("ro.boot.bootloader")
        self.device.radio_version = getprop("gsm.version.baseband")

        # Wi-Fi and Bluetooth MAC
        self.device.wifi_mac = getprop("ro.wifi.mac") or getprop("wifi.interface.mac")
        self.device.bluetooth_mac = getprop("ro.bt.mac") or getprop("persist.vendor.bt.mac")

        # IMEI / MEID (requires elevated privs; best-effort)
        imei_candidates = []
        for phone_slot in ("1", "2"):
            imei = shell(f"service call iphonesubinfo getDeviceIdForPhone {phone_slot} 2>/dev/null")
            imei_clean = self._parse_hex_string(imei)
            if imei_clean and len(imei_clean) >= 14:
                imei_candidates.append(imei_clean)

        if imei_candidates:
            self.device.imei = imei_candidates[0]
            if len(imei_candidates) > 1:
                self.device.imei_slot2 = imei_candidates[1]

        if not self.device.imei:
            fallback_imei = (
                getprop("ro.ril.miui.imei")
                or getprop("persist.radio.imei")
                or getprop("persist.radio.imei1")
                or getprop("ril.imei")
            )
            if fallback_imei:
                self.device.imei = fallback_imei

        if not self.device.imei_slot2:
            fallback_imei2 = getprop("persist.radio.imei2") or getprop("persist.radio.imei2")
            if fallback_imei2:
                self.device.imei_slot2 = fallback_imei2

        # MEID
        meid = shell("service call iphonesubinfo getMeidForPhone 1 2>/dev/null")
        meid_clean = self._parse_hex_string(meid)
        self.device.meid = meid_clean if meid_clean else (getprop("ril.meid") or None)

        # Phone number / subscriber info (best-effort, slot-aware)
        phone_by_slot: dict[str, str] = {}
        for slot in ("1", "2"):
            sub_info = shell(f"service call iphonesubinfo getSubscriberForPhone {slot} 2>/dev/null")
            sub_clean = self._parse_hex_string(sub_info)
            if sub_clean and len(sub_clean) >= 3:
                phone_by_slot[slot] = sub_clean

        self.device.phone_number = phone_by_slot.get("1") or phone_by_slot.get("2") or None
        self.device.phone_number_slot2 = phone_by_slot.get("2") or None

        if not self.device.phone_number:
            self.device.phone_number = (
                getprop("gsm.operator.alpha")
                or getprop("gsm.msisdn")
                or getprop("ro.ril.msisdn")
                or getprop("gsm.sim.msisdn")
                or None
            )
        if self.device.phone_number and not any(ch.isdigit() for ch in self.device.phone_number):
            self.device.phone_number = None

        # SIM / Subscriber info (slot-aware)
        self.device.sim_operator = getprop("gsm.sim.operator.alpha") or getprop("gsm.sim.operator.alpha.1") or None
        self.device.sim_operator_slot2 = getprop("gsm.sim.operator.alpha.2") or None
        self.device.sim_operator_numeric = getprop("gsm.sim.operator.numeric") or None
        self.device.sim_serial = getprop("gsm.sim.iccid") or getprop("ril.iccid.sim1") or None
        self.device.sim_serial_slot2 = getprop("ril.iccid.sim2") or getprop("gsm.sim.iccid.2") or None
        self.device.subscriber_id = getprop("gsm.sim.subscriber_id") or getprop("gsm.sim.subscriber_id.1") or None
        self.device.subscriber_id_slot2 = getprop("gsm.sim.subscriber_id.2") or None

        # Lock screen & encryption status (best-effort)
        lock_check = shell("locksettings verify --old 2>/dev/null; echo 'EXIT:'$?")
        self.device.screen_lock_enabled = "EXIT:0" not in lock_check  # heuristic
        enc_check = getprop("ro.crypto.state")
        self.device.encryption_enabled = enc_check == "encrypted" if enc_check else None

        self.logger.info(
            f"Device info: {self.device.manufacturer} {self.device.model} "
            f"/ Android {self.device.android_version} (SDK {self.device.sdk}, Patch {self.device.security_patch})"
        )
        if self.device.imei:
            self.logger.info(f"IMEI: {self.device.imei[:6]}****** (last 8 digits redacted)")
        if self.device.sim_operator:
            self.logger.info(f"SIM: {self.device.sim_operator}")

    @staticmethod
    def _parse_hex_string(s: str) -> str:
        """Parse hex-dump output from 'service call' commands into a readable string."""
        import re
        if not s:
            return ""
        # Try to extract hex pairs: '0x30 0x31' -> '01', then decode
        hex_pairs = re.findall(r"0x([0-9A-Fa-f]{2})", s)
        if hex_pairs:
            try:
                chars = [chr(int(h, 16)) for h in hex_pairs if int(h, 16) < 128 and chr(int(h, 16)).isprintable()]
                return "".join(chars).strip()
            except Exception:
                pass
        return s.strip()

    def _save(self) -> None:
        dev = self.device
        write_json(
            f"{OUTPUT_DIR}/device.json",
            {
                "serial": dev.serial,
                "manufacturer": dev.manufacturer,
                "model": dev.model,
                "android_version": dev.android_version,
                "sdk": dev.sdk,
                "build_id": dev.build_id,
                "fingerprint": dev.fingerprint,
                "security_patch": dev.security_patch,
                "hardware": dev.hardware,
                "bootloader": dev.bootloader,
                "radio_version": dev.radio_version,
                "wifi_mac": dev.wifi_mac,
                "bluetooth_mac": dev.bluetooth_mac,
                "imei": dev.imei,
                "imei_slot2": dev.imei_slot2,
                "meid": dev.meid,
                "phone_number": dev.phone_number,
                "phone_number_slot2": dev.phone_number_slot2,
                "sim_operator": dev.sim_operator,
                "sim_operator_slot2": dev.sim_operator_slot2,
                "sim_operator_numeric": dev.sim_operator_numeric,
                "sim_serial": dev.sim_serial,
                "sim_serial_slot2": dev.sim_serial_slot2,
                "subscriber_id": dev.subscriber_id,
                "subscriber_id_slot2": dev.subscriber_id_slot2,
                "screen_lock_enabled": dev.screen_lock_enabled,
                "encryption_enabled": dev.encryption_enabled,
            },
        )
        self.logger.info(f"Saved → {OUTPUT_DIR}/device.json")