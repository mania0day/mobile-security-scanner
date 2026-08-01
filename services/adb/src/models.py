from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Device:
    serial: str
    model: str
    manufacturer: str
    android_version: str
    sdk: str
    build_id: str
    fingerprint: str
    security_patch: str = ""

    # Extended device identity
    imei: Optional[str] = None
    imei_slot2: Optional[str] = None
    meid: Optional[str] = None
    phone_number: Optional[str] = None
    phone_number_slot2: Optional[str] = None
    sim_operator: Optional[str] = None
    sim_operator_slot2: Optional[str] = None
    sim_operator_numeric: Optional[str] = None
    sim_serial: Optional[str] = None
    sim_serial_slot2: Optional[str] = None
    subscriber_id: Optional[str] = None
    subscriber_id_slot2: Optional[str] = None
    wifi_mac: Optional[str] = None
    bluetooth_mac: Optional[str] = None
    hardware: Optional[str] = None
    bootloader: Optional[str] = None
    radio_version: Optional[str] = None
    screen_lock_enabled: Optional[bool] = None
    encryption_enabled: Optional[bool] = None