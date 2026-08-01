from dataclasses import dataclass, field
from typing import Dict, Any

@dataclass
class IOSDeviceInfo:
    udid: str = ""
    device_name: str = ""
    device_class: str = "iPhone"
    product_type: str = ""
    product_version: str = ""
    build_version: str = ""
    platform: str = "ios"
    is_connected: bool = False
    error: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
