from dataclasses import dataclass
from enum import Enum

class ExtractionStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    NO_PATH = "no_path"

@dataclass
class ExtractionResult:
    package_name: str
    status: ExtractionStatus
    local_path: str = ""
    device_path: str = ""
    error: str = ""
    is_system_app: bool = False
