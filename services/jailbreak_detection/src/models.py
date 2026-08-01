from pydantic import BaseModel
from typing import List, Dict, Any


class JailbreakResult(BaseModel):
    is_jailbroken: bool
    jailbreak_paths_found: List[str]
    binaries_found: List[str]
    dylibs_found: List[str]
    writable_paths_found: List[str]
    open_ports_found: List[int]
    device_info: Dict[str, Any]
    cve_vulnerabilities: List[str] = []
