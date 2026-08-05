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
    # Real, reachable-over-standard-USB-pairing signal: known jailbreak-tool
    # bundle IDs (Cydia/Sileo/Zebra/etc) found via the installation proxy.
    # jailbreak_paths_found/binaries_found/dylibs_found/writable_paths_found/
    # open_ports_found above require filesystem/SSH access that only a
    # jailbroken device would expose in the first place — kept for schema
    # compatibility but never populated, since there's no way to reach them
    # on a non-jailbroken device to establish a baseline.
    jailbreak_bundle_ids_found: List[str] = []
