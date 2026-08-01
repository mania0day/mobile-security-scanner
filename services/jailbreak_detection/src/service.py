import json
import os
from . import config
from .models import JailbreakResult


def check_ios_vulnerabilities(product_version: str) -> list[str]:
    """
    Audit iOS version against known major CVE vulnerability releases (Pegasus/FORCEDENTRY, WebKit RCEs).
    """
    vulns = []
    if not product_version:
        return vulns

    try:
        parts = [int(p) for p in product_version.split(".")[:2]]
        major = parts[0]
        minor = parts[1] if len(parts) > 1 else 0

        if major < 16:
            vulns.append(f"Legacy iOS Version ({product_version}). Missing core security mitigations; susceptible to FORCEDENTRY / BLASTPASS zero-click exploits (CVE-2023-41064, CVE-2021-30860).")
        elif major == 16 and minor < 6:
            vulns.append(f"Outdated iOS 16 Version ({product_version}). Susceptible to Operation Triangulation kernel RCE vulnerabilities (CVE-2023-32434, CVE-2023-32435).")
    except ValueError:
        pass

    return vulns


class JailbreakDetector:
    def __init__(self, device_data: dict):
        self.device_data = device_data

    def detect(self) -> JailbreakResult:
        # Check against paths configured in config
        found_paths = [p for p in config.JAILBREAK_PATHS if p in self.device_data.get('paths', [])]
        found_bins = [b for b in config.BIN_PATHS if b in self.device_data.get('paths', [])]
        found_dylibs = [d for d in config.DYLIBS if d in self.device_data.get('dylibs', [])]
        found_writable = [w for w in config.WRITE_TEST_PATHS if w in self.device_data.get('writable_paths', [])]
        found_ports = [p for p in config.OPEN_PORTS if p in self.device_data.get('open_ports', [])]

        is_jb = any([found_paths, found_bins, found_dylibs, found_writable, found_ports])

        dev_info = self.device_data.get('device_info', {})
        product_version = dev_info.get('ProductVersion', '')
        cve_vulns = check_ios_vulnerabilities(product_version)

        return JailbreakResult(
            is_jailbroken=bool(is_jb),
            jailbreak_paths_found=found_paths,
            binaries_found=found_bins,
            dylibs_found=found_dylibs,
            writable_paths_found=found_writable,
            open_ports_found=found_ports,
            device_info=dev_info,
            cve_vulnerabilities=cve_vulns
        )


def run_detection(input_file: str, output_file: str):
    device_data = {}
    if os.path.exists(input_file):
        with open(input_file, 'r') as f:
            device_data = json.load(f)

    detector = JailbreakDetector(device_data)
    result = detector.detect()

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        f.write(result.model_dump_json(indent=4))
