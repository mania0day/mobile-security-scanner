from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class ApkidFindings:
    compiler: List[str] = field(default_factory=list)
    obfuscator: List[str] = field(default_factory=list)
    anti_debug: List[str] = field(default_factory=list)
    anti_vm: List[str] = field(default_factory=list)
    packer: List[str] = field(default_factory=list)

@dataclass
class ApkidResult:
    package_name: str
    apk_path: str
    findings: ApkidFindings = field(default_factory=ApkidFindings)
    raw_output: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

@dataclass
class ApkidSummary:
    total_analyzed: int = 0
    total_with_findings: int = 0
    results: List[ApkidResult] = field(default_factory=list)
