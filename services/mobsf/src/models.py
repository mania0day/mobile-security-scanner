from dataclasses import dataclass, field


@dataclass
class MobSFResult:
    """
    Holds the analysis result for one APK from MobSF.

    MobSF returns a rich JSON report. We extract the most
    security-relevant fields to keep our output manageable.
    """
    package_name: str
    apk_path: str
    file_name: str = ""
    hash: str = ""
    scan_type: str = "apk"

    # Security scores
    security_score: int = 0
    average_cvss: float = 0.0
    severity_high: int = 0
    severity_warning: int = 0
    severity_info: int = 0

    # Key findings
    permissions: list = field(default_factory=list)
    certificate_analysis: dict = field(default_factory=dict)
    network_security: dict = field(default_factory=dict)
    code_analysis_high: list = field(default_factory=list)

    # Status
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""
