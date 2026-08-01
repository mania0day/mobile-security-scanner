from dataclasses import dataclass, field


@dataclass
class AppRisk:
    """Risk assessment for a single APK."""
    package_name: str
    risk_score: int = 0
    risk_level: str = "LOW"
    risk_factors: list[str] = field(default_factory=list)

    # Findings summary per source
    yara_matches: int = 0
    yara_severities: dict = field(default_factory=dict)
    cert_issues: list[str] = field(default_factory=list)
    critical_permissions: list[str] = field(default_factory=list)
    high_permissions: list[str] = field(default_factory=list)
    apkid_flags: list[str] = field(default_factory=list)
    vt_malicious: int = 0
    mobsf_score: int = -1  # -1 = not scanned


@dataclass
class DeviceRisk:
    """Risk assessment for the device itself."""
    serial: str
    risk_score: int = 0
    risk_level: str = "LOW"
    risk_factors: list[str] = field(default_factory=list)
    is_rooted: bool = False
    selinux_status: str = ""
    is_debuggable: bool = False
    bootloader_unlocked: bool = False


@dataclass
class RiskAssessment:
    """Unified risk assessment combining device + all apps."""
    scan_timestamp: str
    device_serial: str
    scan_mode: str  # "minimal" or "deep"

    device_risk: DeviceRisk = None
    overall_score: int = 0
    overall_level: str = "LOW"

    total_apps_analyzed: int = 0
    critical_apps: int = 0
    high_apps: int = 0

    app_risks: list[AppRisk] = field(default_factory=list)

    # Which services ran
    services_ran: list[str] = field(default_factory=list)
    services_skipped: list[str] = field(default_factory=list)
