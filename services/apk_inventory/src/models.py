from dataclasses import dataclass, field


@dataclass
class App:
    """
    Represents a single installed Android application.

    Fields:
        package_name:   Unique app identifier (e.g., com.whatsapp)
        is_system_app:  True if pre-installed by manufacturer/OS
        version_name:   Human-readable version (e.g., "2.23.14")
        version_code:   Internal build number used for updates
        installer:      Which store/source installed this app
        apk_paths:      One or more paths on the device (split APKs exist)
    """
    package_name: str
    is_system_app: bool
    version_name: str = ""
    version_code: str = ""
    installer: str = ""
    apk_paths: list[str] = field(default_factory=list)


@dataclass
class AppInventory:
    """Full inventory of installed apps on the device."""
    device_serial: str
    total_count: int
    user_app_count: int
    system_app_count: int
    apps: list[App]
