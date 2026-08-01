from typing import List, Optional
from dataclasses import dataclass, field

@dataclass
class ApkManifest:
    package: str
    min_sdk: str
    target_sdk: str
    debuggable: bool
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)

@dataclass
class AndroguardResult:
    package_name: str
    apk_path: str
    manifest: Optional[ApkManifest] = None
    error: str = ""

    def to_dict(self):
        result = {
            "package_name": self.package_name,
            "apk_path": self.apk_path,
            "error": self.error,
        }
        if self.manifest:
            result["manifest"] = {
                "package": self.manifest.package,
                "min_sdk": self.manifest.min_sdk,
                "target_sdk": self.manifest.target_sdk,
                "debuggable": self.manifest.debuggable,
                "permissions": self.manifest.permissions,
                "activities": self.manifest.activities,
                "services": self.manifest.services,
                "receivers": self.manifest.receivers,
                "providers": self.manifest.providers,
                "libraries": self.manifest.libraries,
            }
        else:
             result["manifest"] = None
        return result
