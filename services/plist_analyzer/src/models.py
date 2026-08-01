from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class ATSInfo(BaseModel):
    allows_arbitrary_loads: bool = False
    exception_domains: Dict[str, Any] = Field(default_factory=dict)

class PrivacyPermissions(BaseModel):
    camera: Optional[str] = None
    microphone: Optional[str] = None
    location_always: Optional[str] = None
    contacts: Optional[str] = None
    other: Dict[str, str] = Field(default_factory=dict)

class PlistInfo(BaseModel):
    bundle_id: str
    version: str
    ats: ATSInfo
    privacy: PrivacyPermissions
    url_schemes: List[str]
    background_modes: List[str]

class EntitlementsInfo(BaseModel):
    keychain_groups: List[str] = Field(default_factory=list)
    app_groups: List[str] = Field(default_factory=list)
    icloud_containers: List[str] = Field(default_factory=list)
    push_notifications: bool = False
    task_allow: bool = False

class AnalyzerResult(BaseModel):
    app_id: str
    plist_info: Optional[PlistInfo] = None
    entitlements_info: Optional[EntitlementsInfo] = None
    errors: List[str] = Field(default_factory=list)
