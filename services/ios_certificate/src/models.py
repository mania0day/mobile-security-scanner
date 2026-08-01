from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime

class CertificateModel(BaseModel):
    sha1_fingerprint: str
    sha256_fingerprint: str
    issuer: str
    expiration: datetime
    is_expired: bool

class ProvisioningProfileModel(BaseModel):
    type: str  # Development, AdHoc, Enterprise, AppStore
    team_name: str
    team_id: List[str]
    app_id: str
    creation_date: datetime
    expiration_date: datetime
    is_expired: bool
    entitlements: Dict[str, Any]
    certificates: List[CertificateModel]
    provisioned_devices: Optional[List[str]] = None
