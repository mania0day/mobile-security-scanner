from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    signature_algorithm: str
    sha1_fingerprint: str
    sha256_fingerprint: str
    serial_number: str
    is_expired: bool
    is_self_signed: bool

    def to_dict(self):
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature_algorithm": self.signature_algorithm,
            "sha1_fingerprint": self.sha1_fingerprint,
            "sha256_fingerprint": self.sha256_fingerprint,
            "serial_number": self.serial_number,
            "is_expired": self.is_expired,
            "is_self_signed": self.is_self_signed
        }

@dataclass
class RiskFlags:
    uses_weak_algorithm: bool
    is_expired: bool
    is_debug_cert: bool
    
    def to_dict(self):
        return {
            "uses_weak_algorithm": self.uses_weak_algorithm,
            "is_expired": self.is_expired,
            "is_debug_cert": self.is_debug_cert
        }

@dataclass
class CertificateResult:
    package_name: str
    apk_path: str
    certificate: Optional[CertificateInfo] = None
    risk_flags: Optional[RiskFlags] = None
    error: str = ""

    def to_dict(self):
        return {
            "package_name": self.package_name,
            "apk_path": self.apk_path,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "risk_flags": self.risk_flags.to_dict() if self.risk_flags else None,
            "error": self.error
        }
