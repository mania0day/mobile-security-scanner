from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class MachoAnalysisResult:
    filename: str
    is_pie: bool = False
    has_arc: bool = False
    has_canary: bool = False
    is_encrypted: bool = False
    has_rpath: bool = False
    weak_crypto_calls: List[str] = field(default_factory=list)
    error: Optional[str] = None
    
    def to_dict(self):
        return {
            "filename": self.filename,
            "is_pie": self.is_pie,
            "has_arc": self.has_arc,
            "has_canary": self.has_canary,
            "is_encrypted": self.is_encrypted,
            "has_rpath": self.has_rpath,
            "weak_crypto_calls": self.weak_crypto_calls,
            "error": self.error
        }
