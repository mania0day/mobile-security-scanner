from pydantic import BaseModel
from typing import List, Optional

class MvtResult(BaseModel):
    scan_mode: str
    mvt_enabled: bool
    skipped: bool
    skip_reason: str
    ioc_matches: List[dict]
    total_ioc_matches: int
    error: str = ""
