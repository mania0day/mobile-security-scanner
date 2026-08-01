from pydantic import BaseModel
from typing import List, Optional

class MatchResult(BaseModel):
    rule: str
    severity: str
    description: str
    matched_strings: List[str]

class YaraAppResult(BaseModel):
    package_name: str
    apk_path: str
    matches: List[MatchResult]
    match_count: int
    error: str = ""

class YaraFinalResult(BaseModel):
    total_analyzed: int
    total_with_matches: int
    results: List[YaraAppResult]
