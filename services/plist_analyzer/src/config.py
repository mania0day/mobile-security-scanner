import os
from pathlib import Path

class Config:
    INPUT_DIR: Path = Path(os.getenv("INPUT_DIR", "/app/backend/output/ipa_inventory"))
    OUTPUT_DIR: Path = Path(os.getenv("OUTPUT_DIR", "/app/backend/output/plist_analyzer"))
    RESULTS_FILE: Path = OUTPUT_DIR / "results.json"
    
config = Config()
