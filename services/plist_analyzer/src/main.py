import json
import logging
from pathlib import Path
from src.config import config
from src.service import PlistAnalyzerService

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def main():
    logger.info("Initializing Plist Analyzer Service")
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    service = PlistAnalyzerService()
    
    inventory_file = config.INPUT_DIR / "extracted.json"
    results = []
    
    if inventory_file.exists():
        with open(inventory_file, 'r') as f:
            try:
                inventory = json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse {inventory_file}")
                inventory = []
                
        for app in inventory:
            app_id = app.get("app_id", "unknown")
            app_path = Path(app.get("extracted_path", ""))
            
            if app_path.exists():
                logger.info(f"Analyzing {app_id} at {app_path}")
                result = service.analyze_app(app_id, app_path)
                results.append(result.model_dump())
            else:
                logger.warning(f"Extracted path does not exist for {app_id}: {app_path}")
    else:
        logger.warning(f"Inventory file not found: {inventory_file}")
        
    with open(config.RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)
        
    logger.info(f"Results saved to {config.RESULTS_FILE}")

if __name__ == "__main__":
    main()
