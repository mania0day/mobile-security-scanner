import logging
from .config import INPUT_FILE, OUTPUT_FILE
from .service import run_detection
from .exceptions import JailbreakDetectionError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    try:
        logger.info(f"Starting jailbreak detection using input {INPUT_FILE}")
        run_detection(INPUT_FILE, OUTPUT_FILE)
        logger.info(f"Successfully wrote results to {OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Error during jailbreak detection: {e}")
        raise JailbreakDetectionError(e)

if __name__ == "__main__":
    main()
