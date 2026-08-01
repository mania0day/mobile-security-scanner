import sys
from shared.logger import get_logger
from service import run_extraction

logger = get_logger("ApkExtractor")


def main() -> None:
    """Main entrypoint for APK Extractor."""
    logger.info("Starting APK Extractor Service")
    try:
        run_extraction()
        logger.info("APK Extractor Service completed successfully")
    except Exception as e:
        logger.error(f"APK Extractor Service failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
