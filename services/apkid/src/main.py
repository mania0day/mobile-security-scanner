import sys
from shared.logger import get_logger
from service import ApkidService

logger = get_logger("APKID")


def main() -> None:
    try:
        ApkidService().run()
    except Exception as e:
        logger.error(f"APKID service failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
