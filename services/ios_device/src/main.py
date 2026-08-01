import sys
from shared.logger import get_logger
from service import IOSDeviceService

logger = get_logger("IOSDevice")


def main() -> None:
    try:
        service = IOSDeviceService()
        res = service.run()
        if not res.is_connected:
            logger.error("No iOS device found")
            sys.exit(1)
    except Exception as e:
        logger.error(f"IOS Device service failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
