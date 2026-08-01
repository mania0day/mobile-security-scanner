import sys
import traceback
from shared.logger import get_logger
from service import ReportGeneratorService

logger = get_logger("ReportGenerator")


def main():
    try:
        service = ReportGeneratorService()
        service.run()
    except Exception as e:
        logger.error(f"Report Generator Service failed: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
