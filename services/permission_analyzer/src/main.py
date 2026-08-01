from shared.logger import get_logger
from config import INPUT_FILE, OUTPUT_FILE
from service import PermissionAnalyzerService

logger = get_logger("PermissionAnalyzer")


def main() -> None:
    service = PermissionAnalyzerService()
    service.run()


if __name__ == "__main__":
    main()
