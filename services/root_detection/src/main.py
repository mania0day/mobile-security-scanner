from shared.logger import get_logger
from config import INPUT_FILE, OUTPUT_FILE
from service import detect_root

logger = get_logger("RootDetection")


def main():
    logger.info("Root Detection service started")
    detect_root(INPUT_FILE, OUTPUT_FILE)
    logger.info("Root Detection service finished")


if __name__ == "__main__":
    main()
