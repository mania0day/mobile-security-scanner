import logging
import os


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger.

    Reads LOG_LEVEL from the environment (default: INFO).
    Valid values: DEBUG, INFO, WARNING, ERROR, CRITICAL.

    Usage:
        logger = get_logger("MyService")
        logger.info("Service started")
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)

        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        )

    return logger