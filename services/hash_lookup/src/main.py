from shared.logger import get_logger
from service import run_hash_lookup

logger = get_logger("HashLookup")


def main():
    logger.info("Hash Lookup service started")
    run_hash_lookup()
    logger.info("Hash Lookup service finished")


if __name__ == "__main__":
    main()
