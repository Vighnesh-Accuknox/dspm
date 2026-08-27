import logging
import sys


def get_logger(name: str) -> logging.Logger:
    """
    Returns a configured Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s",
            ),
        )
        logger.addHandler(handler)
    return logger
