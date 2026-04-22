"""
core/logger.py
==============
Centralised logging configuration for the EDR system.

Import get_logger() in every module:
    from core.logger import get_logger
    logger = get_logger(__name__)
"""

import logging
import os
from datetime import datetime

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

_LOG_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _configure() -> None:
    global _configured
    if _configured:
        return

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # System-wide log
    fh = logging.FileHandler(os.path.join(LOG_DIR, "system.log"), encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
    root.addHandler(fh)

    # Console — WARNING and above only (reduces noise)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
    root.addHandler(ch)

    # Suppress noisy third-party loggers
    for noisy in ("pyshark", "urllib3", "asyncio", "werkzeug"):
        logging.getLogger(noisy).setLevel(logging.CRITICAL)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a named logger, ensuring global config is applied."""
    _configure()
    return logging.getLogger(name)