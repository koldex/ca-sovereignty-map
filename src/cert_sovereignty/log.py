"""Logging configuration using loguru.

Reused directly from mxmap's log.py pattern.
"""

from __future__ import annotations

import sys

from loguru import logger


def setup_logging(verbose: bool = False) -> None:
    """Configure loguru for the application."""
    logger.remove()

    level = "DEBUG" if verbose else "INFO"

    logger.add(
        sys.stderr,
        level=level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> — "
            "<level>{message}</level>"
        ),
        colorize=True,
    )
