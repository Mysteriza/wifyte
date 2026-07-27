"""
Rich console wrapper with rotating file-logging for debugging.

Terminal output uses coloured prefixes; debug logs go to
``logs/debug_log_*.txt`` (last 3 logs kept, oldest auto-removed).
"""

import os
import sys
import glob
import logging
import traceback
from datetime import datetime

from rich.console import Console

from src.config import LOGS_DIR

# ── Console ────────────────────────────────────────────────────────────

console = Console(highlight=False)

# ── Logging setup ──────────────────────────────────────────────────────

_LOGGER: logging.Logger | None = None


def _get_logger() -> logging.Logger:
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER

    os.makedirs(LOGS_DIR, exist_ok=True)

    # Keep last 3 debug logs
    existing = sorted(glob.glob(os.path.join(LOGS_DIR, "debug_log_*.txt")))
    while len(existing) >= 3:
        try:
            os.remove(existing.pop(0))
        except OSError:
            pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOGS_DIR, f"debug_log_{ts}.txt")

    _LOGGER = logging.getLogger("wifyte")
    _LOGGER.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(message)s", datefmt="%H:%M:%S"
    ))
    _LOGGER.addHandler(fh)

    return _LOGGER


# ── Public helpers ──────────────────────────────────────────────────────

def colored_log(level: str, message: str):
    """
    Print a colour-coded log line to the terminal with a prefix,
    and persist to the debug log file.

    Levels: info [*], success [+], warning [!], error [-].
    """
    style_map = {
        "info":    "bright_cyan",
        "success": "green bold",
        "warning": "yellow",
        "error":   "bright_red",
    }
    prefix_map = {
        "info":    "[*]",
        "success": "[+]",
        "warning": "[!]",
        "error":   "[-]",
    }
    style = style_map.get(level, "white")
    prefix = prefix_map.get(level, "[*]")
    console.print(f"{prefix} {message}", style=style)

    # Also persist to file log
    logger = _get_logger()
    log_level_map = {
        "info":    logging.INFO,
        "success": logging.INFO,
        "warning": logging.WARNING,
        "error":   logging.ERROR,
    }
    logger.log(log_level_map.get(level, logging.INFO), message)


def log_debug(message: str, data=None):
    """Write a debug line to the file log (not displayed in terminal)."""
    logger = _get_logger()
    line = message
    if data is not None:
        line += f" | {data}"
    logger.debug(line)


def log_error(message: str, error: Exception | None = None):
    """Log an error to the file and print a brief alert on the terminal."""
    logger = _get_logger()
    logger.error(message)
    if error:
        logger.error(traceback.format_exc())
    if error:
        colored_log("error", f"{message}: {error}")
    else:
        colored_log("error", message)
