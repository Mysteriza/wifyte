"""
Centralised configuration — paths, version constants, URLs, and defaults.

All magic numbers and file locations live here so they can be tweaked
without hunting through the codebase.
"""

import os
import sys
import platform
from pathlib import Path

# ── Project root ───────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ── Data directories (created by setup) ────────────────────────────────

HANDSHAKES_DIR = os.path.join(PROJECT_ROOT, "handshakes")
RESULTS_DIR    = os.path.join(PROJECT_ROOT, "results")
LOGS_DIR       = os.path.join(PROJECT_ROOT, "logs")
HCOV_DIR       = os.path.join(PROJECT_ROOT, "hc22000_cache")
BIN_DIR        = os.path.join(PROJECT_ROOT, "bin")
DEPS_DIR       = os.path.join(PROJECT_ROOT, "deps")

# ── Wordlist ───────────────────────────────────────────────────────────

WORDLIST_NAME          = "wifyte.txt"
DEFAULT_WORDLIST_PATH  = os.path.join(PROJECT_ROOT, WORDLIST_NAME)
WORDLIST_URL           = (
    "https://raw.githubusercontent.com/Mysteriza/WiFi-Password-Wordlist/"
    "main/wifite.txt"
)

# ── aircrack-ng ────────────────────────────────────────────────────────

AIRCRACK_DEPS = ["aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng"]

# Windows aircrack bundle (official — aircrack-ng.exe for CPU cracking only)
AIRCRACK_WIN_URL = (
    "https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip"
)
AIRCRACK_ZIP_NAME = "aircrack-ng-1.7-win.zip"
AIRCRACK_WIN_SHA256 = ""

# ── Hashcat ────────────────────────────────────────────────────────────

HASHCAT_VERSION   = "7.1.2"
HASHCAT_URL_BASE  = "https://github.com/hashcat/hashcat/releases/download/"
HASHCAT_URL_7Z    = f"{HASHCAT_URL_BASE}v{HASHCAT_VERSION}/hashcat-{HASHCAT_VERSION}.7z"
HASHCAT_7Z_SHA256 = (
    "80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98"
)
# tar.gz fallback (extractable with Python's built-in tarfile)
HASHCAT_URL_TARGZ = (
    f"https://hashcat.net/files/hashcat-{HASHCAT_VERSION}.tar.gz"
)

# ── Capture / scanning defaults ────────────────────────────────────────

CAPTURE_TIMEOUT            = 60   # seconds before giving up on a handshake
CLIENT_DETECTION_DURATION  = 15   # seconds to listen for clients
SINGLE_SCAN_DURATION       = 8    # seconds for the legacy single-pass scan
DECLOAK_DURATION           = 10   # seconds to attempt hidden-SSID decloak
DEAUTH_COUNT               = 10   # number of deauth frames per client

# ── System detection ───────────────────────────────────────────────────

SYSTEM    = platform.system()
IS_LINUX  = SYSTEM == "Linux"
IS_WINDOWS = SYSTEM == "Windows"
IS_MACOS  = SYSTEM == "Darwin"

# ── Backend detection flags (optional overrides from CLI) ──────────────

USE_HASHCAT = None           # None = auto-detect, True/False = force
HASHCAT_DISCRETE_GPU = True  # tuned per session after GPU detection
