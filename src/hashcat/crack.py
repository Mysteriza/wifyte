"""
Hashcat backend — GPU-accelerated WPA/WPA2 cracking (mode 22000).

Converts a .cap to .hc22000, warms up the GPU kernel, runs hashcat,
and reads the result from the hashcat potfile.

Exports:
    - crack_with_hashcat()
    - HashcatBackend class
    - HASHCAT_EXHAUSTED sentinel
"""

import os
import re
import sys
import time
import threading
import subprocess
from typing import Optional

from src.console import console, colored_log, log_error, log_debug
from src.config import RESULTS_DIR
from src.utils import sanitize_ssid
from src.hashcat.convert import convert_cap_to_hc22000
from src.hashcat.setup import (
    get_hashcat_path, is_hashcat_available, warmup_hashcat_kernel,
)


# ── Sentinel ────────────────────────────────────────────────────────────

class _ExhaustedType:
    """Sentinel returned when hashcat exhausts the wordlist without finding a key."""
    def __bool__(self):
        return False
    def __repr__(self):
        return "HASHCAT_EXHAUSTED"

HASHCAT_EXHAUSTED = _ExhaustedType()


# ── Potfile reader ──────────────────────────────────────────────────────

_POTFILE = os.path.join(os.path.expanduser("~"), ".hashcat", "hashcat.potfile")
_POTFILE_LOCK = threading.Lock()


def _read_potfile(bssid: str, essid: str) -> str | None:
    """
    Search the hashcat potfile for a matching network.

    Returns the password (everything after the last ``:``) or None.
    """
    if not os.path.exists(_POTFILE):
        return None
    bssid_upper = bssid.upper().replace("-", ":")
    with _POTFILE_LOCK:
        try:
            with open(_POTFILE, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(":")
                    if len(parts) >= 3:
                        # Format: hash:bssid:password
                        pw = parts[-1]
                        stored_bssid = parts[-2].upper().replace("-", ":")
                        if stored_bssid == bssid_upper:
                            return pw
        except OSError:
            pass
    return None


# ── Core cracking function ─────────────────────────────────────────────

_crack_spinner_messages = [
    "Loading kernel into GPU...",
    "Computing PMK for each word...",
    "Running fast hash comparison...",
    "Testing candidate passwords...",
    "Nearly there, checking results...",
]


def crack_with_hashcat(
    hc22000_path: str,
    wordlist_path: str,
    display_essid: str,
    gpu_is_discrete: bool = True,
) -> str | None | _ExhaustedType:
    """
    Crack a .hc22000 handshake using hashcat.

    Args:
        hc22000_path:   Path to the converted hashcat hash file.
        wordlist_path:  Path to the wordlist.
        display_essid:  User-visible network name (for messages).
        gpu_is_discrete: If True, adds ``-O`` kernel optimisation flag.

    Returns:
        - Password string on success.
        - ``HASHCAT_EXHAUSTED`` if the wordlist was fully searched.
        - ``None`` if an error occurred.
    """
    if not os.path.exists(hc22000_path) or not os.path.exists(wordlist_path):
        log_error("Missing hash or wordlist file for hashcat.")
        return None

    hashcat_bin = get_hashcat_path()
    if not hashcat_bin:
        log_error("Hashcat binary not found.")
        return None

    warmup_hashcat_kernel(hc22000_path)

    # Build command
    cmd = [
        hashcat_bin,
        "-m", "22000",
        "-a", "0",
        "--status", "--status-timer=1",
    ]
    if gpu_is_discrete:
        cmd.append("-O")   # Optimised kernel (faster, less compatible)
    cmd.extend([hc22000_path, wordlist_path])

    colored_log("info", f"Running hashcat for {display_essid}...")
    log_debug(f"Hashcat command: {' '.join(cmd)}")

    spinner_stop = threading.Event()
    spinner = threading.Thread(
        target=_hashcat_spinner, args=(spinner_stop,), daemon=True,
    )
    spinner.start()

    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=3600,
        )
    except subprocess.TimeoutExpired:
        colored_log("error", "Hashcat timed out (1 hour).")
        return None
    finally:
        spinner_stop.set()
        spinner.join(timeout=1)

    elapsed = time.time() - start_time
    log_debug(f"Hashcat finished in {elapsed:.1f}s")

    # Check if exhausted (all candidates tested)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    combined = stdout + stderr
    exhausted = "Exhausted" in combined or "All hashes" in combined

    # Read potfile
    password = _read_potfile(hc22000_path, display_essid)

    if password:
        m, s = divmod(int(elapsed), 60)
        time_str = f"{m:02d}:{s:02d}"
        colored_log("success",
                    f"Password found for {display_essid}: [bold]{password}[/bold]")
        console.print(f"  - Time: {time_str}", style="green")
        console.print(f"  - Method: hashcat (GPU)", style="green")
        return password

    if exhausted:
        console.print(f"  Wordlist exhausted — password not found.")
        return HASHCAT_EXHAUSTED

    console.print(f"  Hashcat did not find the password.")
    return None


# ── Spinner ─────────────────────────────────────────────────────────────

def _hashcat_spinner(stop: threading.Event):
    chars = ["-", "\\", "|", "/"]
    msg_idx = 0
    char_idx = 0
    last_switch = time.time()
    while not stop.is_set():
        msg = _crack_spinner_messages[msg_idx % len(_crack_spinner_messages)]
        console.print(f"  {chars[char_idx % 4]} {msg}", style="bright_cyan", end="\r")
        sys.stdout.flush()
        char_idx += 1
        now = time.time()
        if now - last_switch >= 6:
            msg_idx += 1
            last_switch = now
        time.sleep(0.15)
    console.print(" " * 80, end="\r")
    sys.stdout.flush()


# ── Backend class ──────────────────────────────────────────────────────

class HashcatBackend:
    """Hashcat-based cracking backend (GPU)."""

    def crack(
        self,
        handshake_path: str,
        wordlist_path: str,
        display_essid: str,
    ) -> str | None:
        """
        Convert, warm up, crack, and return the password.

        Accepts a .cap file (conversion happens internally).
        """
        # Convert .cap → .hc22000
        hc22000_dir = HCOV_DIR
        os.makedirs(hc22000_dir, exist_ok=True)
        safe = sanitize_ssid(display_essid)
        hc22000_path = os.path.join(hc22000_dir, f"{safe}.hc22000")

        if not convert_cap_to_hc22000(handshake_path, hc22000_path):
            colored_log("warning", "Hashcat conversion failed.")
            return None

        result = crack_with_hashcat(hc22000_path, wordlist_path, display_essid)

        # Cleanup
        try:
            os.remove(hc22000_path)
        except OSError:
            pass

        if result is HASHCAT_EXHAUSTED:
            return None
        return result
