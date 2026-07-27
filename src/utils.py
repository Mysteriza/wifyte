"""
General-purpose utility functions — networking helpers, file operations,
process control, vendor lookup, target selection, banner, etc.
"""

import os
import re
import sys
import math
import time
import glob
import json
import struct
import shutil
import hashlib
import logging
import tempfile
import threading
import platform
import subprocess
import urllib.request
from typing import Optional

from src.console import console, colored_log, log_error, log_debug


# ── SSID / filename helpers ────────────────────────────────────────────

def sanitize_ssid(ssid: str) -> str:
    """Remove characters that are unsafe in filenames."""
    cleaned = re.sub(r'[\\/*?:"<>|]', "", ssid)
    return cleaned.strip().replace(" ", "_")


def strip_capture_extension(path: str) -> str:
    """Return the base filename without .cap / .pcap suffix."""
    base = os.path.basename(path)
    if base.lower().endswith(".cap"):
        return base[:-4]
    if base.lower().endswith(".pcap"):
        return base[:-5]
    return base


# ── Dependency checks ───────────────────────────────────────────────────

def check_dependency(cmd: str) -> bool:
    """Return True if *cmd* is available on the system PATH."""
    return shutil.which(cmd) is not None


def check_dependencies(deps: list[str]) -> list[str]:
    """Return the subset of *deps* that are missing."""
    return [dep for dep in deps if not check_dependency(dep)]


# ── Shell execution ─────────────────────────────────────────────────────

def execute_command(
    command: list[str],
    shell: bool = False,
    capture_output: bool = True,
    timeout: int | None = None,
) -> subprocess.CompletedProcess | None:
    """Run a command and return the CompletedProcess, or None on error."""
    try:
        return subprocess.run(
            command,
            shell=shell,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        colored_log("error", f"Command not found: {command[0]}")
        return None
    except subprocess.TimeoutExpired:
        colored_log("error", f"Command timed out: {command[0]}")
        return None
    except Exception as e:
        colored_log("error", f"Command failed: {e}")
        return None


# ── Process priority ────────────────────────────────────────────────────

def lower_process_priority(pid: int):
    """Reduce CPU priority so cracking doesn't starve the rest of the system."""
    system = platform.system()
    try:
        if system == "Windows":
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if handle:
                ctypes.windll.kernel32.SetPriorityClass(handle, 0x00004000)  # IDLE
                ctypes.windll.kernel32.CloseHandle(handle)
        else:
            os.setpriority(os.PRIO_PROCESS, pid, 19)
    except Exception:
        pass


# ── Vendor lookup ───────────────────────────────────────────────────────

_VENDOR_MAP: dict[str, str] = {}


def load_vendor_db(manuf_path: str) -> int:
    """
    Load a Wireshark-style ``manuf`` file into the global vendor map.
    Returns the number of entries loaded (0 if file absent).
    """
    _VENDOR_MAP.clear()
    if not os.path.exists(manuf_path):
        return 0

    count = 0
    try:
        with open(manuf_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 2)
                if len(parts) < 2:
                    continue
                mac_prefix = parts[0].upper()
                vendor_name = parts[2] if len(parts) == 3 else parts[1]

                octets = mac_prefix.replace("-", ":").split("/")[0].split(":")
                if len(octets) >= 3:
                    normalized = ":".join(octets[:3])
                    _VENDOR_MAP[normalized] = vendor_name
                    count += 1
    except Exception as e:
        log_error("Failed to load vendor DB", e)
    return count


def lookup_vendor(mac: str) -> str:
    """Return vendor name for a MAC address, or ``"Unknown"``."""
    if ":" not in mac:
        return "Unknown"
    normalized = re.sub(r"[^A-Z0-9]", ":", mac.upper())
    octets = normalized.split(":")
    if len(octets) < 3:
        return "Unknown"
    prefix = ":".join(octets[:3])
    return _VENDOR_MAP.get(prefix, "Unknown")


# ── Wordlist helpers ────────────────────────────────────────────────────

def count_wordlist_lines(path: str) -> int:
    """Count lines in a text file efficiently (1 MB buffer)."""
    try:
        with open(path, "rb") as f:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: f.read(1 << 20), b""))
    except OSError:
        return 0


def create_default_wordlist(path: str):
    """Create a minimal default wordlist if none exists."""
    if os.path.exists(path):
        return
    words = ["password", "12345678", "qwerty123", "admin123", "wifi12345"]
    try:
        with open(path, "w") as f:
            f.write("\n".join(words) + "\n")
        colored_log("success", f"Default wordlist created: {path}")
    except OSError as e:
        log_error("Cannot create default wordlist", e)


# ── Download helpers ────────────────────────────────────────────────────

def download_with_progress(
    url: str,
    dest: str,
    label: str = "Downloading",
    expected_sha256: str | None = None,
) -> bool:
    """Download a file with a progress bar, optionally verify SHA-256."""
    try:
        def report(block_count, block_size, total_size):
            downloaded = block_count * block_size / (1024 * 1024)
            total = total_size / (1024 * 1024)
            sys.stdout.write(f"\r{label}: {downloaded:.1f}MB / {total:.1f}MB")
            sys.stdout.flush()

        urllib.request.urlretrieve(url, dest, report)
        sys.stdout.write("\n")

        if expected_sha256:
            sys.stdout.write("Verifying checksum...\n")
            hasher = hashlib.sha256()
            with open(dest, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            actual = hasher.hexdigest().upper()
            if actual != expected_sha256.upper():
                colored_log("error", f"Checksum mismatch for {label}!")
                os.unlink(dest)
                return False
            colored_log("success", "Checksum verified.")

        return True
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        colored_log("warning", f"{label} interrupted.")
        return False
    except Exception as e:
        log_error(f"Download failed: {url}", e)
        return False


def download_wordlist(url: str, dest: str) -> bool:
    """Download wordlist from URL to *dest*."""
    colored_log("info", "Wordlist not found. Downloading...")
    if download_with_progress(url, dest, "Wordlist"):
        colored_log("success", f"Wordlist ready: {dest}")
        return True
    if os.path.exists(dest):
        try:
            os.remove(dest)
        except OSError:
            pass
    colored_log("error", "Failed to download wordlist.")
    return False


# ── ZIP extraction ─────────────────────────────────────────────────────

def extract_local_zip(zip_path: str, extract_to: str, subdir: str | None = None) -> bool:
    """Extract a ZIP archive, optionally scoped to a sub-directory."""
    import zipfile
    try:
        os.makedirs(extract_to, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                if subdir and not member.startswith(subdir):
                    continue
                rel = member[len(subdir):].lstrip("/") if subdir else member
                if not rel:
                    continue
                target = os.path.join(extract_to, rel)
                if member.endswith("/"):
                    os.makedirs(target, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as dst:
                        dst.write(src.read())
        colored_log("success", f"Extracted '{os.path.basename(zip_path)}'.")
        return True
    except Exception as e:
        log_error(f"Extraction failed: {zip_path}", e)
        return False


def download_and_extract_zip(
    url: str,
    extract_to: str,
    subdir: str | None = None,
    expected_sha256: str | None = None,
) -> bool:
    """Download a ZIP and extract it."""
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            tmp = f.name
        if not download_with_progress(url, tmp, "Downloading archive", expected_sha256):
            return False
        return extract_local_zip(tmp, extract_to, subdir)
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ── Scanner helpers ─────────────────────────────────────────────────────

def signal_percent(power_dbm: int) -> int:
    """Convert dBm to a 0-100 signal percentage."""
    return max(0, min(100, int((power_dbm + 100) * 1.42857)))


# ── Target selection ────────────────────────────────────────────────────

def select_target(networks) -> list | None:
    """Interactive target selection — prompt for one or more network IDs."""
    while True:
        try:
            console.print(
                "[?] Select Targets (e.g., '1' or '1, 2, 5') (0 to exit): ",
                style="yellow bold", end="",
            )
            raw = input().strip()
            if raw == "0":
                return None

            ids = [int(i.strip()) - 1 for i in raw.split(",") if i.strip().isdigit()]
            if not ids:
                colored_log("error", "Invalid input. Enter valid numbers.")
                continue

            valid = []
            for idx in ids:
                if 0 <= idx < len(networks):
                    valid.append(networks[idx])
                else:
                    colored_log("warning", f"Network ID {idx + 1} out of range.")

            if not valid:
                colored_log("error", "No valid targets selected.")
                continue
            return valid
        except (ValueError, KeyboardInterrupt):
            colored_log("warning", "Invalid input / cancelled.")
            return None


# ── Spinner ─────────────────────────────────────────────────────────────

def loading_spinner(stop_event: threading.Event, message: str):
    """Show a spinner animation until *stop_event* is set."""
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while not stop_event.is_set():
        console.print(
            f"[*] {message} {chars[idx % len(chars)]}",
            style="bright_cyan", end="\r",
        )
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)
    console.print(" " * 80, end="\r")
    sys.stdout.flush()


# ── Banner ──────────────────────────────────────────────────────────────

BANNER = """
██╗    ██╗██╗███████╗██╗   ██╗████████╗███████╗
██║    ██║██║██╔════╝╚██╗ ██╔╝╚══██╔══╝██╔════╝
██║ █╗ ██║██║█████╗   ╚████╔╝    ██║   █████╗
██║███╗██║██║██╔══╝    ╚██╔╝     ██║   ██╔══╝
╚███╔███╔╝██║██║        ██║      ██║   ███████╗
 ╚══╝╚══╝ ╚═╝╚═╝        ╚═╝      ╚═╝   ╚══════╝
"""


def display_banner():
    """Print the Wifyte ASCII banner."""
    console.print(BANNER, style="bright_cyan bold")
    console.print(
        "WiFi Handshake Capture & Cracking Tool",
        style="yellow", justify="left",
    )
