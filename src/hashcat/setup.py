"""
Hashcat binary discovery — check PATH, download & extract the pre-compiled
binary release, warm up GPU kernel.

Downloads ``hashcat-{VERSION}.7z`` from GitHub releases (the binary
release, NOT the source tarball).  On Windows we auto-download the
standalone ``7zr.exe`` (~300 KB) from 7-zip.org so no external archiver
is needed.

The warm-up step is critical: the first hashcat run after a driver update
or new GPU install takes 30-60 seconds compiling OpenCL kernels. We cache
the compiled kernels so subsequent runs are instant.
"""

import os
import sys
import time
import glob
import shutil
import platform
import threading
import subprocess
from typing import Optional

from src.console import console, colored_log, log_error, log_debug
from src.config import (
    HASHCAT_VERSION, HASHCAT_URL_7Z, HASHCAT_7Z_SHA256,
    BIN_DIR, DEPS_DIR, HCOV_DIR, IS_LINUX, IS_WINDOWS,
)
from src.utils import download_with_progress, execute_command


# ── State ───────────────────────────────────────────────────────────────

_hashcat_path: str | None = None
_SEVEN_ZIP_EXE: str | None = None          # path to 7z(r) for extraction


# ── Discovery ──────────────────────────────────────────────────────────

def get_hashcat_path() -> str | None:
    """Return the cached path to the hashcat binary, or None."""
    return _hashcat_path


def is_hashcat_available() -> bool:
    """Check whether hashcat is currently available (cached or on PATH)."""
    if _hashcat_path and os.path.isfile(_hashcat_path):
        return True
    found = shutil.which("hashcat")
    return found is not None


# ── 7z extraction (standalone 7zr.exe on Windows) ──────────────────────

_7ZR_URL = "https://www.7-zip.org/a/7zr.exe"


def _ensure_7zr() -> bool:
    """Ensure a 7‑Zip executable is available, downloading 7zr.exe if needed."""
    global _SEVEN_ZIP_EXE

    # Already located
    if _SEVEN_ZIP_EXE and os.path.isfile(_SEVEN_ZIP_EXE):
        return True

    # On Linux/macOS try the system 7z
    if not IS_WINDOWS:
        for exe in ("7z", "7zr", "7za"):
            p = shutil.which(exe)
            if p:
                _SEVEN_ZIP_EXE = p
                return True
        log_error("7z not found. Install it: sudo apt-get install p7zip-full")
        return False

    # Windows – download standalone 7zr.exe next to hashcat
    sz = os.path.join(BIN_DIR, "7zr.exe")
    if os.path.isfile(sz):
        _SEVEN_ZIP_EXE = sz
        return True

    colored_log("info", "Downloading standalone 7zr.exe for extraction...")
    if not download_with_progress(_7ZR_URL, sz, "7zr"):
        log_error("Failed to download 7zr.exe from 7-zip.org.")
        return False
    _SEVEN_ZIP_EXE = sz
    return True


def _extract_archive(archive: str, dest: str) -> bool:
    """Extract a .7z archive using the 7‑Zip executable."""
    if not _ensure_7zr():
        return False

    colored_log("info", f"Extracting {os.path.basename(archive)}...")
    try:
        subprocess.run(
            [_SEVEN_ZIP_EXE, "x", archive, f"-o{dest}", "-y"],
            capture_output=True, text=True, check=True, timeout=120,
        )
        colored_log("success", "Extraction complete.")
        return True
    except subprocess.TimeoutExpired:
        log_error("Extraction timed out.")
        return False
    except subprocess.CalledProcessError as e:
        log_error(f"Extraction failed: {e.stderr or e.stdout}")
        return False
    except Exception as e:
        log_error("Extraction error", e)
        return False


# ── Download & install ─────────────────────────────────────────────────

def _add_path(dirpath: str):
    """Add *dirpath* to the system PATH for the current process."""
    if dirpath not in os.environ.get("PATH", ""):
        os.environ["PATH"] = dirpath + os.pathsep + os.environ.get("PATH", "")


def _expected_binary_path() -> str:
    """
    Return the expected path for the hashcat binary *after* the official
    ``.7z`` is extracted under ``BIN_DIR``.
    """
    exe_name = "hashcat.exe" if IS_WINDOWS else "hashcat"
    return os.path.join(BIN_DIR, f"hashcat-{HASHCAT_VERSION}", exe_name)


def ensure_hashcat() -> bool:
    """
    Ensure hashcat is available by checking (in order):

      1. Already cached path.
      2. System PATH.
      3. Local ``bin/hashcat-{VERSION}/hashcat.exe``.
      4. Download ``hashcat-{VERSION}.7z`` from GitHub releases + extract.

    Returns True if available.
    """
    global _hashcat_path

    # 1. Already cached
    if _hashcat_path and os.path.isfile(_hashcat_path):
        return True

    # 2. PATH
    found_on_path = shutil.which("hashcat")
    if found_on_path:
        _hashcat_path = found_on_path
        colored_log("success", f"Hashcat found on PATH: {_hashcat_path}")
        return True

    # 3. Local bin/hashcat-{VERSION}/hashcat.exe
    expected = _expected_binary_path()
    if os.path.isfile(expected):
        _hashcat_path = expected
        _add_path(os.path.dirname(expected))
        colored_log("success", f"Hashcat found locally: {_hashcat_path}")
        return True

    # 4. Download & extract the binary .7z from GitHub
    colored_log("info", "Hashcat not found. Downloading binary release...")
    os.makedirs(DEPS_DIR, exist_ok=True)
    os.makedirs(BIN_DIR, exist_ok=True)

    archive_7z = os.path.join(DEPS_DIR, f"hashcat-{HASHCAT_VERSION}.7z")
    if not download_with_progress(HASHCAT_URL_7Z, archive_7z, "Hashcat", HASHCAT_7Z_SHA256):
        log_error("Failed to download hashcat from GitHub.")
        return False

    if not _extract_archive(archive_7z, BIN_DIR):
        return False

    # After extraction, verify the binary exists
    if os.path.isfile(expected):
        _hashcat_path = expected
        _add_path(os.path.dirname(expected))
        colored_log("success", f"Hashcat installed: {_hashcat_path}")
        return True

    # Fallback: scan the extraction directory for any hashcat binary
    if _locate_hashcat(BIN_DIR):
        return True

    log_error("Hashcat binary not found after extraction.")
    return False


def _locate_hashcat(search_dir: str) -> bool:
    """Walk *search_dir* looking for the hashcat binary (fallback)."""
    global _hashcat_path
    for root, dirs, files in os.walk(search_dir):
        for f in files:
            if f in ("hashcat", "hashcat.exe"):
                _hashcat_path = os.path.join(root, f)
                _add_path(os.path.dirname(_hashcat_path))
                colored_log("success", f"Hashcat installed: {_hashcat_path}")
                return True
    return False


# ── Kernel warm-up ──────────────────────────────────────────────────────

def _has_kernel_cache() -> bool:
    """Check whether compiled kernel files exist already."""
    cache_dirs = [
        os.path.expanduser("~/.hashcat/kernels"),
        os.path.join(os.getcwd(), "kernels"),
    ]
    for cd in cache_dirs:
        if os.path.isdir(cd):
            for f in os.listdir(cd):
                if f.endswith(".kernel") or f.endswith(".bin"):
                    return True
    return False


def warmup_hashcat_kernel(hc22000_path: str | None = None) -> bool:
    """
    Warm up the GPU OpenCL kernel cache.

    If kernels are already cached this is a no-op.
    Otherwise runs hashcat with a real .hc22000 and a dummy wordlist.
    """
    if _has_kernel_cache():
        log_debug("Hashcat kernel cache already warm.")
        return True

    if not is_hashcat_available():
        colored_log("warning", "Hashcat not available — skipping kernel warm-up.")
        return False

    # Create a minimal dummy wordlist
    dummy_wl = os.path.join(DEPS_DIR, "_warmup_wordlist.txt")
    try:
        with open(dummy_wl, "w") as f:
            f.write("testpassword\n")
    except OSError:
        return False

    # If no real hc22000 was provided, create a minimal one for warm-up
    warmup_hash = hc22000_path
    if not warmup_hash or not os.path.exists(warmup_hash):
        warmup_hash = os.path.join(HCOV_DIR, "_warmup.hc22000")
        if not os.path.exists(warmup_hash):
            # Can't warm up without a hash file — skip
            log_debug("No hc22000 available for kernel warm-up.")
            return False

    hc_dir = os.path.dirname(_hashcat_path)

    cmd = [
        _hashcat_path,
        "-m", "22000",
        "-a", "0",
        "--status", "--status-timer=1",
        "-O",
        warmup_hash,
        dummy_wl,
    ]

    colored_log("info", "Compiling GPU kernels for hashcat (30-60s)...")

    from rich.console import Console as _Console
    status = console.status("Compiling GPU kernels...", spinner="dots")
    status.start()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            cwd=hc_dir,
        )
        success = proc.returncode == 0
    except subprocess.TimeoutExpired:
        log_debug("Kernel warm-up timed out — continuing anyway.")
        success = False
    except PermissionError:
        colored_log("warning",
                    "Hashcat execution blocked by system. "
                    "Add an exception for the 'bin/' folder or disable Real-time protection.")
        log_debug("PermissionError during warm-up — continuing anyway.")
        success = False
    except Exception as e:
        log_debug(f"Kernel warm-up failed: {e} — continuing anyway.")
        success = False
    finally:
        status.stop()

    # Cleanup dummy
    for f in [dummy_wl]:
        try:
            os.remove(f)
        except OSError:
            pass

    if success:
        colored_log("success", "Hashcat kernel cache warmed up.")
    return success
