"""
Hashcat binary discovery — check PATH, download & extract tar.gz, warm up GPU kernel.

Downloads ``.tar.gz`` from hashcat.net (extractable with Python's built-in
``tarfile`` — no external archiver needed). Falls back to ``.7z`` from
GitHub if the tar.gz is unavailable (still requires 7-Zip for that path).

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
    HASHCAT_VERSION, HASHCAT_URL_7Z, HASHCAT_7Z_SHA256, HASHCAT_URL_TARGZ,
    BIN_DIR, DEPS_DIR, HCOV_DIR, IS_LINUX, IS_WINDOWS,
)
from src.utils import download_with_progress, execute_command


# ── State ───────────────────────────────────────────────────────────────

_hashcat_path: str | None = None


# ── Discovery ──────────────────────────────────────────────────────────

def get_hashcat_path() -> str | None:
    """Return the cached path to the hashcat binary, or None."""
    return _hashcat_path


def is_hashcat_available() -> bool:
    """Check whether hashcat is currently available (cached or on PATH)."""
    if _hashcat_path and os.path.exists(_hashcat_path):
        return True
    found = shutil.which("hashcat")
    return found is not None


# ── 7z extraction ──────────────────────────────────────────────────────

def _find_7z() -> str | None:
    """Locate a 7-Zip executable on the system."""
    for exe in ["7z", "7zr", "7za"]:
        found = shutil.which(exe)
        if found:
            return found
    # Windows common paths
    paths = [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def _extract_archive(archive: str, dest: str) -> bool:
    """Extract a .7z archive using 7-Zip."""
    sevenz = _find_7z()
    if not sevenz:
        log_error("7-Zip not found. Install 7-Zip or extract manually.")
        return False

    colored_log("info", f"Extracting {os.path.basename(archive)}...")
    try:
        subprocess.run(
            [sevenz, "x", archive, f"-o{dest}", "-y"],
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


# ── Download & install ─────────────────────────────────────────────────

def _add_path(dirpath: str):
    """Add *dirpath* to the system PATH for the current process."""
    if dirpath not in os.environ.get("PATH", ""):
        os.environ["PATH"] = dirpath + os.pathsep + os.environ.get("PATH", "")


def ensure_hashcat() -> bool:
    """
    Ensure hashcat is available.

    Checks (in order):
      1. Already cached path.
      2. System PATH.
      3. Local ``bin/`` directory.
      4. Download + extract to ``deps/``.

    Returns True if available.
    """
    global _hashcat_path

    # 1. Already cached
    if _hashcat_path and os.path.exists(_hashcat_path):
        return True

    # 2. PATH
    path_on_path = shutil.which("hashcat")
    if path_on_path:
        _hashcat_path = path_on_path
        colored_log("success", f"Hashcat found on PATH: {_hashcat_path}")
        return True

    # 3. Local bin/
    local_candidates = [
        os.path.join(BIN_DIR, "hashcat"),
        os.path.join(BIN_DIR, "hashcat.exe"),
        os.path.join(BIN_DIR, "hashcat", "hashcat.exe"),
        os.path.join(BIN_DIR, "hashcat", "hashcat"),
    ]
    for cand in local_candidates:
        if os.path.exists(cand):
            _hashcat_path = cand
            _add_path(os.path.dirname(cand))
            colored_log("success", f"Hashcat found locally: {_hashcat_path}")
            return True

    # 4. Download tar.gz (extractable with Python's built-in tarfile — no 7-Zip needed)
    colored_log("info", "Hashcat not found. Downloading...")
    os.makedirs(DEPS_DIR, exist_ok=True)
    extract_dir = os.path.join(BIN_DIR, "hashcat")

    archive_tgz = os.path.join(DEPS_DIR, f"hashcat-{HASHCAT_VERSION}.tar.gz")
    if not download_with_progress(HASHCAT_URL_TARGZ, archive_tgz, "Hashcat"):
        # Fallback: try 7z from GitHub in case tar.gz is unavailable
        colored_log("info", "tar.gz download failed, trying 7z fallback (requires 7-Zip)...")
        archive_7z = os.path.join(DEPS_DIR, f"hashcat-{HASHCAT_VERSION}.7z")
        if not download_with_progress(HASHCAT_URL_7Z, archive_7z, "Hashcat", HASHCAT_7Z_SHA256):
            log_error("Failed to download hashcat.")
            return False
        if not _extract_archive(archive_7z, extract_dir):
            return False
        if _locate_hashcat(extract_dir):
            return True
        log_error("Hashcat binary not found after 7z extraction.")
        return False

    # Extract tar.gz with Python's built-in tarfile
    import tarfile
    try:
        os.makedirs(extract_dir, exist_ok=True)
        with tarfile.open(archive_tgz, "r:gz") as tar:
            tar.extractall(path=extract_dir)
        colored_log("success", "Extracted hashcat tar.gz.")
    except Exception as e:
        log_error("Failed to extract hashcat tar.gz", e)
        return False

    if _locate_hashcat(extract_dir):
        return True

    log_error("Hashcat binary not found after tar.gz extraction.")
    return False


def _locate_hashcat(search_dir: str) -> bool:
    """Walk *search_dir* looking for the hashcat binary."""
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

    cmd = [
        _hashcat_path,
        "-m", "22000",
        "-a", "0",
        "--status", "--status-timer=1",
        "-O",
        warmup_hash,
        dummy_wl,
    ]

    colored_log("info", "Warming up hashcat GPU kernel (30-60s)...")
    spinner_stop = threading.Event()
    spinner = threading.Thread(
        target=lambda: _warmup_spinner(spinner_stop), daemon=True
    )
    spinner.start()

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )
        success = proc.returncode == 0
    except subprocess.TimeoutExpired:
        log_debug("Kernel warm-up timed out — continuing anyway.")
        success = False
    except PermissionError:
        colored_log("warning", "Hashcat blocked by system (antivirus?). Warm-up skipped.")
        log_debug("PermissionError during warm-up — continuing anyway.")
        success = False
    except Exception as e:
        log_debug(f"Kernel warm-up failed: {e} — continuing anyway.")
        success = False
    finally:
        spinner_stop.set()
        spinner.join(timeout=1)

    # Cleanup dummy
    for f in [dummy_wl]:
        try:
            os.remove(f)
        except OSError:
            pass

    if success:
        colored_log("success", "Hashcat kernel cache warmed up.")
    return success


def _warmup_spinner(stop: threading.Event):
    """Spinner for warm-up progress."""
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while not stop.is_set():
        console.print(f"  Compiling GPU kernels {chars[i % len(chars)]}",
                      style="yellow", end="\r")
        sys.stdout.flush()
        i += 1
        time.sleep(0.2)
    console.print(" " * 50, end="\r")
    sys.stdout.flush()
