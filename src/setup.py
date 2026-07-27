"""
Auto-setup — runs once at startup to ensure the environment is ready.

Checks / installs in order:
  1. Python dependencies (pip install -r requirements.txt).
  2. System-level dependencies (aircrack-ng suite on Linux).
  3. Hashcat binary (download if missing).
  4. Wordlist (download/update from GitHub).
  5. Required directories.
  6. GPU detection.
"""

import os
import sys
import platform
import subprocess

from src.console import console, colored_log, log_error, log_debug
from src.config import (
    PROJECT_ROOT, HANDSHAKES_DIR, RESULTS_DIR, LOGS_DIR, HCOV_DIR, BIN_DIR,
    WORDLIST_NAME, DEFAULT_WORDLIST_PATH, WORDLIST_URL,
    AIRCRACK_DEPS, AIRCRACK_WIN_URL, BIN_DIR, DEPS_DIR,
    AIRCRACK_ZIP_NAME, AIRCRACK_WIN_SHA256,
    SYSTEM, IS_LINUX, IS_WINDOWS,
)
from src.utils import (
    check_dependency, check_dependencies, download_wordlist,
    download_and_extract_zip, extract_local_zip,
)
from src.gpu import detect_gpu
from src.hashcat import ensure_hashcat

# ── Auto-install Python dependencies ────────────────────────────────────

_REQUIREMENTS = os.path.join(PROJECT_ROOT, "requirements.txt")


def _pip_install_requirements(req_path: str) -> bool:
    """Install requirements.txt via pip, with --break-system-packages fallback."""
    base = [sys.executable, "-m", "pip", "install", "--user", "-r", req_path]
    try:
        subprocess.run(base, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        combined = ((e.stderr or "") + (e.stdout or "")).lower()
        if "externally-managed" in combined:
            try:
                subprocess.run(
                    base + ["--break-system-packages"],
                    check=True, capture_output=True, text=True,
                )
                return True
            except subprocess.CalledProcessError:
                return False
        return False
    except Exception:
        return False


def ensure_python_deps() -> bool:
    """Auto-install missing Python packages from requirements.txt."""
    if not os.path.isfile(_REQUIREMENTS):
        colored_log("warning", "requirements.txt not found, skipping Python deps.")
        return True

    # Check if core deps are already importable
    missing = []
    for mod in ["rich", "scapy"]:
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)

    if not missing:
        log_debug("All Python dependencies already installed.")
        return True

    colored_log("info", f"Installing missing Python packages: {', '.join(missing)}...")
    if _pip_install_requirements(_REQUIREMENTS):
        colored_log("success", "Python dependencies installed.")
        return True

    colored_log("error", "Failed to install Python dependencies.")
    colored_log("info", f"Try manually: pip install --user -r {_REQUIREMENTS}")
    return False


# ── System-level dependencies (aircrack-ng suite) ───────────────────────

def _find_exe_in_path(exe: str) -> str | None:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d.strip('"'), exe)
        if os.path.isfile(p):
            return p
    return None


def _add_parent_to_path(found_path: str):
    parent = os.path.dirname(os.path.abspath(found_path))
    if parent not in os.environ.get("PATH", ""):
        os.environ["PATH"] = parent + os.pathsep + os.environ.get("PATH", "")


def ensure_aircrack() -> bool:
    """Ensure aircrack-ng suite is available (install on Linux, download on Windows)."""
    # Already available?
    missing = check_dependencies(AIRCRACK_DEPS)
    if not missing:
        colored_log("success", "aircrack-ng suite detected.")
        return True

    if IS_LINUX:
        # Try apt-get install
        pm = _find_exe_in_path("apt-get")
        if not pm:
            pm = _find_exe_in_path("pacman")
        if not pm:
            colored_log("error", "No supported package manager found. Install aircrack-ng manually.")
            return False

        if "apt-get" in (pm or ""):
            cmd = ["sudo", "apt-get", "install", "-y", "aircrack-ng"]
        else:
            cmd = ["sudo", "pacman", "-S", "--noconfirm", "aircrack-ng"]

        colored_log("info", f"Installing aircrack-ng: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120)
            missing = check_dependencies(AIRCRACK_DEPS)
            if not missing:
                colored_log("success", "aircrack-ng suite installed.")
                return True
        except subprocess.TimeoutExpired:
            colored_log("error", "Installation timed out (sudo may be needed).")
            colored_log("info", f"Run manually: {' '.join(cmd)}")
            return False
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        colored_log("error", "Could not install aircrack-ng automatically.")
        return False

    elif IS_WINDOWS:
        # Download and extract aircrack-ng for Windows
        os.makedirs(BIN_DIR, exist_ok=True)
        local_zip = os.path.join(DEPS_DIR, AIRCRACK_ZIP_NAME)
        if os.path.isfile(local_zip):
            colored_log("info", "Found local aircrack-ng ZIP, extracting...")
            if extract_local_zip(local_zip, BIN_DIR, "aircrack-ng-1.7-win/bin"):
                # Update PATH
                for exe in AIRCRACK_DEPS:
                    exe_name = f"{exe}.exe" if not exe.endswith(".exe") else exe
                    for root, dirs, files in os.walk(BIN_DIR):
                        if exe_name in files:
                            _add_parent_to_path(os.path.join(root, exe_name))
                            break
                return True

        return download_and_extract_zip(
            AIRCRACK_WIN_URL, BIN_DIR,
            "aircrack-ng-1.7-win/bin", AIRCRACK_WIN_SHA256,
        )

    else:
        colored_log("error", f"Unsupported OS: {SYSTEM}. Install aircrack-ng manually.")
        return False


# ── Wordlist ────────────────────────────────────────────────────────────

def _get_latest_wordlist_url() -> str:
    """Return the raw URL for the latest wifite.txt from the master branch."""
    return "https://raw.githubusercontent.com/Mysteriza/WiFi-Password-Wordlist/main/wifite.txt"


def ensure_wordlist() -> bool:
    """Download or update the wordlist from GitHub."""
    url = _get_latest_wordlist_url()

    if os.path.exists(DEFAULT_WORDLIST_PATH):
        local_size = os.path.getsize(DEFAULT_WORDLIST_PATH)
        colored_log("info", f"Local wordlist found ({local_size // 1024} KB). Checking for updates...")

        try:
            import urllib.request
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                remote_size = int(resp.headers.get("Content-Length", 0))
            if remote_size > local_size:
                colored_log("info", f"Newer wordlist available ({remote_size // 1024} KB). Updating...")
                if download_wordlist(url, DEFAULT_WORDLIST_PATH):
                    colored_log("success", f"Wordlist updated ({remote_size // 1024} KB).")
                    return True
                return True
            else:
                colored_log("success", f"Wordlist is up-to-date ({local_size // 1024} KB).")
                return True
        except Exception:
            colored_log("success", f"Using local wordlist ({local_size // 1024} KB).")
            return True

    # No local wordlist — download
    colored_log("info", "No local wordlist found. Downloading from GitHub...")
    return download_wordlist(url, DEFAULT_WORDLIST_PATH)


# ── Directories ─────────────────────────────────────────────────────────

def ensure_directories() -> bool:
    """Create all required directories."""
    for d in [HANDSHAKES_DIR, RESULTS_DIR, LOGS_DIR, HCOV_DIR, BIN_DIR, DEPS_DIR]:
        try:
            os.makedirs(d, exist_ok=True)
        except (OSError, PermissionError) as e:
            log_error(f"Cannot create directory: {d}", e)
            if d == RESULTS_DIR:
                return False
    return True


# ── Main setup routine ──────────────────────────────────────────────────

def auto_setup() -> dict:
    """
    Run the full setup pipeline.

    Returns a dict with detection results:
        gpu_name: str | None
        gpu_is_discrete: bool
        use_hashcat: bool  (hashcat binary available)
        aircrack_available: bool
    """
    colored_log("info", "Running auto-setup...")

    # 1. Ensure directories
    ensure_directories()

    # 2. Python dependencies
    ensure_python_deps()

    # 3. System dependencies (aircrack-ng)
    aircrack_ok = ensure_aircrack()

    # 4. Hashcat
    hashcat_ok = ensure_hashcat()

    # 5. Wordlist
    ensure_wordlist()

    # 6. GPU detection
    gpu_name, gpu_is_discrete = detect_gpu()

    # 7. Determine backend priority
    use_hashcat = False
    if hashcat_ok and gpu_name:
        use_hashcat = True
        gpu_type = "Discrete" if gpu_is_discrete else "Integrated"
        colored_log("success", f"GPU detected: {gpu_name} ({gpu_type}) — hashcat ready.")
    elif hashcat_ok:
        use_hashcat = True
        colored_log("info", "Hashcat available (GPU detection incomplete).")
    else:
        colored_log("info", "No GPU / hashcat found — will use aircrack-ng (CPU).")

    if not aircrack_ok:
        colored_log("error", "aircrack-ng suite is NOT available. Cracking will fail.")

    return {
        "gpu_name": gpu_name,
        "gpu_is_discrete": gpu_is_discrete,
        "use_hashcat": use_hashcat,
        "aircrack_available": aircrack_ok,
        "hashcat_available": hashcat_ok,
    }
