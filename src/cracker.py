"""
Cracking orchestration — hashcat (GPU) → aircrack-ng (CPU) fallback,
plus the parallel AircrackBackend implementation.
"""

import os
import re
import math
import time
import atexit
import tempfile
import threading
import subprocess

from src.console import console, colored_log, log_error, log_debug
from src.config import RESULTS_DIR
from src.utils import sanitize_ssid, lower_process_priority
from src.backend import CrackerBackend
from src.hashcat import (
    is_hashcat_available,
    convert_cap_to_hc22000,
    crack_with_hashcat,
    HASHCAT_EXHAUSTED,
)

from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
#  Orchestration
# ═══════════════════════════════════════════════════════════════════════

def crack_password(
    handshake_path: str,
    wordlist_path: str,
    network,
    silent: bool = False,
    use_hashcat: Optional[bool] = None,
    has_discrete_gpu: bool = True,
) -> str | None:
    """
    High-level password cracker.

    Args:
        handshake_path: Path to the .cap handshake file.
        wordlist_path:  Path to the wordlist.
        network:        WiFiNetwork object (for display/logging).
        silent:         If True, suppresses most output.
        use_hashcat:    True = force hashcat, False = force aircrack-ng,
                        None = auto-detect.
        has_discrete_gpu: Hint for hashcat ``-O`` flag.

    Returns:
        The cracked password, or None.
    """
    if not os.path.exists(handshake_path) or not os.path.exists(wordlist_path):
        if not silent:
            colored_log("error", "Handshake or wordlist not found!")
        return None

    # Auto-detect hashcat
    if use_hashcat is None:
        use_hashcat = is_hashcat_available()
        if use_hashcat and not silent:
            colored_log("success", "Hashcat detected — GPU cracking preferred.")

    # ── Hashcat path ──────────────────────────────────────────────
    if use_hashcat:
        if not is_hashcat_available():
            if not silent:
                colored_log("warning", "Hashcat unavailable — falling back to aircrack-ng.")
            use_hashcat = False
        else:
            if not silent:
                colored_log("success", "Attempting GPU cracking with hashcat...")

    if use_hashcat:
        # Convert .cap → .hc22000
        hc22000_dir = os.path.join(os.getcwd(), "hc22000_cache")
        os.makedirs(hc22000_dir, exist_ok=True)
        safe = sanitize_ssid(network.essid)
        hc22000_path = os.path.join(hc22000_dir, f"{safe}.hc22000")

        if not silent:
            colored_log("info", "Converting handshake to hashcat format...")

        if not convert_cap_to_hc22000(handshake_path, hc22000_path):
            if not silent:
                colored_log("warning", "Conversion failed — falling back to aircrack-ng.")
            use_hashcat = False
        else:
            password = crack_with_hashcat(
                hc22000_path, wordlist_path, network.essid, has_discrete_gpu,
            )

            # Cleanup temp
            try:
                os.remove(hc22000_path)
            except OSError:
                pass

            if password and password is not HASHCAT_EXHAUSTED:
                # Save result
                _save_result(network, password, "hashcat (GPU)")
                return password

            if password is HASHCAT_EXHAUSTED:
                if not silent:
                    colored_log("warning", "Wordlist exhausted — password not in list.")
                # Still fall through to aircrack-ng? No — wordlist is exhausted.
                return None

            # Hashcat didn't find it — fall through
            if not silent:
                colored_log("warning", "Hashcat didn't crack it. Trying aircrack-ng (CPU)...")

    # ── Aircrack-ng path ───────────────────────────────────────────
    if not silent:
        colored_log("info", "Cracking with aircrack-ng (CPU)...")

    backend = AircrackBackend()
    password = backend.crack(handshake_path, wordlist_path, network.essid)

    if password:
        _save_result(network, password, "aircrack-ng (CPU)")
    return password


def _save_result(network, password: str, method: str):
    """Write the cracked result to ``results/<essid>_result.txt``."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    safe = sanitize_ssid(network.essid)
    path = os.path.join(RESULTS_DIR, f"{safe}_result.txt")
    try:
        with open(path, "r") as f:
            existing = f.read()
    except (FileNotFoundError, OSError):
        existing = ""

    if "Password:" not in existing:
        with open(path, "w") as f:
            f.write(f"Network: {network.essid} ({network.bssid})\n")
            f.write(f"Password: {password}\n")
            f.write(f"Channel: {network.channel}\n")
            f.write(f"Encryption: {network.encryption}\n")
            f.write(f"Power: {network.power} dBm\n")
            f.write(f"Cracking Method: {method}\n")
        colored_log("info", f"Result saved to {path}")
    else:
        colored_log("info", f"Result already saved for {network.essid}")


# ═══════════════════════════════════════════════════════════════════════
#  AircrackBackend (parallel CPU cracking)
# ═══════════════════════════════════════════════════════════════════════

_active_procs: list[subprocess.Popen] = []
_active_procs_lock = threading.Lock()
_cached_chunks: dict[str, list[str]] = {}


def _terminate_all():
    with _active_procs_lock:
        for proc in _active_procs[:]:
            try:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)
            except Exception:
                pass
        _active_procs.clear()


def _cleanup_chunks():
    for paths in _cached_chunks.values():
        if not paths:
            continue
        chunk_dir = os.path.dirname(paths[0])
        for p in paths:
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(chunk_dir)
        except OSError:
            pass
    _cached_chunks.clear()


atexit.register(_terminate_all)
atexit.register(_cleanup_chunks)


def _crack_worker(chunk_path: str, handshake_path: str, results: list):
    try:
        proc = subprocess.Popen(
            ["aircrack-ng", "-w", chunk_path, handshake_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
        )
    except OSError as e:
        if getattr(e, "winerror", None) == 225:
            _clear_status()
            console.print("  Windows Defender blocked aircrack-ng.exe. Add an exclusion.")
        else:
            _clear_status()
            console.print(f"  Failed to launch aircrack-ng: {e}")
        return

    with _active_procs_lock:
        _active_procs.append(proc)

    lower_process_priority(proc.pid)

    try:
        stdout, _ = proc.communicate()
        if "KEY FOUND!" in stdout:
            results.append(stdout)
    finally:
        with _active_procs_lock:
            if proc in _active_procs:
                _active_procs.remove(proc)


class AircrackBackend:
    """Crack handshakes using aircrack-ng (CPU) with parallel wordlist chunks."""

    def crack(
        self,
        handshake_path: str,
        wordlist_path: str,
        display_essid: str,
    ) -> str | None:
        start_time = time.time()
        found_results: list[str] = []

        # Split wordlist into chunks
        if wordlist_path not in _cached_chunks:
            n = max(1, (os.cpu_count() or 2) // 2)
            chunk_dir = tempfile.mkdtemp(prefix="hs_crack_")
            paths: list[str] = []
            wl_size = os.path.getsize(wordlist_path)
            chunk_size = math.ceil(wl_size / n)

            with open(wordlist_path, "rb") as f:
                for i in range(n):
                    cp = os.path.join(chunk_dir, f"chunk_{i}.txt")
                    with open(cp, "wb") as cf:
                        written = 0
                        while written < chunk_size:
                            buf = f.read(min(1 << 20, chunk_size - written))
                            if not buf:
                                break
                            written += len(buf)
                            cf.write(buf)
                        if written > 0 and not buf.endswith(b"\n"):
                            remainder = f.readline()
                            cf.write(remainder)
                    paths.append(cp)
            _cached_chunks[wordlist_path] = paths

        chunk_paths = _cached_chunks[wordlist_path]
        threads = []

        for cp in chunk_paths:
            t = threading.Thread(
                target=_crack_worker,
                args=(cp, handshake_path, found_results),
                daemon=True,
            )
            t.start()
            threads.append(t)

        # ── Wait silently with a single-line Rich status ──────────
        from rich.console import Console as _Console
        status = console.status(
            f"Cracking [bold]{display_essid}[/] with aircrack-ng...",
            spinner="dots",
        )
        status.start()
        try:
            while not found_results and any(t.is_alive() for t in threads):
                time.sleep(0.5)
        finally:
            status.stop()

        for t in threads:
            if t.is_alive():
                t.join(timeout=2)

        if not found_results:
            console.print("  Password not found in wordlist. Try a larger wordlist.")
            return None

        stdout = found_results[0]
        match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", stdout)
        if not match:
            console.print("  Password not found in wordlist.")
            return None

        password = match.group(1)
        elapsed = time.time() - start_time
        m, s = divmod(int(elapsed), 60)
        time_str = f"{m:02d}:{s:02d}"

        console.print(f"  Password: {password}")
        console.print(f"  Time: {time_str}")
        return password
