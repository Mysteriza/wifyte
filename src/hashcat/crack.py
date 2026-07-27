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
import sys
import time
import subprocess
from typing import Optional

from src.console import console, colored_log, log_error, log_debug
from src.config import RESULTS_DIR
from src.utils import sanitize_ssid, lower_process_priority
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

def _read_potfile_raw(path: str) -> set[str]:
    """Read all lines from a potfile into a set."""
    if not os.path.exists(path):
        return set()
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return set(f.read().splitlines())
    except Exception:
        return set()


def _extract_password_from_lines(lines: set[str]) -> str | None:
    """
    Extract a valid password (8-63 chars) from potfile lines.

    Password is the segment after the last ``:`` that does not start with ``#``.
    """
    for line in lines:
        if ":" in line and not line.startswith("#"):
            pw = line[line.rfind(":") + 1:].strip()
            if 8 <= len(pw) <= 63:
                return pw
    return None


def _check_new_potfile_entry(potfile: str, before: set[str]) -> str | None:
    """Check if any new entries were added to the potfile, return password."""
    after = _read_potfile_raw(potfile)
    new_entries = after - before
    if new_entries:
        pw = _extract_password_from_lines(new_entries)
        if pw:
            return pw
    # Fallback: check full potfile (in case it was replaced)
    if not before:
        return _extract_password_from_lines(after)
    return None


# ── Core cracking function ─────────────────────────────────────────────

_HASHCAT_MESSAGES = [
    "Initializing kernel into GPU...",
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

    # Build command
    cmd = [
        hashcat_bin,
        "-m", "22000",
        "-a", "0",
        "-w", "4" if gpu_is_discrete else "2",
    ]
    if gpu_is_discrete:
        cmd.append("-O")   # Optimised kernel (faster, less compatible)
    cmd.extend(["--session", sanitize_ssid(display_essid),
                hc22000_path, wordlist_path])

    hc_dir = os.path.dirname(hashcat_bin)
    potfile = os.path.join(hc_dir, "hashcat.potfile")

    # ── Fresh potfile every run ──────────────────────────────────
    # Wipe any leftover potfile so we can detect new entries
    # reliably (otherwise hashcat skips already-cracked hashes
    # and our before/after diff sees no change).
    try:
        if os.path.exists(potfile):
            os.remove(potfile)
    except OSError:
        pass

    # Add --potfile-path so we know exactly where to look
    cmd.extend(["--potfile-path", potfile])

    # Warm up GPU kernel (compilation may take 30-90 seconds first run)
    colored_log("info", f"Warming up GPU kernel for {display_essid}...")
    warmup_hashcat_kernel(hc22000_path)

    log_debug(f"Hashcat command: {' '.join(cmd)}")

    # Kill any lingering hashcat processes
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/f", "/im", "hashcat.exe"],
                           capture_output=True, timeout=10)
        else:
            subprocess.run(["pkill", "-9", "-x", "hashcat"],
                           capture_output=True, timeout=10)
    except Exception:
        pass

    # Read potfile before cracking (should be empty/absent now)
    potfile_before = _read_potfile_raw(potfile)

    start_time = time.time()
    proc = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            cwd=hc_dir,
            stdin=subprocess.DEVNULL,
        )
        if proc.stdout is None:
            raise RuntimeError("stdout pipe not created")

        kernel_init_done = False
        msg_idx = 0
        last_msg_switch = time.time()
        hashcat_output: list[str] = []

        # Use Rich status for clean single-line display
        from rich.console import Console as _Console
        status = console.status(
            f"Hashcat compiling GPU kernels for [bold]{display_essid}[/]...",
            spinner="dots",
        )
        status.start()

        try:
            for raw_line in proc.stdout:
                line = raw_line.rstrip()
                hashcat_output.append(line)

                # Detect kernel init done (first non-empty line that isn't the hash itself)
                if not kernel_init_done and line and not line.startswith("WPA*02*"):
                    kernel_init_done = True
                    # Lower process priority after kernel compilation
                    try:
                        lower_process_priority(proc.pid)
                    except Exception:
                        pass
                    status.update(
                        status=f"Cracking [bold]{display_essid}[/] with hashcat..."
                    )

                # Rotate message every 8 seconds
                now = time.time()
                if now - last_msg_switch >= 8:
                    msg_idx = (msg_idx + 1) % len(_HASHCAT_MESSAGES)
                    last_msg_switch = now
                    if kernel_init_done:
                        status.update(
                            status=f"{_HASHCAT_MESSAGES[msg_idx]} [bold]{display_essid}[/]"
                        )
        finally:
            status.stop()

        proc.wait()

        elapsed = time.time() - start_time
        log_debug(f"Hashcat finished in {elapsed:.1f}s, rc={proc.returncode}")

        # Check potfile for new entries
        password = _check_new_potfile_entry(potfile, potfile_before)

        if password:
            m, s = divmod(int(elapsed), 60)
            time_str = f"{m:02d}:{s:02d}"
            colored_log("success",
                        f"Password found for {display_essid}: [bold]{password}[/bold]")
            console.print(f"  - Time: {time_str}", style="green")
            console.print(f"  - Method: hashcat (GPU)", style="green")
            return password

        # Exhausted? (all candidates tested)
        combined = "\n".join(hashcat_output)
        if "Exhausted" in combined or "All hashes" in combined:
            console.print(f"  Wordlist exhausted — password not found.")
            return HASHCAT_EXHAUSTED

        console.print(f"  Hashcat did not find the password.")
        return None

    except FileNotFoundError as e:
        log_error("Hashcat binary not found", e)
        return None
    except PermissionError as e:
        colored_log("warning",
                    "Hashcat execution blocked. "
                    "Add an exception for the 'bin/' folder in your security software.")
        log_error("Hashcat execution blocked (PermissionError)", e)
        return None
    except KeyboardInterrupt:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        colored_log("warning", "Hashcat cracking interrupted by user.")
        return HASHCAT_EXHAUSTED
    except Exception as e:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        log_error("Hashcat execution failed", e)
        return None


# ── Backend class ──────────────────────────────────────────────────────

class HashcatBackend:
    """Hashcat-based cracking backend (GPU)."""

    def __init__(
        self,
        gpu_is_discrete: bool = False,
        packets_map: dict | None = None,
    ):
        self.gpu_is_discrete = gpu_is_discrete
        self.packets_map = packets_map or {}

    def crack(
        self,
        handshake_path: str,
        wordlist_path: str,
        display_essid: str,
    ) -> str | None:
        """
        Convert, warm up, crack, and return the password.

        Accepts a .cap file (conversion happens internally).
        Uses pre-loaded packets from validator when available.
        """
        # Convert .cap → .hc22000
        hc22000_dir = HCOV_DIR
        os.makedirs(hc22000_dir, exist_ok=True)
        safe = sanitize_ssid(display_essid)
        hc22000_path = os.path.join(hc22000_dir, f"{safe}.hc22000")

        packets = self.packets_map.get(handshake_path)
        if not convert_cap_to_hc22000(handshake_path, hc22000_path, packets):
            colored_log("warning", "Hashcat conversion failed.")
            return None

        result = crack_with_hashcat(
            hc22000_path, wordlist_path, display_essid,
            gpu_is_discrete=self.gpu_is_discrete,
        )

        # Cleanup
        try:
            os.remove(hc22000_path)
        except OSError:
            pass

        if result is HASHCAT_EXHAUSTED:
            return None
        return result
