#!/usr/bin/env python3
"""
Wifyte — WiFi Handshake Capture & Cracking Tool

Usage:
    sudo python main.py [-w WORDLIST] [--hashcat] [--no-hashcat]
    python main.py --offile CAP_FILE [-w WORDLIST] [--hashcat]

Orchestrates the full workflow:
    1. Auto-setup (check deps, GPU, wordlist)
    2. Interface selection & monitor mode (Linux only)
    3. Network scanning (live continuous) (Linux only)
    4. Handshake capture (deauth + airodump-ng) (Linux only)
    5. Password cracking (hashcat GPU → aircrack-ng CPU fallback)

Use --offline on Windows to crack existing .cap files directly.
"""

import argparse
import os
import sys
import signal
import atexit
import tempfile
import shutil

from src.console import console, colored_log, log_error, log_debug
from src.config import (
    HANDSHAKES_DIR, RESULTS_DIR, LOGS_DIR, DEFAULT_WORDLIST_PATH,
    IS_LINUX, IS_WINDOWS,
)
from src.utils import (
    display_banner, select_target, sanitize_ssid, check_dependency,
    execute_command, create_default_wordlist,
)
from src.interface import setup_interface, toggle_monitor_mode
from src.scanner import scan_networks_continuous, decloak_ssid
from src.capture import capture_handshake
from src.cracker import crack_password
from src.setup import auto_setup


# ── Cleanup manager (same role as original) ─────────────────────────────

class CleanupManager:
    """Manages safe teardown of monitor mode on SIGINT/SIGTERM/exit."""

    def __init__(self):
        self.monitor_interface: str | None = None
        self.original_interface: str | None = None
        self.interface_info: dict | None = None
        self.cleanup_done = False

    def register(self, original: str | None, monitor: str | None, info: dict | None):
        self.original_interface = original
        self.monitor_interface = monitor
        self.interface_info = info
        signal.signal(signal.SIGINT, self._handler)
        signal.signal(signal.SIGTERM, self._handler)
        atexit.register(self._atexit)

    def pause(self):
        """Temporarily restore default SIGINT (for continuous scan)."""
        signal.signal(signal.SIGINT, signal.default_int_handler)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

    def resume(self):
        signal.signal(signal.SIGINT, self._handler)
        signal.signal(signal.SIGTERM, self._handler)

    def _handler(self, signum, _frame):
        name = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
        colored_log("warning", f"\n{name} received — cleaning up...")
        self.cleanup()
        sys.exit(0)

    def _atexit(self):
        if not self.cleanup_done:
            self.cleanup()

    def cleanup(self):
        if self.cleanup_done:
            return
        self.cleanup_done = True
        if not self.monitor_interface:
            return
        colored_log("info", "Disabling monitor mode...")
        try:
            toggle_monitor_mode(self.monitor_interface, enable=False,
                                interface_info=self.interface_info)
        except Exception as e:
            log_error("Cleanup error", e)
            if not (self.interface_info and self.interface_info.get("likely_external")):
                execute_command(["service", "NetworkManager", "restart"])


# ── Main application class ──────────────────────────────────────────────

class Wifyte:
    """Core application — orchestrates the full capture-and-crack flow."""

    def __init__(self, args: argparse.Namespace):
        self.interface: str | None = None
        self.interface_info: dict | None = None
        self.monitor_interface: str | None = None
        self.networks: list = []
        self.temp_dir = tempfile.mkdtemp(prefix="wifyte_")
        self.wordlist_path: str = DEFAULT_WORDLIST_PATH
        self.offline_cap: str | None = None
        self.use_hashcat: bool | None = None
        self.hashcat_discrete_gpu = True
        self.cleanup = CleanupManager()

        # ── Apply CLI args ────────────────────────────────────────
        if args.wordlist:
            path = os.path.abspath(args.wordlist)
            if not os.path.exists(path):
                colored_log("error", f"Wordlist not found: {path}")
                sys.exit(1)
            self.wordlist_path = path
            colored_log("success", f"Using custom wordlist: {path}")

        if args.offline:
            path = os.path.abspath(args.offline)
            if not os.path.exists(path):
                colored_log("error", f"Capture file not found: {path}")
                sys.exit(1)
            self.offline_cap = path
            colored_log("success", f"Offline mode — using capture: {path}")

        if args.hashcat:
            self.use_hashcat = True
        elif args.no_hashcat:
            self.use_hashcat = False
        # None = auto-detect at crack time

    def __del__(self):
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    # ── Run ───────────────────────────────────────────────────────

    def run(self):
        os.system("cls" if os.name == "nt" else "clear")
        display_banner()

        # ── 1. Auto-setup ─────────────────────────────────────────
        setup_result = auto_setup()

        # Store backend hints from detection
        if self.use_hashcat is None:
            self.use_hashcat = setup_result.get("use_hashcat", False)
        self.hashcat_discrete_gpu = setup_result.get("gpu_is_discrete", True)

        # Ensure wordlist exists
        if not os.path.exists(self.wordlist_path):
            create_default_wordlist(self.wordlist_path)

        # ── 2. Offline / Live mode ────────────────────────────────
        if self.offline_cap or IS_WINDOWS:
            # Mode offline / Windows: skip capture, langsung crack
            cap_path = self.offline_cap
            if not cap_path:
                # Cari file .cap di handshakes/ jika ada
                handshakes_dir = HANDSHAKES_DIR
                import glob as _glob
                caps = _glob.glob(os.path.join(handshakes_dir, "*.cap"))
                if caps:
                    cap_path = caps[0]
                    colored_log("info", f"Menggunakan handshake existing: {cap_path}")
                else:
                    colored_log("error",
                        "Tidak ada file .cap. Gunakan --offline PATH_TO_CAP "
                        "untuk cracking file capture yang sudah ada.")
                    colored_log("info",
                        "Atau jalankan di Linux dengan adapter WiFi untuk "
                        "melakukan scan & capture langsung.")
                    return

            # Ekstrak ESSID dari filename atau pakai basename
            essid = os.path.splitext(os.path.basename(cap_path))[0]
            from src.scanner import WiFiNetwork
            mock_target = WiFiNetwork(
                id=1, bssid="00:00:00:00:00:00",
                channel=0, power=0, essid=essid, encryption="WPA2",
            )

            colored_log("info", f"Offline/Windows mode — cracking: {cap_path}")
            pw = crack_password(cap_path, self.wordlist_path, mock_target,
                                use_hashcat=self.use_hashcat,
                                has_discrete_gpu=self.hashcat_discrete_gpu)
            if pw:
                colored_log("success",
                    f"Password ditemukan: [bold]{pw}[/bold]")
            else:
                colored_log("warning", "Password tidak ditemukan di wordlist.")
            return

        # ── 3. Interface setup (Linux only) ───────────────────────
        try:
            setup_interface(self)
        except (KeyboardInterrupt, SystemExit):
            return

        self.cleanup.register(self.interface, self.monitor_interface,
                              self.interface_info)

        # ── 4. Scan ───────────────────────────────────────────────
        self.cleanup.pause()
        try:
            self.networks = scan_networks_continuous(self)
        finally:
            self.cleanup.resume()

        if not self.networks:
            colored_log("error", "No networks found!")
            return

        # ── 5. Target selection ───────────────────────────────────
        targets = select_target(self.networks)
        if not targets:
            return

        if len(targets) > 1:
            console.print("\n=== Multiple Targets Mode ===", style="bold magenta")
            for t in targets:
                console.print(f"  - {t.essid} ({t.bssid})", style="green")

        successful: list[tuple[str, object]] = []   # (cap_path, network)

        for i, target in enumerate(targets, 1):
            if len(targets) > 1:
                console.print(f"\n[Processing Target {i}/{len(targets)}]",
                              style="bold yellow")
            colored_log("success", f"Selected: {target.essid} ({target.bssid})")

            # ── Decloak hidden SSID ───────────────────────────────
            if target.essid == "<HIDDEN SSID>":
                revealed = decloak_ssid(self, target)
                if revealed:
                    target.essid = revealed
                    colored_log("success", f"SSID decloaked: {target.essid}")
                else:
                    colored_log("warning", "Could not decloak SSID. Proceeding anyway.")

            # ── Check for existing handshake ──────────────────────
            safe = sanitize_ssid(target.essid)
            existing_cap = os.path.join(HANDSHAKES_DIR, f"{safe}.cap")
            if os.path.exists(existing_cap):
                console.print("[?] Use existing handshake? (y/n): ",
                              style="yellow bold", end="")
                if input().strip().lower() == "y":
                    successful.append((existing_cap, target))
                    continue
                colored_log("info", "Capturing new handshake...")

            handshake = capture_handshake(self, target)
            if handshake:
                successful.append((handshake, target))
            else:
                colored_log("warning",
                            f"Skipping {target.essid} — capture failed.")

        # ── 6. Cracking ───────────────────────────────────────────
        if not successful:
            colored_log("warning", "No handshakes captured.")
            return

        if len(targets) > 1:
            console.print("\n=== Starting Password Cracking ===", style="bold magenta")

        cracked_ssids: dict[str, str] = {}

        for i, (cap_path, target) in enumerate(successful, 1):
            if len(successful) > 1:
                console.print(f"\n[Cracking {i}/{len(successful)}]",
                              style="bold yellow")

            # If the same SSID was already cracked, just verify
            if target.essid in cracked_ssids:
                prev_pw = cracked_ssids[target.essid]
                tmp = tempfile.NamedTemporaryFile(mode="w", delete=False)
                tmp.write(f"{prev_pw}\n")
                tmp.close()
                try:
                    pw = crack_password(cap_path, tmp.name, target,
                                        use_hashcat=self.use_hashcat,
                                        has_discrete_gpu=self.hashcat_discrete_gpu,
                                        silent=True)
                    if pw:
                        colored_log("success",
                                    f"Same password verified: [bold]{pw}[/bold]")
                        continue
                    colored_log("warning", "Different password; full crack needed.")
                finally:
                    os.unlink(tmp.name)

            pw = crack_password(cap_path, self.wordlist_path, target,
                                use_hashcat=self.use_hashcat,
                                has_discrete_gpu=self.hashcat_discrete_gpu)
            if pw:
                cracked_ssids[target.essid] = pw


# ── Entry point ─────────────────────────────────────────────────────────

def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="WiFi Handshake Capture & Cracking Tool"
    )
    parser.add_argument(
        "--wordlist", "-w",
        help="Path to custom wordlist file",
    )
    parser.add_argument(
        "--hashcat", action="store_true", default=False,
        help="Force hashcat (GPU) cracking",
    )
    parser.add_argument(
        "--no-hashcat", action="store_true", default=False,
        dest="no_hashcat",
        help="Force aircrack-ng (CPU) even if hashcat is available",
    )
    parser.add_argument(
        "--offline", "-o",
        type=str, default=None,
        metavar="CAP_FILE",
        help="Path to existing .cap file untuk cracking offline "
             "(skip scan/capture, langsung crack). Berguna di Windows.",
    )
    return parser


def main():
    # Parse args FIRST so --help works even without dependencies
    parser = _build_arg_parser()
    args = parser.parse_args()

    # Root check (Linux only — aircrack-ng needs root)
    if IS_LINUX and os.geteuid() != 0:
        colored_log("error", "Root access required. Run with: sudo python main.py")
        sys.exit(1)

    # ── Dependency check (platform-aware) ────────────────────────
    if IS_WINDOWS:
        # Windows: hanya aircrack-ng.exe untuk CPU cracking, capture tools tidak ada
        required_win = ["aircrack-ng"]
        missing_win = [d for d in required_win if not check_dependency(d)]
        if missing_win:
            colored_log("warning",
                "aircrack-ng tidak ditemukan. Cracking via CPU tidak tersedia, "
                "tapi hashcat GPU tetap bisa dipakai jika GPU terdeteksi.")
            colored_log("info",
                "Download aircrack-ng: https://www.aircrack-ng.org/downloads.html")
        else:
            colored_log("success", "aircrack-ng detected (CPU cracking available).")

        colored_log("info",
            "Windows mode: capture handshake tidak bisa (monitor mode tidak support). "
            "Gunakan --offline untuk crack file .cap yang sudah ada.")
    else:
        # Linux: semua tool capture + cracking wajib ada
        required = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
        missing = [d for d in required if not check_dependency(d)]
        if missing:
            colored_log("error", f"Missing dependencies: {', '.join(missing)}")
            colored_log("warning", "Install aircrack-ng suite first.")
            sys.exit(1)

    try:
        app = Wifyte(args)
        app.run()
    except KeyboardInterrupt:
        colored_log("warning", "Interrupted by user.")
    except Exception as e:
        log_error("Fatal error", e)
        raise


if __name__ == "__main__":
    main()
