#!/usr/bin/env python3
import os
import sys
import tempfile
import shutil
from interface import setup_interface
from scanner import scan_networks, decloak_ssid
from capture import capture_handshake
from cracker import crack_password
from utils import colored_log, select_target, _display_banner, _exit_program
from rich.console import Console

# Rich console setup
console = Console()


class Wifyte:
    def __init__(self):
        self.interface = None
        self.monitor_interface = None
        self.networks = []
        self.temp_dir = tempfile.mkdtemp()
        self.handshake_dir = os.path.join(os.getcwd(), "handshakes")
        self.stop_capture = False
        self.handshake_found = False

        # Create handshake directory if it doesn't exist
        os.makedirs(self.handshake_dir, exist_ok=True)

        # Setup default wordlist
        self.wordlist_path = os.path.join(os.getcwd(), "wifyte.txt")
        if not os.path.exists(self.wordlist_path):
            colored_log("warning", f"Wordlist not found in {self.wordlist_path}")
            colored_log("warning", "Creating default wordlist")
            with open(self.wordlist_path, "w") as f:
                f.write("password\n12345678\nqwerty123\nadmin123\nwifi12345\n")
            colored_log("success", "Default wordlist created")

    def __del__(self):
        try:
            shutil.rmtree(self.temp_dir)
        except Exception as e:
            colored_log("error", f"Error clearing temp directory: {e}")

    def run(self):
        """Main program flow"""
        _display_banner()

        try:
            # Setup and scan
            setup_interface(self)
            self.networks = scan_networks(self)

            if not self.networks:
                colored_log("error", "No networks found")
                _exit_program(self)
                return

            # Display networks and proceed directly to target selection
            console.print(
                f"\n===== {len(self.networks)} Networks found =====",
                style="bright_cyan",
            )
            for network in self.networks:
                console.print(str(network))

            # Select target
            target = select_target(self.networks)
            if not target:
                _exit_program(self)
                return

            # Decloak hidden SSID if necessary
            if target.essid == "<HIDDEN SSID>":
                revealed_ssid = decloak_ssid(self, target)
                if revealed_ssid:
                    target.essid = revealed_ssid
                    colored_log("success", f"Target SSID updated to: {target.essid}")
                else:
                    colored_log(
                        "error",
                        "Failed to decloak SSID. Proceeding with capture anyway",
                    )

            colored_log("success", f"Selected target: {target.essid} ({target.bssid})")

            # Check for existing .cap file before detecting clients
            cap_file = os.path.join(
                self.handshake_dir, f"{target.essid.replace(' ', '_')}.cap"
            )
            if os.path.exists(cap_file):
                colored_log("info", f"Found existing handshake file: {cap_file}")
                console.print(
                    "[?] Use existing handshake file and skip capture? (y/n)",
                    style="yellow bold",
                    end=": ",
                )
                use_existing = input().lower() == "y"
                if use_existing:
                    # Skip capture and go straight to cracking with network details
                    crack_password(cap_file, self.wordlist_path, target)
                    _exit_program(self)
                    return
            else:
                colored_log(
                    "info", f"No existing handshake file found for {target.essid}"
                )

            # Proceed with capture if no existing file or user chooses "n"
            handshake_path = capture_handshake(self, target)
            if handshake_path:
                crack_password(handshake_path, self.wordlist_path, target)
            _exit_program(self)

        except KeyboardInterrupt:
            colored_log("warning", "Program cancelled by user")
            _exit_program(self)


if __name__ == "__main__":
    # Check root access
    if os.geteuid() != 0:
        colored_log(
            "error", "This program requires root access. Please run with 'sudo'"
        )
        sys.exit(1)

    # Check dependencies
    dependencies = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
    missing = [dep for dep in dependencies if shutil.which(dep) is None]

    if missing:
        colored_log("error", f"Missing dependencies: {', '.join(missing)}")
        colored_log(
            "warning",
            "Please install aircrack-ng suite: sudo apt-get install aircrack-ng",
        )
        sys.exit(1)

    try:
        wifyte = Wifyte()
        wifyte.run()
    except Exception as e:
        colored_log("error", f"Unexpected error: {e}")
