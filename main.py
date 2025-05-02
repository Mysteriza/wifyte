#!/usr/bin/env python3
import os
import sys
import tempfile
import shutil
from interface import setup_interface
from scanner import scan_networks, decloak_ssid
from capture import capture_handshake
from cracker import crack_password
from utils import (
    colored_log,
    execute_command,
    select_target,
    _display_banner,
    _exit_program,
    sanitize_ssid,
)
from helpers import check_dependency
from mac_vendor_lookup import MacLookup
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
        """Main program flow with support for multiple targets"""
        _display_banner()

        try:
            # Setup and scan
            setup_interface(self)
            self.networks = scan_networks(self)

            if not self.networks:
                colored_log("error", "No networks found!")
                _exit_program(self)
                return

            # Display networks
            console.print(
                f"\n===== {len(self.networks)} Networks found =====",
                style="bright_cyan",
            )
            for network in self.networks:
                console.print(str(network))

            # Select target(s)
            targets = select_target(self.networks)
            if not targets:
                _exit_program(self)
                return

            # Handle single or multiple targets
            if len(targets) > 1:
                console.print("\n=== Multiple Targets Mode ===", style="bold magenta")
                console.print(
                    f"Selected {len(targets)} targets for processing:",
                    style="bright_cyan",
                )
                for target in targets:
                    console.print(f"- {target.essid} ({target.bssid})", style="green")

            successful_targets = []

            for i, target in enumerate(targets, 1):
                if len(targets) > 1:
                    console.print(
                        f"\n[Processing Target {i}/{len(targets)}]", style="bold yellow"
                    )
                    colored_log(
                        "success", f"Selected target: {target.essid} ({target.bssid})"
                    )

                # Decloak hidden SSID if necessary
                if target.essid == "<HIDDEN SSID>":
                    revealed_ssid = decloak_ssid(self, target)
                    if revealed_ssid:
                        target.essid = revealed_ssid
                        colored_log(
                            "success", f"Target SSID updated to: {target.essid}"
                        )
                    else:
                        colored_log(
                            "error",
                            "Failed to decloak SSID. Proceeding with capture anyway!",
                        )

                # Sanitize SSID before use
                safe_essid = sanitize_ssid(target.essid)
                cap_file = os.path.join(self.handshake_dir, f"{safe_essid}.cap")

                # Check existing .cap file
                if os.path.exists(cap_file):
                    colored_log("info", f"Found existing handshake file: {cap_file}")
                    console.print(
                        "[?] Use existing handshake file and skip capture? (y/n)",
                        style="yellow bold",
                        end=": ",
                    )
                    use_existing = input().lower() == "y"

                    if use_existing:
                        successful_targets.append((cap_file, target))
                        continue
                    else:
                        colored_log(
                            "info",
                            "User chose to capture new handshake even though one exists!",
                        )
                else:
                    colored_log(
                        "info", f"No existing handshake file found for {target.essid}!"
                    )

                # Capture new handshake only if no existing was used
                handshake_path = capture_handshake(self, target)
                if handshake_path:
                    successful_targets.append((handshake_path, target))
                else:
                    colored_log(
                        "warning",
                        f"Failed to capture handshake for {target.essid}. Skipping to next target.",
                    )

            # Crack passwords for all captured handshakes
            if successful_targets:
                if len(targets) > 1:
                    console.print(
                        "\n=== Starting Password Cracking ===", style="bold magenta"
                    )
                for i, (handshake_path, target) in enumerate(successful_targets, 1):
                    if len(targets) > 1:
                        console.print(
                            f"\n[Cracking Target {i}/{len(successful_targets)}]",
                            style="bold yellow",
                        )
                    colored_log("info", f"Cracking {target.essid} ({target.bssid})...")
                    crack_password(handshake_path, self.wordlist_path, target)
            else:
                colored_log("warning", "No handshakes captured for cracking.")

            _exit_program(self)

        except KeyboardInterrupt:
            colored_log("warning", "Program cancelled by user!")
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
    from utils import check_dependency

    missing = [dep for dep in dependencies if not check_dependency(dep)]

    if missing:
        colored_log("error", f"Missing dependencies: {', '.join(missing)}")
        colored_log(
            "warning",
            "Please install aircrack-ng suite: sudo apt-get install aircrack-ng!",
        )
        sys.exit(1)

    try:
        wifyte = Wifyte()
        wifyte.run()
    except Exception as e:
        colored_log("error", f"Unexpected error: {e}")
