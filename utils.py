import logging
import subprocess
import threading
import time
import sys
import re
import shutil
import os
from typing import Optional, List
from rich.console import Console

# Rich console setup
console = Console()

# Logging configuration for terminal only
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("wifyte")

# Global vendor map loaded from manuf file
VENDOR_MAP = {}


def load_manuf_file(manuf_path: str = "manuf"):
    """Load MAC address prefix to vendor mapping from local manuf file"""
    global VENDOR_MAP
    VENDOR_MAP = {}

    if not os.path.exists(manuf_path):
        console.print(
            "[!] 'manuf' file not found. Vendor lookup will be disabled.",
            style="yellow",
        )
        return

    try:
        with open(manuf_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(None, 2)  # Split into up to 3 parts
                if len(parts) < 2:
                    continue

                mac_prefix = parts[0].upper()
                vendor_name = parts[2] if len(parts) == 3 else parts[1]

                # Handle special prefixes like '/36'
                if "/" in mac_prefix:
                    base_mask = mac_prefix.split("/")[0]
                    octets = base_mask.replace("-", ":").split(":")
                else:
                    octets = mac_prefix.replace("-", ":").split(":")

                if len(octets) >= 3:
                    normalized = ":".join(octets[:3])  # First 3 octets only
                    VENDOR_MAP[normalized] = vendor_name
    except Exception as e:
        console.print(f"[!] Error loading manuf file: {e}", style="red")


# Load vendor map at startup
load_manuf_file()


def lookup_vendor(mac: str) -> str:
    """
    Look up vendor using local manuf file only.
    Returns 'Unknown' if no match is found.
    """
    if ":" not in mac:
        return "Unknown"

    # Normalize MAC
    normalized = re.sub(r"[^A-Z0-9]", ":", mac.upper())
    octets = normalized.split(":")
    if len(octets) < 3:
        return "Unknown"

    prefix = ":".join(octets[:3])
    return VENDOR_MAP.get(prefix, "Unknown")


def check_dependency(cmd: str) -> bool:
    """Check if a CLI tool is available in system PATH"""
    return shutil.which(cmd) is not None


def check_handshake(cap_file: str) -> bool:
    """
    Check if capture file contains a valid handshake.
    Centralized function to avoid duplication.
    """
    if not os.path.exists(cap_file):
        return False
    result = execute_command(["aircrack-ng", cap_file])
    return result and "1 handshake" in result.stdout


def sanitize_ssid(ssid: str) -> str:
    """
    Sanitize SSID to be safe for use as filename.
    Removes invalid characters and trims whitespace.
    """
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", ssid)
    return sanitized.strip()


def colored_log(level: str, msg: str, enabled=True):
    """Log with rich styling to terminal"""
    if not enabled:
        return

    style_map = {
        "info": "bright_cyan",
        "success": "green bold",
        "warning": "yellow",
        "error": "bright_red",
    }
    prefix_map = {
        "info": "[*]",
        "success": "[+]",
        "warning": "[!]",
        "error": "[!]",
    }

    style = style_map.get(level, "white")
    prefix = prefix_map.get(level, "[*]")
    console.print(f"{prefix} {msg}", style=style)


def execute_command(
    command, shell=False, capture_output=True
) -> Optional[subprocess.CompletedProcess]:
    """Run shell command with error handling"""
    try:
        return subprocess.run(
            command, shell=shell, capture_output=capture_output, text=True
        )
    except Exception as e:
        colored_log("error", f"Error executing command: {e}")
        return None


def select_target(networks: List) -> Optional[List]:
    """Select one or multiple target networks with input validation"""
    while True:
        try:
            console.print(
                "[?] Select Targets (e.g., '1' or '1, 2, 5')(0 to exit): ",
                style="yellow bold",
                end="",
            )
            user_input = input().strip()
            if user_input == "0":
                return None

            target_ids = [
                int(i.strip()) - 1 for i in user_input.split(",") if i.strip().isdigit()
            ]
            if not target_ids:
                colored_log("error", "Invalid input. Please enter valid network IDs.")
                continue

            valid_targets = []
            for idx in target_ids:
                if 0 <= idx < len(networks):
                    valid_targets.append(networks[idx])
                else:
                    colored_log(
                        "warning", f"Network ID {idx + 1} is out of range. Skipping."
                    )

            if not valid_targets:
                colored_log("error", "No valid targets selected.")
                continue

            return valid_targets
        except (ValueError, KeyboardInterrupt):
            colored_log("warning", "Invalid input or cancelled!")
            return None


def _display_banner():
    """Display program banner with rich"""
    banner = """
██╗    ██╗██╗███████╗██╗   ██╗████████╗███████╗
██║    ██║██║██╔════╝╚██╗ ██╔╝╚══██╔══╝██╔════╝
██║ █╗ ██║██║█████╗   ╚████╔╝    ██║   █████╗  
██║███╗██║██║██╔══╝    ╚██╔╝     ██║   ██╔══╝  
╚███╔███╔╝██║██║        ██║      ██║   ███████╗
 ╚══╝╚══╝ ╚═╝╚═╝        ╚═╝      ╚═╝   ╚══════╝
"""
    console.print(banner, style="bright_cyan bold")
    console.print(
        "WiFi Handshake Capture & Cracking Tool", style="yellow", justify="left"
    )


def _exit_program(self):
    """Clean exit with rich"""
    try:
        from interface import toggle_monitor_mode

        console.print("[?] Disable monitor mode? (y/n)", style="yellow bold", end=": ")
        disable_monitor = input().lower() == "y"

        if disable_monitor and self.monitor_interface:
            success = toggle_monitor_mode(
                self.monitor_interface, 
                enable=False,
                interface_info=getattr(self, 'interface_info', None)
            )
            if success:
                # Silent success or simple message if needed, but user asked to remove one.
                # The user said: Hapus salah satunya saja: [+] Monitor mode disabled (NetworkManager was not stopped). [+] Monitor mode disabled successfully.
                # I will keep the specific one if it returns specific info, or just a generic one.
                # interface.py toggle_monitor_mode returns True/False.
                # I'll keep "Monitor mode disabled successfully." but maybe interface.py also prints?
                # Let's just print one clean message.
                colored_log("success", "Monitor mode disabled.")
                # Mark as cleaned to prevent double cleanup
                if hasattr(self, 'cleanup_manager'):
                    self.cleanup_manager.cleanup_done = True
                self.monitor_interface = None  # Clear to prevent auto-cleanup
            else:
                colored_log("warning", "Failed to disable monitor mode cleanly.")
        elif self.monitor_interface:
            colored_log(
                "success", f"Monitor mode remains active on {self.monitor_interface}"
            )
            # IMPORTANT: Mark cleanup as done so main.py doesn't force cleanup
            if hasattr(self, 'cleanup_manager'):
                self.cleanup_manager.cleanup_done = True

        colored_log("info", "Program closed, Thank You!")
    except KeyboardInterrupt:
        colored_log("warning", "Program cancelled by user!")
        if self.monitor_interface:
            colored_log(
                "success", f"Monitor mode remains active on {self.monitor_interface}!"
            )


def loading_spinner(stop_event: threading.Event, message: str):
    """Display a modern spinning loader animation until stop_event is set"""
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while not stop_event.is_set():
        console.print(
            f"[*] {message} {spinner[idx % len(spinner)]}",
            style="bright_cyan",
            end="\r",
        )
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)
    console.print(f"{' ' * (len(message) + 10)}", end="\r\n")
    sys.stdout.flush()
