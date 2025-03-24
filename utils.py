import logging
import subprocess
import threading
import time
import sys
from typing import Optional, List
from rich.console import Console

# Rich console setup
console = Console()

# Logging configuration for terminal only
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("wifyte")

# Log with rich styling
def colored_log(level: str, msg: str, enabled=True):
    """Log with rich styling to terminal"""
    if not enabled:
        return

    style_map = {
        "info": "bright_cyan",  # Brighter cyan for info
        "success": "green bold",  # Kept as requested
        "warning": "yellow",  # Kept as requested
        "error": "bright_red",  # Brighter red for error
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

def execute_command(command, shell=False, capture_output=True) -> Optional[subprocess.CompletedProcess]:
    """Run shell command with error handling"""
    try:
        return subprocess.run(command, shell=shell, capture_output=capture_output, text=True)
    except Exception as e:
        colored_log("error", f"Error executing command: {e}")
        return None

def select_target(networks: List) -> Optional[List]:
    """Select one or multiple target networks with input validation"""
    while True:
        try:
            console.print("[?] Select Targets (e.g., '1' or '1, 2, 5')(0 to exit): ", style="yellow bold", end="")
            user_input = input().strip()
            if user_input == "0":
                return None
            
            # Parse input untuk multiple targets
            target_ids = [int(i.strip()) - 1 for i in user_input.split(",") if i.strip().isdigit()]
            if not target_ids:
                colored_log("error", "Invalid input. Please enter valid network IDs.")
                continue

            # Validasi dan kumpulkan target
            valid_targets = []
            for idx in target_ids:
                if 0 <= idx < len(networks):
                    valid_targets.append(networks[idx])
                else:
                    colored_log("warning", f"Network ID {idx + 1} is out of range. Skipping.")

            if not valid_targets:
                colored_log("error", "No valid targets selected.")
                continue
            
            return valid_targets
        except (ValueError, KeyboardInterrupt):
            colored_log("warning", "Invalid input or cancelled")
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
    console.print("WiFi Handshake Capture & Cracking Tool", style="yellow", justify="left")

def _exit_program(self):
    """Clean exit with rich"""
    try:
        from interface import toggle_monitor_mode

        console.print("[?] Disable monitor mode? (y/n)", style="yellow bold", end=": ")
        disable_monitor = input().lower() == "y"

        if disable_monitor and self.monitor_interface:
            toggle_monitor_mode(self, self.monitor_interface, enable=False)
        elif self.monitor_interface:
            colored_log("success", f"Monitor mode remains active on {self.monitor_interface}")

        colored_log("info", "Program closed, thank you")
    except KeyboardInterrupt:
        colored_log("warning", "Program cancelled by user")
        if self.monitor_interface:
            colored_log("success", f"Monitor mode remains active on {self.monitor_interface}")

# Animation for loading spinner (modern Braille style with color)
def loading_spinner(stop_event: threading.Event, message: str):
    """Display a modern spinning loader animation until stop_event is set"""
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while not stop_event.is_set():
        console.print(f"[*] {message} {spinner[idx % len(spinner)]}", style="bright_cyan", end="\r")
        sys.stdout.flush()
        time.sleep(0.1)
        idx += 1
    console.print(f"{' ' * (len(message) + 10)}", end="\r\n")
    sys.stdout.flush()