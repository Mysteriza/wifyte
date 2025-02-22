import logging
import subprocess
import threading
import time
import sys
from typing import Optional

# Logging configuration for terminal only
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("wifyte")


# ANSI Color codes
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


# Log with color to terminal only
def colored_log(level, msg, enabled=True):
    """Log with color to terminal"""
    if not enabled:
        return

    color_map = {
        "info": Colors.BLUE,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
    }
    prefix = {"info": "[*]", "success": "[+]", "warning": "[!]", "error": "[!]"}
    logger.info(f"{color_map.get(level, '')}{prefix.get(level, '')} {msg}{Colors.ENDC}")


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


def select_target(networks):
    """Select target network with input validation"""
    while True:
        try:
            choice = int(
                input(
                    f"\n{Colors.YELLOW}[?] Select Target [1-{len(networks)}]: {Colors.ENDC}"
                )
            )
            if 1 <= choice <= len(networks):
                return networks[choice - 1]
            else:
                colored_log("error", "Invalid choice. Please try again.")
        except (ValueError, KeyboardInterrupt):
            colored_log("warning", "Invalid input or cancelled.")
            return None


def _display_banner():
    """Display program banner"""
    banner = f"""
{Colors.BOLD}{Colors.BLUE}
██╗    ██╗██╗███████╗██╗   ██╗████████╗███████╗
██║    ██║██║██╔════╝╚██╗ ██╔╝╚══██╔══╝██╔════╝
██║ █╗ ██║██║█████╗   ╚████╔╝    ██║   █████╗  
██║███╗██║██║██╔══╝    ╚██╔╝     ██║   ██╔══╝  
╚███╔███╔╝██║██║        ██║      ██║   ███████╗
 ╚══╝╚══╝ ╚═╝╚═╝        ╚═╝      ╚═╝   ╚══════╝
{Colors.ENDC}
{Colors.YELLOW}  WiFi Handshake Capture & Cracking Tool{Colors.ENDC}
"""
    print(banner)


def _exit_program(self):
    """Clean exit"""
    try:
        from interface import toggle_monitor_mode

        disable_monitor = (
            input(
                f"\n{Colors.YELLOW}[?] Disable monitor mode? (y/n): {Colors.ENDC}"
            ).lower()
            == "y"
        )

        if disable_monitor and self.monitor_interface:
            toggle_monitor_mode(self, self.monitor_interface, enable=False)
        elif self.monitor_interface:
            colored_log(
                "success",
                f"Monitor mode remains active on {self.monitor_interface}.",
            )

        colored_log("info", "Program closed, thank you!")
    except KeyboardInterrupt:
        colored_log("warning", "Program cancelled by user!")
        if self.monitor_interface:
            colored_log(
                "success",
                f"Monitor mode remains active on {self.monitor_interface}.",
            )


# Animation for loading spinner (modern Braille style)
def loading_spinner(stop_event: threading.Event, message: str):
    """Display a modern spinning loader animation until stop_event is set"""
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while not stop_event.is_set():
        sys.stdout.write(
            f"\r{Colors.BLUE}[*] {message} {spinner[idx % len(spinner)]}{Colors.ENDC}"
        )
        sys.stdout.flush()
        time.sleep(0.1)
        idx += 1
    # Clear the line completely and move to new line
    sys.stdout.write(f"\r{' ' * (len(message) + 10)}\r{Colors.ENDC}\n")
    sys.stdout.flush()
