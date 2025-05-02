import sys
import re
import subprocess
from utils import execute_command, colored_log
from mac_vendor_lookup import MacLookup


def get_interface_info(interface: str) -> dict:
    """Get detailed info about a WiFi interface"""
    result = execute_command(["iwconfig", interface])
    if not result:
        return {
            "name": interface,
            "mac": "Unknown",
            "vendor": "Unknown",
            "is_internal": None,
            "likely_external": False,
        }

    mac_match = re.search(r"HWaddr\s([0-9A-Fa-f:]{17})", result.stdout)
    mac = mac_match.group(1) if mac_match else "Unknown"

    try:
        vendor = MacLookup().lookup(mac) if mac != "Unknown" else "Unknown"
    except Exception:
        vendor = "Unknown"

    is_internal = interface.startswith("wl") and not interface.startswith("wlx")
    likely_external = interface.startswith("wlx") or "phy" in result.stdout

    return {
        "name": interface,
        "mac": mac,
        "vendor": vendor,
        "is_internal": is_internal,
        "likely_external": likely_external,
    }


def find_wifi_interfaces() -> list[dict]:
    """Find available wifi interfaces with extended information"""
    result = execute_command(["iwconfig"])
    if not result or result.returncode != 0:
        colored_log("error", "Failed to get wifi interface list!")
        sys.exit(1)

    raw_interfaces = [
        line.split()[0] for line in result.stdout.split("\n") if "IEEE 802.11" in line
    ]

    return [get_interface_info(iface) for iface in raw_interfaces]


def toggle_monitor_mode(interface: str, enable=True) -> str | bool | None:
    """Toggle monitor mode on/off for a specific interface"""
    if enable:
        # Kill interfering processes
        execute_command(["airmon-ng", "check", "kill"])

        # Turn off interface and enable monitor mode
        execute_command(["ifconfig", interface, "down"])
        result = execute_command(["airmon-ng", "start", interface])

        if not result or result.returncode != 0:
            colored_log("error", f"Failed to enable monitor mode on {interface}!")
            return None

        # Find monitor interface name
        match = re.search(
            r"(Created monitor mode interface|monitor mode enabled on) (\w+)",
            result.stdout,
        )
        if match:
            monitor_interface = match.group(2)
        else:
            # Backup method to find monitor interface
            monitor_interface = next(
                (
                    iface
                    for iface in [info["name"] for info in find_wifi_interfaces()]
                    if "Mode:Monitor" in execute_command(["iwconfig", iface]).stdout
                ),
                f"{interface}mon",
            )

        # Ensure interface is up
        execute_command(["ifconfig", monitor_interface, "up"])
        colored_log("success", f"Monitor mode active on {monitor_interface}.")
        return monitor_interface
    else:
        # Disable monitor mode
        result = execute_command(["airmon-ng", "stop", interface])
        if not result or result.returncode != 0:
            colored_log("error", "Failed to disable monitor mode!")
            return False

        # Restart network services
        execute_command(["service", "NetworkManager", "restart"], capture_output=False)
        colored_log("success", "Monitor mode disabled and NetworkManager restarted.")
        return True


def select_interface() -> str:
    """Prompt user to select a WiFi interface with detailed info"""
    interfaces = find_wifi_interfaces()
    if not interfaces:
        colored_log("error", "No WiFi interfaces found!")
        sys.exit(1)

    from rich.console import Console

    console = Console()

    console.print("[*] Available WiFi Interfaces:", style="bright_cyan")
    for idx, intf in enumerate(interfaces):
        name = intf["name"]
        mac = intf["mac"]
        vendor = intf["vendor"]
        type_str = "External" if intf["likely_external"] else "Internal"
        warning = (
            "⚠️ Likely unsupported"
            if not intf["likely_external"] and not intf["is_internal"]
            else ""
        )

        console.print(f"  [{idx + 1}] {name} ({type_str})")
        console.print(f"      - MAC: {mac}")
        console.print(f"      - Vendor: {vendor} {warning}")

    console.print(
        "[?] Select the interface you want to use: ", end="", style="yellow bold"
    )

    while True:
        try:
            choice = int(input()) - 1
            if 0 <= choice < len(interfaces):
                selected_intf = interfaces[choice]["name"]
                colored_log("info", f"Selected interface: {selected_intf}")
                return selected_intf
            else:
                raise ValueError
        except ValueError:
            print("[!] Invalid selection. Please enter a valid number: ", end="")


def setup_interface(self):
    """Setup wifi interface for scanning by selecting one manually first"""
    colored_log("info", "Searching for wifi interfaces...")
    self.interface = select_interface()

    # Check if already in monitor mode
    output = execute_command(["iwconfig", self.interface]).stdout
    if output and "Mode:Monitor" in output:
        colored_log("success", f"Interface {self.interface} already in monitor mode!")
        self.monitor_interface = self.interface
        return

    # Enable monitor mode
    colored_log("info", f"Activating monitor mode on {self.interface}...")
    self.monitor_interface = toggle_monitor_mode(self.interface, enable=True)

    if not self.monitor_interface:
        colored_log("error", "Failed to enable monitor mode!")
        sys.exit(1)
