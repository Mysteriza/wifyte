import sys
from utils import execute_command, colored_log


def find_wifi_interfaces() -> list[str]:
    """Find available wifi interfaces"""
    result = execute_command(["iwconfig"], shell=True)
    if not result or result.returncode != 0:
        colored_log("error", "Failed to get wifi interface list")
        sys.exit(1)

    return [
        line.split()[0] for line in result.stdout.split("\n") if "IEEE 802.11" in line
    ]


def toggle_monitor_mode(interface, enable=True) -> str | bool | None:
    """Toggle monitor mode on/off"""
    if enable:
        # Kill interfering processes
        execute_command(["airmon-ng", "check", "kill"])

        # Turn off interface and enable monitor mode
        execute_command(["ifconfig", interface, "down"])
        result = execute_command(["airmon-ng", "start", interface])

        if not result or result.returncode != 0:
            colored_log("error", f"Failed to enable monitor mode on {interface}")
            return None

        # Find monitor interface name
        import re

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
                    for iface in find_wifi_interfaces()
                    if "Mode:Monitor" in execute_command(["iwconfig", iface]).stdout
                ),
                f"{interface}mon",
            )

        # Ensure interface is up
        execute_command(["ifconfig", monitor_interface, "up"])
        colored_log("success", f"Monitor mode active on {monitor_interface}")
        return monitor_interface
    else:
        # Disable monitor mode
        result = execute_command(["airmon-ng", "stop", interface])
        if not result or result.returncode != 0:
            colored_log("error", "Failed to disable monitor mode")
            return False

        # Restart network services
        execute_command(["service", "NetworkManager", "restart"], capture_output=False)
        colored_log("success", "Monitor mode disabled and NetworkManager restarted.")
        return True


def setup_interface(self):
    """Setup wifi interface for scanning"""
    colored_log("info", "Searching for wifi interfaces...")
    interfaces = find_wifi_interfaces()

    if not interfaces:
        colored_log("error", "No wifi interface found")
        sys.exit(1)

    # Check if any interface already in monitor mode
    for interface in interfaces:
        if "Mode:Monitor" in execute_command(["iwconfig", interface]).stdout:
            colored_log("success", f"Interface {interface} already in monitor mode")
            self.monitor_interface = interface
            return

    # Enable monitor mode on first interface
    self.interface = interfaces[0]
    colored_log("success", f"Using interface {self.interface}")
    self.monitor_interface = toggle_monitor_mode(self, self.interface, enable=True)

    if not self.monitor_interface:
        colored_log("error", "Failed to enable monitor mode")
        sys.exit(1)
