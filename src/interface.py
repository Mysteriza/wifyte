"""
Wi-Fi interface management — detection, monitor-mode toggling, VM-aware setup.

All operations require root privileges on Linux.
"""

import os
import re
import sys

from src.console import console, colored_log, log_error, log_debug
from src.utils import execute_command, lookup_vendor


# ── VM detection (Linux DMI) ──────────────────────────────────────────

def _detect_vm_environment() -> bool:
    """Check DMI sysfs files for VM indicators (VirtualBox, VMware, QEMU, etc.)."""
    vm_keywords = {
        "virtualbox": ["virtualbox", "vbox", "oracle"],
        "vmware": ["vmware", "vmw"],
        "qemu": ["qemu", "bochs"],
        "kvm": ["kvm"],
        "xen": ["xen"],
        "hyperv": ["microsoft corporation", "hyper-v"],
        "parallels": ["parallels"],
    }
    dmi_files = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/bios_vendor",
    ]
    for dmi_file in dmi_files:
        if not os.path.exists(dmi_file):
            continue
        try:
            with open(dmi_file) as f:
                content = f.read().strip().lower()
            for vm_type, keywords in vm_keywords.items():
                if any(kw in content for kw in keywords) and len(content) < 50:
                    log_debug(f"VM detected via {dmi_file}: {content}")
                    return True
        except (OSError, IOError):
            continue
    return False


# ── Interface info ────────────────────────────────────────────────────

def get_interface_info(interface: str) -> dict:
    """
    Gather extended details about a Wi-Fi interface.

    Returns a dict with keys: name, mac, driver, likely_external, in_vm.
    """
    result = execute_command(["ip", "link", "show", interface])
    if not result:
        return {
            "name": interface,
            "mac": "Unknown",
            "driver": "Unknown",
            "likely_external": False,
            "in_vm": False,
        }

    mac = "Unknown"
    mac_match = re.search(r"link/ether ([0-9A-Fa-f:]{17})", result.stdout)
    if mac_match:
        mac = mac_match.group(1).upper()

    driver = "Unknown"
    phy = execute_command(["ethtool", "-i", interface])
    if phy and "driver:" in phy.stdout:
        drv = re.search(r"driver:\s*(\S+)", phy.stdout)
        if drv:
            driver = drv.group(1)

    # Determine if this is an external USB adapter
    likely_external = bool(
        interface.startswith("wlx") or interface.startswith("usb")
    )
    if not likely_external:
        for probe in [
            f"/sys/class/net/{interface}/device/uevent",
            f"/sys/class/net/{interface}/device",
        ]:
            try:
                if os.path.exists(probe):
                    if os.path.islink(probe):
                        real = os.path.realpath(probe)
                        if "/usb" in real.lower():
                            likely_external = True
                            break
                    else:
                        with open(probe) as f:
                            if "usb" in f.read().lower():
                                likely_external = True
                                break
            except (OSError, IOError):
                continue

    in_vm = _detect_vm_environment()
    return {
        "name": interface,
        "mac": mac,
        "driver": driver,
        "likely_external": likely_external,
        "in_vm": in_vm,
    }


# ── Interface discovery ───────────────────────────────────────────────

def find_wifi_interfaces() -> list[dict]:
    """Return a list of interface-info dicts for all 802.11 interfaces."""
    result = execute_command(["iwconfig"])
    if not result or result.returncode != 0:
        log_error("iwconfig failed — is aircrack-ng installed and do you have root?")
        return []

    raw = [
        line.split()[0]
        for line in result.stdout.split("\n")
        if "IEEE 802.11" in line
    ]
    return [get_interface_info(iface) for iface in raw]


def select_interface() -> tuple[str, dict]:
    """Interactive interface selection with extended info display."""
    interfaces = find_wifi_interfaces()
    if not interfaces:
        colored_log("error", "No Wi-Fi interfaces found!")
        sys.exit(1)

    console.print("[*] Available Wi-Fi Interfaces:", style="bright_cyan")
    for idx, intf in enumerate(interfaces):
        name = intf["name"]
        type_str = "External" if intf["likely_external"] else "Internal"
        vm = " [VM]" if intf.get("in_vm") else ""
        console.print(f"  [{idx + 1}] {name} ({type_str}{vm})")
        console.print(f"      - MAC: {intf['mac']}")
        console.print(f"      - Driver: {intf['driver']}")

    console.print("[?] Select the interface you want to use: ", style="yellow bold", end="")
    while True:
        try:
            choice = int(input().strip()) - 1
            if not (0 <= choice < len(interfaces)):
                raise ValueError
            info = interfaces[choice]
            name = info["name"]
            colored_log("info", f"Selected interface: {name}")

            # Single-interface: ask whether external
            if len(interfaces) == 1 and (info["in_vm"] or not info["likely_external"]):
                console.print(
                    "\n[?] Is this an external USB Wi-Fi adapter? (y/n): ",
                    style="yellow bold", end="",
                )
                ans = input().lower()
                if ans == "y":
                    info["likely_external"] = True
                    colored_log("info", "Marked external — NetworkManager stays active.")
                elif ans == "n":
                    info["likely_external"] = False
                    colored_log("warning", "Marked internal — NetworkManager may be stopped.")

            return name, info
        except (ValueError, IndexError):
            print("[!] Invalid selection. Enter a valid number: ", end="")


# ── Monitor mode ──────────────────────────────────────────────────────

def toggle_monitor_mode(
    interface: str,
    enable: bool = True,
    interface_info: dict | None = None,
) -> str | bool | None:
    """
    Enable or disable monitor mode on *interface*.

    When enabling, returns the monitor interface name (e.g. wlan0mon).
    When disabling, returns True on success.
    Returns None on failure.
    """
    if enable:
        is_ext = bool(interface_info and interface_info.get("likely_external"))

        if not is_ext:
            colored_log("warning", "Internal adapter — stopping NetworkManager.")
            execute_command(["airmon-ng", "check", "kill"])
        else:
            colored_log("success", "External adapter — keeping NetworkManager active.")
            execute_command(["airmon-ng", "check"])

        execute_command(["ifconfig", interface, "down"])
        result = execute_command(["airmon-ng", "start", interface])

        if not result or result.returncode != 0:
            colored_log("error", f"Failed to enable monitor mode on {interface}!")
            return None

        # Extract the monitor interface name
        mon_iface = None
        match = re.search(
            r"(Created monitor mode interface|monitor mode enabled on) (\w+)",
            result.stdout,
        )
        if match:
            mon_iface = match.group(2)
        else:
            # Fallback: scan interfaces for "Mode:Monitor"
            for info in find_wifi_interfaces():
                iw = execute_command(["iwconfig", info["name"]])
                if iw and "Mode:Monitor" in iw.stdout:
                    mon_iface = info["name"]
                    break
            if not mon_iface:
                mon_iface = f"{interface}mon"

        execute_command(["ifconfig", mon_iface, "up"])
        colored_log("success", f"Monitor mode active on {mon_iface}.")
        return mon_iface

    else:
        # Disable monitor mode
        result = execute_command(["airmon-ng", "stop", interface])
        if not result or result.returncode != 0:
            colored_log("error", "Failed to disable monitor mode!")
            return False

        is_ext = bool(interface_info and interface_info.get("likely_external"))
        if not is_ext:
            execute_command(["service", "NetworkManager", "restart"], capture_output=False)
            colored_log("success", "Monitor mode disabled, NetworkManager restarted.")
        return True


# ── High-level setup ──────────────────────────────────────────────────

def setup_interface(self):
    """Select an interface and activate monitor mode (attached to the Wifyte instance)."""
    colored_log("info", "Searching for Wi-Fi interfaces...")
    self.interface, self.interface_info = select_interface()

    iw_out = execute_command(["iwconfig", self.interface])
    if iw_out and "Mode:Monitor" in iw_out.stdout:
        colored_log("success", f"{self.interface} already in monitor mode.")
        self.monitor_interface = self.interface
        return

    colored_log("info", f"Activating monitor mode on {self.interface}...")
    self.monitor_interface = toggle_monitor_mode(
        self.interface,
        enable=True,
        interface_info=self.interface_info,
    )
    if not self.monitor_interface:
        colored_log("error", "Failed to enable monitor mode!")
        sys.exit(1)
