import sys
import re
import subprocess
import os
from utils import execute_command, colored_log, lookup_vendor
from rich.console import Console

# Rich console setup
console = Console()


def _detect_vm_environment() -> bool:
    """Detect if running in a virtual machine (strict detection to avoid false positives)"""
    vm_indicators = {
        "virtualbox": ["virtualbox", "vbox", "oracle"],
        "vmware": ["vmware", "vmw"],
        "qemu": ["qemu", "bochs"],
        "kvm": ["kvm"],
        "xen": ["xen"],
        "hyperv": ["microsoft corporation", "hyper-v"],
        "parallels": ["parallels"]
    }
    
    vm_detected = False
    
    try:
        # Method 1: Check DMI files (require exact matches, not substrings)
        dmi_files = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/bios_vendor"
        ]
        
        for dmi_file in dmi_files:
            if os.path.exists(dmi_file):
                try:
                    with open(dmi_file, 'r') as f:
                        content = f.read().strip().lower()
                        # Require stronger match - full word matches
                        for vm_type, keywords in vm_indicators.items():
                            for keyword in keywords:
                                if keyword in content and len(content) < 50:  # Avoid false positives from long strings
                                    vm_detected = True
                                    break
                            if vm_detected:
                                break
                except:
                    pass
            if vm_detected:
                break
                    
    except Exception:
        pass
    
    return vm_detected


def get_interface_info(interface: str) -> dict:
    """Get detailed info about a WiFi interface with smart USB and VM detection"""
    result = execute_command(["ip", "link", "show", interface])
    if not result:
        return {
            "name": interface,
            "mac": "Unknown",
            "driver": "Unknown",
            "likely_external": False,
            "in_vm": False,
        }

    # Extract MAC address
    mac_match = re.search(r"link/ether ([0-9A-Fa-f:]{17})", result.stdout)
    mac = mac_match.group(1).upper() if mac_match else "Unknown"

    # Get driver info
    phy_result = execute_command(["ethtool", "-i", interface])
    driver = "Unknown"
    if phy_result and "driver:" in phy_result.stdout:
        driver_match = re.search(r"driver:\s*(\S+)", phy_result.stdout)
        if driver_match:
            driver = driver_match.group(1)

    # ENHANCED DETECTION: Multiple methods
    likely_external = False
    
    # Method 1: Name-based detection (existing)
    if interface.startswith("wlx") or interface.startswith("usb"):
        likely_external = True
    
    # Method 2: USB detection via sysfs
    if not likely_external:
        try:
            # Check if connected via USB bus
            usb_path = f"/sys/class/net/{interface}/device/uevent"
            if os.path.exists(usb_path):
                with open(usb_path, 'r') as f:
                    content = f.read().lower()
                    if 'usb' in content:
                        likely_external = True
                        
            # Alternative: check device path
            device_path = f"/sys/class/net/{interface}/device"
            if os.path.exists(device_path):
                real_path = os.path.realpath(device_path)
                if '/usb' in real_path.lower():
                    likely_external = True
        except Exception:
            pass
    
    # Method 3: VM environment detection
    in_vm = _detect_vm_environment()

    return {
        "name": interface,
        "mac": mac,
        "driver": driver,
        "likely_external": likely_external,
        "in_vm": in_vm,
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


def select_interface() -> tuple[str, dict]:
    """Prompt user to select a WiFi interface with extended info"""
    interfaces = find_wifi_interfaces()
    if not interfaces:
        colored_log("error", "No WiFi interfaces found!")
        sys.exit(1)

    console = Console()

    console.print("[*] Available WiFi Interfaces:", style="bright_cyan")
    for idx, intf in enumerate(interfaces):
        name = intf["name"]
        mac = intf["mac"]
        driver = intf["driver"]
        type_str = "External" if intf["likely_external"] else "Internal"
        warning = (
            "⚠️ Likely unsupported!"
            if not intf["likely_external"] and not intf.get("is_internal", False)
            else ""
        )
        
        # Show VM indicator if detected
        vm_indicator = " [VM Detected]" if intf.get("in_vm") else ""

        console.print(f"  [{idx + 1}] {name} ({type_str}{vm_indicator})")
        console.print(f"      - MAC: {mac}")
        console.print(f"      - Driver: {driver}")
        if warning:
            console.print(f"      {warning}", style="yellow")

    console.print(
        "[?] Select the interface you want to use: ", end="", style="yellow bold"
    )

    while True:
        try:
            choice = int(input()) - 1
            if 0 <= choice < len(interfaces):
                selected_info = interfaces[choice]
                selected_intf = selected_info["name"]
                colored_log("info", f"Selected interface: {selected_intf}")
                
                # SMART PROMPT: If single adapter in VM or uncertain detection
                if len(interfaces) == 1:
                    intf_info = interfaces[0]
                    # Ask user if in VM or if detection is uncertain
                    if intf_info['in_vm'] or not intf_info['likely_external']:
                        console.print(
                            "\n[?] Is this an external USB Wi-Fi adapter? (y/n)",
                            style="yellow bold",
                            end=": "
                        )
                        is_external_input = input().lower()
                        if is_external_input == 'y':
                            selected_info['likely_external'] = True
                            colored_log("info", "Adapter marked as external (NetworkManager will stay active)")
                        elif is_external_input == 'n':
                            selected_info['likely_external'] = False
                            colored_log("warning", "Adapter marked as internal (NetworkManager will be stopped)")
                
                return selected_intf, selected_info
            else:
                raise ValueError
        except ValueError:
            print("[!] Invalid selection. Please enter a valid number: ", end="")


def toggle_monitor_mode(interface: str, enable=True, interface_info: dict = None) -> str | bool | None:
    """Toggle monitor mode with smart interface isolation"""
    if enable:
        # SMART DECISION: Only kill NetworkManager if using internal adapter
        is_external = interface_info and interface_info.get('likely_external', False)
        
        if not is_external:
            # Internal adapter: need to kill NetworkManager
            colored_log("warning", "Using internal adapter - NetworkManager will be stopped")
            execute_command(["airmon-ng", "check", "kill"])
        else:
            # External adapter: keep NetworkManager running
            colored_log("success", "Using external adapter - keeping NetworkManager active for internet!")
            # Only check for interfering processes, don't kill NetworkManager
            execute_command(["airmon-ng", "check"])

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

        # Only restart NetworkManager if we killed it (internal adapter)
        is_external = interface_info and interface_info.get('likely_external', False)
        if not is_external:
            execute_command(["service", "NetworkManager", "restart"], capture_output=False)
            colored_log("success", "Monitor mode disabled and NetworkManager restarted.")
        else:
            colored_log("success", "Monitor mode disabled (NetworkManager was not stopped).")
        
        return True


def setup_interface(self):
    """Setup wifi interface for scanning with smart isolation"""
    colored_log("info", "Searching for wifi interfaces...")
    self.interface, self.interface_info = select_interface()

    # Check if already in monitor mode
    output = execute_command(["iwconfig", self.interface]).stdout
    if output and "Mode:Monitor" in output:
        colored_log("success", f"Interface {self.interface} already in monitor mode!")
        self.monitor_interface = self.interface
        return

    # Enable monitor mode with interface info for smart isolation
    colored_log("info", f"Activating monitor mode on {self.interface}...")
    self.monitor_interface = toggle_monitor_mode(
        self.interface, 
        enable=True,
        interface_info=self.interface_info
    )

    if not self.monitor_interface:
        colored_log("error", "Failed to enable monitor mode!")
        sys.exit(1)
