import os
import time
import signal
import subprocess
from dataclasses import dataclass
from utils import colored_log, Colors


@dataclass
class WiFiNetwork:
    id: int
    bssid: str
    channel: int
    power: int
    essid: str
    encryption: str

    def __str__(self) -> str:
        return f"{Colors.BOLD}[{self.id}]{Colors.ENDC} {Colors.GREEN}{self.essid}{Colors.ENDC} ({self.bssid}) - CH:{self.channel} PWR:{self.power} {Colors.YELLOW}{self.encryption}{Colors.ENDC}"


def scan_networks(self) -> list[WiFiNetwork]:
    """Scan available wifi networks"""
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
        # Scan for 8 seconds without logging every second
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
                    if len(parts) >= 14 and parts[13].strip():
                        network_id += 1
                        try:
                            networks.append(
                                WiFiNetwork(
                                    id=network_id,
                                    bssid=parts[0],
                                    channel=(
                                        int(parts[3]) if parts[3].isdigit() else 0
                                    ),
                                    power=(
                                        int(parts[8])
                                        if parts[8].lstrip("-").isdigit()
                                        else 0
                                    ),
                                    encryption=f"{parts[5]} {parts[6]}".strip(),
                                    essid=parts[13].strip().replace("\x00", ""),
                                )
                            )
                        except (ValueError, IndexError):
                            continue
        except Exception as e:
            colored_log("error", f"Error reading scan results: {e}")
    else:
        colored_log("error", "Scan results file not found")

    if networks:
        colored_log("success", f"Found {len(networks)} networks.")
    else:
        colored_log("warning", "No networks detected.")

    return networks


def detect_connected_clients(self, network: WiFiNetwork) -> list[str]:
    """Detect connected clients to the target network"""
    colored_log(
        "info",
        f"Detecting connected clients for {network.essid}...",
    )
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
        # Wait for 10 seconds without logging every second
        time.sleep(10)
    except KeyboardInterrupt:
        colored_log("warning", "Client detection stopped by user!")
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
        colored_log("success", f"Detected {len(clients)} connected clients.")
    else:
        colored_log("warning", "No connected clients detected.")

    return clients
