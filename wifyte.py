import os
import subprocess
import time
import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configuration
SCAN_DURATION = 12  # Total scanning duration in seconds
SCAN_INTERVAL = 3  # Interval between scans in seconds


def detect_wifi_adapter() -> str:
    print(Fore.CYAN + "[+] Detecting Wi-Fi adapter...")
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
            print(Fore.RED + "[-] No Wi-Fi adapter found that supports monitor mode.")
            sys.exit(1)
        print(Fore.GREEN + f"[+] Supported Wi-Fi adapters: {', '.join(adapters)}")
        return adapters[0]  # Select the first adapter
    except subprocess.TimeoutExpired:
        print(Fore.RED + "[-] Command timed out.")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to detect Wi-Fi adapter: {e}")
        sys.exit(1)


def enable_monitor_mode(interface: str) -> str:
    print(Fore.CYAN + f"[+] Enabling monitor mode on {interface}...")
    try:
        subprocess.run(["airmon-ng", "check", "kill"], check=True)
        subprocess.run(["airmon-ng", "start", interface], check=True)
        return f"{interface}mon"
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Failed to enable monitor mode: {e}")
        sys.exit(1)


def scan_networks(interface: str):
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

            # Clear the screen and display the updated list
            os.system("clear" if os.name != "nt" else "cls")
            print(Fore.CYAN + "[+] Available Wi-Fi networks:")
            if not networks:
                print(Fore.YELLOW + "[-] No networks detected yet. Please wait...")
            else:
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

        except Exception as e:
            print(Fore.RED + f"[-] Failed to scan networks: {e}")

    print(Fore.CYAN + "[+] Scanning complete!")
    return networks


def main():
    # Step 1: Detect Wi-Fi adapter
    adapter = detect_wifi_adapter()

    # Step 2: Enable monitor mode
    monitor_interface = enable_monitor_mode(adapter)

    try:
        # Step 3: Scan for Wi-Fi networks
        scan_networks(monitor_interface)
    finally:
        # Step 4: Disable monitor mode
        choice = input(
            Fore.CYAN + "[+] Do you want to disable monitor mode? (y/n): "
        ).lower()
        if choice == "y":
            subprocess.run(["airmon-ng", "stop", monitor_interface], check=True)
        print(Fore.CYAN + "[+] Program finished.")


if __name__ == "__main__":
    main()
