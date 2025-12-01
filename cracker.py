import os
import re
import threading
import time
from utils import (
    colored_log,
    execute_command,
    loading_spinner,
    sanitize_ssid,
    check_handshake,
    check_dependency,
    console,
)


def crack_password(handshake_path: str, wordlist_path: str, network, silent: bool = False) -> str | None:
    """Crack password from handshake with validation and save results"""
    if not os.path.exists(handshake_path) or not os.path.exists(wordlist_path):
        if not silent:
            colored_log("error", "Handshake file or wordlist not found!")
        return None

    if not check_handshake(handshake_path):
        if not silent:
            colored_log(
                "warning", "Invalid or incomplete handshake detected. Skipping cracking!"
            )
        return None

    if not silent:
        colored_log("info", f"Using wordlist: {wordlist_path}")

    stop_event = threading.Event()
    animation_thread = None
    
    if not silent:
        animation_thread = threading.Thread(
            target=loading_spinner,
            args=(stop_event, "Cracking password, this will take some time!"),
        )
        animation_thread.daemon = True
        animation_thread.start()

    start_time = time.time()
    result = execute_command(["aircrack-ng", "-w", wordlist_path, handshake_path])

    if not silent and animation_thread:
        stop_event.set()
        animation_thread.join()

    if not result:
        if not silent:
            colored_log("error", "Error cracking password!")
        return None

    if "KEY FOUND!" in result.stdout:
        match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result.stdout)
        if match:
            password = match.group(1)
            elapsed_time = time.time() - start_time
            minutes, seconds = divmod(int(elapsed_time), 60)
            time_str = f"{minutes:02d}:{seconds:02d}"

            if not silent:
                colored_log(
                    "success",
                    f"Password found for {network.essid} ({network.bssid}): [bold]{password}[/bold]",
                )
                console.print(f"  - Channel: {network.channel}", style="green")
                console.print(f"  - Encryption: {network.encryption}", style="green")
                console.print(f"  - Power: {network.power} dBm", style="green")
                console.print(f"  - Time taken: {time_str}", style="green")

            results_dir = "results"
            os.makedirs(results_dir, exist_ok=True)
            safe_essid = sanitize_ssid(network.essid)
            result_file = os.path.join(results_dir, f"{safe_essid}_result.txt")
            with open(result_file, "w") as f:
                f.write(f"Network: {network.essid} ({network.bssid})\n")
                f.write(f"Password: {password}\n")
                f.write(f"Channel: {network.channel}\n")
                f.write(f"Encryption: {network.encryption}\n")
                f.write(f"Power: {network.power} dBm\n")
                f.write(f"Time taken: {time_str}\n")
            
            if not silent:
                colored_log("info", f"Results saved to {result_file}")
            return password

    if not silent:
        colored_log("error", "Password not found in wordlist! Better luck next time!")
    return None
