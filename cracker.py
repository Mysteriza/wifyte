import os
import re
import threading
import time
from utils import colored_log, execute_command, loading_spinner, sanitize_ssid
from helpers import check_dependency
from rich.console import Console

# Rich console setup
console = Console()


def crack_password(handshake_path: str, wordlist_path: str, network) -> str | None:
    """Crack password from handshake with validation and save results"""
    if not os.path.exists(handshake_path) or not os.path.exists(wordlist_path):
        colored_log("error", "Handshake file or wordlist not found!")
        return None

    # Validate handshake before cracking
    if not _check_handshake(handshake_path):
        colored_log(
            "warning", "Invalid or incomplete handshake detected. Skipping cracking!"
        )
        return None

    colored_log("info", f"Using wordlist: {wordlist_path}")

    # Start loading animation
    stop_event = threading.Event()
    animation_thread = threading.Thread(
        target=loading_spinner,
        args=(stop_event, "Cracking password, this will take some time!"),
    )
    animation_thread.daemon = True
    animation_thread.start()

    # Measure cracking time
    start_time = time.time()
    result = execute_command(["aircrack-ng", "-w", wordlist_path, handshake_path])

    # Stop animation after cracking is done
    stop_event.set()
    animation_thread.join()

    if not result:
        colored_log("error", "Error cracking password!")
        return None

    # Check results
    if "KEY FOUND!" in result.stdout:
        match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result.stdout)
        if match:
            password = match.group(1)
            elapsed_time = time.time() - start_time
            minutes, seconds = divmod(int(elapsed_time), 60)
            time_str = f"{minutes:02d}:{seconds:02d}"

            # Display detailed success message
            colored_log(
                "success",
                f"Password found for {network.essid} ({network.bssid}): [bold]{password}[/bold]",
            )
            console.print(f"  - Channel: {network.channel}", style="green")
            console.print(f"  - Encryption: {network.encryption}", style="green")
            console.print(f"  - Power: {network.power} dBm", style="green")
            console.print(f"  - Time taken: {time_str}", style="green")

            # Save results to file
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
            colored_log("info", f"Results saved to {result_file}")
            return password

    colored_log("error", "Password not found in wordlist! Better luck next time!")
    return None


def _check_handshake(cap_file: str) -> bool:
    """Check if capture file contains a valid handshake"""
    if not os.path.exists(cap_file):
        return False
    result = execute_command(["aircrack-ng", cap_file])
    return result and "1 handshake" in result.stdout
