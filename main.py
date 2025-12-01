#!/usr/bin/env python3
import argparse
import os
import sys
import tempfile
import shutil
import signal
import atexit
from interface import setup_interface, toggle_monitor_mode
from scanner import scan_networks_continuous, decloak_ssid
from capture import capture_handshake
from cracker import crack_password
from utils import (
    colored_log,
    execute_command,
    select_target,
    _display_banner,
    _exit_program,
    sanitize_ssid,
    check_dependency,
    console,
)


class CleanupManager:
    """Manages cleanup operations to ensure safe exit in all scenarios"""
    
    def __init__(self):
        self.monitor_interface = None
        self.original_interface = None
        self.interface_info = None
        self.cleanup_registered = False
        self.cleanup_done = False
        
    def register(self, original_interface, monitor_interface, interface_info):
        """Register interfaces for cleanup"""
        self.original_interface = original_interface
        self.monitor_interface = monitor_interface
        self.interface_info = interface_info
        
        if not self.cleanup_registered:
            self.original_sigint_handler = signal.signal(signal.SIGINT, self._signal_handler)
            self.original_sigterm_handler = signal.signal(signal.SIGTERM, self._signal_handler)
            
            atexit.register(self._atexit_cleanup)
            
            self.cleanup_registered = True
    
    def pause_signal_handlers(self):
        """Temporarily disable signal handlers (for continuous scanning)"""
        if self.cleanup_registered:
            signal.signal(signal.SIGINT, signal.default_int_handler)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
    
    def resume_signal_handlers(self):
        """Re-enable signal handlers after scanning"""
        if self.cleanup_registered:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle SIGINT (Ctrl+C) and SIGTERM"""
        signal_name = "SIGINT (Ctrl+C)" if signum == signal.SIGINT else "SIGTERM"
        colored_log("warning", f"\n{signal_name} received - cleaning up safely...")
        self._cleanup()
        colored_log("info", "Cleanup completed. Exiting...")
        sys.exit(0)
    
    def _atexit_cleanup(self):
        """Cleanup called by atexit on program termination"""
        if not self.cleanup_done:
            self._cleanup()
    
    def _cleanup(self):
        """Perform actual cleanup operations"""
        if self.cleanup_done or not self.monitor_interface:
            return
        
        self.cleanup_done = True
        
        try:
            colored_log("info", "Disabling monitor mode and restoring network...")
            
            success = toggle_monitor_mode(
                self.monitor_interface,
                enable=False,
                interface_info=self.interface_info
            )
            
            if success:
                colored_log("success", "Network interfaces restored successfully!")
            else:
                is_external = self.interface_info and self.interface_info.get('likely_external', False)
                if not is_external:
                    colored_log("warning", "Monitor mode disable failed - attempting NetworkManager restart...")
                    try:
                        execute_command(["service", "NetworkManager", "restart"])
                        colored_log("success", "NetworkManager restarted as fallback")
                    except:
                        pass
                else:
                    colored_log("warning", "Monitor mode disable reported issues (external adapter - no NetworkManager restart needed)")
        except Exception as e:
            colored_log("error", f"Cleanup error: {e}")
            is_external = self.interface_info and self.interface_info.get('likely_external', False)
            if not is_external:
                try:
                    execute_command(["service", "NetworkManager", "restart"])
                    colored_log("warning", "Forced NetworkManager restart")
                except:
                    colored_log("error", "Could not restore network - manual intervention may be needed")


class Wifyte:
    def __init__(self):
        self.interface = None
        self.interface_info = None
        self.monitor_interface = None
        self.networks = []
        self.temp_dir = tempfile.mkdtemp()
        self.handshake_dir = os.path.join(os.getcwd(), "handshakes")
        self.results_dir = os.path.join(os.getcwd(), "results")
        os.makedirs(self.handshake_dir, exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)
        self.stop_capture = False
        self.handshake_found = False
        self.cleanup_manager = CleanupManager()

        parser = argparse.ArgumentParser(
            description="WiFi Handshake Capture & Cracking Tool"
        )
        parser.add_argument(
            "--wordlist", "-w", type=str, help="Path to custom wordlist file"
        )
        args = parser.parse_args()

        if args.wordlist:
            self.wordlist_path = os.path.abspath(args.wordlist)
            if not os.path.exists(self.wordlist_path):
                colored_log(
                    "error", f"Custom wordlist not found at {self.wordlist_path}"
                )
                sys.exit(1)
            colored_log("success", f"Using custom wordlist: {self.wordlist_path}")
        else:
            self.wordlist_path = os.path.join(os.getcwd(), "wifyte.txt")
            if not os.path.exists(self.wordlist_path):
                colored_log("warning", f"Wordlist not found in {self.wordlist_path}")
                colored_log("warning", "Creating default wordlist...")
                with open(self.wordlist_path, "w") as f:
                    f.write("password\n12345678\nqwerty123\nadmin123\nwifi12345\n")
                colored_log("success", "Default wordlist created!")

    def __del__(self):
        try:
            shutil.rmtree(self.temp_dir)
        except Exception as e:
            colored_log("error", f"Error clearing temp directory: {e}")

    def run(self):
        """Main program flow with support for multiple targets"""
        os.system("cls" if os.name == "nt" else "clear")
        _display_banner()

        try:
            setup_interface(self)
            
            self.cleanup_manager.register(
                self.interface,
                self.monitor_interface,
                self.interface_info
            )
            
            self.cleanup_manager.pause_signal_handlers()
            
            try:
                self.networks = scan_networks_continuous(self)
            finally:
                self.cleanup_manager.resume_signal_handlers()


            if not self.networks:
                colored_log("error", "No networks found!")
                _exit_program(self)
                return

            targets = select_target(self.networks)
            if not targets:
                _exit_program(self)
                return

            if len(targets) > 1:
                console.print("\n=== Multiple Targets Mode ===", style="bold magenta")
                console.print(
                    f"Selected {len(targets)} targets for processing:",
                    style="bright_cyan",
                )
                for target in targets:
                    console.print(f"- {target.essid} ({target.bssid})", style="green")

            successful_targets = []

            for i, target in enumerate(targets, 1):
                if len(targets) > 1:
                    console.print(
                        f"\n[Processing Target {i}/{len(targets)}]", style="bold yellow"
                    )
                    colored_log(
                        "success", f"Selected target: {target.essid} ({target.bssid})"
                    )

                if target.essid == "<HIDDEN SSID>":
                    revealed_ssid = decloak_ssid(self, target)
                    if revealed_ssid:
                        target.essid = revealed_ssid
                        colored_log(
                            "success", f"Target SSID updated to: {target.essid}"
                        )
                    else:
                        colored_log(
                            "error",
                            "Failed to decloak SSID. Proceeding with capture anyway!",
                        )

                safe_essid = sanitize_ssid(target.essid)
                cap_file = os.path.join(self.handshake_dir, f"{safe_essid}.cap")

                if os.path.exists(cap_file):
                    colored_log("info", f"Found existing handshake file: {cap_file}")
                    console.print(
                        "[?] Use existing handshake file and skip capture? (y/n)",
                        style="yellow bold",
                        end=": ",
                    )
                    use_existing = input().lower() == "y"

                    if use_existing:
                        successful_targets.append((cap_file, target))
                        continue
                    else:
                        colored_log(
                            "info",
                            "User chose to capture new handshake even though one exists!",
                        )
                else:
                    colored_log(
                        "info", f"No existing handshake file found for {target.essid}!"
                    )

                handshake_path = capture_handshake(self, target)
                if handshake_path:
                    successful_targets.append((handshake_path, target))
                else:
                    colored_log(
                        "warning",
                        f"Failed to capture handshake for {target.essid}. Skipping to next target.",
                    )

            if successful_targets:
                if len(targets) > 1:
                    console.print(
                        "\n=== Starting Password Cracking ===", style="bold magenta"
                    )
                
                cracked_ssids = {}
                
                for i, (handshake_path, target) in enumerate(successful_targets, 1):
                    if len(targets) > 1:
                        console.print(
                            f"\n[Cracking Target {i}/{len(successful_targets)}]",
                            style="bold yellow",
                        )
                    
                    if target.essid in cracked_ssids:
                        previous_password = cracked_ssids[target.essid]
                        colored_log("info", f"Checking if {target.essid} uses the same password as previous target...")
                        
                        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_wl:
                            tmp_wl.write(f"{previous_password}\n")
                            tmp_wl_path = tmp_wl.name
                        
                        try:
                            verified_password = crack_password(handshake_path, tmp_wl_path, target, silent=True)
                            
                            if verified_password:
                                colored_log("success", f"Confirmed! Same password works: [bold]{verified_password}[/bold]")
                                console.print(f"  - Skipped full cracking (password verified)", style="dim")
                                
                                results_dir = "results"
                                os.makedirs(results_dir, exist_ok=True)
                                safe_essid = sanitize_ssid(target.essid)
                                result_file = os.path.join(results_dir, f"{safe_essid}_result.txt")
                                with open(result_file, "a") as f:
                                    f.write(f"\n--- Duplicate SSID Target ---\n")
                                    f.write(f"Network: {target.essid} ({target.bssid})\n")
                                    f.write(f"Password: {verified_password}\n")
                                    f.write(f"Channel: {target.channel}\n")
                                    f.write(f"Encryption: {target.encryption}\n")
                                    f.write(f"Power: {target.power} dBm\n")
                                    f.write(f"Note: Result verified from previously cracked target in same session\n")
                                colored_log("info", f"Results saved to {result_file}")
                                continue
                            else:
                                colored_log("warning", "Different password detected! Proceeding with full cracking...")
                        finally:
                            if os.path.exists(tmp_wl_path):
                                os.unlink(tmp_wl_path)

                    colored_log("info", f"Cracking {target.essid} ({target.bssid})...")
                    password = crack_password(handshake_path, self.wordlist_path, target)
                    
                    if password:
                        cracked_ssids[target.essid] = password
            else:
                colored_log("warning", "No handshakes captured for cracking.")

            _exit_program(self)
            if not self.monitor_interface:
                self.cleanup_manager.cleanup_done = True

        except KeyboardInterrupt:
            colored_log("warning", "Program interrupted by user!")
        except Exception as e:
            colored_log("error", f"Unexpected error: {e}")
        finally:
            if not self.cleanup_manager.cleanup_done and self.monitor_interface:
                self.cleanup_manager._cleanup()


if __name__ == "__main__":
    if os.geteuid() != 0:
        colored_log(
            "error", "This program requires root access. Please run with 'sudo'"
        )
        sys.exit(1)

    dependencies = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]

    missing = [dep for dep in dependencies if not check_dependency(dep)]

    if missing:
        colored_log("error", f"Missing dependencies: {', '.join(missing)}")
        colored_log(
            "warning",
            "Please install aircrack-ng suite: sudo apt-get install aircrack-ng!",
        )
        sys.exit(1)

    try:
        wifyte = Wifyte()
        wifyte.run()
    except Exception as e:
        colored_log("error", f"Unexpected error: {e}")
