![Repository Size](https://img.shields.io/github/repo-size/Mysteriza/wifyte)
![Python Version](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

# WIFYTE

**Wifyte** is a simple yet powerful Python-based tool for capturing Wi-Fi handshakes and cracking passwords, inspired by [Wifite](https://github.com/derv82/wifite2). Built on top of tools like `airodump-ng`, `aireplay-ng`, and `aircrack-ng`, Wifyte automates the Wi-Fi pentesting process with an intuitive and efficient workflow. Perfect for educational purposes, ethical hacking, and strengthening network security.

## Key Features
- **Automated Network Scanning**: Quickly scans for encrypted Wi-Fi networks in range.
- **Hidden SSID Detection**: Identifies and decloaks hidden SSIDs for further analysis.
- **Multiple Targets Capture**: Capture handshakes and crack passwords for multiple networks sequentially by selecting several targets (e.g., "1, 2, 5").
- **Client Deauthentication**: Forces clients to reconnect, enabling handshake capture.
- **Password Cracking**: Cracks passwords from captured handshakes using a custom wordlist.
- **Vendor Information**: Displays router vendor names (e.g., ZTE, ASKEY) based on BSSID.
- **Colorful Interface**: Enhanced terminal output with `rich` for a user-friendly experience.
- **Lightweight & Fast**: Optimized for speed and low resource usage.

## Screenshot
![Screenshot 2025-02-23 170050](https://github.com/user-attachments/assets/ffa191b6-de9f-49dc-9b01-4b9f62615479)


## Requirements
- **Operating System**: Linux (recommended: [Kali Linux](https://www.kali.org/get-kali/#kali-platforms) or any distro with `aircrack-ng` support).
- **Wi-Fi Adapter**: A monitor-mode-capable adapter (e.g., [TP-Link TL-WN722N V1](https://shopee.co.id/Tp-link-Tl-wn722N-versi-1-Second-i.225940473.8844432053) or [ALFA Network AWUS036ACS](https://a.co/d/7L9FeR4) or [AR9271 802.11n 150Mbps](https://a.co/d/j7zGR3T)).
- **System Dependencies**: 
  - `aircrack-ng` suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`).
  - Install via:
    ```
    sudo apt update && sudo apt install aircrack-ng
    ```
## Installation
  - Clone the Repository:
    ```
    git clone https://github.com/Mysteriza/wifyte.git && cd wifyte
    ```
  - Install library:
    ```
    sudo python3 -m pip install -r requirements.txt
    ```
  - Run:
    ```
    sudo python3 main.py
    ```
## How it works
After running the tool, it will:
- Scan and list encrypted or hidden Wi-Fi networks with signal strength and vendor details.
- Prompt you to select a target network.
- Offer to use an existing handshake file (if any) or capture a new one.
- Perform deauthentication and crack the password using the specified wordlist.
- If the password is in the wordlist, the program will give you the password. This shows that your WiFi is not secure because the password is commonly used.

## Disclaimer
Wifyte is intended for educational and ethical testing purposes only. By using this tool, you agree to:
- Use it only on networks or systems for which you have explicit permission.
- Refrain from any illegal, malicious, or unauthorized activities.
- Understand that misuse of this tool may violate applicable laws and is strictly prohibited.
  
The developers and maintainers are not liable for any damage, harm, or legal consequences resulting from misuse. Use responsibly and comply with local laws.
