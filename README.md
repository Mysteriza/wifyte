![Visitor Count](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/Mysteriza/wifyte&count_bg=%2379C83D&title_bg=%23555555&icon=github.svg&icon_color=%23E7E7E7&title=Visitors&edge_flat=false)
![Repository Size](https://img.shields.io/github/repo-size/Mysteriza/wifyte)

# WIFYTE
Wifyte is a simple Python-based WiFi handshake capture and password cracking tool that leverages tools like airodump-ng, aireplay-ng, and aircrack-ng, inspired by the [Wifite](https://github.com/derv82/wifite2) tool. It simplifies the workflow by handling tasks such as:
- Scanning for available WiFi networks.
- Detecting connected clients on a target network.
- Deauthenticating clients to force reconnection and capture handshakes.
- Saving captured handshakes for further analysis.
- Cracking passwords using a customizable wordlist.

The tool is designed to be user-friendly, with clear logging and minimal dependencies. It is ideal for educational purposes, penetration testing, and improving network security.

## Key Features
- Automated Workflow : Automatically scans networks, detects clients, and captures handshakes.
- Deauthentication Attacks : Forces clients to reconnect, increasing the chances of capturing a handshake.
- Password Cracking : Uses a wordlist to crack captured handshakes efficiently.
- Lightweight and Fast : Optimized for speed and minimal resource usage.

## Screenshot
![Screenshot 2025-02-19 194710](https://github.com/user-attachments/assets/c08a95c5-13a2-4730-8619-026f390bfb79)

You need the TP-Link TL-WN722N V1 WiFi Adapter or another wifi adapter that supports running this program to use Monitor Mode.

## How to use
- Clone this repo:
  ```
  git clone https://github.com/Mysteriza/wifyte.git && cd wifyte
  ```
- Run the command:
  ```
  sudo python3 wifyte.py
  ```
## Disclaimer
This tool is intended solely for educational and ethical purposes. It has been developed to help users understand Wi-Fi security vulnerabilities and improve network protection.

By using this tool, you agree to the following terms:

1. You will only use this tool on networks or systems for which you have explicit permission.
2. You will not use this tool for any illegal, malicious, or unauthorized activities.
3. Any misuse of this tool is strictly prohibited and may violate applicable laws and regulations.
4. The developer(s) and maintainer(s) of this tool are not responsible for any damage, harm, or legal consequences caused by the misuse of this software.

Use it responsibly and always act within the boundaries of the law.
