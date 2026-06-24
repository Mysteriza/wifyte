![Repository Size](https://img.shields.io/github/repo-size/Mysteriza/wifyte)
![Python Version](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

# Wifyte - WiFi Handshake Capture & Cracking Tool

**Wifyte** is an optimized Python-based WiFi penetration testing tool for capturing WPA/WPA2 handshakes and cracking passwords. Inspired by [Wifite2](https://github.com/derv82/wifite2), built with speed, accuracy, and a modern UI powered by **Rich**.

---

## ✨ Key Features

### 🎯 **Core Functionality**
- **WPA/WPA2 Handshake Capture** - Fast and reliable handshake capturing
- **Password Cracking** - Dictionary-based password recovery with aircrack-ng
- **HIDDEN SSID Detection & Decloaking** - Automatically detect and reveal hidden networks
- **Multi-Target Support** - Capture multiple networks in one session
- **Smart VM Detection** - Accurate detection with USB adapter identification

### 🚀 **Optimization Features** (New!)
- **Continuous Real-Time Scanning** - Live network table with dynamic updates (wifite2-style)
- **Rich Modern UI** - Beautiful panels, tables, and progress indicators
- **Fast Parallel Deauth** - Threading-based deauthentication for quick handshakes
- **Intelligent Client Detection** - 15-second scan with progress tracking
- **Vendor Identification** - MAC address vendor lookup with graceful fallback
- **Sequential Network IDs** - Auto-sorted by signal strength (1-N)

### 🛡️ **Safety & Reliability**
- **Smart Interface Detection** - Automatic WiFi adapter selection with validation
- **Monitor Mode Management** - Safe enable/disable with cleanup handlers
- **NetworkManager Handling** - Selective stopping (VM-aware)
- **Signal Handlers** - Proper Ctrl+C handling with graceful cleanup
- **Temporary File Management** - Auto-cleanup of capture files

### 🎨 **User Experience**
- **Interactive Interface** - Ctrl+C to stop scanning, not exit
- **Progress Tracking** - Real-time countdowns and progress bars
- **Color-Coded Output** - Signal strength visualization
- **Client MAC Tables** - Formatted display of detected devices
- **Detailed Results** - Saved reports with timestamps

---

## Screenshot

![Screenshot Example](https://github.com/user-attachments/assets/e490e4bc-78bd-4bd4-bca3-fab95c8d7d2a)
![Screenshot Example](https://github.com/user-attachments/assets/1794b6d1-5311-4334-95cf-7ff833ea68d4)

---

## 📋 Requirements

- **OS**: Linux (Debian/Ubuntu/Kali recommended)
- **Python**: 3.10+
- **Tools**: aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng)
- **Privileges**: Root/sudo access required
- **Wi-Fi Adapter**: Monitor-mode capable (e.g., TP-Link TL-WN722N V1, ALFA AWUS036ACS, AR9271)

### Python Dependencies

```bash
pip install rich mac-vendor-lookup
```

Or using `uv` (recommended):
```bash
uv pip install rich mac-vendor-lookup
```

---

## 🚀 Installation

```bash
# Install aircrack-ng suite
sudo apt update && sudo apt install aircrack-ng

# Clone repository
git clone https://github.com/Mysteriza/wifyte.git
cd wifyte

# Install Python dependencies
sudo python3 -m pip install -r requirements.txt

# Run the tool
sudo python3 main.py
```

---

## 📖 Usage

### Basic Usage

To run with **root privileges** (required) while using the virtual environment:

```bash
sudo ./venv/bin/python3 main.py
```

Or if you installed dependencies globally:
```bash
sudo python3 main.py
```

### Workflow

1. **Interface Selection** - Auto-detects WiFi adapters (internal/external)
2. **Monitor Mode** - Automatically enables monitor mode
3. **Network Scanning** - Continuous live scan (press Ctrl+C when ready)
4. **Target Selection** - Choose one or multiple networks (e.g., "1, 2, 5")
5. **Client Detection** - 15s scan with progress bar
6. **Deauthentication** - Parallel threading for speed
7. **Handshake Capture** - Real-time monitoring (~3-5s detection)
8. **Password Cracking** - Dictionary attack with aircrack-ng
9. **Results** - Saved to `results/` directory

---

## 🎯 Example Session

```
WiFi Handshake Capture & Cracking Tool

[*] Available WiFi Interfaces:
  [1] wlp1s0 (Internal) - ⚠️ Likely unsupported!
  [2] wlx18d6c70831ae (External)
[?] Select interface: 2

[+] Monitor mode active on wlan0mon

╭─────────── 14 Networks Found - Scanning... ───────────╮
│ ID │ SSID          │ CH │ PWR  │ ENC       │ VENDOR │
├────┼───────────────┼────┼──────┼───────────┼────────┤
│ 1  │ HomeNetwork   │ 7  │ 61%  │ WPA2 CCMP │ ZTE    │
│ 2  │ <HIDDEN SSID> │ 11 │ 57%  │ WPA2      │ Huawei │
╰────────────────────────────────────────────────────────╯

[?] Select Targets: 1

⠋ Scanning for clients ████████████████ 15/15s

╭───────── ✓ 5 Client(s) Detected ─────────╮
│  #  │ Client MAC          │
│  1  │ 98:AF:65:17:C9:FB   │
│  2  │ 0C:98:38:DA:4F:9D   │
╰──────────────────────────────────────────╯

[*] Deauthenticating clients...
[+] Deauthentication completed!

📡 Capturing handshake for HomeNetwork...
⏱ Time: 5s / 60s | Remaining: 00:55
✓ Handshake detected!

[*] Cracking password...
[+] Password found: mypassword123
```

---

## 📁 Project Structure

```
wifyte/
├── main.py              # Entry point & orchestration
├── interface.py         # Interface detection & monitor mode
├── scanner.py           # Network scanning & client detection
├── capture.py           # Handshake capture logic
├── cracker.py           # Password cracking
├── utils.py             # Helper functions
├── wifyte.txt           # Default wordlist
├── handshakes/          # Captured handshakes (.cap)
├── results/             # Cracking results (.txt)
└── temp/                # Temporary scan files
```

---

## 🔧 Configuration

### Wordlist

Default: `wifyte.txt` (included)

Custom wordlist:
```python
# In main.py, modify:
self.wordlist = "/path/to/your/wordlist.txt"
```

Popular wordlists:
- rockyou.txt - `/usr/share/wordlists/rockyou.txt`
- SecLists - https://github.com/danielmiessler/SecLists

### Scan Duration

Client detection: 15 seconds (configurable)
```python
# In capture.py:
clients = detect_connected_clients(self, network, duration=15)
```

---

## 🎨 Features Showcase

### Live Network Scanning
- **Continuous updates** without scrolling
- **Ctrl+C** stops scan, not program
- **Auto-sorted** by signal strength
- **Vendor lookup** for each BSSID
- **HIDDEN SSID** detection and decloaking

### Client Detection
- **Progress bar** with countdown
- **15-second scan** for better accuracy
- **Rich table display** of MACs

### Handshake Capture
- **Fast detection** (~3-5 seconds typical)
- **Parallel deauth** using threading
- **Real-time countdown** with styled output

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

This tool is intended for:
- Authorized penetration testing
- Security research on YOUR OWN networks
- Educational purposes in controlled environments

**UNAUTHORIZED ACCESS TO NETWORKS IS ILLEGAL**

Users are responsible for compliance with local laws. The author assumes no liability for misuse.

By using this tool, you agree to:
- Use it only on networks for which you have explicit permission
- Refrain from illegal, malicious, or unauthorized activities
- Understand that misuse may violate applicable laws

---

## 🐛 Troubleshooting

### Interface Issues

**Problem**: No WiFi interfaces detected
```bash
# Check interfaces
iwconfig
ip link

# Ensure wireless tools installed
sudo apt install wireless-tools
```

**Problem**: Monitor mode fails
```bash
# Kill interfering processes
sudo airmon-ng check kill

# Manual monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### Capture Issues

**Problem**: No clients detected
- Ensure network has active clients
- Increase scan duration to 20-30s
- Try different times of day

**Problem**: Handshake not captured
- Ensure clients reconnect after deauth
- Check capture file manually: `aircrack-ng handshake.cap`
- Verify network encryption (WPA/WPA2 only)

### VM Environment

**Problem**: USB adapter not recognized
- Ensure USB passthrough enabled
- Check adapter in VMware/VirtualBox settings
- Verify driver support: `lsusb` and `dmesg`

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

---

## 📜 License

MIT License - see LICENSE file

---

## 🙏 Credits

- **aircrack-ng** - Core WiFi tools
- **Rich** - Beautiful terminal UI
- **mac-vendor-lookup** - MAC address vendor database
- **Wifite2** - Inspiration for workflow and features

---

## 📝 Changelog

### v2.0 (Latest) - Optimization Release
- ✨ Continuous real-time scanning with live display
- ✨ Rich modern UI (panels, tables, progress bars)
- ✨ Improved VM detection (no false positives)
- ✨ Vendor lookup with graceful fallback
- ✨ 15-second client detection with progress
- ✨ Sequential network IDs sorted by signal
- 🐛 Fixed Ctrl+C behavior during scanning
- 🐛 Fixed screen clearing issues
- ⚡ Maintained original fast capture speed
- ⚡ Threading-based parallel deauthentication

### v1.0 - Initial Release
- Basic handshake capture & cracking
- Monitor mode management
- Client detection & deauthentication
- HIDDEN SSID decloaking
- Multi-target support

---

## 📧 Contact

For issues, questions, or suggestions:
- **GitHub Issues**: [Wifyte Issues](https://github.com/Mysteriza/wifyte/issues)
- **GitHub**: [@Mysteriza](https://github.com/Mysteriza)

---

**Happy Ethical Hacking! 🔐**
