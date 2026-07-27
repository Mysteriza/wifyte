![Repository Size](https://img.shields.io/github/repo-size/Mysteriza/wifyte)
![Python Version](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

# Wifyte - WiFi Handshake Capture & Cracking Tool

**Wifyte** is an optimized Python-based WiFi penetration testing tool for capturing WPA/WPA2 handshakes and cracking passwords. Inspired by [Wifite2](https://github.com/derv82/wifite2), built with speed, accuracy, and a modern UI powered by **Rich**.

Now with **hashcat GPU acceleration** for ~100× faster cracking!

---

## ✨ Key Features

### 🎯 **Core Functionality**
- **WPA/WPA2 Handshake Capture** - Fast and reliable handshake capturing
- **Dual Cracking Backends** - aircrack-ng (CPU) **+** hashcat (GPU) with auto-fallback
- **GPU Acceleration** - Auto-detect discrete/integrated GPU for optimal hashcat tuning
- **HIDDEN SSID Detection & Decloaking** - Automatically detect and reveal hidden networks
- **Multi-Target Support** - Capture multiple networks in one session
- **Smart VM Detection** - Accurate detection with USB adapter identification

### 🚀 **Optimization Features**
- **Continuous Real-Time Scanning** - Live network table with dynamic updates (wifite2-style)
- **Rich Modern UI** - Beautiful panels, tables, and progress indicators
- **Fast Parallel Deauth** - Threading-based deauthentication for quick handshakes
- **Intelligent Client Detection** - 15-second scan with progress tracking
- **Auto-Setup** - Automatic dependency installation, wordlist download, GPU detection
- **File Logging** - Rotating debug logs (`logs/debug_log_*.txt`) with Rich console output

### 🛡️ **Safety & Reliability**
- **Smart Interface Detection** - Automatic WiFi adapter selection with validation
- **Monitor Mode Management** - Safe enable/disable with cleanup handlers
- **NetworkManager Handling** - Selective stopping (VM-aware)
- **Signal Handlers** - Proper Ctrl+C handling with graceful cleanup
- **Temporary File Management** - Auto-cleanup of capture files

---

## 📋 Requirements

- **OS**: Linux (Debian/Ubuntu/Kali recommended), Windows (partial support)
- **Python**: 3.10+
- **Tools**: aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng)
- **Optional**: hashcat 7.1.2+ (auto-downloaded if missing) with compatible GPU
- **Privileges**: Root/sudo access required (Linux)
- **Wi-Fi Adapter**: Monitor-mode capable (e.g., TP-Link TL-WN722N V1, ALFA AWUS036ACS, AR9271)

### Python Dependencies

```bash
pip install -r requirements.txt
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

# Run the tool (auto-setup handles wordlist download, GPU detection, hashcat)
sudo python3 main.py
```

---

## 📖 Usage

### Basic Usage

```bash
sudo python3 main.py
```

With custom wordlist:
```bash
sudo python3 main.py --wordlist /path/to/rockyou.txt
```

Force hashcat (GPU):
```bash
sudo python3 main.py --hashcat
```

Force aircrack-ng (CPU):
```bash
sudo python3 main.py --no-hashcat
```

### Workflow

1. **Auto-Setup** - Detects GPU, downloads wordlist, installs dependencies
2. **Interface Selection** - Auto-detects WiFi adapters (internal/external)
3. **Monitor Mode** - Automatically enables monitor mode
4. **Network Scanning** - Continuous live scan (press Ctrl+C when ready)
5. **Target Selection** - Choose one or multiple networks (e.g., "1, 2, 5")
6. **Client Detection** - 15s scan with progress bar
7. **Deauthentication** - Parallel threading for speed
8. **Handshake Capture** - Real-time monitoring (~3-5s detection)
9. **Password Cracking** - hashcat (GPU) → aircrack-ng (CPU) fallback
10. **Results** - Saved to `results/` directory

---

## 📁 Project Structure

```
wifyte/
├── main.py              # Entry point & orchestration
├── src/
│   ├── __init__.py      # Package marker
│   ├── config.py        # Centralised constants & paths
│   ├── console.py       # Rich console + file logging
│   ├── backend.py       # CrackerBackend Protocol
│   ├── gpu.py           # GPU detection (discrete/integrated)
│   ├── validator.py     # Handshake validation (scapy EAPOL)
│   ├── utils.py         # General utilities & vendor lookup
│   ├── interface.py     # Interface detection & monitor mode
│   ├── scanner.py       # Network scanning & client detection
│   ├── capture.py       # Handshake capture logic
│   ├── cracker.py       # Cracking orchestration + AircrackBackend
│   ├── setup.py         # Auto-setup pipeline
│   └── hashcat/
│       ├── __init__.py  # Package re-exports
│       ├── convert.py   # .cap → .hc22000 conversion (scapy)
│       ├── setup.py     # Hashcat binary discovery & kernel warmup
│       └── crack.py     # HashcatBackend (GPU cracking)
├── wifyte.txt           # Default wordlist (auto-downloaded)
├── handshakes/          # Captured handshakes (.cap)
├── hc22000_cache/       # Converted hashcat hashes
├── results/             # Cracking results (.txt)
├── logs/                # Debug logs
├── bin/                 # Downloaded binaries (hashcat, aircrack-ng)
└── deps/                # Downloaded archives
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
