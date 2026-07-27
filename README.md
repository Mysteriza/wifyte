![Repository Size](https://img.shields.io/github/repo-size/Mysteriza/wifyte)
![Python Version](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

# Wifyte — WiFi Handshake Capture & Cracking Tool

> **If you only need to crack an existing handshake (no capture), consider the simpler companion tool:
> [handshakeCracker](https://github.com/Mysteriza/handshakeCracker)** — GPU-accelerated WPA/WPA2
> cracker using hashcat + aircrack-ng, without the capture workflow.

**Wifyte** is an all-in-one WiFi penetration testing tool that captures WPA/WPA2 handshakes and
cracks passwords. It combines a full capture pipeline (scan, deauth, capture) with dual-backend
cracking — **hashcat (GPU)** for speed, **aircrack-ng (CPU)** as fallback.

Inspired by [Wifite2](https://github.com/derv82/wifite2), built for modern hardware with a Rich
terminal UI.

---

## 🔗 Companion Tool

| Tool | Purpose |
|------|---------|
| **[handshakeCracker](https://github.com/Mysteriza/handshakeCracker)** | Crack-only — supply a `.cap` file and wordlist, no WiFi adapter needed. Ideal for Windows users. |
| **Wifyte (this repo)** | Full pipeline — scan, capture, **and** crack. Requires Linux + monitor-mode adapter for capture. |

---

## ✨ Features

### 🎯 Capture & Scanning
- **WPA/WPA2 Handshake Capture** — fast deauthentication-based capture with parallel threading
- **Continuous Live Scanning** — real-time network table (Rich) with signal sorting, vendor lookup
- **Hidden SSID Decloaking** — automatically detect and reveal hidden networks
- **Multi-Target Support** — capture multiple networks in a single session
- **Client Detection** — 15-second probe with progress tracking
- **Smart VM Detection** — accurate virtual-machine adapter identification

### ⚡ Cracking Backends
- **hashcat (GPU)** — mode 22000, auto-detects discrete vs integrated GPU for optimal flags (`-O` / `--optimized-kernel-enable`)
- **aircrack-ng (CPU)** — parallel wordlist chunking using all CPU cores, auto-fallback when GPU unavailable
- **Automatic Fallback** — hashcat → aircrack-ng if conversion fails or password not found
- **Potfile Lookup** — skips already-cracked passwords via `~/.hashcat/hashcat.potfile`

### 🧰 Automation & Setup
- **Auto-Setup** — on first run: installs Python deps, downloads hashcat (`.tar.gz`, no 7-Zip needed), fetches wordlist, detects GPU
- **Offline / Windows Mode** — skip capture, crack existing `.cap` / `.pcap` / `.pcapng` files directly
- **File Logging** — rotating debug logs (`logs/debug_log_*.txt`, keeps last 3)
- **Auto-Cleanup** — signal handlers restore monitor mode, remove temp files

### 🖥️ User Interface
- **Rich Terminal UI** — coloured logs, tables, panels, live displays, spinners
- **Multi-Target Deduplication** — same SSID password verified once, not re-cracked
- **Result Saving** — cracked passwords written to `results/<essid>_result.txt`

---

## 📋 Requirements

### Full Functionality (Linux)

| Requirement | Details |
|-------------|---------|
| **OS** | Linux (Debian, Ubuntu, Kali, Arch recommended) |
| **Python** | 3.10+ |
| **Wi-Fi Adapter** | Monitor-mode capable (e.g., TP-Link TL-WN722N V1, ALFA AWUS036ACS, AR9271) |
| **Tools** | `aircrack-ng` suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`) |
| **Optional** | hashcat 7.1.2+ (auto-downloaded), compatible GPU (AMD/NVIDIA/Intel) |
| **Privileges** | Root/sudo (required for monitor mode and packet injection) |

### Windows (Cracking Only)

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10 / 11 |
| **Python** | 3.10+ |
| **Tools** | `aircrack-ng.exe` (auto-extracted from bundled ZIP if present in `deps/`) |
| **Optional** | hashcat 7.1.2+ (auto-downloaded), compatible GPU |

> **⚠️ Windows cannot capture handshakes** — Windows does not support monitor mode or packet
> injection. Use `--offline` to crack an existing `.cap` / `.pcap` / `.pcapng` file captured
> elsewhere (e.g., from Linux, Raspberry Pi, or OpenWrt).

---

## 🚀 Installation

### Linux (Full Capture + Cracking)

```bash
# 1. Install aircrack-ng suite
sudo apt update && sudo apt install aircrack-ng
# (or: sudo pacman -S aircrack-ng on Arch)

# 2. Clone the repository
git clone https://github.com/Mysteriza/wifyte.git
cd wifyte

# 3. Install Python dependencies
sudo python3 -m pip install -r requirements.txt

# 4. Run — auto-setup downloads wordlist, hashcat, detects GPU
sudo python3 main.py
```

### Windows (Cracking Only)

```powershell
# 1. Clone the repository
git clone https://github.com/Mysteriza/wifyte.git
cd wifyte

# 2. Install Python dependencies
python -m pip install -r requirements.txt

# 3. (Optional) Download aircrack-ng for CPU cracking
#    Place aircrack-ng-1.7-win.zip in the deps/ folder.
#    The program will auto-extract it on startup.

# 4. Run with an existing handshake file
python main.py --offline handshakes\my_capture.pcap
```

> On Windows the program automatically detects the OS and skips all capture-related steps.
> No administrator privileges are needed for cracking.

---

## 📖 Usage

### Basic (Linux — Full Workflow)

```bash
sudo python3 main.py
```

Follow the interactive prompts:

1. **Auto-Setup** — GPU detection, wordlist download, hashcat download
2. **Interface** — select your WiFi adapter from the list
3. **Scan** — live network table; press `Ctrl+C` when ready
4. **Select Targets** — e.g., `1, 3, 5` to attack multiple networks
5. **Capture** — tool detects clients, sends deauth frames, captures handshake
6. **Crack** — hashcat GPU → aircrack-ng CPU fallback → password displayed

### Windows / Offline — Cracking Only

```bash
# Provide an existing handshake file
python main.py --offline handshakes/my_capture.pcap

# Or just run without --offline on Windows; the tool will auto-detect
# any .cap / .pcap / .pcapng file in the handshakes/ directory
python main.py
```

### Command-Line Options

| Argument | Description |
|----------|-------------|
| `--wordlist PATH` | Path to wordlist (default: `wifyte.txt`) |
| `--hashcat` | Force hashcat GPU cracking |
| `--no-hashcat` | Force aircrack-ng CPU cracking |
| `--offline FILE` | Crack an existing `.cap`/`.pcap`/`.pcapng` file (skip scan/capture) |

### Examples

```bash
# Use a custom wordlist
sudo python3 main.py --wordlist /usr/share/wordlists/rockyou.txt

# GPU-only cracking (Linux)
sudo python3 main.py --hashcat

# CPU-only cracking on a headless system
sudo python3 main.py --no-hashcat

# Windows: crack a capture from a Raspberry Pi
python main.py --offline C:\captures\corner_wifi.pcap

# Windows: use a specific wordlist with hashcat
python main.py --offline handshakes\corner_wifi.pcap --hashcat --wordlist wifyte.txt
```

---

## 📁 Project Structure

```
wifyte/
├── main.py                # Entry point & orchestration
├── requirements.txt       # Python dependencies
├── wifyte.txt             # Default wordlist (auto-updated)
├── README.md              # This file
├── .gitignore
│
├── src/
│   ├── __init__.py        # Package marker (v2.0.0)
│   ├── config.py          # Constants, paths, versions, URLs
│   ├── console.py         # Rich console + rotating file logging
│   ├── backend.py         # CrackerBackend Protocol
│   ├── gpu.py             # GPU detection (discrete / integrated)
│   ├── validator.py       # Handshake validation via scapy EAPOL
│   ├── utils.py           # Helpers: vendor lookup, download, spinner
│   ├── interface.py       # WiFi interface detection & monitor mode
│   ├── scanner.py         # Network scanning, client detection
│   ├── capture.py         # Deauth & handshake capture
│   ├── cracker.py         # Cracking orchestration + AircrackBackend
│   ├── setup.py           # Auto-setup pipeline
│   └── hashcat/
│       ├── __init__.py    # Re-exports
│       ├── convert.py     # .cap → .hc22000 (scapy EAPOL parsing)
│       ├── setup.py       # Binary discovery, download, kernel warmup
│       └── crack.py       # HashcatBackend (GPU cracking)
│
├── handshakes/            # Captured handshake files (.cap / .pcap)
├── hc22000_cache/         # Converted hashcat-format hashes
├── results/               # Cracked passwords (.txt)
├── logs/                  # Debug logs (auto-rotating, keeps 3)
├── bin/                   # Downloaded binaries (hashcat, aircrack-ng)
└── deps/                  # Downloaded archives (hashcat .tar.gz, aircrack-ng .zip)
```

---

## ⚠️ Platform Limitations

### Linux 🐧 — Full Support
- ✅ Monitor mode & packet injection
- ✅ Network scanning & client detection
- ✅ Deauthentication & handshake capture
- ✅ hashcat GPU cracking
- ✅ aircrack-ng CPU cracking

### Windows 🪟 — Cracking Only
- ❌ **No monitor mode** — Windows does not support raw 802.11 monitor mode
- ❌ **No packet injection** — cannot send deauth frames
- ❌ **No handshake capture**
- ✅ Cracking existing handshakes via hashcat (GPU) or aircrack-ng (CPU)
- ✅ Automatic detection of `.cap` / `.pcap` / `.pcapng` files in `handshakes/`
- ✅ Offline mode (`--offline` flag)

> If you only need to crack handshake files on Windows (or any OS), check out
> **[handshakeCracker](https://github.com/Mysteriza/handshakeCracker)** — a lighter tool
> focused purely on cracking without the capture pipeline.

---

## 🔧 Configuration

Key constants in `src/config.py`:

| Constant | Default | Description |
|----------|---------|-------------|
| `CAPTURE_TIMEOUT` | 60 s | Max wait for handshake |
| `CLIENT_DETECTION_DURATION` | 15 s | Client probe duration |
| `SINGLE_SCAN_DURATION` | 8 s | Legacy scan duration |
| `DEAUTH_COUNT` | 10 | Deauth frames per client |
| `HASHCAT_VERSION` | 7.1.2 | Hashcat version to download |

### Wordlist

Default wordlist: `wifyte.txt` (downloaded automatically on first run, checked for updates).

Popular alternatives:
- **rockyou.txt** — `/usr/share/wordlists/rockyou.txt` (Kali) or [download](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
- **SecLists** — [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

This tool is intended for:
- Authorized penetration testing with written permission
- Security research on **YOUR OWN** networks and devices
- Educational purposes in controlled lab environments

**UNAUTHORIZED ACCESS TO NETWORKS IS ILLEGAL**

Users are responsible for complying with all applicable local, state, and federal laws.
The author assumes **no liability** for any misuse or damage caused by this tool.

By using this tool you agree to:
- Use it only on networks you own or have explicit written permission to test
- Refrain from any illegal, malicious, or unauthorized activities
- Accept full responsibility for your actions

---

## 🐛 Troubleshooting

### Interface Issues

**Problem**: No WiFi interfaces detected
```bash
# Check available wireless interfaces
iwconfig
ip link

# Ensure wireless tools are installed
sudo apt install wireless-tools
```

**Problem**: Monitor mode fails
```bash
# Kill interfering processes
sudo airmon-ng check kill

# Manually enable monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### GPU / Hashcat Issues

**Problem**: Hashcat not using GPU
- Ensure GPU drivers are installed (AMD ROCm, NVIDIA CUDA, or Intel OpenCL)
- Run `sudo python3 main.py --hashcat` to force GPU mode
- Check `logs/debug_log_*.txt` for detection details

**Problem**: "Incomplete handshake" during conversion
- The `.cap` file does not contain a full 4-way handshake (need at least M1 + M2)
- Recapture the handshake ensuring the client connects during capture

### Windows Issues

**Problem**: Windows Defender blocks aircrack-ng.exe
- Add an exclusion for the `bin/` and `deps/` folders in Windows Security
- Or use `--hashcat` to skip aircrack-ng entirely

**Problem**: hashcat .7z extraction fails (no 7-Zip)
- The program now downloads `.tar.gz` by default, extracted with Python's built-in `tarfile` — no 7-Zip required
- If the `.tar.gz` download fails, it falls back to `.7z` (still requires 7-Zip for that path)

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome. Feel free to open an issue or submit a pull request.

---

## 🙏 Acknowledgements

- [Wifite2](https://github.com/derv82/wifite2) — original inspiration
- [hashcat](https://hashcat.net/hashcat/) — GPU-accelerated password recovery
- [aircrack-ng](https://www.aircrack-ng.org/) — de facto WiFi security tools
- [Rich](https://github.com/Textualize/rich) — beautiful terminal formatting
- [scapy](https://scapy.net/) — packet manipulation for handshake conversion
- [mac-vendor-lookup](https://github.com/bauerj/mac_vendor_lookup) — MAC vendor database
