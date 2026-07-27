"""
Convert .cap / .pcap files to hashcat's hc22000 format (mode 22000).

Parses EAPOL frames from a capture using scapy and writes
``WPA*02*...`` lines suitable for ``hashcat -m 22000``.
"""

import os
import re
from typing import Optional

from src.console import colored_log, log_error, log_debug


# ── Helpers ─────────────────────────────────────────────────────────────

def _format_mac(raw: bytes) -> str:
    """Convert 6-byte MAC to ``XX:XX:XX:XX:XX:XX``."""
    return ":".join(f"{b:02x}" for b in raw)


def _classify_eapol(packet) -> str | None:
    """
    Classify an EAPOL frame as M1/M2/M3/M4 based on key-info flags.

    Uses the same logic as `validator._classify_eapol`.
    """
    try:
        from scapy.layers.eap import EAPOL
    except ImportError:
        return None

    if not packet.haslayer(EAPOL):
        return None
    eapol = packet[EAPOL]

    try:
        key_info = eapol.load[1]
    except (IndexError, TypeError):
        return None

    ack     = bool(key_info & 0x80)
    mic     = bool(key_info & 0x01)
    install = bool(key_info & 0x40)
    secure  = bool(key_info & 0x08)

    if not ack and not mic and not install:
        return "M1"
    if ack and mic and not install:
        return "M2"
    if ack and mic and install:
        return "M3"
    if ack and mic and secure:
        return "M4"
    return None


# ── Public API ─────────────────────────────────────────────────────────

def convert_cap_to_hc22000(cap_path: str, output_path: str) -> bool:
    """
    Convert a .cap / .pcap file to a single-line hashcat hc22000 hash.

    Args:
        cap_path:   Path to the capture file.
        output_path: Destination for the .hc22000 file.

    Returns:
        ``True`` if conversion succeeded and at least one valid hash line
        was written.
    """
    if not os.path.exists(cap_path):
        log_error(f"Capture file not found: {cap_path}")
        return False

    try:
        from scapy.utils import rdpcap
        from scapy.layers.dot11 import Dot11, Dot11Elt
        from scapy.layers.eap import EAPOL
    except ImportError as e:
        log_error("scapy is required for hc22000 conversion.", e)
        return False

    try:
        packets = rdpcap(cap_path)
    except Exception as e:
        log_error(f"Failed to read capture: {cap_path}", e)
        return False

    # Collect EAPOL frames
    eapol_packets = [p for p in packets if p.haslayer(EAPOL)]
    if not eapol_packets:
        colored_log("warning", "No EAPOL frames found in capture.")
        return False

    # Classify and find the best pair
    classified = {}
    for pkt in eapol_packets:
        msg = _classify_eapol(pkt)
        if msg:
            classified.setdefault(msg, []).append(pkt)

    # Need at least M1 and M2 for a valid handshake
    if "M1" not in classified or "M2" not in classified:
        colored_log("warning", "Incomplete handshake — need at least M1+M2.")
        return False

    # Use M2 for extraction (it has MIC, ANonce, SNonce, etc.)
    m2 = classified["M2"][0]

    try:
        dot11 = m2[Dot11]
        eapol = m2[EAPOL]

        ap_mac   = dot11.addr2   # transmitter (AP)
        sta_mac  = dot11.addr1   # receiver (client)
        bssid    = dot11.addr3   # often the AP BSSID

        raw = bytes(eapol.load)
        if len(raw) < 100:
            colored_log("warning", "EAPOL frame too short — possible parse error.")
            return False

        # EAPOL key data starts at offset 0 in the load
        # ANonce at offset 13 (32 bytes)
        # SNonce at offset 45 (32 bytes)
        # MIC at offset 81 (16 bytes)
        anonce  = raw[13:45]
        snonce  = raw[45:81]
        mic     = raw[81:97]
        eapol_raw = raw[:97]    # first 97 bytes for hashcat format

        # Determine message pair
        # "02" if M3/M4 present (final message pair)
        # "00" if only M1/M2 (first message pair)
        msg_pair = "02" if ("M3" in classified or "M4" in classified) else "00"

        # Build ESSID from Dot11Elt
        essid = ""
        for elt in packets:
            if elt.haslayer(Dot11Elt):
                for e in elt[Dot11Elt]:
                    if e.ID == 0:
                        essid = e.info.decode("utf-8", errors="replace")
                        break
                if essid:
                    break

        if not essid:
            colored_log("warning", "Could not extract ESSID from capture.")
            return False

        # Build hc22000 line
        # Format: WPA*<msg_pair>*<mic>#...#*<ap_mac>*<sta_mac>*<essid>
        # Zero out MIC (bytes 81-97) before writing
        eapol_zeroed = bytearray(eapol_raw)
        eapol_zeroed[81:97] = b"\x00" * 16

        line = (
            f"WPA*{msg_pair}*"
            f"{mic.hex()}*"
            f"{anonce.hex()}*"
            f"{snonce.hex()}*"
            f"{_format_mac(ap_mac)}*"
            f"{_format_mac(sta_mac)}*"
            f"{essid}*"
            f"{_format_mac(bssid)}*"
            f"{eapol_zeroed.hex()}\n"
        )

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            f.write(line)

        colored_log("success", f"Converted → {output_path}")
        return True

    except Exception as e:
        log_error(f"Conversion failed for {cap_path}", e)
        return False
