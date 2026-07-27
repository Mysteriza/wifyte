"""
Convert .cap / .pcap files to hashcat's hc22000 format (mode 22000).

Parses EAPOL frames from a capture using scapy and writes
``WPA*02*...`` lines suitable for ``hashcat -m 22000``.

Matches the exact conversion logic from handshakeCracker.
"""

import os
from typing import Optional

from src.console import colored_log, log_error, log_debug


# ── Helpers ─────────────────────────────────────────────────────────────

def _format_mac(raw) -> str:
    """Convert a MAC address (str or bytes) to ``xx:xx:xx:xx:xx:xx``."""
    if isinstance(raw, str):
        raw = raw.replace("-", ":").replace(" ", "")
        parts = raw.split(":")
        if len(parts) == 6:
            return ":".join(f"{p.lower():0>2s}" for p in parts)
        # bare hex
        try:
            b = bytes.fromhex(raw)
            return ":".join(f"{x:02x}" for x in b)
        except ValueError:
            return "00:00:00:00:00:00"
    if isinstance(raw, bytes) and len(raw) == 6:
        return ":".join(f"{x:02x}" for x in raw)
    return "00:00:00:00:00:00"


def _classify_eapol(packet) -> str | None:
    """
    Classify an EAPOL frame as M1/M2/M3/M4 based on key-info flags.

    Uses Scapy's high-level ``EAPOL_KEY`` fields matching the reference
    implementation from handshakeCracker.
    """
    try:
        from scapy.layers.eap import EAPOL_KEY
    except ImportError:
        return None

    if not packet.haslayer(EAPOL_KEY):
        return None
    ek = packet[EAPOL_KEY]

    ack = bool(ek.key_ack)
    mic = bool(ek.has_key_mic)
    ins = bool(ek.install)
    sec = bool(ek.secure)

    if ack and not mic and not ins and not sec:
        return "M1"
    if not ack and mic and not ins and not sec:
        return "M2"
    if ack and mic and ins and sec:
        return "M3"
    if not ack and mic and not ins and sec:
        return "M4"
    return None


def _extract_raw_eapol(pkt) -> bytes | None:
    """Extract the raw EAPOL frame bytes from a packet."""
    try:
        from scapy.layers.eap import EAPOL
        return bytes(pkt[EAPOL])
    except Exception:
        return None


# ── Public API ─────────────────────────────────────────────────────────

def convert_cap_to_hc22000(
    cap_path: str,
    output_path: str,
    packets: list | None = None,
) -> bool:
    """
    Convert a .cap / .pcap file to a single-line hashcat hc22000 hash.

    Args:
        cap_path:   Path to the capture file.
        output_path: Destination for the .hc22000 file.
        packets:    Optional pre-loaded packet list (from validator).

    Returns:
        ``True`` if conversion succeeded and a valid hash line was written.
    """
    if not os.path.exists(cap_path):
        log_error(f"Capture file not found: {cap_path}")
        return False

    try:
        from scapy.all import PcapReader
        from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
        from scapy.layers.eap import EAPOL, EAPOL_KEY
    except ImportError as e:
        log_error("scapy is required for hc22000 conversion.", e)
        return False

    # ── Load packets (use pre-loaded list when available) ──────────
    if packets is None:
        try:
            packets = []
            with PcapReader(cap_path) as pcap:
                for pkt in pcap:
                    if pkt.haslayer(EAPOL_KEY) or pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                        packets.append(pkt)
        except Exception as e:
            log_error(f"Failed to read capture: {cap_path}", e)
            return False

    # ── Collect ESSID from beacons ─────────────────────────────────
    essid = ""
    ap_mac = None
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        essid = elt.info.decode("utf-8", errors="replace")
                    except Exception:
                        essid = elt.info.hex()
                    if not ap_mac:
                        ap_mac = _format_mac(pkt[Dot11].addr2)
                    break
                elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
        if essid:
            break

    # ── Classify EAPOL frames ──────────────────────────────────────
    frames = {}
    for pkt in packets:
        if not pkt.haslayer(EAPOL_KEY):
            continue
        ek = pkt[EAPOL_KEY]
        msg = _classify_eapol(pkt)
        if msg:
            frames[msg] = pkt

    log_debug(f"convert: EAPOL frames found={list(frames.keys())}")

    # Need at least M2 (minimum for hc22000 format)
    if "M2" not in frames:
        colored_log("warning", "Incomplete handshake — M2 not found.")
        return False

    # ── Extract fields from M2 ─────────────────────────────────────
    m2_pkt = frames["M2"]
    m2_ek = m2_pkt[EAPOL_KEY]

    # Determine AP/STA MACs
    if ap_mac:
        if m2_pkt.haslayer(Dot11):
            s = m2_pkt[Dot11].addr2
            if _format_mac(s) != ap_mac:
                sta_mac = _format_mac(s)
            else:
                sta_mac = _format_mac(m2_pkt[Dot11].addr1)
    elif m2_pkt.haslayer(Dot11):
        ap_mac = _format_mac(m2_pkt[Dot11].addr1)
        sta_mac = _format_mac(m2_pkt[Dot11].addr2)
    else:
        log_error("Cannot determine MAC addresses.")
        return False

    # ANonce from M1 (preferred) or M3
    anonce = None
    if "M1" in frames:
        anonce = bytes(frames["M1"][EAPOL_KEY].key_nonce).hex()
    elif "M3" in frames:
        anonce = bytes(frames["M3"][EAPOL_KEY].key_nonce).hex()

    if not anonce:
        colored_log("warning", "ANonce not found (need M1 or M3).")
        return False

    snonce = bytes(m2_ek.key_nonce).hex()
    mic = bytes(m2_ek.key_mic).hex()
    key_ver = m2_ek.key_descriptor_type_version if hasattr(m2_ek, "key_descriptor_type_version") else 2

    # ── Extract & zero MIC in raw EAPOL frame ─────────────────────
    eapol_raw_bytes = _extract_raw_eapol(m2_pkt)
    if eapol_raw_bytes is None:
        log_error("Failed to extract raw EAPOL bytes from M2.")
        return False

    # Trim EAPOL to declared length
    declared_len = 4 + m2_pkt[EAPOL].len
    if len(eapol_raw_bytes) > declared_len:
        log_debug(f"convert: trimming EAPOL from {len(eapol_raw_bytes)} to {declared_len}")
        eapol_raw_bytes = eapol_raw_bytes[:declared_len]

    if len(eapol_raw_bytes) < 81 + 16:
        log_error("EAPOL frame too short for MIC zeroing.", Exception(f"len={len(eapol_raw_bytes)}"))
        return False

    eapol_bytes = bytearray(eapol_raw_bytes)
    eapol_bytes[81:97] = b"\x00" * 16
    eapol_hex = bytes(eapol_bytes).hex()

    # ── Build hc22000 line ─────────────────────────────────────────
    if not essid:
        essid = "Unknown"
    essid_hex = essid.encode("utf-8", errors="replace").hex()

    ap_mac_no_colon = ap_mac.replace(":", "")
    sta_mac_no_colon = sta_mac.replace(":", "")

    has_m3 = "M3" in frames
    has_m4 = "M4" in frames
    message_pair = "02" if (has_m3 or has_m4) else "00"

    line = (
        f"WPA*{key_ver:02x}*{mic}*"
        f"{ap_mac_no_colon}*{sta_mac_no_colon}*"
        f"{essid_hex}*{anonce}*"
        f"{eapol_hex}*{message_pair}\n"
    )

    # ── Write output ──────────────────────────────────────────────
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(line)

    colored_log("success", "Conversion to hc22000 succeeded.")
    log_debug(
        f"convert: OK essid={essid!r} "
        f"ap={ap_mac_no_colon} sta={sta_mac_no_colon} "
        f"anonce_len={len(anonce)} eapol_len={len(eapol_hex)}"
    )
    return True
