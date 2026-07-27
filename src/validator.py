"""
Handshake validation using scapy — EAPOL frame classification (M1/M2/M3/M4).

Exposes ``validate_handshake()`` and ``validate_all_handshakes()``.
"""

import os
from dataclasses import dataclass, field
from typing import Optional

from rich.table import Table

from src.console import console, colored_log, log_debug, log_error


# ── Result type ─────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    """Wraps a validation outcome for one capture file."""

    filepath: str
    is_valid: bool = False
    has_m1: bool = False
    has_m2: bool = False
    has_m3: bool = False
    has_m4: bool = False
    error: str | None = None
    essid: str | None = None
    bssid: str | None = None
    relevant_packets: list = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.is_valid

    def __str__(self) -> str:
        icon = "[green]✓[/green]" if self.is_valid else "[red]✗[/red]"
        parts = []
        if self.has_m1: parts.append("M1")
        if self.has_m2: parts.append("M2")
        if self.has_m3: parts.append("M3")
        if self.has_m4: parts.append("M4")
        return f"{icon} {os.path.basename(self.filepath)} — [{', '.join(parts)}] {self.essid or '?'}"


# ── Scapy-based classification ─────────────────────────────────────────

def _classify_eapol(packet) -> str | None:
    """
    Classify an EAPOL frame as M1, M2, M3, or M4 based on key-info flags.

    Uses Scapy's high-level ``EAPOL_KEY`` fields (``key_ack``, ``has_key_mic``,
    ``install``, ``secure``) matching the reference implementation from
    handshakeCracker.

    +-------+---------+---------+---------+--------+
    | Frame | Key ACK | Key MIC | Install | Secure |
    +-------+---------+---------+---------+--------+
    | M1    | 1       | 0       | 0       | 0      |
    | M2    | 0       | 1       | 0       | 0      |
    | M3    | 1       | 1       | 1       | 1      |
    | M4    | 0       | 1       | 0       | 1      |
    +-------+---------+---------+---------+--------+
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


# ── Public API ─────────────────────────────────────────────────────────

def validate_handshake(filepath: str) -> ValidationResult:
    """
    Open a .cap / .pcap file and classify EAPOL frames found inside.

    A handshake is considered **valid** if it contains **M1 AND M2** EAPOL
    frames (M3/M4 are optional bonuses).  References the same validation
    logic as handshakeCracker.
    """
    result = ValidationResult(filepath=filepath)

    if not os.path.exists(filepath):
        result.error = "file not found"
        return result

    try:
        from scapy.all import PcapReader
        from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt
        from scapy.layers.eap import EAPOL_KEY
    except ImportError:
        result.error = "scapy not available"
        log_error("scapy is required for handshake validation.")
        return result

    try:
        with PcapReader(filepath) as pcap:
            for pkt in pcap:
                if pkt.haslayer(EAPOL_KEY):
                    result.relevant_packets.append(pkt)
                    msg = _classify_eapol(pkt)
                    if msg == "M1":
                        result.has_m1 = True
                    elif msg == "M2":
                        result.has_m2 = True
                    elif msg == "M3":
                        result.has_m3 = True
                    elif msg == "M4":
                        result.has_m4 = True
                elif pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    result.relevant_packets.append(pkt)
                    # Extract ESSID from beacon
                    if not result.essid and pkt.haslayer(Dot11Elt):
                        elt = pkt[Dot11Elt]
                        while elt:
                            if elt.ID == 0 and elt.info:
                                try:
                                    result.essid = elt.info.decode("utf-8", errors="replace")
                                except Exception:
                                    result.essid = elt.info.hex()
                                break
                            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
                    if not result.bssid and pkt.haslayer(Dot11Beacon):
                        from scapy.layers.dot11 import Dot11
                        result.bssid = pkt[Dot11].addr3
    except Exception as e:
        result.error = f"cannot read pcap: {e}"
        return result

    result.is_valid = result.has_m1 and result.has_m2
    return result


def _build_messages_list(result: ValidationResult) -> str:
    """Build a compact M1/M2/M3/M4 string for display."""
    parts = []
    if result.has_m1: parts.append("M1")
    if result.has_m2: parts.append("M2")
    if result.has_m3: parts.append("M3")
    if result.has_m4: parts.append("M4")
    return ", ".join(parts) if parts else "-"


def validate_all_handshakes(
    file_list: list[str],
) -> tuple[dict[str, ValidationResult], list[str]]:
    """
    Validate every file in *file_list* and print an ASCII table.

    Returns:
        (valid_map, invalid_paths)
    """
    valid_map: dict[str, ValidationResult] = {}
    invalid: list[str] = []

    table = Table(title="Handshake Validation", header_style="bold cyan")
    table.add_column("File", style="cyan")
    table.add_column("ESSID", style="green")
    table.add_column("Messages", style="yellow")
    table.add_column("Status", style="bold")

    for fpath in file_list:
        res = validate_handshake(fpath)
        status = "[green]✓ Valid[/green]" if res.valid else "[red]✗ Invalid[/red]"
        table.add_row(
            os.path.basename(fpath),
            res.essid or "?",
            _build_messages_list(res),
            status,
        )
        if res.valid:
            valid_map[fpath] = res
        else:
            invalid.append(fpath)

    console.print(table)
    console.print(f"  {len(valid_map)} valid, {len(invalid)} invalid")
    return valid_map, invalid
