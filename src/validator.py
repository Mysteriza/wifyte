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
    valid: bool
    essid: str | None = None
    bssid: str | None = None
    eapol_messages: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        icon = "[green]✓[/green]" if self.valid else "[red]✗[/red]"
        essid_str = self.essid or "?"
        return f"{icon} {os.path.basename(self.filepath)} — {essid_str} [{', '.join(self.eapol_messages)}]"


# ── Scapy-based classification ─────────────────────────────────────────

def _classify_eapol(packet) -> str | None:
    """
    Classify an EAPOL frame as M1, M2, M3, or M4 based on key-info flags.

    Returns ``"M1"``, ``"M2"``, ``"M3"``, ``"M4"``, or ``None``.
    """
    try:
        from scapy.layers.eap import EAPOL
        from scapy.layers.dot11 import Dot11
    except ImportError:
        return None

    if not packet.haslayer(EAPOL):
        return None
    eapol = packet[EAPOL]

    try:
        key_info = eapol.load[1]
    except (IndexError, TypeError):
        return None

    ack    = bool(key_info & 0x80)   # bit 7
    mic    = bool(key_info & 0x01)   # bit 0
    install = bool(key_info & 0x40)  # bit 6
    secure = bool(key_info & 0x08)   # bit 3

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

def validate_handshake(filepath: str) -> ValidationResult:
    """
    Open a .cap / .pcap file and classify EAPOL frames found inside.

    A handshake is considered **valid** if at least two distinct EAPOL
    message types are present (e.g. M1 + M2 + …).
    """
    result = ValidationResult(filepath=filepath, valid=False)

    if not os.path.exists(filepath):
        return result

    try:
        from scapy.utils import rdpcap
    except ImportError:
        log_error("scapy is required for handshake validation.")
        return result

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        log_debug(f"scapy failed to read {filepath}: {e}")
        return result

    seen: set[str] = set()

    for pkt in packets:
        msg = _classify_eapol(pkt)
        if msg and msg not in seen:
            seen.add(msg)
            result.eapol_messages.append(msg)

    result.valid = len(seen) >= 2

    # Try to extract ESSID / BSSID from first packet
    if packets:
        try:
            from scapy.layers.dot11 import Dot11, Dot11Elt
            p = packets[0]
            if p.haslayer(Dot11):
                result.bssid = p[Dot11].addr3
            if p.haslayer(Dot11Elt):
                for elt in p[Dot11Elt]:
                    if elt.ID == 0:  # SSID
                        result.essid = elt.info.decode("utf-8", errors="replace")
                        break
        except Exception:
            pass

    return result


def validate_all_handshakes(file_list: list[str]) -> tuple[dict[str, ValidationResult], list[str]]:
    """
    Validate every file in *file_list*.

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
            ", ".join(res.eapol_messages) or "-",
            status,
        )
        if res.valid:
            valid_map[fpath] = res
        else:
            invalid.append(fpath)

    console.print(table)
    return valid_map, invalid
