"""Hashcat sub-package — conversion, setup/discovery, and cracking."""

from .convert import convert_cap_to_hc22000
from .setup import ensure_hashcat, is_hashcat_available, get_hashcat_path, warmup_hashcat_kernel
from .crack import crack_with_hashcat, HashcatBackend, HASHCAT_EXHAUSTED

__all__ = [
    "convert_cap_to_hc22000",
    "ensure_hashcat",
    "is_hashcat_available",
    "get_hashcat_path",
    "warmup_hashcat_kernel",
    "crack_with_hashcat",
    "HashcatBackend",
    "HASHCAT_EXHAUSTED",
]
