"""
GPU detection — identify discrete vs integrated GPUs.

Windows: PowerShell CIM/WMI then WMIC fallback.
Linux:   lspci -vnn parsing.
"""

import platform
import subprocess
import re
from typing import Optional

from src.console import colored_log, log_debug


_DISCRETE_KEYWORDS = [
    "rtx", "gtx", "quadro", "tesla", "nvidia",
    "rx ", "rx ", "firepro", "pro wx", "radeon",
    "arc ", "iris xe",
]

_SKIP_KEYWORDS = [
    "intel", "microsoft", "basic display", "vmware",
    "virtualbox", "parsec", "remote", "indirect",
]


def _is_discrete(name: str) -> bool:
    """Heuristic: discrete GPU keywords beat skip keywords."""
    lower = name.lower()
    if any(kw in lower for kw in _SKIP_KEYWORDS):
        return False
    return any(kw in lower for kw in _DISCRETE_KEYWORDS)


def _detect_windows() -> tuple[Optional[str], bool]:
    """Return (name, is_discrete) via PowerShell CIM/WMI + WMIC fallback."""
    # Try Get-CimInstance first (PowerShell 5+)
    ps_script = (
        "Get-CimInstance -ClassName Win32_VideoController | "
        "Select-Object -Property Name | Format-Table -HideTableHeaders"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=10,
        )
        gpu_lines = [l.strip() for l in out.stdout.split("\n") if l.strip()]
    except Exception:
        gpu_lines = []

    if not gpu_lines:
        # Fallback: Get-WmiObject
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WmiObject Win32_VideoController | Select-Object -Property Name"],
                capture_output=True, text=True, timeout=10,
            )
            gpu_lines = [l.strip() for l in out.stdout.split("\n")
                         if l.strip() and "Name" not in l and "---" not in l]
        except Exception:
            gpu_lines = []

    if not gpu_lines:
        # Fallback: wmic
        try:
            out = subprocess.run(
                ["wmic", "path", "win32_videocontroller", "get", "name"],
                capture_output=True, text=True, timeout=10,
            )
            gpu_lines = [l.strip() for l in out.stdout.split("\n")
                         if l.strip() and "Name" not in l]
        except Exception:
            gpu_lines = []

    for line in gpu_lines:
        name = line.strip()
        if not name or any(kw in name.lower() for kw in _SKIP_KEYWORDS):
            continue
        log_debug(f"Windows GPU found: {name}")
        return name, _is_discrete(name)

    return None, False


def _detect_linux() -> tuple[Optional[str], bool]:
    """Return (name, is_discrete) by parsing ``lspci -vnn``."""
    try:
        out = subprocess.run(
            ["lspci", "-vnn"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None, False

    # Find VGA / 3D / Display controller sections
    gpu_sections = re.split(
        r"\n(?=[0-9a-f]{2}:[0-9a-f]{2}\.\d )",
        out.stdout,
    )
    for section in gpu_sections:
        if not any(tag in section for tag in ["VGA", "3D", "Display"]):
            continue
        lines = section.strip().split("\n")
        if not lines:
            continue
        # First line: "XX:XX.X CLASS: Device Name"
        header = lines[0]
        name_part = header.split(": ", 1)[-1] if ": " in header else header
        log_debug(f"Linux GPU found: {name_part.strip()}")
        return name_part.strip(), _is_discrete(name_part.strip())

    return None, False


def detect_gpu() -> tuple[Optional[str], bool]:
    """
    Detect the primary GPU.

    Returns:
        (gpu_name, is_discrete)
        If no GPU is found both values are ``(None, False)``.
    """
    system = platform.system()
    if system == "Windows":
        return _detect_windows()
    elif system == "Linux":
        return _detect_linux()
    else:
        return None, False
