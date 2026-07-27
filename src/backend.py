"""
CrackerBackend protocol — interface for all cracking backends.

Every backend (hashcat, aircrack-ng) must implement ``crack()``.
"""

from typing import Protocol


class CrackerBackend(Protocol):
    """Protocol for a password-cracking backend."""

    def crack(
        self,
        handshake_path: str,
        wordlist_path: str,
        display_essid: str,
    ) -> str | None:
        """
        Attempt to crack the handshake.

        Args:
            handshake_path: Path to the captured .cap (or .hc22000) file.
            wordlist_path:  Path to the wordlist to try.
            display_essid:  Human-readable ESSID for status messages.

        Returns:
            The password string on success, or ``None`` if not found.
        """
        ...
