"""
ZeroCore Agent — Firewall Interface
Abstract contract for kernel-space firewall managers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class IFirewallManager(ABC):

    @abstractmethod
    def block_ip(self, ip_address: str) -> bool:
        """Inject a DROP rule for the given IP. Returns True on success."""

    @abstractmethod
    def unblock_ip(self, ip_address: str) -> bool:
        """Remove the DROP rule for the given IP. Returns True on success."""

    @abstractmethod
    def is_blocked(self, ip_address: str) -> bool:
        """Return True if the given IP is currently blocked."""
