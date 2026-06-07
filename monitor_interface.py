"""
ZeroCore Agent — Monitor Interface
Abstract contract for all monitoring subsystems.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class IMonitorService(ABC):

    @abstractmethod
    async def start_monitoring(self) -> None:
        """Start the background monitoring process."""

    @abstractmethod
    async def stop_monitoring(self) -> None:
        """Gracefully stop the background monitoring process."""

    @abstractmethod
    def is_running(self) -> bool:
        """Return True if the monitor is currently active."""
