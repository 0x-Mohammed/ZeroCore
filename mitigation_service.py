"""
ZeroCore Agent — Mitigation Service
Kernel firewall management via iptables (no sudo — requires CAP_NET_ADMIN).
Active Response Engine with per-IP cooldown and global rate limiting.
"""
from __future__ import annotations

import ipaddress
import subprocess
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from src.core.database import Database
from src.core.exceptions import FirewallError, RateLimitExceededError
from src.core.logging import get_logger
from src.core.settings import get_settings
from src.domain.models import (
    ActionStatus,
    ActionType,
    MitigationAction,
    SecurityEvent,
    Severity,
)
from src.interfaces.firewall_interface import IFirewallManager

logger = get_logger("ZeroCore.Mitigation")


def _validate_ip(ip: str) -> str:
    """Validate and return the IP address string. Raises ValueError on invalid input."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError(f"'{ip}' is not a valid IP address")


# =============================================================================
# Linux Firewall Manager
# Uses iptables directly — process must have CAP_NET_ADMIN capability.
# In Docker: add cap_add: [NET_ADMIN] to the service definition.
# In systemd: AmbientCapabilities=CAP_NET_ADMIN in the unit file.
# =============================================================================

class LinuxFirewallManager(IFirewallManager):
    """
    Manages iptables DROP rules for malicious IPs.
    Does NOT use sudo — relies on CAP_NET_ADMIN process capability.
    """

    _CHAIN = "INPUT"
    _TARGET = "DROP"

    def _run(self, args: list[str], check: bool = False) -> subprocess.CompletedProcess:
        """Run an iptables command. Raises FirewallError on non-zero exit when check=True."""
        try:
            result = subprocess.run(
                ["iptables"] + args,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if check and result.returncode != 0:
                raise FirewallError(
                    f"iptables command failed: {result.stderr.strip()}",
                    context={"args": args, "stderr": result.stderr},
                )
            return result
        except FileNotFoundError:
            raise FirewallError("iptables binary not found. Is it installed?")
        except subprocess.TimeoutExpired:
            raise FirewallError("iptables command timed out after 5 seconds")

    def block_ip(self, ip_address: str) -> bool:
        ip = _validate_ip(ip_address)
        try:
            if self.is_blocked(ip):
                logger.debug("firewall.already_blocked", ip=ip)
                return True
            self._run(["-A", self._CHAIN, "-s", ip, "-j", self._TARGET], check=True)
            logger.warning("firewall.blocked", ip=ip)
            return True
        except (FirewallError, ValueError) as exc:
            logger.error("firewall.block_failed", ip=ip, error=str(exc))
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        ip = _validate_ip(ip_address)
        try:
            if not self.is_blocked(ip):
                logger.debug("firewall.not_blocked", ip=ip)
                return True
            self._run(["-D", self._CHAIN, "-s", ip, "-j", self._TARGET], check=True)
            logger.info("firewall.unblocked", ip=ip)
            return True
        except (FirewallError, ValueError) as exc:
            logger.error("firewall.unblock_failed", ip=ip, error=str(exc))
            return False

    def is_blocked(self, ip_address: str) -> bool:
        ip = _validate_ip(ip_address)
        result = self._run(["-C", self._CHAIN, "-s", ip, "-j", self._TARGET])
        return result.returncode == 0


# =============================================================================
# Active Response Engine
# =============================================================================

class ActiveResponseEngine:
    """
    Reacts to high/critical SecurityEvents with automated firewall rules.

    Rate limiting:
    - Per-IP cooldown: prevents hammering iptables for the same IP
    - Global rate limit: caps total auto-block actions per minute
    """

    def __init__(self, firewall_manager: IFirewallManager, db: Database) -> None:
        self._firewall = firewall_manager
        self._db = db
        self._settings = get_settings()

        # Per-IP cooldown: ip -> last block timestamp
        self._ip_cooldown: Dict[str, datetime] = {}
        # Sliding window rate limit: list of block timestamps in current window
        self._block_timestamps: list[datetime] = []

    def _is_ip_in_cooldown(self, ip: str) -> bool:
        last = self._ip_cooldown.get(ip)
        if last is None:
            return False
        return (datetime.now(timezone.utc) - last) < timedelta(
            seconds=self._settings.block_cooldown_seconds
        )

    def _is_rate_limited(self) -> bool:
        now = datetime.now(timezone.utc)
        window = timedelta(seconds=60)
        # Purge old entries
        self._block_timestamps = [t for t in self._block_timestamps if now - t < window]
        return len(self._block_timestamps) >= self._settings.max_blocks_per_minute

    async def handle_security_event(self, event: SecurityEvent) -> None:
        if not self._settings.auto_block:
            return

        if event.severity < Severity.HIGH:
            return

        source_ip = event.metadata.get("source_ip")
        if not source_ip:
            return

        # Validate IP before any action
        try:
            source_ip = _validate_ip(source_ip)
        except ValueError:
            logger.warning("mitigation.invalid_ip", ip=source_ip, event_id=event.event_id)
            return

        if self._is_ip_in_cooldown(source_ip):
            logger.debug("mitigation.cooldown_active", ip=source_ip)
            return

        if self._is_rate_limited():
            logger.warning(
                "mitigation.rate_limited",
                max_per_minute=self._settings.max_blocks_per_minute,
            )
            return

        success = self._firewall.block_ip(source_ip)
        status = ActionStatus.SUCCESS if success else ActionStatus.FAILED

        if success:
            self._ip_cooldown[source_ip] = datetime.now(timezone.utc)
            self._block_timestamps.append(datetime.now(timezone.utc))

        action = MitigationAction(
            action_id=str(uuid.uuid4()),
            event_id=event.event_id,
            target=source_ip,
            action_type=ActionType.BLOCK_IP,
            status=status,
            details=f"Automated block triggered by {event.severity.value} event: {event.event_id}",
            agent_id=self._settings.agent_id,
        )

        await self._db.insert_action(action)
        logger.warning(
            "mitigation.action_taken",
            action_id=action.action_id,
            target=source_ip,
            status=status.value,
            event_id=event.event_id,
        )
