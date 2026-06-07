"""
ZeroCore Agent — Domain Models
Core data structures shared across all subsystems.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# Enumerations
# =============================================================================

class EventType(str, Enum):
    FIM = "FIM"
    NETWORK = "NETWORK"
    PROCESS = "PROCESS"
    AUTH = "AUTH"
    SYSTEM = "SYSTEM"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def numeric(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    def __ge__(self, other: "Severity") -> bool:
        return self.numeric >= other.numeric

    def __gt__(self, other: "Severity") -> bool:
        return self.numeric > other.numeric


class ActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    UNBLOCK_IP = "UNBLOCK_IP"
    KILL_PROCESS = "KILL_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    ALERT_ONLY = "ALERT_ONLY"


class ActionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


# =============================================================================
# Core Domain Models
# =============================================================================

class SecurityEvent(BaseModel):
    """
    Immutable record of a detected security-relevant system change.
    Written to the database; never mutated after creation.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=_utcnow)
    event_type: EventType
    severity: Severity
    source: str = Field(..., min_length=1, max_length=128)
    description: str = Field(..., min_length=1, max_length=1024)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    remediated: bool = False
    agent_id: str = Field(default="zerocore-agent-01")

    model_config = {"frozen": True}


class MitigationAction(BaseModel):
    """
    Immutable record of an automated or manual defensive action taken.
    """
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utcnow)
    target: str = Field(..., min_length=1, max_length=256)
    action_type: ActionType
    status: ActionStatus
    details: Optional[str] = Field(default=None, max_length=512)
    agent_id: str = Field(default="zerocore-agent-01")

    model_config = {"frozen": True}


class FileBaselineEntry(BaseModel):
    """
    SHA-256 baseline snapshot of a monitored file.
    Used by FIM to detect unauthorized changes via hash comparison.
    """
    path: str
    sha256: str
    size_bytes: int
    permissions: str
    recorded_at: datetime = Field(default_factory=_utcnow)
    last_modified: datetime

    model_config = {"frozen": True}


# =============================================================================
# API Request / Response Models
# =============================================================================

class BlockIPRequest(BaseModel):
    ip_address: str = Field(..., description="IPv4 or IPv6 address to block")
    reason: str = Field(..., min_length=1, max_length=256, description="Reason for the block")
    requested_by: str = Field(..., min_length=1, max_length=64, description="Operator identity")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IPv4 or IPv6 address")
        return v


class UnblockIPRequest(BaseModel):
    ip_address: str
    requested_by: str = Field(..., min_length=1, max_length=64)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v


class AgentStatusResponse(BaseModel):
    status: str
    agent_id: str
    environment: str
    uptime_seconds: float
    events_processed: int
    actions_taken: int
    fim_active: bool
    version: str = "2.0.0"


class PaginatedEventsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[SecurityEvent]


class PaginatedActionsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[MitigationAction]
