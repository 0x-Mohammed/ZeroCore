"""
ZeroCore Agent — Exception Hierarchy
Clean, typed exception tree for all subsystems.
"""
from __future__ import annotations


class ZeroCoreError(Exception):
    """Base exception for all ZeroCore errors."""

    def __init__(self, message: str, context: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context = context or {}


# --- Configuration ---
class ConfigurationError(ZeroCoreError):
    """Raised when configuration is invalid or a required env var is missing."""


# --- Database ---
class DatabaseError(ZeroCoreError):
    """Raised when a database operation fails."""


class RecordNotFoundError(DatabaseError):
    """Raised when a requested record does not exist."""


# --- Monitoring ---
class MonitorError(ZeroCoreError):
    """Raised when a monitoring subsystem encounters a fatal error."""


class PathNotFoundError(MonitorError):
    """Raised when a watch path does not exist on the filesystem."""


# --- Mitigation ---
class MitigationError(ZeroCoreError):
    """Raised when an automated defense action fails."""


class FirewallError(MitigationError):
    """Raised when a kernel firewall rule operation fails."""


class RateLimitExceededError(MitigationError):
    """Raised when the auto-block rate limit is exceeded."""


# --- Authentication ---
class AuthenticationError(ZeroCoreError):
    """Raised when authentication fails."""


class TokenExpiredError(AuthenticationError):
    """Raised when a JWT token has expired."""


class InvalidTokenError(AuthenticationError):
    """Raised when a JWT token is malformed or invalid."""
