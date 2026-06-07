"""
ZeroCore Agent — API Dependencies
FastAPI dependency injection: settings, database, auth verification.
"""
from __future__ import annotations

import hmac

from fastapi import Depends, Header, HTTPException, Request, status

from src.core.database import Database
from src.core.exceptions import AuthenticationError
from src.core.logging import get_logger
from src.core.settings import AgentSettings, get_settings

logger = get_logger("ZeroCore.Auth")


def get_db(request: Request) -> Database:
    """Inject the shared Database instance from app state."""
    return request.app.state.db


def get_settings_dep() -> AgentSettings:
    return get_settings()


def verify_api_key(
    x_zerocore_api_key: str = Header(..., alias="X-ZeroCore-API-Key"),
    settings: AgentSettings = Depends(get_settings_dep),
) -> None:
    """
    Validate the API key using constant-time comparison (hmac.compare_digest)
    to prevent timing-based enumeration attacks.
    """
    if not x_zerocore_api_key:
        logger.warning("auth.missing_api_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-ZeroCore-API-Key header",
        )
    if not hmac.compare_digest(x_zerocore_api_key, settings.api_key):
        logger.warning("auth.invalid_api_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
