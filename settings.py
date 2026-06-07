"""
ZeroCore Agent — Core Settings
All configuration is driven by environment variables.
No secrets are ever stored in code or YAML.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    """
    Immutable, validated settings loaded exclusively from environment variables.
    Raises on startup if any required field is missing or invalid.
    """

    model_config = SettingsConfigDict(
        env_prefix="ZEROCORE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Agent Identity ---
    agent_id: str = Field(default="zerocore-agent-01", description="Unique agent identifier")
    environment: str = Field(default="production", description="Deployment environment")
    log_level: str = Field(default="INFO", description="Logging verbosity")

    # --- Security (required, no defaults) ---
    secret_key: str = Field(..., min_length=32, description="JWT signing secret — minimum 32 chars")
    api_key: str = Field(..., min_length=16, description="API authentication key")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expire_minutes: int = Field(default=60, ge=5, le=1440)

    # --- Server ---
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000, ge=1024, le=65535)

    # --- Database ---
    db_path: str = Field(default="data/zerocore.db")

    # --- Monitoring ---
    watch_paths: str = Field(
        default="/etc/passwd,/etc/shadow,/etc/sudoers,/bin,/sbin,/usr/bin"
    )
    excluded_extensions: str = Field(default=".tmp,.swp,.lock")

    # --- Mitigation ---
    auto_block: bool = Field(default=True)
    block_duration_seconds: int = Field(default=3600, ge=60)
    block_cooldown_seconds: int = Field(default=60, ge=10)
    max_blocks_per_minute: int = Field(default=10, ge=1, le=100)

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v.lower() not in allowed:
            raise ValueError(f"environment must be one of: {allowed}")
        return v.lower()

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"log_level must be one of: {allowed}")
        return v.upper()

    @property
    def watch_paths_list(self) -> List[str]:
        return [p.strip() for p in self.watch_paths.split(",") if p.strip()]

    @property
    def excluded_extensions_list(self) -> List[str]:
        return [e.strip() for e in self.excluded_extensions.split(",") if e.strip()]


@lru_cache(maxsize=1)
def get_settings() -> AgentSettings:
    """
    Returns a cached, validated settings singleton.
    Called once on startup; subsequent calls return the same object.
    Raises pydantic.ValidationError if required env vars are missing.
    """
    return AgentSettings()
