"""
ZeroCore Agent — Test Suite
Tests cover: FIM severity logic, EventBus dispatch, Mitigation rate limiting,
API authentication, endpoint contracts, and IP validation.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Environment must be set before any app import
# ---------------------------------------------------------------------------
os.environ.setdefault("ZEROCORE_SECRET_KEY", "test_secret_key_minimum_32_characters_here")
os.environ.setdefault("ZEROCORE_API_KEY", "test-api-key-for-unit-tests")
os.environ.setdefault("ZEROCORE_ENVIRONMENT", "development")
os.environ.setdefault("ZEROCORE_DB_PATH", ":memory:")
os.environ.setdefault("ZEROCORE_WATCH_PATHS", "/tmp")
os.environ.setdefault("ZEROCORE_AUTO_BLOCK", "false")

from src.core.settings import get_settings
from src.domain.models import (
    ActionStatus,
    ActionType,
    EventType,
    MitigationAction,
    SecurityEvent,
    Severity,
)
from src.services.event_bus import EventBus
from src.services.fim_service import _classify_severity, _should_ignore
from src.services.mitigation_service import ActiveResponseEngine, LinuxFirewallManager

VALID_API_KEY = os.environ["ZEROCORE_API_KEY"]
AUTH_HEADERS = {"X-ZeroCore-API-Key": VALID_API_KEY}


# =============================================================================
# FIM — Severity Classification
# =============================================================================

class TestFIMSeverityClassification:
    def test_boot_path_is_critical(self):
        assert _classify_severity("/boot/grub/grub.cfg") == Severity.CRITICAL

    def test_bin_path_is_critical(self):
        assert _classify_severity("/bin/bash") == Severity.CRITICAL

    def test_usr_bin_path_is_critical(self):
        assert _classify_severity("/usr/bin/python3") == Severity.CRITICAL

    def test_passwd_is_high(self):
        assert _classify_severity("/etc/passwd") == Severity.HIGH

    def test_shadow_is_high(self):
        assert _classify_severity("/etc/shadow") == Severity.HIGH

    def test_sudoers_is_high(self):
        assert _classify_severity("/etc/sudoers") == Severity.HIGH

    def test_ssh_config_is_high(self):
        assert _classify_severity("/etc/ssh/sshd_config") == Severity.HIGH

    def test_generic_etc_is_medium(self):
        assert _classify_severity("/etc/timezone") == Severity.MEDIUM

    def test_unknown_path_is_low(self):
        assert _classify_severity("/home/user/document.txt") == Severity.LOW

    def test_etc_medium_not_critical(self):
        # /etc/timezone should NOT be HIGH — this was the old bug
        result = _classify_severity("/etc/timezone")
        assert result != Severity.HIGH
        assert result != Severity.CRITICAL


class TestFIMIgnoreLogic:
    def test_ignore_zerocore_path(self):
        assert _should_ignore("/var/log/zerocore/agent.log", []) is True

    def test_ignore_var_log(self):
        assert _should_ignore("/var/log/syslog", []) is True

    def test_ignore_proc(self):
        assert _should_ignore("/proc/1/status", []) is True

    def test_ignore_tmp_extension(self):
        assert _should_ignore("/etc/important.tmp", [".tmp"]) is True

    def test_ignore_swp_extension(self):
        assert _should_ignore("/etc/passwd.swp", [".swp"]) is True

    def test_do_not_ignore_etc_passwd(self):
        assert _should_ignore("/etc/passwd", [".tmp"]) is False

    def test_do_not_ignore_bin_bash(self):
        assert _should_ignore("/bin/bash", []) is False


# =============================================================================
# EventBus — Async Dispatch
# =============================================================================

class TestEventBus:
    def _make_event(self, severity: Severity = Severity.HIGH) -> SecurityEvent:
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.FIM,
            severity=severity,
            source="test",
            description="test event",
        )

    @pytest.mark.asyncio
    async def test_single_subscriber_called(self):
        bus = EventBus()
        called_with = []

        async def handler(event: SecurityEvent):
            called_with.append(event.event_id)

        bus.subscribe("FIM", handler)
        event = self._make_event()
        await bus.publish(event)
        assert event.event_id in called_with

    @pytest.mark.asyncio
    async def test_multiple_subscribers_all_called(self):
        bus = EventBus()
        results = []

        async def h1(e): results.append("h1")
        async def h2(e): results.append("h2")

        bus.subscribe("FIM", h1)
        bus.subscribe("FIM", h2)
        await bus.publish(self._make_event())
        assert "h1" in results
        assert "h2" in results

    @pytest.mark.asyncio
    async def test_failing_subscriber_does_not_block_others(self):
        bus = EventBus()
        results = []

        async def bad_handler(e):
            raise RuntimeError("intentional failure")

        async def good_handler(e):
            results.append("good")

        bus.subscribe("FIM", bad_handler)
        bus.subscribe("FIM", good_handler)
        await bus.publish(self._make_event())
        assert "good" in results  # good_handler ran despite bad_handler failing

    @pytest.mark.asyncio
    async def test_no_subscribers_does_not_raise(self):
        bus = EventBus()
        await bus.publish(self._make_event())  # Should not raise

    @pytest.mark.asyncio
    async def test_unsubscribe_removes_handler(self):
        bus = EventBus()
        results = []

        async def handler(e): results.append("called")

        bus.subscribe("FIM", handler)
        bus.unsubscribe("FIM", handler)
        await bus.publish(self._make_event())
        assert results == []

    @pytest.mark.asyncio
    async def test_wrong_event_type_not_dispatched(self):
        bus = EventBus()
        results = []

        async def handler(e): results.append("called")

        bus.subscribe("NETWORK", handler)
        await bus.publish(self._make_event())  # FIM event
        assert results == []


# =============================================================================
# Mitigation — Rate Limiting & Cooldown
# =============================================================================

class TestActiveResponseEngine:
    def _make_event(self, severity: Severity, ip: str) -> SecurityEvent:
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.FIM,
            severity=severity,
            source="test",
            description="test",
            metadata={"source_ip": ip},
        )

    def _make_engine(self, auto_block=True):
        os.environ["ZEROCORE_AUTO_BLOCK"] = str(auto_block).lower()
        # Reset settings cache for each test
        get_settings.cache_clear()
        mock_fw = MagicMock()
        mock_fw.block_ip.return_value = True
        mock_db = AsyncMock()
        mock_db.insert_action = AsyncMock()
        engine = ActiveResponseEngine(firewall_manager=mock_fw, db=mock_db)
        return engine, mock_fw, mock_db

    @pytest.mark.asyncio
    async def test_high_severity_triggers_block(self):
        engine, fw, _ = self._make_engine(auto_block=True)
        event = self._make_event(Severity.HIGH, "10.0.0.1")
        await engine.handle_security_event(event)
        fw.block_ip.assert_called_once_with("10.0.0.1")

    @pytest.mark.asyncio
    async def test_low_severity_does_not_trigger_block(self):
        engine, fw, _ = self._make_engine(auto_block=True)
        event = self._make_event(Severity.LOW, "10.0.0.2")
        await engine.handle_security_event(event)
        fw.block_ip.assert_not_called()

    @pytest.mark.asyncio
    async def test_medium_severity_does_not_trigger_block(self):
        engine, fw, _ = self._make_engine(auto_block=True)
        event = self._make_event(Severity.MEDIUM, "10.0.0.3")
        await engine.handle_security_event(event)
        fw.block_ip.assert_not_called()

    @pytest.mark.asyncio
    async def test_auto_block_disabled_skips_block(self):
        engine, fw, _ = self._make_engine(auto_block=False)
        event = self._make_event(Severity.CRITICAL, "10.0.0.4")
        await engine.handle_security_event(event)
        fw.block_ip.assert_not_called()

    @pytest.mark.asyncio
    async def test_cooldown_prevents_duplicate_block(self):
        engine, fw, _ = self._make_engine(auto_block=True)
        event = self._make_event(Severity.CRITICAL, "10.0.0.5")
        await engine.handle_security_event(event)
        await engine.handle_security_event(event)
        # Second call should be blocked by cooldown
        assert fw.block_ip.call_count == 1

    @pytest.mark.asyncio
    async def test_no_ip_in_metadata_skips_block(self):
        engine, fw, _ = self._make_engine(auto_block=True)
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.FIM,
            severity=Severity.CRITICAL,
            source="test",
            description="no ip",
            metadata={},  # No source_ip
        )
        await engine.handle_security_event(event)
        fw.block_ip.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_ip_skips_block(self):
        engine, fw, _ = self._make_engine(auto_block=True)
        event = self._make_event(Severity.CRITICAL, "not.an.ip.address")
        await engine.handle_security_event(event)
        fw.block_ip.assert_not_called()

    @pytest.mark.asyncio
    async def test_rate_limit_caps_blocks(self):
        engine, fw, _ = self._make_engine(auto_block=True)
        # Max blocks per minute is set via settings
        # We'll test by exhausting the rate limit manually
        for i in range(engine._settings.max_blocks_per_minute):
            engine._block_timestamps.append(datetime.now(timezone.utc))
        event = self._make_event(Severity.CRITICAL, "10.0.0.99")
        await engine.handle_security_event(event)
        fw.block_ip.assert_not_called()


# =============================================================================
# IP Validation
# =============================================================================

class TestIPValidation:
    def test_valid_ipv4(self):
        from src.services.mitigation_service import _validate_ip
        assert _validate_ip("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        from src.services.mitigation_service import _validate_ip
        assert _validate_ip("::1") == "::1"

    def test_invalid_ip_raises(self):
        from src.services.mitigation_service import _validate_ip
        with pytest.raises(ValueError):
            _validate_ip("not-an-ip")

    def test_command_injection_blocked(self):
        from src.services.mitigation_service import _validate_ip
        with pytest.raises(ValueError):
            _validate_ip("1.2.3.4; rm -rf /")

    def test_empty_string_raises(self):
        from src.services.mitigation_service import _validate_ip
        with pytest.raises(ValueError):
            _validate_ip("")


# =============================================================================
# API — Authentication & Endpoints
# =============================================================================

@pytest.fixture
def client():
    """
    Sync test client that bypasses lifespan (DB/FIM) for fast unit tests.
    Database dependency is mocked at the route level.
    """
    from unittest.mock import AsyncMock, MagicMock, patch
    from src.main import create_app

    app = create_app()

    # Attach a mock DB to app.state
    mock_db = AsyncMock()
    mock_db.get_events = AsyncMock(return_value=([], 0))
    mock_db.get_actions = AsyncMock(return_value=([], 0))
    mock_db.get_all_baselines = AsyncMock(return_value=[])

    app.state.db = mock_db
    app.state.fim = MagicMock()
    app.state.fim.is_running.return_value = True

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


class TestAPIAuthentication:
    def test_missing_api_key_returns_401(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 401

    def test_invalid_api_key_returns_401(self, client):
        response = client.get("/api/v1/health", headers={"X-ZeroCore-API-Key": "wrong-key"})
        assert response.status_code == 401

    def test_valid_api_key_returns_200(self, client):
        response = client.get("/api/v1/health", headers=AUTH_HEADERS)
        assert response.status_code == 200

    def test_public_health_requires_no_auth(self, client):
        response = client.get("/health")
        assert response.status_code == 200

    def test_security_headers_present(self, client):
        response = client.get("/health")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_request_id_header_present(self, client):
        response = client.get("/health")
        assert "X-Request-ID" in response.headers


class TestAPIEndpoints:
    def test_health_response_schema(self, client):
        response = client.get("/api/v1/health", headers=AUTH_HEADERS)
        data = response.json()
        assert data["status"] == "operational"
        assert "agent_id" in data
        assert "uptime_seconds" in data
        assert "fim_active" in data

    def test_events_endpoint_returns_paginated(self, client):
        response = client.get("/api/v1/events", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data
        assert "page" in data

    def test_actions_endpoint_returns_paginated(self, client):
        response = client.get("/api/v1/actions", headers=AUTH_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data

    def test_block_ip_invalid_body_returns_422(self, client):
        response = client.post(
            "/api/v1/mitigation/block",
            headers=AUTH_HEADERS,
            json={"ip_address": "not-an-ip", "reason": "test", "requested_by": "tester"},
        )
        assert response.status_code == 422

    def test_block_ip_missing_fields_returns_422(self, client):
        response = client.post(
            "/api/v1/mitigation/block",
            headers=AUTH_HEADERS,
            json={"ip_address": "1.2.3.4"},  # missing reason and requested_by
        )
        assert response.status_code == 422

    def test_events_pagination_params_validated(self, client):
        response = client.get(
            "/api/v1/events?page=0",  # page must be >= 1
            headers=AUTH_HEADERS,
        )
        assert response.status_code == 422

    def test_events_page_size_capped(self, client):
        response = client.get(
            "/api/v1/events?page_size=999",  # max is 200
            headers=AUTH_HEADERS,
        )
        assert response.status_code == 422
