"""
ZeroCore Agent — API Routes
All endpoints are authenticated via X-ZeroCore-API-Key dependency.
Inputs are validated via Pydantic models — never raw query parameters for actions.
"""
from __future__ import annotations

import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from src.api.dependencies import get_db, verify_api_key
from src.core.database import Database
from src.core.logging import get_logger
from src.core.settings import get_settings
from src.domain.models import (
    AgentStatusResponse,
    BlockIPRequest,
    EventType,
    MitigationAction,
    PaginatedActionsResponse,
    PaginatedEventsResponse,
    SecurityEvent,
    Severity,
    UnblockIPRequest,
)
from src.services.mitigation_service import LinuxFirewallManager

logger = get_logger("ZeroCore.Routes")

router = APIRouter(prefix="/api/v1", dependencies=[Depends(verify_api_key)])

_firewall = LinuxFirewallManager()
_startup_time = time.time()

# =============================================================================
# Health & Status
# =============================================================================

@router.get(
    "/health",
    response_model=AgentStatusResponse,
    summary="Agent health and operational status",
    tags=["System"],
)
async def health_check(request: Request, db: Database = Depends(get_db)):
    settings = get_settings()
    fim = getattr(request.app.state, "fim", None)
    _, events_total = await db.get_events(page=1, page_size=1)
    _, actions_total = await db.get_actions(page=1, page_size=1)
    return AgentStatusResponse(
        status="operational",
        agent_id=settings.agent_id,
        environment=settings.environment,
        uptime_seconds=round(time.time() - _startup_time, 1),
        events_processed=events_total,
        actions_taken=actions_total,
        fim_active=fim.is_running() if fim else False,
    )


# =============================================================================
# Security Events
# =============================================================================

@router.get(
    "/events",
    response_model=PaginatedEventsResponse,
    summary="Retrieve paginated security events",
    tags=["Events"],
)
async def list_events(
    db: Database = Depends(get_db),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=200, description="Items per page"),
    severity: Severity | None = Query(default=None, description="Filter by severity"),
    event_type: EventType | None = Query(default=None, description="Filter by event type"),
):
    events, total = await db.get_events(
        page=page, page_size=page_size, severity=severity, event_type=event_type
    )
    return PaginatedEventsResponse(
        total=total, page=page, page_size=page_size, items=events
    )


# =============================================================================
# Mitigation Actions
# =============================================================================

@router.get(
    "/actions",
    response_model=PaginatedActionsResponse,
    summary="Retrieve paginated mitigation actions",
    tags=["Mitigation"],
)
async def list_actions(
    db: Database = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    actions, total = await db.get_actions(page=page, page_size=page_size)
    return PaginatedActionsResponse(
        total=total, page=page, page_size=page_size, items=actions
    )


@router.post(
    "/mitigation/block",
    response_model=MitigationAction,
    status_code=status.HTTP_201_CREATED,
    summary="Manually block an IP address",
    tags=["Mitigation"],
)
async def manual_block_ip(
    body: BlockIPRequest,
    db: Database = Depends(get_db),
):
    """
    Inject an iptables DROP rule for the given IP.
    Requires CAP_NET_ADMIN capability on the host process.
    """
    settings = get_settings()
    ip = str(body.ip_address)

    success = _firewall.block_ip(ip)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to inject firewall rule for {ip}. Check agent logs.",
        )

    action = MitigationAction(
        action_id=str(uuid.uuid4()),
        target=ip,
        action_type="BLOCK_IP",
        status="SUCCESS",
        details=f"Manual block by {body.requested_by}: {body.reason}",
        agent_id=settings.agent_id,
    )
    await db.insert_action(action)
    logger.warning(
        "mitigation.manual_block",
        ip=ip,
        requested_by=body.requested_by,
        reason=body.reason,
    )
    return action


@router.post(
    "/mitigation/unblock",
    response_model=MitigationAction,
    status_code=status.HTTP_201_CREATED,
    summary="Manually unblock an IP address",
    tags=["Mitigation"],
)
async def manual_unblock_ip(
    body: UnblockIPRequest,
    db: Database = Depends(get_db),
):
    settings = get_settings()
    ip = str(body.ip_address)

    success = _firewall.unblock_ip(ip)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove firewall rule for {ip}. Check agent logs.",
        )

    action = MitigationAction(
        action_id=str(uuid.uuid4()),
        target=ip,
        action_type="UNBLOCK_IP",
        status="SUCCESS",
        details=f"Manual unblock by {body.requested_by}",
        agent_id=settings.agent_id,
    )
    await db.insert_action(action)
    logger.info("mitigation.manual_unblock", ip=ip, requested_by=body.requested_by)
    return action


# =============================================================================
# Baseline
# =============================================================================

@router.get(
    "/baseline",
    summary="List all file baseline entries",
    tags=["FIM"],
)
async def list_baseline(db: Database = Depends(get_db)):
    entries = await db.get_all_baselines()
    return {"total": len(entries), "items": [e.model_dump() for e in entries]}


@router.post(
    "/baseline/snapshot",
    summary="Trigger a baseline snapshot of all watched paths",
    tags=["FIM"],
)
async def trigger_snapshot(request: Request):
    fim = getattr(request.app.state, "fim", None)
    if not fim:
        raise HTTPException(status_code=503, detail="FIM service not available")
    count = await fim.snapshot_baseline()
    return {"status": "snapshot_complete", "files_recorded": count}
