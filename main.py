"""
ZeroCore Agent — Application Entry Point v3
Unified cross-platform detection engine:
  Linux  → eBPF probe (vfs_write + execve, BTF/CO-RE)
  Windows → ETW consumer + Sysmon parser
  Both   → ProcessMonitor correlation cache → FIM enrichment
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from src.api.middleware import RequestLoggingMiddleware
from src.api.routes import router
from src.core.database import Database
from src.core.logging import configure_logging, get_logger
from src.core.settings import get_settings
from src.services.event_bus import EventBus
from src.services.fim_service import FileIntegrityMonitor
from src.services.mitigation_service import ActiveResponseEngine, LinuxFirewallManager
from src.services.process_monitor import ProcessMonitor
from bridge.unified_bridge import UnifiedBridge

configure_logging()
logger = get_logger("ZeroCore.Main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logger.info("agent.starting", agent_id=settings.agent_id, environment=settings.environment)

    # --- Database ---
    db = Database()
    await db.open()
    app.state.db = db

    # --- Event Bus ---
    bus = EventBus()

    # --- Process Monitor (kernel bridge correlation cache) ---
    process_monitor = ProcessMonitor()
    app.state.process_monitor = process_monitor

    # --- Unified Bridge (eBPF on Linux, ETW on Windows) ---
    bridge = UnifiedBridge()
    app.state.bridge = bridge

    if bridge.available:
        bridge.register_handler(process_monitor.handle_process_event)
        bridge.start(asyncio.get_event_loop())
        logger.info("agent.bridge_active", platform=__import__("sys").platform)
    else:
        logger.warning(
            "agent.bridge_unavailable",
            message="Running in FIM-only mode — no process attribution",
        )

    # --- Mitigation Engine ---
    firewall = LinuxFirewallManager()
    response_engine = ActiveResponseEngine(firewall_manager=firewall, db=db)
    bus.subscribe("FIM", response_engine.handle_security_event)

    # --- Cache purge background task ---
    async def _purge_loop():
        while True:
            await asyncio.sleep(30)
            purged = await process_monitor.purge_expired()
            if purged:
                logger.debug("process_monitor.purged_expired", count=purged)

    purge_task = asyncio.create_task(_purge_loop())

    # --- FIM (with process attribution injected) ---
    fim = FileIntegrityMonitor(
        event_bus=bus,
        db=db,
        process_monitor=process_monitor,
    )
    app.state.fim = fim

    try:
        snapped = await fim.snapshot_baseline()
        logger.info("agent.baseline_complete", files=snapped)
    except Exception as exc:
        logger.warning("agent.baseline_failed", error=str(exc))

    try:
        await fim.start_monitoring()
    except Exception as exc:
        logger.error("agent.fim_start_failed", error=str(exc))

    logger.info("agent.ready", host=settings.host, port=settings.port)

    yield  # Running

    # --- Teardown ---
    logger.info("agent.shutting_down")
    purge_task.cancel()
    bridge.stop()
    await fim.stop_monitoring()
    await db.close()
    logger.info("agent.stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ZeroCore Automated Incident Response Agent",
        version="3.0.0",
        description=(
            "Cross-platform automated incident response agent. "
            "eBPF (Linux) + ETW/Sysmon (Windows) process attribution, "
            "SHA-256 FIM, active IP blocking, structured REST API."
        ),
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        openapi_url="/openapi.json" if settings.environment != "production" else None,
        lifespan=lifespan,
    )
    app.add_middleware(RequestLoggingMiddleware)
    app.include_router(router)

    @app.get("/health", include_in_schema=False)
    async def public_health():
        return JSONResponse({"status": "ok"})

    return app


app = create_app()

if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_config=None,
        access_log=False,
    )
