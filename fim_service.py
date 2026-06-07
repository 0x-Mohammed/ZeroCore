"""
ZeroCore Agent — File Integrity Monitor (FIM) v2
SHA-256 baseline comparison + Process Attribution via kernel bridge.

When the kernel bridge is active, every SecurityEvent includes:
    metadata.process_attribution = {
        "pid":          4122,
        "process_name": "python3",
        "command_line": "python3 exploit.py",
        "is_root":      true,
        "is_suspicious_exec": true
    }

Without the bridge (macOS dev / no CAP_BPF), events are emitted
without process attribution — FIM still works, attribution is None.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from src.core.database import Database
from src.core.exceptions import MonitorError
from src.core.logging import get_logger
from src.core.settings import get_settings
from src.domain.models import EventType, FileBaselineEntry, SecurityEvent, Severity
from src.interfaces.monitor_interface import IMonitorService
from src.services.event_bus import EventBus

logger = get_logger("ZeroCore.FIM")

# =============================================================================
# Severity Classification Rules
# =============================================================================
_SEVERITY_RULES: List[tuple[str, Severity]] = [
    ("/boot/",         Severity.CRITICAL),
    ("/bin/",          Severity.CRITICAL),
    ("/sbin/",         Severity.CRITICAL),
    ("/usr/bin/",      Severity.CRITICAL),
    ("/usr/sbin/",     Severity.CRITICAL),
    ("/lib/",          Severity.CRITICAL),
    ("/usr/lib/",      Severity.CRITICAL),
    ("/etc/passwd",    Severity.HIGH),
    ("/etc/shadow",    Severity.HIGH),
    ("/etc/sudoers",   Severity.HIGH),
    ("/etc/sudoers.d/",Severity.HIGH),
    ("/etc/ssh/",      Severity.HIGH),
    ("/etc/pam.d/",    Severity.HIGH),
    ("/etc/",          Severity.MEDIUM),
]

_IGNORED_PATH_FRAGMENTS = [
    "zerocore", "/var/log/", "/proc/", "/sys/", "/run/", "/tmp/", "/dev/",
]


def _classify_severity(path: str) -> Severity:
    for prefix, severity in _SEVERITY_RULES:
        if path.startswith(prefix):
            return severity
    return Severity.LOW


def _should_ignore(path: str, excluded_extensions: List[str]) -> bool:
    if any(frag in path for frag in _IGNORED_PATH_FRAGMENTS):
        return True
    _, ext = os.path.splitext(path)
    return ext in excluded_extensions


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError, PermissionError):
        return None


def _file_permissions(path: str) -> str:
    try:
        mode = os.stat(path).st_mode
        return oct(stat.S_IMODE(mode))
    except OSError:
        return "unknown"


# =============================================================================
# Watchdog Handler
# =============================================================================

class _FIMHandler(FileSystemEventHandler):
    def __init__(
        self,
        event_bus: EventBus,
        db: Database,
        loop: asyncio.AbstractEventLoop,
        settings,
        process_monitor=None,
    ) -> None:
        super().__init__()
        self._bus = event_bus
        self._db = db
        self._loop = loop
        self._settings = settings
        self._excluded = settings.excluded_extensions_list
        self._agent_id = settings.agent_id
        self._process_monitor = process_monitor

    def on_modified(self, event) -> None:
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self._handle("MODIFIED", event.src_path), self._loop
            )

    def on_created(self, event) -> None:
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self._handle("CREATED", event.src_path), self._loop
            )

    def on_deleted(self, event) -> None:
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self._handle("DELETED", event.src_path), self._loop
            )

    async def _handle(self, action: str, path: str) -> None:
        if _should_ignore(path, self._excluded):
            return

        severity = _classify_severity(path)
        current_hash: Optional[str] = None
        hash_mismatch = False
        baseline_hash = "N/A"

        # --- Process Attribution ---
        # Query the ProcessMonitor cache for who wrote to this path.
        # The eBPF vfs_write event fires before inotify, so it's already cached.
        process_ctx = None
        if self._process_monitor and action in ("MODIFIED", "CREATED"):
            process_ctx = await self._process_monitor.get_context(path)
            if process_ctx and process_ctx.is_suspicious_exec and severity < Severity.HIGH:
                severity = Severity.HIGH  # promote: interpreter modifying files = suspicious

        # --- SHA-256 Baseline Check ---
        if action in ("MODIFIED", "CREATED"):
            current_hash = _sha256_file(path)
            if current_hash:
                baseline = await self._db.get_baseline(path)
                if baseline and baseline.sha256 != current_hash:
                    hash_mismatch = True
                    baseline_hash = baseline.sha256
                    if severity < Severity.HIGH:
                        severity = Severity.HIGH

                try:
                    st = os.stat(path)
                    await self._db.upsert_baseline(
                        FileBaselineEntry(
                            path=path,
                            sha256=current_hash,
                            size_bytes=st.st_size,
                            permissions=_file_permissions(path),
                            recorded_at=datetime.now(timezone.utc),
                            last_modified=datetime.fromtimestamp(
                                st.st_mtime, tz=timezone.utc
                            ),
                        )
                    )
                except OSError:
                    pass

        # --- Build Description ---
        description_parts = [f"File {action}: {path}"]
        if hash_mismatch:
            description_parts.append(
                f"SHA-256 changed (was {baseline_hash[:16]}...)"
            )
        if process_ctx:
            description_parts.append(
                f"Modified By: {process_ctx.format_attribution()}"
            )

        description = " | ".join(description_parts)

        # --- Build Metadata ---
        metadata: dict = {
            "file_path":    path,
            "action":       action,
            "sha256":       current_hash,
            "hash_mismatch": hash_mismatch,
            "permissions":  _file_permissions(path) if action != "DELETED" else None,
        }

        if process_ctx:
            metadata.update(process_ctx.to_event_metadata())

        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=EventType.FIM,
            severity=severity,
            source="FileIntegrityMonitor",
            description=description,
            metadata=metadata,
            agent_id=self._agent_id,
        )

        await self._db.insert_event(event)
        await self._bus.publish(event)

        logger.info(
            "fim.event",
            path=path,
            action=action,
            severity=severity.value,
            pid=process_ctx.pid if process_ctx else None,
            process=process_ctx.process_name if process_ctx else None,
            hash_mismatch=hash_mismatch,
        )


# =============================================================================
# File Integrity Monitor Service
# =============================================================================

class FileIntegrityMonitor(IMonitorService):
    def __init__(
        self,
        event_bus: EventBus,
        db: Database,
        process_monitor=None,
    ) -> None:
        self._bus = event_bus
        self._db = db
        self._settings = get_settings()
        self._process_monitor = process_monitor
        self._observer: Optional[Observer] = None
        self._running = False

    async def start_monitoring(self) -> None:
        if self._running:
            return

        loop = asyncio.get_event_loop()
        handler = _FIMHandler(
            self._bus, self._db, loop, self._settings, self._process_monitor
        )
        self._observer = Observer()

        valid_paths = 0
        for path in self._settings.watch_paths_list:
            if not os.path.exists(path):
                logger.warning("fim.path_not_found", path=path)
                continue
            recursive = os.path.isdir(path)
            self._observer.schedule(handler, path=path, recursive=recursive)
            logger.info("fim.watching", path=path, recursive=recursive)
            valid_paths += 1

        if valid_paths == 0:
            raise MonitorError("No valid watch paths found.")

        self._observer.start()
        self._running = True
        logger.info("fim.started", paths=valid_paths)

    async def stop_monitoring(self) -> None:
        if self._observer and self._running:
            self._observer.stop()
            self._observer.join()
            self._running = False
            logger.info("fim.stopped")

    def is_running(self) -> bool:
        return self._running

    async def snapshot_baseline(self) -> int:
        count = 0
        for watch_path in self._settings.watch_paths_list:
            if not os.path.exists(watch_path):
                continue
            paths_to_hash = (
                [watch_path] if os.path.isfile(watch_path)
                else [
                    os.path.join(r, f)
                    for r, _, files in os.walk(watch_path)
                    for f in files
                ]
            )
            for path in paths_to_hash:
                if _should_ignore(path, self._settings.excluded_extensions_list):
                    continue
                sha = _sha256_file(path)
                if not sha:
                    continue
                try:
                    st = os.stat(path)
                    await self._db.upsert_baseline(
                        FileBaselineEntry(
                            path=path,
                            sha256=sha,
                            size_bytes=st.st_size,
                            permissions=_file_permissions(path),
                            recorded_at=datetime.now(timezone.utc),
                            last_modified=datetime.fromtimestamp(
                                st.st_mtime, tz=timezone.utc
                            ),
                        )
                    )
                    count += 1
                except OSError:
                    continue
        logger.info("fim.baseline_snapshot", files_recorded=count)
        return count
