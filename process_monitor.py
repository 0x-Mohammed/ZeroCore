"""
ZeroCore Agent — Process Monitor
Receives ProcessContext events from the kernel bridge (eBPF / ETW).
Maintains a short-lived correlation cache: file_path -> ProcessContext.
When FIM detects a file change, it queries this cache to get full
process attribution — answering WHO and HOW, not just WHAT.

This closes the detection chain:
    eBPF vfs_write -> ProcessContext -> FIM event enrichment -> SecurityEvent
    with metadata:
        process_attribution.pid          = 4122
        process_attribution.process_name = "python3"
        process_attribution.command_line = "python3 exploit.py"
        process_attribution.is_root      = true
        process_attribution.is_suspicious_exec = true
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.core.logging import get_logger
from src.core.settings import get_settings
from src.domain.process_models import ProcessContext, ProcessEventType

logger = get_logger("ZeroCore.ProcessMonitor")

# Maximum number of path->context entries in the correlation cache
_CACHE_MAX_SIZE = 4096

# How long a cached entry remains valid (seconds)
# vfs_write and inotify fire within microseconds of each other
_CACHE_TTL_SECONDS = 5


class _CacheEntry:
    __slots__ = ("ctx", "expires_at")

    def __init__(self, ctx: ProcessContext) -> None:
        self.ctx = ctx
        self.expires_at = datetime.now(timezone.utc) + timedelta(seconds=_CACHE_TTL_SECONDS)

    def is_valid(self) -> bool:
        return datetime.now(timezone.utc) < self.expires_at


class ProcessMonitor:
    """
    Subscribes to ProcessContext events from the unified bridge.
    Stores them in a TTL correlation cache keyed by file_path.

    FIM service calls get_context(file_path) to enrich its SecurityEvents.
    """

    def __init__(self) -> None:
        # OrderedDict used as an LRU cache (evict oldest on overflow)
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._stats = {"received": 0, "cache_hits": 0, "cache_misses": 0}

    async def handle_process_event(self, ctx: ProcessContext) -> None:
        """
        Async handler registered with UnifiedBridge.
        Called for every kernel-level file/exec event.
        """
        self._stats["received"] += 1

        # We only cache file-write events for FIM correlation.
        # Exec events are stored separately for process launch tracking.
        if ctx.event_type not in (
            ProcessEventType.FILE_WRITE,
            ProcessEventType.FILE_CREATE,
            ProcessEventType.FILE_DELETE,
            ProcessEventType.FILE_RENAME,
        ):
            return

        if not ctx.file_path:
            return

        async with self._lock:
            # Evict oldest entry if at capacity
            if len(self._cache) >= _CACHE_MAX_SIZE:
                self._cache.popitem(last=False)

            self._cache[ctx.file_path] = _CacheEntry(ctx)
            self._cache.move_to_end(ctx.file_path)

        logger.debug(
            "process_monitor.cached",
            path=ctx.file_path,
            pid=ctx.pid,
            process=ctx.process_name,
            uid=ctx.uid,
        )

    async def get_context(self, file_path: str) -> Optional[ProcessContext]:
        """
        Query the correlation cache for the most recent process that
        wrote to file_path. Returns None if no recent match exists.

        Called by FIM service immediately after detecting a file change.
        The eBPF event and inotify event are typically < 1ms apart.
        """
        async with self._lock:
            entry = self._cache.get(file_path)

        if entry is None:
            self._stats["cache_misses"] += 1
            return None

        if not entry.is_valid():
            async with self._lock:
                self._cache.pop(file_path, None)
            self._stats["cache_misses"] += 1
            return None

        self._stats["cache_hits"] += 1
        return entry.ctx

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "cache_size": len(self._cache),
            "cache_ttl_seconds": _CACHE_TTL_SECONDS,
        }

    async def purge_expired(self) -> int:
        """Remove all expired entries. Called periodically by a background task."""
        async with self._lock:
            expired = [k for k, v in self._cache.items() if not v.is_valid()]
            for k in expired:
                del self._cache[k]
        return len(expired)
