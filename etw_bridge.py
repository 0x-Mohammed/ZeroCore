"""
ZeroCore Agent — Windows ETW Bridge
Spawns the compiled Go ETW consumer binary as a subprocess.
Reads newline-delimited JSON from its stdout pipe.
Identical interface to eBPFBridge — unified_bridge.py selects
the correct one at runtime based on platform.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import threading
from pathlib import Path
from typing import Callable, Awaitable

from src.core.logging import get_logger
from src.domain.process_models import ProcessContext, ProcessEventType

logger = get_logger("ZeroCore.ETWBridge")

_DEFAULT_ETW_BINARY = Path(__file__).parent.parent / "ebpf" / "windows" / "zerocore-etw.exe"

AsyncHandler = Callable[[ProcessContext], Awaitable[None]]


class ETWBridge:
    """
    Manages lifecycle of the Go ETW consumer subprocess (Windows only).
    Identical public interface to eBPFBridge for transparent substitution.
    """

    def __init__(
        self,
        etw_binary: Path | None = None,
    ) -> None:
        self._binary = Path(etw_binary or _DEFAULT_ETW_BINARY)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._handlers: list[AsyncHandler] = []

    def register_handler(self, handler: AsyncHandler) -> None:
        self._handlers.append(handler)

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

        if not self._binary.exists():
            logger.error(
                "etw_bridge.binary_not_found",
                path=str(self._binary),
                hint="Build with: cd ebpf/windows && go build -o zerocore-etw.exe .",
            )
            return

        try:
            self._proc = subprocess.Popen(
                [str(self._binary)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            logger.error("etw_bridge.launch_failed", error=str(exc))
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._reader_loop,
            daemon=True,
            name="etw-bridge-reader",
        )
        self._thread.start()
        logger.info("etw_bridge.started", pid=self._proc.pid)

    def stop(self) -> None:
        self._running = False
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("etw_bridge.stopped")

    def is_running(self) -> bool:
        return self._running and self._proc is not None and self._proc.poll() is None

    def _reader_loop(self) -> None:
        assert self._proc is not None
        assert self._proc.stdout is not None

        for line in self._proc.stdout:
            if not self._running:
                break
            line = line.strip()
            if not line:
                continue
            ctx = self._parse_line(line)
            if ctx is None:
                continue
            for handler in self._handlers:
                asyncio.run_coroutine_threadsafe(handler(ctx), self._loop)

    def _parse_line(self, line: str) -> ProcessContext | None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        try:
            event_type = _map_event_type(data.get("event_type", ""))
            if event_type is None:
                return None

            return ProcessContext(
                pid=int(data.get("pid", 0)),
                ppid=int(data.get("ppid", 0)),
                uid=0,   # Windows: no UID concept — resolved separately
                gid=0,
                process_name=data.get("process", ""),
                file_path=data.get("file_path", ""),
                command_line=data.get("args", ""),
                event_type=event_type,
                source=data.get("source", "etw"),
                raw_timestamp=data.get("timestamp", ""),
                extra={
                    "user": data.get("user", ""),
                    "hashes": data.get("hashes", ""),
                    "dest_ip": data.get("dest_ip", ""),
                    "dest_port": data.get("dest_port", ""),
                },
            )
        except (KeyError, ValueError, TypeError) as exc:
            logger.debug("etw_bridge.model_error", error=str(exc))
            return None


def _map_event_type(raw: str) -> ProcessEventType | None:
    mapping = {
        "vfs_write":       ProcessEventType.FILE_WRITE,
        "execve":          ProcessEventType.PROCESS_EXEC,
        "file_create":     ProcessEventType.FILE_CREATE,
        "file_delete":     ProcessEventType.FILE_DELETE,
        "file_rename":     ProcessEventType.FILE_RENAME,
        "network_connect": ProcessEventType.NETWORK_CONNECT,
    }
    return mapping.get(raw)
