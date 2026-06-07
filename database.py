"""
ZeroCore Agent — Database Layer
Async SQLite persistence for events and mitigation actions.
Replaces the in-memory list that was lost on every restart.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import aiosqlite

from src.core.exceptions import DatabaseError
from src.core.logging import get_logger
from src.core.settings import get_settings
from src.domain.models import (
    ActionStatus,
    ActionType,
    EventType,
    FileBaselineEntry,
    MitigationAction,
    SecurityEvent,
    Severity,
)

logger = get_logger("ZeroCore.Database")

_CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS security_events (
    event_id     TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    severity     TEXT NOT NULL,
    source       TEXT NOT NULL,
    description  TEXT NOT NULL,
    metadata     TEXT NOT NULL DEFAULT '{}',
    remediated   INTEGER NOT NULL DEFAULT 0,
    agent_id     TEXT NOT NULL
);
"""

_CREATE_ACTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS mitigation_actions (
    action_id    TEXT PRIMARY KEY,
    event_id     TEXT,
    timestamp    TEXT NOT NULL,
    target       TEXT NOT NULL,
    action_type  TEXT NOT NULL,
    status       TEXT NOT NULL,
    details      TEXT,
    agent_id     TEXT NOT NULL
);
"""

_CREATE_BASELINE_TABLE = """
CREATE TABLE IF NOT EXISTS file_baseline (
    path          TEXT PRIMARY KEY,
    sha256        TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    permissions   TEXT NOT NULL,
    recorded_at   TEXT NOT NULL,
    last_modified TEXT NOT NULL
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_events_severity  ON security_events(severity);",
    "CREATE INDEX IF NOT EXISTS idx_events_type      ON security_events(event_type);",
    "CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON mitigation_actions(timestamp DESC);",
]


class Database:
    """
    Async SQLite database manager.
    Use as an async context manager or call open()/close() explicitly.
    """

    def __init__(self, db_path: str | None = None) -> None:
        settings = get_settings()
        self._db_path = db_path or settings.db_path
        self._conn: aiosqlite.Connection | None = None

    async def open(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) if os.path.dirname(self._db_path) else ".", exist_ok=True)
        try:
            self._conn = await aiosqlite.connect(self._db_path)
            self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA journal_mode=WAL;")
            await self._conn.execute("PRAGMA foreign_keys=ON;")
            await self._migrate()
            logger.info("database.connected", path=self._db_path)
        except Exception as exc:
            raise DatabaseError(f"Failed to open database at {self._db_path}: {exc}") from exc

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None
            logger.info("database.closed")

    async def __aenter__(self) -> "Database":
        await self.open()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def _migrate(self) -> None:
        assert self._conn is not None
        await self._conn.execute(_CREATE_EVENTS_TABLE)
        await self._conn.execute(_CREATE_ACTIONS_TABLE)
        await self._conn.execute(_CREATE_BASELINE_TABLE)
        for idx in _CREATE_INDEXES:
            await self._conn.execute(idx)
        await self._conn.commit()

    # -------------------------------------------------------------------------
    # Security Events
    # -------------------------------------------------------------------------

    async def insert_event(self, event: SecurityEvent) -> None:
        assert self._conn is not None
        try:
            await self._conn.execute(
                """
                INSERT INTO security_events
                    (event_id, timestamp, event_type, severity, source, description, metadata, remediated, agent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.severity.value,
                    event.source,
                    event.description,
                    json.dumps(event.metadata),
                    int(event.remediated),
                    event.agent_id,
                ),
            )
            await self._conn.commit()
        except Exception as exc:
            raise DatabaseError(f"Failed to insert event {event.event_id}: {exc}") from exc

    async def get_events(
        self,
        page: int = 1,
        page_size: int = 50,
        severity: Optional[Severity] = None,
        event_type: Optional[EventType] = None,
    ) -> Tuple[List[SecurityEvent], int]:
        assert self._conn is not None
        where_clauses = []
        params: list = []

        if severity:
            where_clauses.append("severity = ?")
            params.append(severity.value)
        if event_type:
            where_clauses.append("event_type = ?")
            params.append(event_type.value)

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        offset = (page - 1) * page_size

        count_row = await self._conn.execute(
            f"SELECT COUNT(*) FROM security_events {where_sql}", params
        )
        total = (await count_row.fetchone())[0]

        cursor = await self._conn.execute(
            f"SELECT * FROM security_events {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [page_size, offset],
        )
        rows = await cursor.fetchall()
        events = [_row_to_event(row) for row in rows]
        return events, total

    async def mark_remediated(self, event_id: str) -> None:
        assert self._conn is not None
        await self._conn.execute(
            "UPDATE security_events SET remediated = 1 WHERE event_id = ?", (event_id,)
        )
        await self._conn.commit()

    # -------------------------------------------------------------------------
    # Mitigation Actions
    # -------------------------------------------------------------------------

    async def insert_action(self, action: MitigationAction) -> None:
        assert self._conn is not None
        try:
            await self._conn.execute(
                """
                INSERT INTO mitigation_actions
                    (action_id, event_id, timestamp, target, action_type, status, details, agent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.action_id,
                    action.event_id,
                    action.timestamp.isoformat(),
                    action.target,
                    action.action_type.value,
                    action.status.value,
                    action.details,
                    action.agent_id,
                ),
            )
            await self._conn.commit()
        except Exception as exc:
            raise DatabaseError(f"Failed to insert action {action.action_id}: {exc}") from exc

    async def get_actions(
        self, page: int = 1, page_size: int = 50
    ) -> Tuple[List[MitigationAction], int]:
        assert self._conn is not None
        offset = (page - 1) * page_size
        count_row = await self._conn.execute("SELECT COUNT(*) FROM mitigation_actions")
        total = (await count_row.fetchone())[0]
        cursor = await self._conn.execute(
            "SELECT * FROM mitigation_actions ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (page_size, offset),
        )
        rows = await cursor.fetchall()
        actions = [_row_to_action(row) for row in rows]
        return actions, total

    # -------------------------------------------------------------------------
    # File Baseline
    # -------------------------------------------------------------------------

    async def upsert_baseline(self, entry: FileBaselineEntry) -> None:
        assert self._conn is not None
        await self._conn.execute(
            """
            INSERT INTO file_baseline (path, sha256, size_bytes, permissions, recorded_at, last_modified)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                sha256        = excluded.sha256,
                size_bytes    = excluded.size_bytes,
                permissions   = excluded.permissions,
                recorded_at   = excluded.recorded_at,
                last_modified = excluded.last_modified
            """,
            (
                entry.path,
                entry.sha256,
                entry.size_bytes,
                entry.permissions,
                entry.recorded_at.isoformat(),
                entry.last_modified.isoformat(),
            ),
        )
        await self._conn.commit()

    async def get_baseline(self, path: str) -> Optional[FileBaselineEntry]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM file_baseline WHERE path = ?", (path,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return FileBaselineEntry(
            path=row["path"],
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            permissions=row["permissions"],
            recorded_at=datetime.fromisoformat(row["recorded_at"]),
            last_modified=datetime.fromisoformat(row["last_modified"]),
        )

    async def get_all_baselines(self) -> List[FileBaselineEntry]:
        assert self._conn is not None
        cursor = await self._conn.execute("SELECT * FROM file_baseline")
        rows = await cursor.fetchall()
        return [
            FileBaselineEntry(
                path=r["path"],
                sha256=r["sha256"],
                size_bytes=r["size_bytes"],
                permissions=r["permissions"],
                recorded_at=datetime.fromisoformat(r["recorded_at"]),
                last_modified=datetime.fromisoformat(r["last_modified"]),
            )
            for r in rows
        ]


# =============================================================================
# Row Mappers
# =============================================================================

def _row_to_event(row: aiosqlite.Row) -> SecurityEvent:
    return SecurityEvent(
        event_id=row["event_id"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        event_type=EventType(row["event_type"]),
        severity=Severity(row["severity"]),
        source=row["source"],
        description=row["description"],
        metadata=json.loads(row["metadata"]),
        remediated=bool(row["remediated"]),
        agent_id=row["agent_id"],
    )


def _row_to_action(row: aiosqlite.Row) -> MitigationAction:
    return MitigationAction(
        action_id=row["action_id"],
        event_id=row["event_id"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        target=row["target"],
        action_type=ActionType(row["action_type"]),
        status=ActionStatus(row["status"]),
        details=row["details"],
        agent_id=row["agent_id"],
    )
