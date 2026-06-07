"""
ZeroCore Agent — Async Event Bus
Fully async pub/sub dispatcher. Callbacks are coroutines gathered concurrently.
All exceptions in subscribers are caught, logged, and isolated — one failing
subscriber never blocks others.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Dict, List

from src.core.logging import get_logger
from src.domain.models import SecurityEvent

logger = get_logger("ZeroCore.EventBus")

AsyncCallback = Callable[[SecurityEvent], Awaitable[None]]


class EventBus:
    """
    Async publish/subscribe event dispatcher.

    Usage:
        bus = EventBus()
        bus.subscribe("FIM", my_async_handler)
        await bus.publish(event)
    """

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[AsyncCallback]] = {}

    def subscribe(self, event_type: str, callback: AsyncCallback) -> None:
        """Register an async callback for a given event type."""
        self._subscribers.setdefault(event_type, []).append(callback)
        logger.debug("eventbus.subscribed", event_type=event_type, callback=callback.__name__)

    def unsubscribe(self, event_type: str, callback: AsyncCallback) -> None:
        """Remove a previously registered callback."""
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                cb for cb in self._subscribers[event_type] if cb is not callback
            ]

    async def publish(self, event: SecurityEvent) -> None:
        """
        Publish an event to all subscribers concurrently.
        Exceptions in individual subscribers are logged but do not propagate.
        """
        logger.info(
            "eventbus.publish",
            event_id=event.event_id,
            event_type=event.event_type.value,
            severity=event.severity.value,
            source=event.source,
        )

        handlers = self._subscribers.get(event.event_type.value, [])
        if not handlers:
            return

        results = await asyncio.gather(
            *[handler(event) for handler in handlers],
            return_exceptions=True,
        )

        for handler, result in zip(handlers, results):
            if isinstance(result, Exception):
                logger.error(
                    "eventbus.handler_failed",
                    handler=handler.__name__,
                    event_id=event.event_id,
                    error=str(result),
                )
