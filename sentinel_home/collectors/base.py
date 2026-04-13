"""Abstract base class for all collectors."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class CollectorStats:
    running: bool = False
    last_event: datetime | None = None
    events_per_min: float = 0.0
    errors: int = 0
    total_events: int = 0


class BaseCollector(ABC):
    """Base class all collectors must implement."""

    name: str = "base"

    def __init__(self):
        self.stats = CollectorStats()
        self._task: asyncio.Task | None = None

    @abstractmethod
    async def start(self) -> None:
        """Start the collector (long-running coroutine or background task)."""

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully stop the collector."""

    def get_stats(self) -> dict:
        return {
            "running": self.stats.running,
            "last_event": self.stats.last_event.isoformat() if self.stats.last_event else None,
            "events_per_min": round(self.stats.events_per_min, 2),
            "errors": self.stats.errors,
        }

    def _record_event(self) -> None:
        self.stats.last_event = datetime.now(timezone.utc)
        self.stats.total_events += 1

    def _record_error(self, exc: Exception) -> None:
        self.stats.errors += 1
        logger.error("[%s] Error: %s", self.name, exc, exc_info=True)
