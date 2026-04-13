"""Thread-safe in-memory counters for high-volume events.

WAN firewall blocks are the biggest event volume on any home network.
Instead of writing each one to the events table, they're counted in
memory and flushed to EventRollup hourly.

The rule engine still sees every event for real-time pattern detection
(port scans, targeted attacks), but storage is aggregated.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CounterBucket:
    """Aggregated stats for one (source, category, event_type) in one hour."""

    count: int = 0
    unique_sources: set = field(default_factory=set)  # unique src IPs
    unique_destinations: set = field(default_factory=set)  # unique dst IPs
    top_ports: dict = field(default_factory=lambda: defaultdict(int))  # port -> count
    top_sources: dict = field(default_factory=lambda: defaultdict(int))  # src IP -> count
    first_seen: float = 0.0
    last_seen: float = 0.0

    def record(self, fields: dict) -> None:
        now = time.time()
        self.count += 1
        if not self.first_seen:
            self.first_seen = now
        self.last_seen = now

        src = fields.get("src", "")
        dst = fields.get("dst", "")
        dpt = fields.get("dpt", "")

        if src:
            self.unique_sources.add(src)
            self.top_sources[src] += 1
        if dst:
            self.unique_destinations.add(dst)
        if dpt:
            self.top_ports[str(dpt)] += 1

        # Cap set sizes to prevent unbounded growth.
        # Trim by keeping only the sources/destinations with the highest counts
        # so the most significant IPs are retained rather than a random slice.
        if len(self.unique_sources) > 5000:
            top_2500 = {s for s, _ in sorted(
                self.top_sources.items(), key=lambda x: x[1], reverse=True
            )[:2500]}
            self.unique_sources &= top_2500
        if len(self.unique_destinations) > 1000:
            self.unique_destinations = set(list(self.unique_destinations)[:500])

    def to_metadata(self) -> dict:
        """Serialize to JSON-safe metadata for EventRollup."""
        sorted_ports = sorted(self.top_ports.items(), key=lambda x: x[1], reverse=True)[:20]
        sorted_sources = sorted(self.top_sources.items(), key=lambda x: x[1], reverse=True)[:50]
        return {
            "unique_source_count": len(self.unique_sources),
            "unique_dest_count": len(self.unique_destinations),
            "top_ports": dict(sorted_ports),
            "top_sources": dict(sorted_sources),
            "sample_sources": list(self.unique_sources)[:10],  # kept for compat
        }


class EventCounters:
    """Thread-safe in-memory event counters, keyed by (source, category, event_type)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str, str], CounterBucket] = {}

    def record(self, source: str, category: str, event_type: str, fields: dict) -> None:
        """Increment counter for this event type."""
        key = (source, category, event_type)
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = CounterBucket()
            self._buckets[key].record(fields)

    def flush(self) -> dict[tuple[str, str, str], CounterBucket]:
        """Return all buckets and reset. Called by the hourly rollup job."""
        with self._lock:
            buckets = self._buckets
            self._buckets = {}
        return buckets

    def get_snapshot(self) -> dict:
        """Return current counts without flushing (for /api/v1/status)."""
        with self._lock:
            return {
                f"{s}/{c}/{t}": b.count
                for (s, c, t), b in self._buckets.items()
            }

    def get_detailed_snapshot(self) -> dict:
        """Return full bucket info including unique_sources and top_ports."""
        with self._lock:
            return {
                f"{s}/{c}/{t}": {
                    "count": b.count,
                    "unique_sources": list(b.unique_sources),
                    "top_ports": dict(b.top_ports),
                }
                for (s, c, t), b in self._buckets.items()
            }


# Module-level singleton
_counters: EventCounters | None = None


def get_counters() -> EventCounters:
    global _counters
    if _counters is None:
        _counters = EventCounters()
    return _counters
