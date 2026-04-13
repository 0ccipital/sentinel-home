"""UDP syslog server — receives syslog over the network on port 514.

Any router/AP/switch can point its syslog at the Sentinel container IP:514.
Lines are fed through the parser chain identically to file-based syslog.
"""

from __future__ import annotations

import asyncio
import logging

from sentinel_home.collectors.base import BaseCollector
from sentinel_home.collectors.syslog_base import (
    process_result, should_pre_filter, update_device_type, upsert_wifi_device,
)
from sentinel_home.config import get_settings
from sentinel_home.parsers import parse_line

logger = logging.getLogger(__name__)

_WIFI_UPSERT_EVENTS = {"sta_assoc", "sta_join", "sta_ip_assign", "sta_roam"}


class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol that queues received syslog lines."""

    def __init__(self, queue: asyncio.Queue):
        self._queue = queue
        self._drop_count = 0

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            text = data.decode("utf-8", errors="replace")
            source_ip = addr[0]
            for line in text.splitlines():
                line = line.strip()
                if line:
                    self._queue.put_nowait((line, source_ip))
        except asyncio.QueueFull:
            self._drop_count += 1
            if self._drop_count % 100 == 1:
                logger.warning(
                    "Syslog queue full — dropped %d messages (queue size %d)",
                    self._drop_count, self._queue.maxsize,
                )
        except Exception as exc:
            logger.debug("Syslog datagram processing error: %s", exc)

    def error_received(self, exc: Exception) -> None:
        logger.debug("Syslog UDP error: %s", exc)


class SyslogServerCollector(BaseCollector):
    """UDP syslog listener that feeds lines through the parser chain."""

    name = "syslog_server"

    def __init__(self):
        super().__init__()
        self._stop_event = asyncio.Event()
        self._transport = None
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
        self._source_counts: dict[str, int] = {}

    async def start(self) -> None:
        self.stats.running = True
        settings = get_settings()
        port = settings.syslog.udp_port

        loop = asyncio.get_running_loop()
        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: _SyslogProtocol(self._queue),
                local_addr=("0.0.0.0", port),
            )
            logger.info("Syslog UDP server listening on port %d", port)
        except OSError as exc:
            logger.warning("Could not bind UDP port %d: %s — syslog server disabled", port, exc)
            self.stats.running = False
            return

        self._task = asyncio.create_task(self._process_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._transport:
            self._transport.close()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                pass
        self.stats.running = False
        logger.info("Syslog UDP server stopped")

    def get_stats(self) -> dict:
        base = super().get_stats()
        base["source_counts"] = dict(self._source_counts)
        base["queue_depth"] = self._queue.qsize()
        return base

    async def _process_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                line, source_ip = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue

            try:
                await self._process_line(line, source_ip)
            except Exception as exc:
                self._record_error(exc)

    async def _process_line(self, line: str, source_ip: str) -> None:
        if should_pre_filter(line):
            return

        header, result = parse_line(line)
        if result is None:
            return

        self._record_event()
        self._source_counts[source_ip] = self._source_counts.get(source_ip, 0) + 1

        # Run sync DB operations off the event loop to avoid blocking
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, process_result, result, self.name, source_ip)

        if result.device_type_hint and source_ip:
            await loop.run_in_executor(None, update_device_type, source_ip, result.device_type_hint)

        mac = result.fields.get("mac")
        if mac and result.event_type in _WIFI_UPSERT_EVENTS:
            await loop.run_in_executor(None, upsert_wifi_device, mac, result.fields)
