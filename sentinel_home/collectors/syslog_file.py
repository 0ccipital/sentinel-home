"""Generic syslog file tailer — watches a directory for syslog-*.log files.

Replaces both UniFiSyslogCollector and SyslogCollector with a single
generic collector that auto-detects content via the parser chain.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path

from sentinel_home.collectors.base import BaseCollector
from sentinel_home.collectors.syslog_base import (
    process_result, should_pre_filter, update_device_type, upsert_wifi_device,
)
from sentinel_home.config import get_settings
from sentinel_home.parsers import parse_line

logger = logging.getLogger(__name__)

_SYSLOG_FILE_RE = re.compile(r"syslog-(?P<ip>[\d.]+)\.log$")

# WiFi events that carry enough data to create/update a Device
_WIFI_UPSERT_EVENTS = {"sta_assoc", "sta_join", "sta_ip_assign", "sta_roam"}


class SyslogFileCollector(BaseCollector):
    """Tail all syslog-*.log files in a directory through the parser chain."""

    name = "syslog_file"

    def __init__(self):
        super().__init__()
        self._stop_event = asyncio.Event()
        self._file_positions: dict[str, int] = {}
        self._device_event_counts: dict[str, int] = {}

    async def start(self) -> None:
        self.stats.running = True
        logger.info("Syslog file collector starting")
        self._task = asyncio.create_task(self._watch_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                pass
        self.stats.running = False
        logger.info("Syslog file collector stopped")

    def get_stats(self) -> dict:
        base = super().get_stats()
        base["device_event_counts"] = dict(self._device_event_counts)
        base["watched_files"] = len(self._file_positions)
        return base

    async def _watch_loop(self) -> None:
        settings = get_settings()
        syslog_dir = Path(settings.syslog.file_dir)
        poll_interval = settings.syslog.poll_interval_seconds

        if not syslog_dir.exists():
            logger.warning("Syslog dir %s not found — collector idle", syslog_dir)
            await self._stop_event.wait()
            return

        self._discover_files(syslog_dir)

        while not self._stop_event.is_set():
            self._discover_files(syslog_dir)

            for fpath_str, pos in list(self._file_positions.items()):
                try:
                    fpath = Path(fpath_str)
                    if not fpath.exists():
                        continue

                    current_size = fpath.stat().st_size

                    if current_size < pos:
                        logger.info("Log file %s rotated", fpath.name)
                        pos = 0

                    if current_size <= pos:
                        continue

                    # Cap read to 1 MB
                    max_read = 1024 * 1024
                    read_from = max(pos, current_size - max_read) if (current_size - pos) > max_read else pos
                    if read_from > pos:
                        logger.warning("Syslog %s grew %d bytes — skipping to last 1MB",
                                       fpath.name, current_size - pos)

                    with fpath.open(errors="replace") as f:
                        f.seek(read_from)
                        new_data = f.read()
                    self._file_positions[fpath_str] = current_size

                    m = _SYSLOG_FILE_RE.search(fpath.name)
                    source_ip = m.group("ip") if m else None

                    for line in new_data.splitlines():
                        line = line.strip()
                        if line:
                            await self._process_line(line, source_ip)

                except Exception as exc:
                    self._record_error(exc)

            await asyncio.sleep(poll_interval)

    def _discover_files(self, syslog_dir: Path) -> None:
        for fpath in syslog_dir.glob("syslog-*.log"):
            key = str(fpath)
            if key not in self._file_positions:
                self._file_positions[key] = fpath.stat().st_size
                logger.info("Watching syslog file: %s (%d bytes)", fpath.name, self._file_positions[key])

    async def _process_line(self, line: str, source_ip: str | None) -> None:
        if should_pre_filter(line):
            return

        header, result = parse_line(line)
        if result is None:
            return

        self._record_event()
        if source_ip:
            self._device_event_counts[source_ip] = self._device_event_counts.get(source_ip, 0) + 1

        # Run sync DB operations off the event loop to avoid blocking
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, process_result, result, self.name, source_ip)

        if result.device_type_hint and source_ip:
            await loop.run_in_executor(None, update_device_type, source_ip, result.device_type_hint)

        mac = result.fields.get("mac")
        if mac and result.event_type in _WIFI_UPSERT_EVENTS:
            await loop.run_in_executor(None, upsert_wifi_device, mac, result.fields)
