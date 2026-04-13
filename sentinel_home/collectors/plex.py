"""Plex Media Server collector — monitors active sessions and remote access.

Plex runs on the local server at {plex.host}:{plex.port} (host network mode).
Uses the local Plex API — no Plex account token needed for LAN access
if "Secure connections" is set to "Preferred" (default).

This collector detects:
  - Unexpected remote streaming sessions (non-LAN IPs)
  - New devices accessing the Plex server
  - Server going offline / becoming unreachable
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from sentinel_home.collectors.base import BaseCollector
from sentinel_home.config import get_settings
from sentinel_home.database import session_scope
from sentinel_home.models import Event

logger = logging.getLogger(__name__)


class PlexCollector(BaseCollector):
    name = "plex"

    def __init__(self):
        super().__init__()
        self._stop_event = asyncio.Event()
        self._known_players: set[str] = set()  # Track known player IDs
        self._alerted_remote_sessions: set[str] = set()  # Session keys already alerted
        self._was_reachable: bool | None = None

    async def start(self) -> None:
        self.stats.running = True
        logger.info("Plex collector starting")
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                pass
        self.stats.running = False
        logger.info("Plex collector stopped")

    async def _poll_loop(self) -> None:
        settings = get_settings()
        host = settings.plex.host
        port = settings.plex.port
        token = settings.plex.token
        interval = settings.plex.poll_interval_seconds

        if not host:
            logger.warning("Plex host not configured — collector idle")
            await self._stop_event.wait()
            return

        base = f"http://{host}:{port}"
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Plex-Token"] = token

        logger.info("Plex collector polling %s every %ds", base, interval)

        while not self._stop_event.is_set():
            try:
                await self._poll(base, headers)
            except Exception as exc:
                self._record_error(exc)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
                break  # Stop event was set
            except asyncio.TimeoutError:
                pass  # Normal — sleep completed, run next poll

    async def _poll(self, base: str, headers: dict) -> None:
        settings = get_settings()
        lan_prefix = settings.network.lan_cidr.rsplit(".", 1)[0]  # e.g. "192.168.1"

        async with httpx.AsyncClient(timeout=10) as client:
            # Check server reachability
            try:
                resp = await client.get(f"{base}/identity", headers=headers)
                is_reachable = resp.status_code == 200
            except Exception:
                is_reachable = False

            # Detect state change
            if self._was_reachable is not None and self._was_reachable and not is_reachable:
                logger.warning("Plex server became unreachable")
                self._persist_event("plex_offline", "warning", "Plex server unreachable", {})
            elif self._was_reachable is not None and not self._was_reachable and is_reachable:
                logger.info("Plex server back online")
                self._persist_event("plex_online", "info", "Plex server back online", {})
            self._was_reachable = is_reachable

            if not is_reachable:
                return

            self._record_event()

            # Active sessions
            try:
                resp = await client.get(f"{base}/status/sessions", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    media_container = data.get("MediaContainer", {})
                    sessions = media_container.get("Metadata", [])
                    size = media_container.get("size", 0)

                    # Track active remote session keys so we can clear stale alerts
                    current_remote_keys: set[str] = set()

                    for session in sessions:
                        player = session.get("Player", {})
                        player_address = player.get("address", "")
                        player_title = player.get("title", "unknown")
                        player_id = player.get("machineIdentifier", "")
                        session_key = session.get("sessionKey", player_id or player_address)
                        user = session.get("User", {}).get("title", "unknown")
                        media_title = session.get("title", "unknown")

                        # Detect remote (non-LAN) sessions
                        is_local = player_address.startswith(lan_prefix) or player_address.startswith("127.")
                        if not is_local and player_address:
                            current_remote_keys.add(session_key)
                            # Only alert once per session
                            if session_key not in self._alerted_remote_sessions:
                                self._alerted_remote_sessions.add(session_key)
                                logger.warning("Remote Plex session: %s from %s (%s) watching '%s'",
                                             user, player_address, player_title, media_title)
                                self._persist_event("plex_remote_session", "warning",
                                    f"Remote stream: {user} from {player_address} ({player_title}) watching '{media_title}'",
                                    {"user": user, "address": player_address, "player": player_title, "media": media_title})

                        # Detect new player devices
                        if player_id and player_id not in self._known_players:
                            self._known_players.add(player_id)
                            logger.info("New Plex player: %s (%s) from %s",
                                       player_title, player_id[:8], player_address)
                            self._persist_event("plex_new_player", "info",
                                f"New Plex player: {player_title} ({player_address})",
                                {"player": player_title, "player_id": player_id, "address": player_address, "user": user})

                    # Clear ended remote sessions so they can re-alert if they come back
                    self._alerted_remote_sessions -= (self._alerted_remote_sessions - current_remote_keys)

                    if size > 0:
                        self._persist_event("plex_sessions", "info",
                            f"Plex: {size} active session(s)",
                            {"session_count": size})

            except Exception as exc:
                self._record_error(exc)

    def _persist_event(self, event_type: str, severity: str, message: str, raw: dict) -> None:
        try:
            with session_scope() as session:
                session.add(Event(
                    source="plex",
                    event_type=event_type,
                    severity=severity,
                    message=message,
                    raw=raw,
                ))
        except Exception as exc:
            logger.error("Failed to persist Plex event: %s", exc)

    def get_stats(self) -> dict:
        base = super().get_stats()
        base["reachable"] = self._was_reachable
        base["known_players"] = len(self._known_players)
        return base
