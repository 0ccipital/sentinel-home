"""GET /api/v1/status, /config, /collectors"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from sentinel_home.api.envelope import ok_envelope
from sentinel_home.config import get_settings

router = APIRouter()


@router.get("/status")
async def get_status():
    from sentinel_home.database import session_scope
    from sentinel_home.models import Job
    from sentinel_home.main import _collectors

    queue_depth = 0
    try:
        with session_scope() as session:
            queue_depth = session.query(Job).filter(Job.status == "pending").count()
    except Exception:
        pass

    collector_stats = {}
    for c in _collectors:
        collector_stats[c.name] = c.get_stats()

    # Agent status
    agent_status = None
    try:
        from sentinel_home.agent.scheduler import get_agent_status
        agent_status = get_agent_status()
    except Exception:
        pass

    return ok_envelope({
        "system": "SentinelHome",
        "version": "1.0.0-dev",
        "uptime_seconds": _uptime_seconds(),
        "db_ok": True,
        "collectors": collector_stats,
        "queue_depth": queue_depth,
        "agent": agent_status,
    })


@router.get("/config")
async def get_config():
    """Return config with secrets redacted."""
    settings = get_settings()
    cfg = settings.model_dump()
    cfg.get("agent", {}).pop("api_key", None)
    cfg.get("pihole", {}).pop("password", None)
    cfg.get("plex", {}).pop("token", None)
    cfg.get("server", {}).pop("api_key", None)
    return ok_envelope(cfg)


@router.get("/collectors")
async def get_collectors():
    from sentinel_home.main import _collectors

    if not _collectors:
        return ok_envelope({"message": "No collectors running (dev mode or startup pending)"})

    result = {}
    for c in _collectors:
        result[c.name] = c.get_stats()
    return ok_envelope(result)


_start_time = datetime.now(timezone.utc)


def _uptime_seconds() -> float:
    return (datetime.now(timezone.utc) - _start_time).total_seconds()
