"""Changelog endpoint — what changed since the agent's last check.

GET /api/v1/changelog?since=<ISO timestamp>

Returns a digest of everything that happened, designed as the actor's
starting point each cycle. Compact, structured, easy for the orchestrator
to iterate over without the LLM needing to understand the API.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from sqlalchemy import func

from sentinel_home.api.envelope import ok_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import (
    Alert, Device, Event, EventRollup, Finding, Job, Rule, RuleMetricWindow,
)

router = APIRouter()


def _parse_since(since: str | None) -> datetime:
    """Parse ISO timestamp or default to 1 hour ago."""
    if since:
        try:
            dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc) - timedelta(hours=1)


@router.get("/changelog")
async def get_changelog(since: str | None = Query(None)):
    """What changed since the given timestamp. Agent's primary entry point."""
    cutoff = _parse_since(since)

    with session_scope() as session:
        # New devices since cutoff
        new_devices = session.query(Device).filter(Device.first_seen >= cutoff).all()
        device_list = [
            {"mac": d.mac, "ip": d.ip, "vendor": d.vendor,
             "device_type": d.device_type, "first_seen": d.first_seen.isoformat() if d.first_seen else None}
            for d in new_devices
        ]

        # Events by category — counts + sample of notable ones
        event_counts = (
            session.query(Event.category, Event.event_type, func.count(Event.id))
            .filter(Event.ts >= cutoff)
            .group_by(Event.category, Event.event_type)
            .all()
        )
        event_summary = {}
        for cat, etype, cnt in event_counts:
            key = f"{cat}/{etype}"
            event_summary[key] = cnt

        # Notable events (high/critical severity)
        notable_events = (
            session.query(Event)
            .filter(Event.ts >= cutoff, Event.severity.in_(["high", "critical"]))
            .order_by(Event.ts.desc())
            .limit(20)
            .all()
        )
        notable_list = [
            {"id": e.id, "ts": e.ts.isoformat() if e.ts else None,
             "event_type": e.event_type, "severity": e.severity,
             "device_id": e.device_id, "message": (e.message or "")[:200]}
            for e in notable_events
        ]

        # Rules that fired
        fired_rules = (
            session.query(Rule)
            .filter(Rule.last_fired >= cutoff)
            .all()
        )
        rule_fires = [
            {"id": r.id, "name": r.name, "fire_count": r.fire_count,
             "severity": r.severity, "last_fired": r.last_fired.isoformat() if r.last_fired else None}
            for r in fired_rules
        ]

        # New alerts
        new_alerts = (
            session.query(Alert)
            .filter(Alert.ts >= cutoff)
            .order_by(Alert.ts.desc())
            .all()
        )
        alert_list = [
            {"id": a.id, "ts": a.ts.isoformat() if a.ts else None,
             "rule_name": a.rule_name, "severity": a.severity,
             "device_id": a.device_id, "message": (a.message or "")[:200],
             "sent": a.sent}
            for a in new_alerts
        ]

        # New findings
        new_findings = (
            session.query(Finding)
            .filter(Finding.ts >= cutoff)
            .order_by(Finding.ts.desc())
            .all()
        )
        finding_list = [
            {"id": f.id, "severity": f.severity, "summary": (f.summary or "")[:200],
             "source": f.source, "device_id": f.device_id}
            for f in new_findings
        ]

        # Queue depth
        pending_jobs = session.query(Job).filter(Job.status == "pending").count()
        user_flagged = session.query(Job).filter(
            Job.status == "pending", Job.source == "user"
        ).count()

        # WAN block summary from rollups
        wan_rollups = (
            session.query(func.coalesce(func.sum(EventRollup.count), 0))
            .filter(EventRollup.hour >= cutoff, EventRollup.event_type == "fw_wan_block")
            .scalar()
        ) or 0

    return ok_envelope({
        "since": cutoff.isoformat(),
        "now": datetime.now(timezone.utc).isoformat(),
        "new_devices": device_list,
        "new_device_count": len(device_list),
        "event_summary": event_summary,
        "notable_events": notable_list,
        "rule_fires": rule_fires,
        "alerts": alert_list,
        "alert_count": len(alert_list),
        "findings": finding_list,
        "queue_depth": pending_jobs,
        "user_flagged_jobs": user_flagged,
        "wan_blocks": wan_rollups,
    })
