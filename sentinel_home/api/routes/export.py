"""Export endpoints — CSV/JSON download for devices, events, alerts, rules.

GET /api/v1/export/devices?format=csv|json
GET /api/v1/export/events?format=csv|json&hours=24
GET /api/v1/export/alerts?format=csv|json&hours=168
GET /api/v1/export/rules?format=csv|json
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse, JSONResponse

from sentinel_home.database import session_scope
from sentinel_home.models import Alert, Device, Event, Rule

router = APIRouter()


def _csv_response(rows: list[dict], filename: str) -> StreamingResponse:
    """Convert a list of dicts to a CSV streaming response."""
    if not rows:
        return StreamingResponse(
            io.StringIO("No data\n"),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/devices")
async def export_devices(format: str = Query("csv", pattern="^(csv|json)$")):
    with session_scope() as session:
        devices = session.query(Device).order_by(Device.last_seen.desc()).all()
        rows = [
            {
                "mac": d.mac, "ip": d.ip, "vendor": d.vendor,
                "device_type": d.device_type, "label": d.label,
                "os_family": d.os_family, "connection_type": d.connection_type,
                "ap": d.ap, "network_role": d.network_role,
                "first_seen": d.first_seen.isoformat() if d.first_seen else "",
                "last_seen": d.last_seen.isoformat() if d.last_seen else "",
            }
            for d in devices
        ]

    if format == "json":
        return JSONResponse(rows, headers={
            "Content-Disposition": 'attachment; filename="devices.json"'
        })
    return _csv_response(rows, "devices.csv")


@router.get("/export/events")
async def export_events(
    format: str = Query("csv", pattern="^(csv|json)$"),
    hours: int = Query(24, ge=1, le=720),
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    with session_scope() as session:
        events = (
            session.query(Event)
            .filter(Event.ts >= cutoff)
            .order_by(Event.ts.desc())
            .limit(10000)
            .all()
        )
        rows = [
            {
                "id": e.id,
                "ts": e.ts.isoformat() if e.ts else "",
                "source": e.source, "event_type": e.event_type,
                "severity": e.severity, "category": e.category,
                "device_id": e.device_id or "",
                "message": (e.message or "")[:500],
            }
            for e in events
        ]

    if format == "json":
        return JSONResponse(rows, headers={
            "Content-Disposition": 'attachment; filename="events.json"'
        })
    return _csv_response(rows, "events.csv")


@router.get("/export/alerts")
async def export_alerts(
    format: str = Query("csv", pattern="^(csv|json)$"),
    hours: int = Query(168, ge=1, le=8760),
):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    with session_scope() as session:
        alerts = (
            session.query(Alert)
            .filter(Alert.ts >= cutoff)
            .order_by(Alert.ts.desc())
            .limit(10000)
            .all()
        )
        rows = [
            {
                "id": a.id,
                "ts": a.ts.isoformat() if a.ts else "",
                "rule_name": a.rule_name, "severity": a.severity,
                "device_id": a.device_id or "",
                "message": (a.message or "")[:500],
                "acknowledged": a.sent,
            }
            for a in alerts
        ]

    if format == "json":
        return JSONResponse(rows, headers={
            "Content-Disposition": 'attachment; filename="alerts.json"'
        })
    return _csv_response(rows, "alerts.csv")


@router.get("/export/rules")
async def export_rules(format: str = Query("csv", pattern="^(csv|json)$")):
    with session_scope() as session:
        rules = session.query(Rule).order_by(Rule.name).all()
        rows = [
            {
                "id": r.id, "name": r.name, "description": r.description,
                "category": r.category, "severity": r.severity,
                "source": r.source, "enabled": r.enabled,
                "approved": r.approved, "frozen": r.frozen,
                "action": r.action, "cooldown_seconds": r.cooldown_seconds,
                "fire_count": r.fire_count,
                "true_positive_count": r.true_positive_count or 0,
                "false_positive_count": r.false_positive_count or 0,
                "last_fired": r.last_fired.isoformat() if r.last_fired else "",
            }
            for r in rules
        ]

    if format == "json":
        return JSONResponse(rows, headers={
            "Content-Disposition": 'attachment; filename="rules.json"'
        })
    return _csv_response(rows, "rules.csv")
