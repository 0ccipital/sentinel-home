"""Event endpoints: /api/v1/events"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from sentinel_home.api.envelope import error_envelope, ok_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Event, Note, Pattern

router = APIRouter()


@router.get("/events")
async def list_events(
    source: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    device_id: str | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    with session_scope() as session:
        q = session.query(Event).order_by(Event.ts.desc())
        if source:
            q = q.filter(Event.source == source)
        if event_type:
            q = q.filter(Event.event_type == event_type)
        if severity:
            q = q.filter(Event.severity == severity)
        if device_id:
            q = q.filter(Event.device_id == device_id)
        events = q.offset(offset).limit(limit).all()
        return ok_envelope([_event_to_dict(e) for e in events])


@router.get("/events/{event_id}")
async def get_event(event_id: int):
    with session_scope() as session:
        event = session.query(Event).filter(Event.id == event_id).first()
        if not event:
            from sentinel_home.api.envelope import error_envelope
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Event {event_id} not found"))
        return ok_envelope(_event_to_dict(event, include_raw=True))


@router.post("/events/{event_id}/flag")
async def flag_event(event_id: int):
    """Flag an event for investigation — creates a queue job."""
    # First session: read event data and add note
    with session_scope() as session:
        event = session.get(Event, event_id)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

        # Extract what we need before session closes
        job_context = {
            "event_id": event_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "message": (event.message or "")[:500],
            "flagged_by": "user",
        }
        rule_name = f"rule_{event.rule_id}" if event.rule_id else "user_flagged"
        device_id = event.device_id
        event_type = event.event_type

        # Add a note (same session, no nesting)
        session.add(
            Note(
                entity_type="event_type",
                entity_id=event_type,
                source="user",
                text=f"User flagged event #{event_id} for investigation",
            )
        )

    # Second: enqueue job after first session is closed (avoids nested sessions)
    from sentinel_home.queue.manager import enqueue_job
    enqueue_job(
        source="user_flag",
        rule_name=rule_name,
        device_id=device_id,
        priority=1,
        context=job_context,
    )

    return ok_envelope({"status": "flagged", "event_id": event_id})


@router.post("/events/{event_id}/suppress")
async def suppress_event(event_id: int, request: Request):
    """Suppress future events matching this pattern."""
    body = {}
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
    reason = body.get("reason", "")

    with session_scope() as session:
        event = session.get(Event, event_id)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

        # Create suppression pattern
        pattern_name = f"suppress_{event.event_type}_{event.device_id or 'all'}"
        existing = session.query(Pattern).filter(Pattern.name == pattern_name).first()
        if not existing:
            session.add(
                Pattern(
                    name=pattern_name,
                    pattern_type="suppression",
                    scope=event.device_id or "*",
                    definition={
                        "event_type": event.event_type,
                        "source": event.source,
                        "device_id": event.device_id,
                    },
                    confidence=1.0,
                    created_by="user",
                )
            )

        # Add a note
        note_text = f"User suppressed {event.event_type} events"
        if event.device_id:
            note_text += f" for device {event.device_id}"
        if reason:
            note_text += f": {reason}"
        session.add(
            Note(
                entity_type="event_type",
                entity_id=event.event_type,
                source="user",
                text=note_text,
            )
        )

    return ok_envelope({"status": "suppressed", "event_id": event_id})


def _event_to_dict(e: Event, include_raw: bool = False) -> dict:
    d = {
        "id": e.id,
        "ts": e.ts.isoformat() if e.ts else None,
        "source": e.source,
        "event_type": e.event_type,
        "severity": e.severity,
        "device_id": e.device_id,
        "message": e.message,
    }
    if include_raw:
        d["raw"] = e.raw
    return d
