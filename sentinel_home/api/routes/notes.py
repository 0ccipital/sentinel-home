"""Notes CRUD — universal annotations for any entity."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Note, Device, Finding, Rule, Event

router = APIRouter()

VALID_ENTITY_TYPES = {"device", "rule", "event_type", "finding", "general"}


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class NoteCreate(BaseModel):
    entity_type: str
    entity_id: str | None = None
    text: str
    source: str = "user"
    chat_id: str | None = None


class DeviceNoteCreate(BaseModel):
    text: str
    source: str = "user"
    chat_id: str | None = None


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

@router.post("/notes")
async def create_note(body: NoteCreate):
    if body.entity_type not in VALID_ENTITY_TYPES:
        raise HTTPException(
            status_code=400,
            detail=error_envelope("INVALID_ENTITY_TYPE", f"entity_type must be one of: {', '.join(sorted(VALID_ENTITY_TYPES))}"),
        )
    if body.entity_type != "general" and not body.entity_id:
        raise HTTPException(
            status_code=400,
            detail=error_envelope("MISSING_ENTITY_ID", "entity_id is required for non-general notes"),
        )
    with session_scope() as session:
        note = Note(
            entity_type=body.entity_type,
            entity_id=body.entity_id,
            text=body.text,
            source=body.source,
            chat_id=body.chat_id,
        )
        session.add(note)
        session.flush()
        return ok_envelope(_note_dict(note))


@router.get("/notes")
async def list_notes(
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    with session_scope() as session:
        q = session.query(Note)
        if entity_type:
            q = q.filter(Note.entity_type == entity_type)
        if entity_id:
            q = q.filter(Note.entity_id == entity_id)
        notes = q.order_by(Note.ts.desc()).offset(offset).limit(limit).all()
        return ok_envelope([_note_dict(n) for n in notes])


@router.get("/notes/{note_id}")
async def get_note(note_id: int):
    with session_scope() as session:
        note = session.query(Note).filter(Note.id == note_id).first()
        if not note:
            raise HTTPException(
                status_code=404,
                detail=error_envelope("NOT_FOUND", f"Note {note_id} not found"),
            )
        return ok_envelope(_note_dict(note))


@router.delete("/notes/{note_id}")
async def delete_note(note_id: int):
    with session_scope() as session:
        note = session.query(Note).filter(Note.id == note_id).first()
        if not note:
            raise HTTPException(
                status_code=404,
                detail=error_envelope("NOT_FOUND", f"Note {note_id} not found"),
            )
        session.delete(note)
        return ok_envelope({"deleted": note_id})


# ---------------------------------------------------------------------------
# Device note shortcuts
# ---------------------------------------------------------------------------

@router.post("/devices/{mac}/notes")
async def create_device_note(mac: str, body: DeviceNoteCreate):
    with session_scope() as session:
        device = session.query(Device).filter(Device.mac == mac).first()
        if not device:
            raise HTTPException(
                status_code=404,
                detail=error_envelope("NOT_FOUND", f"Device {mac} not found"),
            )
        note = Note(
            entity_type="device",
            entity_id=mac,
            text=body.text,
            source=body.source,
            chat_id=body.chat_id,
        )
        session.add(note)
        session.flush()
        return ok_envelope(_note_dict(note))


@router.get("/devices/{mac}/notes")
async def get_device_notes(mac: str, limit: int = 50, offset: int = 0):
    with session_scope() as session:
        notes = (
            session.query(Note)
            .filter(Note.entity_type == "device", Note.entity_id == mac)
            .order_by(Note.ts.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return ok_envelope([_note_dict(n) for n in notes])


# ---------------------------------------------------------------------------
# Context endpoint — LLM-optimized entity summary
# ---------------------------------------------------------------------------

@router.get("/context/{entity_type}/{entity_id}")
async def get_entity_context(entity_type: str, entity_id: str):
    if entity_type not in VALID_ENTITY_TYPES:
        raise HTTPException(
            status_code=400,
            detail=error_envelope("INVALID_ENTITY_TYPE", f"entity_type must be one of: {', '.join(sorted(VALID_ENTITY_TYPES))}"),
        )

    with session_scope() as session:
        lines: list[str] = []

        if entity_type == "device":
            lines.extend(_device_context(session, entity_id))
        elif entity_type == "rule":
            lines.extend(_rule_context(session, entity_id))
        elif entity_type == "finding":
            lines.extend(_finding_context(session, entity_id))
        elif entity_type == "event_type":
            lines.extend(_event_type_context(session, entity_id))
        elif entity_type == "general":
            lines.append("GENERAL NOTES")

        # Append notes for any entity type
        notes = (
            session.query(Note)
            .filter(Note.entity_type == entity_type, Note.entity_id == entity_id)
            .order_by(Note.ts.asc())
            .all()
        )
        if notes:
            lines.append("Notes:")
            for n in notes:
                ts_str = n.ts.strftime("%Y-%m-%d") if n.ts else "unknown"
                lines.append(f"- [{ts_str} {n.source}] {n.text}")
        else:
            lines.append("Notes: (none)")

        return ok_envelope({"context": "\n".join(lines)})


# ---------------------------------------------------------------------------
# Context builders
# ---------------------------------------------------------------------------

def _device_context(session, mac: str) -> list[str]:
    device = session.query(Device).filter(Device.mac == mac).first()
    if not device:
        return [f"DEVICE: unknown ({mac})", "No device record found."]

    label = device.label or device.vendor or "Unknown"
    lines = [f"DEVICE: {label} ({device.mac})"]

    parts = []
    if device.ip:
        parts.append(f"IP: {device.ip}")
    if device.vendor:
        parts.append(f"Vendor: {device.vendor}")
    if device.device_type:
        parts.append(f"Type: {device.device_type}")
    if device.network_role:
        parts.append(f"Role: {device.network_role}")
    if parts:
        lines.append(" | ".join(parts))

    if device.os_family:
        lines.append(f"OS: {device.os_family}")
    if device.connection_type:
        conn = f"Connection: {device.connection_type}"
        if device.ap:
            conn += f" (AP: {device.ap})"
        lines.append(conn)

    if device.hostnames:
        names = []
        for src, name in device.hostnames.items():
            names.append(f"{name} ({src})")
        lines.append(f"Hostnames: {', '.join(names)}")

    if device.services:
        svc_parts = []
        if isinstance(device.services, dict):
            for port, info in device.services.items():
                if isinstance(info, dict):
                    svc_name = info.get("name", "")
                    product = info.get("product", "")
                    desc = f"{port}/{svc_name}"
                    if product:
                        desc += f" ({product})"
                    svc_parts.append(desc)
                else:
                    svc_parts.append(f"{port}/{info}")
        elif isinstance(device.services, list):
            for svc in device.services:
                if isinstance(svc, dict):
                    port = svc.get("port", "?")
                    name = svc.get("name", "")
                    svc_parts.append(f"{port}/{name}")
                else:
                    svc_parts.append(str(svc))
        if svc_parts:
            lines.append(f"Services: {', '.join(svc_parts)}")

    if device.first_seen:
        lines.append(f"First seen: {device.first_seen.strftime('%Y-%m-%d %H:%M')}")
    if device.last_seen:
        lines.append(f"Last seen: {device.last_seen.strftime('%Y-%m-%d %H:%M')}")
    if device.device_notes:
        lines.append(f"Device notes: {device.device_notes}")

    return lines


def _rule_context(session, rule_id_str: str) -> list[str]:
    try:
        rule_id = int(rule_id_str)
    except ValueError:
        return [f"RULE: {rule_id_str}", "Invalid rule ID."]

    rule = session.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        return [f"RULE: #{rule_id_str}", "No rule record found."]

    lines = [f"RULE: {rule.name} (#{rule.id})"]
    lines.append(f"Category: {rule.category} | Severity: {rule.severity} | Priority: {rule.priority}")
    if rule.description:
        lines.append(f"Description: {rule.description}")
    lines.append(f"Source: {rule.source} | Enabled: {rule.enabled} | Approved: {rule.approved} | Frozen: {rule.frozen}")
    lines.append(f"Fires: {rule.fire_count} | TP: {rule.true_positive_count} | FP: {rule.false_positive_count}")
    if rule.last_fired:
        lines.append(f"Last fired: {rule.last_fired.strftime('%Y-%m-%d %H:%M')}")

    return lines


def _finding_context(session, finding_id_str: str) -> list[str]:
    try:
        finding_id = int(finding_id_str)
    except ValueError:
        return [f"FINDING: {finding_id_str}", "Invalid finding ID."]

    finding = session.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return [f"FINDING: #{finding_id_str}", "No finding record found."]

    lines = [f"FINDING: #{finding.id}"]
    lines.append(f"Severity: {finding.severity} | Confidence: {finding.confidence} | Source: {finding.source}")
    lines.append(f"Summary: {finding.summary}")
    if finding.rule_name:
        lines.append(f"Rule: {finding.rule_name}")
    if finding.device_id:
        lines.append(f"Device: {finding.device_id}")
    if finding.likely_cause:
        lines.append(f"Likely cause: {finding.likely_cause}")
    if finding.recommended_action:
        lines.append(f"Action: {finding.recommended_action}")
    if finding.ts:
        lines.append(f"Time: {finding.ts.strftime('%Y-%m-%d %H:%M')}")

    return lines


def _event_type_context(session, event_type_name: str) -> list[str]:
    lines = [f"EVENT TYPE: {event_type_name}"]

    # Count recent events of this type
    from sqlalchemy import func
    count = session.query(func.count(Event.id)).filter(Event.event_type == event_type_name).scalar()
    lines.append(f"Total events: {count}")

    # Get a sample of recent events
    recent = (
        session.query(Event)
        .filter(Event.event_type == event_type_name)
        .order_by(Event.ts.desc())
        .limit(5)
        .all()
    )
    if recent:
        lines.append("Recent samples:")
        for e in recent:
            ts_str = e.ts.strftime("%Y-%m-%d %H:%M") if e.ts else "?"
            msg = e.message[:120] if e.message else "(no message)"
            device = e.device_id or "?"
            lines.append(f"  [{ts_str}] device={device} sev={e.severity} — {msg}")

    return lines


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _note_dict(n: Note) -> dict:
    return {
        "id": n.id,
        "ts": n.ts.isoformat() if n.ts else None,
        "entity_type": n.entity_type,
        "entity_id": n.entity_id,
        "source": n.source,
        "text": n.text,
        "chat_id": n.chat_id,
    }
