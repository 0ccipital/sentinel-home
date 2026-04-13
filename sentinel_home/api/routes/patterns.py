"""Pattern CRUD — agent-learned network patterns.

Types: baseline (what's normal), suppression (ignore this), watchlist (watch closely).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Pattern, PatternVersion

router = APIRouter()


@router.get("/patterns")
async def list_patterns(pattern_type: str | None = None, scope: str | None = None):
    with session_scope() as session:
        q = session.query(Pattern).order_by(Pattern.updated_at.desc())
        if pattern_type:
            q = q.filter(Pattern.pattern_type == pattern_type)
        if scope:
            q = q.filter(Pattern.scope == scope)
        patterns = q.all()
        return ok_envelope([_pattern_dict(p) for p in patterns])


@router.get("/patterns/{pattern_id}")
async def get_pattern(pattern_id: int):
    with session_scope() as session:
        p = session.query(Pattern).filter(Pattern.id == pattern_id).first()
        if not p:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Pattern {pattern_id} not found"))
        return ok_envelope(_pattern_dict(p))


@router.post("/patterns")
async def create_pattern(body: dict):
    name = body.get("name")
    if not name:
        raise HTTPException(400, detail=error_envelope("BAD_REQUEST", "name is required"))

    ptype = body.get("pattern_type", "baseline")
    if ptype not in ("baseline", "suppression", "watchlist"):
        raise HTTPException(400, detail=error_envelope("BAD_REQUEST", "pattern_type must be baseline/suppression/watchlist"))

    with session_scope() as session:
        existing = session.query(Pattern).filter(Pattern.name == name).first()
        if existing:
            raise HTTPException(409, detail=error_envelope("CONFLICT", f"Pattern '{name}' already exists"))

        p = Pattern(
            name=name,
            pattern_type=ptype,
            scope=body.get("scope", "*"),
            definition=body.get("definition", {}),
            confidence=body.get("confidence", 0.5),
            sample_count=body.get("sample_count", 0),
            created_by=body.get("created_by", "agent"),
            notes=body.get("notes"),
        )
        session.add(p)
        session.flush()
        pid = p.id

    return ok_envelope({"id": pid, "name": name})


@router.put("/patterns/{pattern_id}")
async def update_pattern(pattern_id: int, body: dict):
    with session_scope() as session:
        p = session.query(Pattern).filter(Pattern.id == pattern_id).first()
        if not p:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Pattern {pattern_id} not found"))

        # Snapshot before mutation
        _snapshot_pattern(session, p, body.get("changed_by", "agent"), body.get("change_reason", ""))

        # Apply updates
        if "definition" in body:
            p.definition = body["definition"]
        if "confidence" in body:
            p.confidence = body["confidence"]
        if "scope" in body:
            p.scope = body["scope"]
        if "sample_count" in body:
            p.sample_count = body["sample_count"]
        if "notes" in body:
            p.notes = body["notes"]

    return ok_envelope({"id": pattern_id, "updated": True})


@router.delete("/patterns/{pattern_id}")
async def delete_pattern(pattern_id: int):
    with session_scope() as session:
        p = session.query(Pattern).filter(Pattern.id == pattern_id).first()
        if not p:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Pattern {pattern_id} not found"))
        session.delete(p)

    return ok_envelope({"id": pattern_id, "deleted": True})


def _snapshot_pattern(session, p: Pattern, changed_by: str, reason: str) -> None:
    """Create a version snapshot before modifying a pattern."""
    from sqlalchemy import func
    max_ver = session.query(func.coalesce(func.max(PatternVersion.version), 0)).filter(
        PatternVersion.pattern_id == p.id
    ).scalar()
    session.add(PatternVersion(
        pattern_id=p.id,
        version=max_ver + 1,
        definition=p.definition,
        confidence=p.confidence,
        scope=p.scope,
        changed_by=changed_by,
        change_reason=reason,
    ))


def _pattern_dict(p: Pattern) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "pattern_type": p.pattern_type,
        "scope": p.scope,
        "definition": p.definition,
        "confidence": p.confidence,
        "sample_count": p.sample_count,
        "created_by": p.created_by,
        "notes": p.notes,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }
