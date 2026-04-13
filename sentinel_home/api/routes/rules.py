"""Rule engine endpoints — full CRUD + feedback + versions + rollback + metrics.

POST /rules                     — create rule (agent/user)
PUT  /rules/{id}                — modify rule (auto-snapshots, respects frozen)
DELETE /rules/{id}              — delete rule (only agent/user-created, not system)
POST /rules/{id}/feedback       — TP/FP feedback
POST /rules/{id}/freeze         — lock rule from agent changes
POST /rules/{id}/unfreeze       — unlock rule
POST /rules/{id}/approve        — approve agent-suggested rule
GET  /rules/{id}/versions       — version history
GET  /rules/{id}/metrics        — daily performance windows
POST /rules/{id}/rollback/{ver} — revert to version N (creates new version)
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Rule, RuleVersion, RuleMetricWindow, Alert

router = APIRouter()


# ---------------------------------------------------------------------------
# List / Get
# ---------------------------------------------------------------------------

@router.get("/rules")
async def list_rules(source: str | None = None, enabled: bool | None = None):
    with session_scope() as session:
        q = session.query(Rule).order_by(Rule.priority.asc(), Rule.name.asc())
        if source:
            q = q.filter(Rule.source == source)
        if enabled is not None:
            q = q.filter(Rule.enabled == enabled)
        rules = q.all()
        return ok_envelope([_rule_summary(r) for r in rules])


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: int):
    with session_scope() as session:
        rule = session.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Rule {rule_id} not found"))
        return ok_envelope(_rule_detail(rule))


# ---------------------------------------------------------------------------
# Create / Update / Delete
# ---------------------------------------------------------------------------

@router.post("/rules")
async def create_rule(body: dict):
    """Create a new rule. Agent-created rules start with approved=False."""
    name = body.get("name")
    if not name:
        raise HTTPException(400, detail=error_envelope("BAD_REQUEST", "name is required"))

    source = body.get("source", "agent")
    if source not in ("agent", "user"):
        raise HTTPException(400, detail=error_envelope("BAD_REQUEST", "source must be agent or user"))

    with session_scope() as session:
        existing = session.query(Rule).filter(Rule.name == name).first()
        if existing:
            raise HTTPException(409, detail=error_envelope("CONFLICT", f"Rule '{name}' already exists"))

        rule = Rule(
            name=name,
            description=body.get("description", ""),
            category=body.get("category", "network"),
            severity=body.get("severity", "medium"),
            priority=body.get("priority", 2),
            source=source,
            enabled=body.get("enabled", True),
            approved=source == "user",  # User rules auto-approve, agent rules need approval
            parameters=body.get("parameters", {}),
            action=body.get("action", "alert"),
            cooldown_seconds=body.get("cooldown_seconds", 300),
            created_by=source,
            notes=body.get("notes"),
        )
        session.add(rule)
        session.flush()
        rid = rule.id

    return ok_envelope({"id": rid, "name": name, "approved": source == "user"})


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: int, body: dict):
    """Modify a rule. Creates version snapshot first. Respects frozen flag."""
    with session_scope() as session:
        rule = session.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Rule {rule_id} not found"))

        changed_by = body.get("changed_by", "agent")

        # Frozen check — only user can modify frozen rules
        if rule.frozen and changed_by != "user":
            raise HTTPException(403, detail=error_envelope("FROZEN", "Rule is frozen. Only user can modify."))

        # Snapshot before mutation
        _snapshot_rule(session, rule, changed_by, body.get("change_reason", ""))

        # Apply updates
        if "parameters" in body:
            rule.parameters = body["parameters"]
        if "severity" in body:
            rule.severity = body["severity"]
        if "enabled" in body:
            rule.enabled = body["enabled"]
        if "cooldown_seconds" in body:
            rule.cooldown_seconds = body["cooldown_seconds"]
        if "action" in body:
            rule.action = body["action"]
        if "priority" in body:
            rule.priority = body["priority"]
        if "description" in body:
            rule.description = body["description"]
        if "notes" in body:
            rule.notes = body["notes"]

        rule.last_tuned = datetime.now(timezone.utc)

    # Invalidate rule engine cache
    try:
        from sentinel_home.rules.engine import get_rule_engine
        get_rule_engine()._cache_ts = 0
    except Exception:
        pass

    return ok_envelope({"id": rule_id, "updated": True})


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int):
    """Delete a rule. Cannot delete system rules."""
    with session_scope() as session:
        rule = session.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Rule {rule_id} not found"))
        if rule.source == "system":
            raise HTTPException(403, detail=error_envelope("FORBIDDEN", "Cannot delete system rules. Disable instead."))
        session.delete(rule)

    return ok_envelope({"id": rule_id, "deleted": True})


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------

@router.post("/rules/{rule_id}/feedback")
async def rule_feedback(rule_id: int, body: dict):
    """Record TP/FP feedback for a rule fire."""
    feedback = body.get("feedback", "").lower()
    if feedback not in ("tp", "fp"):
        raise HTTPException(400, detail=error_envelope("BAD_REQUEST", "feedback must be 'tp' or 'fp'"))

    with session_scope() as session:
        rule = session.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Rule {rule_id} not found"))
        if feedback == "tp":
            rule.true_positive_count = (rule.true_positive_count or 0) + 1
        else:
            rule.false_positive_count = (rule.false_positive_count or 0) + 1

    return ok_envelope({"rule_id": rule_id, "feedback": feedback})


# ---------------------------------------------------------------------------
# Freeze / Approve
# ---------------------------------------------------------------------------

@router.post("/rules/{rule_id}/freeze")
async def freeze_rule(rule_id: int):
    """Lock a rule — agent cannot modify it."""
    with session_scope() as session:
        rule = session.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Rule {rule_id} not found"))
        rule.frozen = True
    return ok_envelope({"id": rule_id, "frozen": True})


@router.post("/rules/{rule_id}/unfreeze")
async def unfreeze_rule(rule_id: int):
    """Unlock a rule — agent can modify it again."""
    with session_scope() as session:
        rule = session.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Rule {rule_id} not found"))
        rule.frozen = False
    return ok_envelope({"id": rule_id, "frozen": False})


@router.post("/rules/{rule_id}/approve")
async def approve_rule(rule_id: int):
    """Approve an agent-suggested rule — activates it."""
    with session_scope() as session:
        rule = session.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Rule {rule_id} not found"))
        rule.approved = True
    return ok_envelope({"id": rule_id, "approved": True})


# ---------------------------------------------------------------------------
# Versions + Rollback
# ---------------------------------------------------------------------------

@router.get("/rules/{rule_id}/versions")
async def rule_versions(rule_id: int):
    """Version history for a rule."""
    with session_scope() as session:
        versions = (
            session.query(RuleVersion)
            .filter(RuleVersion.rule_id == rule_id)
            .order_by(RuleVersion.version.desc())
            .all()
        )
        return ok_envelope([
            {
                "version": v.version,
                "parameters": v.parameters,
                "severity": v.severity,
                "enabled": v.enabled,
                "cooldown_seconds": v.cooldown_seconds,
                "changed_by": v.changed_by,
                "change_reason": v.change_reason,
                "fire_count_at_change": v.fire_count_at_change,
                "tp_count_at_change": v.tp_count_at_change,
                "fp_count_at_change": v.fp_count_at_change,
                "created_at": v.created_at.isoformat() if v.created_at else None,
            }
            for v in versions
        ])


@router.post("/rules/{rule_id}/rollback/{version}")
async def rollback_rule(rule_id: int, version: int):
    """Revert a rule to a previous version. Creates a NEW version (never destructive)."""
    with session_scope() as session:
        rule = session.query(Rule).filter(Rule.id == rule_id).first()
        if not rule:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Rule {rule_id} not found"))

        target = session.query(RuleVersion).filter(
            RuleVersion.rule_id == rule_id, RuleVersion.version == version
        ).first()
        if not target:
            raise HTTPException(404, detail=error_envelope("NOT_FOUND", f"Version {version} not found"))

        # Snapshot current state first
        _snapshot_rule(session, rule, "user", f"rollback to v{version}")

        # Apply the old version's values
        rule.parameters = target.parameters
        rule.severity = target.severity
        rule.enabled = target.enabled
        rule.cooldown_seconds = target.cooldown_seconds
        rule.last_tuned = datetime.now(timezone.utc)

    return ok_envelope({"id": rule_id, "rolled_back_to": version})


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@router.get("/rules/{rule_id}/metrics")
async def rule_metrics(rule_id: int, days: int = 30):
    """Daily performance windows for a rule. The critic's primary input."""
    with session_scope() as session:
        windows = (
            session.query(RuleMetricWindow)
            .filter(RuleMetricWindow.rule_id == rule_id)
            .order_by(RuleMetricWindow.window_date.desc())
            .limit(days)
            .all()
        )
        return ok_envelope([
            {
                "date": w.window_date.isoformat() if w.window_date else None,
                "fire_count": w.fire_count,
                "tp_count": w.tp_count,
                "fp_count": w.fp_count,
                "auto_resolved_count": w.auto_resolved_count,
                "version_at_window": w.version_at_window,
            }
            for w in windows
        ])


# ---------------------------------------------------------------------------
# Alerts (kept alongside rules)
# ---------------------------------------------------------------------------

@router.get("/alerts")
async def list_alerts(limit: int = 50, unacked_only: bool = False):
    with session_scope() as session:
        q = session.query(Alert).order_by(Alert.ts.desc())
        if unacked_only:
            q = q.filter(Alert.sent == False)
        alerts = q.limit(limit).all()
        return ok_envelope([
            {
                "id": a.id,
                "ts": a.ts.isoformat() if a.ts else None,
                "rule_name": a.rule_name,
                "device_id": a.device_id,
                "severity": a.severity,
                "message": a.message,
                "sent": a.sent,
            }
            for a in alerts
        ])


@router.post("/rules/{name}/test")
async def test_rule(name: str):
    return ok_envelope({"name": name, "would_fire": False, "reason": "Dry-run not yet implemented"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snapshot_rule(session, rule: Rule, changed_by: str, reason: str) -> None:
    """Create a version snapshot before modifying a rule."""
    from sqlalchemy import func
    max_ver = session.query(func.coalesce(func.max(RuleVersion.version), 0)).filter(
        RuleVersion.rule_id == rule.id
    ).scalar()
    session.add(RuleVersion(
        rule_id=rule.id,
        version=max_ver + 1,
        parameters=rule.parameters,
        severity=rule.severity,
        enabled=rule.enabled,
        cooldown_seconds=rule.cooldown_seconds,
        changed_by=changed_by,
        change_reason=reason,
        fire_count_at_change=rule.fire_count,
        tp_count_at_change=rule.true_positive_count or 0,
        fp_count_at_change=rule.false_positive_count or 0,
    ))


def _rule_summary(r: Rule) -> dict:
    return {
        "id": r.id, "name": r.name, "source": r.source,
        "severity": r.severity, "description": r.description,
        "action": r.action, "enabled": r.enabled, "approved": r.approved,
        "frozen": r.frozen, "fire_count": r.fire_count,
        "last_fired": r.last_fired.isoformat() if r.last_fired else None,
    }


def _rule_detail(r: Rule) -> dict:
    return {
        **_rule_summary(r),
        "category": r.category, "priority": r.priority,
        "parameters": r.parameters, "cooldown_seconds": r.cooldown_seconds,
        "true_positive_count": r.true_positive_count,
        "false_positive_count": r.false_positive_count,
        "last_tuned": r.last_tuned.isoformat() if r.last_tuned else None,
        "created_by": r.created_by, "notes": r.notes,
    }
