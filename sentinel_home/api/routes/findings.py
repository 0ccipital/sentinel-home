"""Finding endpoints: /api/v1/findings"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Finding

router = APIRouter()


@router.get("/findings")
async def list_findings(
    severity: str | None = None,
    acknowledged: bool | None = None,
    dismissed: bool | None = None,
    device_id: str | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    with session_scope() as session:
        q = session.query(Finding).order_by(Finding.ts.desc())
        if severity:
            q = q.filter(Finding.severity == severity)
        if acknowledged is not None:
            q = q.filter(Finding.acknowledged == acknowledged)
        if dismissed is not None:
            q = q.filter(Finding.dismissed == dismissed)
        if device_id:
            q = q.filter(Finding.device_id == device_id)
        findings = q.offset(offset).limit(limit).all()
        return ok_envelope([_finding_to_dict(f) for f in findings])


@router.get("/findings/summary")
async def get_findings_summary():
    with session_scope() as session:
        total = session.query(Finding).count()
        by_severity = {}
        for sev in ("low", "medium", "high", "critical"):
            by_severity[sev] = session.query(Finding).filter(Finding.severity == sev).count()
        return ok_envelope({
            "total": total,
            "by_severity": by_severity,
            "unacknowledged": session.query(Finding).filter(
                Finding.acknowledged == False, Finding.dismissed == False  # noqa: E712
            ).count(),
        })


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: int):
    with session_scope() as session:
        finding = session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Finding {finding_id} not found"))
        return ok_envelope(_finding_to_dict(finding, full=True))


@router.post("/findings/{finding_id}/acknowledge")
async def acknowledge_finding(finding_id: int):
    with session_scope() as session:
        finding = session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Finding {finding_id} not found"))
        finding.acknowledged = True
        return ok_envelope({"acknowledged": True})


@router.post("/findings/{finding_id}/dismiss")
async def dismiss_finding(finding_id: int):
    with session_scope() as session:
        finding = session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Finding {finding_id} not found"))
        finding.dismissed = True
        return ok_envelope({"dismissed": True})


def _finding_to_dict(f: Finding, full: bool = False) -> dict:
    d = {
        "id": f.id,
        "job_id": f.job_id,
        "ts": f.ts.isoformat() if f.ts else None,
        "severity": f.severity,
        "confidence": f.confidence,
        "summary": f.summary,
        "device_id": f.device_id,
        "rule_name": f.rule_name,
        "acknowledged": f.acknowledged,
        "dismissed": f.dismissed,
    }
    if full:
        d.update({
            "reasoning": f.reasoning,
            "likely_cause": f.likely_cause,
            "recommended_action": f.recommended_action,
            "needs_followup": f.needs_followup,
            "followup_question": f.followup_question,
            "followup_result": f.followup_result,
            "mitre_reference": f.mitre_reference,
        })
    return d
