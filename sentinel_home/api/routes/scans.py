"""Scan endpoints: /api/v1/scans"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Scan

router = APIRouter()


@router.get("/scans")
async def list_scans(limit: int = 20):
    with session_scope() as session:
        scans = session.query(Scan).order_by(Scan.ts.desc()).limit(limit).all()
        return ok_envelope([_scan_summary(s) for s in scans])


@router.get("/scans/latest")
async def get_latest_scan():
    with session_scope() as session:
        scan = session.query(Scan).order_by(Scan.ts.desc()).first()
        if not scan:
            return ok_envelope(None)
        return ok_envelope(_scan_detail(scan))


@router.get("/scans/diff")
async def get_scan_diff():
    with session_scope() as session:
        scans = session.query(Scan).order_by(Scan.ts.desc()).limit(2).all()
        if len(scans) < 2:
            return ok_envelope({"message": "Not enough scans for a diff yet"})
        return ok_envelope(scans[0].diff or {})


@router.post("/scans/trigger")
async def trigger_scan():
    # Rate limiting and actual execution will be wired in once nmap collector is ready
    return ok_envelope({"message": "Scan requested", "accepted": True})


def _scan_summary(s: Scan) -> dict:
    return {
        "id": s.id,
        "ts": s.ts.isoformat() if s.ts else None,
        "target": s.target,
        "scan_type": s.scan_type,
        "findings_count": s.findings_count,
        "triggered_by": s.triggered_by,
    }


def _scan_detail(s: Scan) -> dict:
    return {**_scan_summary(s), "result": s.result, "diff": s.diff}
