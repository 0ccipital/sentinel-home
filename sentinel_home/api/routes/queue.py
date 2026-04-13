"""Queue & inference endpoints: /api/v1/queue, /api/v1/inference"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Job

router = APIRouter()


@router.get("/queue")
async def get_queue_status():
    from sqlalchemy import func
    with session_scope() as session:
        # Single GROUP BY instead of 4 separate COUNT queries
        counts = dict(
            session.query(Job.status, func.count())
            .group_by(Job.status)
            .all()
        )
        oldest = (
            session.query(Job)
            .filter(Job.status == "pending")
            .order_by(Job.created_at.asc())
            .first()
        )
        return ok_envelope({
            "pending_count": counts.get("pending", 0),
            "processing_count": counts.get("processing", 0),
            "compacted_count": counts.get("compacted", 0),
            "done_count": counts.get("done", 0),
            "oldest_job_age_seconds": _age_seconds(oldest.created_at) if oldest else None,
        })


@router.get("/queue/jobs")
async def list_queue_jobs(status: str = "pending", limit: int = 50):
    with session_scope() as session:
        jobs = (
            session.query(Job)
            .filter(Job.status == status)
            .order_by(Job.priority.asc(), Job.created_at.desc())
            .limit(limit)
            .all()
        )
        return ok_envelope([_job_summary(j) for j in jobs])


@router.get("/queue/jobs/{job_id}")
async def get_job(job_id: int):
    with session_scope() as session:
        job = session.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Job {job_id} not found"))
        return ok_envelope(_job_detail(job))


@router.post("/queue/jobs/{job_id}/prioritize")
async def prioritize_job(job_id: int):
    with session_scope() as session:
        job = session.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Job {job_id} not found"))
        job.priority = 1
        return ok_envelope({"job_id": job_id, "priority": 1})


@router.put("/queue/jobs/{job_id}/status")
async def update_job_status(job_id: int, body: dict):
    """Worker calls this to mark a job as processing."""
    new_status = body.get("status", "")
    if new_status not in ("processing", "failed"):
        raise HTTPException(status_code=400, detail=error_envelope("BAD_REQUEST", "status must be 'processing' or 'failed'"))

    with session_scope() as session:
        job = session.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Job {job_id} not found"))
        job.status = new_status
    return ok_envelope({"job_id": job_id, "status": new_status})


@router.put("/queue/jobs/{job_id}/verdict")
async def submit_verdict(job_id: int, body: dict):
    """Worker submits LLM verdict. Creates a Finding and marks job done."""
    from sentinel_home.queue.manager import mark_done
    with session_scope() as session:
        job = session.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Job {job_id} not found"))
    mark_done(job_id, body)
    return ok_envelope({"job_id": job_id, "status": "done", "finding_created": True})


@router.post("/queue/compact")
async def trigger_compaction():
    from sentinel_home.queue.compaction import run_compaction
    compacted = run_compaction()
    return ok_envelope({"message": "Compaction triggered", "compacted": compacted})


@router.post("/queue/submit")
async def submit_custom_job(body: dict):
    with session_scope() as session:
        job = Job(
            source="agent",
            rule_name="custom",
            priority=2,
            context=body.get("context", {}),
            device_id=body.get("device_id"),
        )
        session.add(job)
        session.flush()
        return ok_envelope({"job_id": job.id})


@router.get("/inference/status")
async def get_inference_status():
    """Check if LLM provider is reachable and return last batch info."""
    from sentinel_home.config import get_settings
    import httpx

    settings = get_settings()
    cfg = settings.agent
    if not cfg.enabled or not cfg.url:
        return ok_envelope({
            "agent_enabled": False,
            "agent_url": None,
            "model": cfg.model,
            "last_batch_time": None,
        })

    base_url = cfg.url.rstrip("/")
    reachable = False
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(f"{base_url}/health")
            reachable = resp.status_code == 200
    except Exception:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                resp = await client.get(f"{base_url}/api/models")
                reachable = resp.status_code in (200, 401)
        except Exception:
            pass

    with session_scope() as session:
        last_done = (
            session.query(Job)
            .filter(Job.status == "done")
            .order_by(Job.processed_at.desc())
            .first()
        )

    return ok_envelope({
        "agent_enabled": True,
        "agent_reachable": reachable,
        "agent_url": base_url,
        "model": cfg.model,
        "last_batch_time": last_done.processed_at.isoformat() if last_done and last_done.processed_at else None,
    })


@router.post("/inference/trigger")
async def trigger_inference():
    return ok_envelope({"message": "Out-of-schedule inference requested", "accepted": True})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _age_seconds(ts) -> float | None:
    if ts is None:
        return None
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        from datetime import timezone as tz
        ts = ts.replace(tzinfo=tz.utc)
    return (now - ts).total_seconds()


def _job_summary(j: Job) -> dict:
    return {
        "id": j.id,
        "created_at": j.created_at.isoformat() if j.created_at else None,
        "source": j.source,
        "rule_name": j.rule_name,
        "device_id": j.device_id,
        "priority": j.priority,
        "status": j.status,
        "compacted_count": j.compacted_count,
    }


def _job_detail(j: Job) -> dict:
    return {
        **_job_summary(j),
        "context": j.context,
        "processed_at": j.processed_at.isoformat() if j.processed_at else None,
        "verdict": j.verdict,
    }
