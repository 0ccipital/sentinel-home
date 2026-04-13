"""Queue manager — enqueue, prioritize, and retrieve jobs."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sentinel_home.database import session_scope
from sentinel_home.models import Job

logger = logging.getLogger(__name__)


def enqueue_job(
    source: str,
    rule_name: str,
    context: dict,
    device_id: str | None = None,
    priority: int = 2,
    rule_id: int | None = None,
) -> int:
    """Create a new pending job. Returns the job ID."""
    with session_scope() as session:
        job = Job(
            source=source,
            rule_name=rule_name,
            rule_id=rule_id,
            device_id=device_id,
            priority=priority,
            context=context,
        )
        session.add(job)
        session.flush()
        job_id = job.id
        logger.debug("Enqueued job %d (rule=%s, rule_id=%s, device=%s, priority=%d)", job_id, rule_name, rule_id, device_id, priority)
    return job_id


def get_pending_jobs(limit: int = 100) -> list[dict]:
    """Return pending jobs ordered by priority then age."""
    with session_scope() as session:
        jobs = (
            session.query(Job)
            .filter(Job.status == "pending")
            .order_by(Job.priority.asc(), Job.created_at.asc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": j.id,
                "source": j.source,
                "rule_name": j.rule_name,
                "device_id": j.device_id,
                "priority": j.priority,
                "context": j.context,
                "created_at": j.created_at.isoformat() if j.created_at else None,
                "compacted_count": j.compacted_count,
            }
            for j in jobs
        ]


def mark_processing(job_id: int) -> None:
    with session_scope() as session:
        job = session.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = "processing"


def mark_done(job_id: int, verdict: dict) -> None:
    with session_scope() as session:
        job = session.query(Job).filter(Job.id == job_id).first()
        if job:
            job.status = "done"
            job.verdict = verdict
            job.processed_at = datetime.now(timezone.utc)

            # Create finding from verdict
            from sentinel_home.models import Finding
            finding = Finding(
                job_id=job_id,
                severity=verdict.get("severity", "medium"),
                confidence=verdict.get("confidence", "medium"),
                summary=verdict.get("summary", ""),
                reasoning=verdict.get("reasoning"),
                likely_cause=verdict.get("likely_cause"),
                recommended_action=verdict.get("recommended_action"),
                needs_followup=verdict.get("needs_followup", False),
                followup_question=verdict.get("followup_question"),
                mitre_reference=verdict.get("mitre_reference"),
                device_id=job.device_id,
                rule_name=job.rule_name,
            )
            session.add(finding)
