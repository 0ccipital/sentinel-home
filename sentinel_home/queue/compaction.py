"""Compaction logic — collapses stale duplicate jobs per spec Section 5."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from sentinel_home.database import session_scope
from sentinel_home.models import Job

logger = logging.getLogger(__name__)

_compaction_lock = threading.Lock()


def run_compaction() -> int:
    """
    Run compaction across all pending jobs.

    For each device_id with > 1 pending job:
      - Keep the top 1 per rule_name (most recent + highest priority)
      - Mark dropped jobs as 'compacted'
      - Append a summary of collapsed events to the kept job's context

    Returns number of jobs compacted.
    """
    threshold_hours = 2  # Compact jobs older than 2 hours
    cutoff = datetime.now(timezone.utc) - timedelta(hours=threshold_hours)

    if not _compaction_lock.acquire(blocking=False):
        logger.debug("Compaction already running — skipping")
        return 0

    total_compacted = 0
    try:
        with session_scope() as session:
            # Find device_ids with multiple pending jobs older than threshold
            from sqlalchemy import func
            device_ids = (
                session.query(Job.device_id)
                .filter(
                    Job.status == "pending",
                    Job.created_at <= cutoff,
                    Job.device_id.isnot(None),
                )
                .group_by(Job.device_id)
                .having(func.count(Job.id) > 1)
                .all()
            )

            for (device_id,) in device_ids:
                compacted = _compact_device(session, device_id)
                total_compacted += compacted

        if total_compacted:
            logger.info("Compaction complete: %d jobs collapsed", total_compacted)
    finally:
        _compaction_lock.release()

    return total_compacted


def _compact_device(session, device_id: str) -> int:
    """Compact all pending jobs for a single device. Returns count compacted."""
    pending = (
        session.query(Job)
        .filter(Job.device_id == device_id, Job.status == "pending")
        .order_by(Job.priority.asc(), Job.created_at.desc())
        .all()
    )

    # Group by rule_name
    by_rule: dict[str, list[Job]] = {}
    for job in pending:
        by_rule.setdefault(job.rule_name, []).append(job)

    compacted_count = 0
    for rule_name, jobs in by_rule.items():
        if len(jobs) <= 1:
            continue
        keep = jobs[0]  # highest priority, most recent (already ordered)
        drop = jobs[1:]

        oldest_ts = min((j.created_at for j in drop), default=keep.created_at)
        total_dropped = len(drop)

        # Update kept job context with collapse summary
        ctx = dict(keep.context)
        ctx["compaction_note"] = (
            f"{total_dropped} similar {rule_name} event(s) for this device were collapsed "
            f"covering the period from {oldest_ts.isoformat() if oldest_ts else 'unknown'} "
            f"to {datetime.now(timezone.utc).isoformat()}."
        )
        ctx["collapsed_events"] = total_dropped
        keep.context = ctx
        keep.compacted_count = (keep.compacted_count or 0) + total_dropped

        for job in drop:
            job.status = "compacted"

        compacted_count += total_dropped

    return compacted_count
