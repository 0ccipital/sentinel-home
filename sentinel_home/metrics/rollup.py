"""Hourly rollup — flushes counters to EventRollup, computes stats, runs retention.

Scheduled jobs:
  - Every hour: flush counters → EventRollup rows
  - Every hour: recompute DashboardStats
  - Daily: compute RuleMetricWindow snapshots
  - Daily: retention cleanup (delete old events, rollups, stale jobs)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sentinel_home.config import get_settings
from sentinel_home.database import session_scope
from sentinel_home.metrics.counters import get_counters

logger = logging.getLogger(__name__)


def flush_counters() -> int:
    """Flush in-memory counters to EventRollup table. Returns rows written."""
    from sentinel_home.models import EventRollup

    buckets = get_counters().flush()
    if not buckets:
        return 0

    now = datetime.now(timezone.utc)
    # Round to the current hour
    hour = now.replace(minute=0, second=0, microsecond=0)

    count = 0
    with session_scope() as session:
        for (source, category, event_type), bucket in buckets.items():
            session.add(EventRollup(
                hour=hour,
                source=source,
                category=category,
                event_type=event_type,
                count=bucket.count,
                extra=bucket.to_metadata(),
            ))
            count += 1

    if count:
        total_events = sum(b.count for b in buckets.values())
        logger.info("Flushed %d counter buckets (%d total events) to rollups", count, total_events)

    return count


def compute_dashboard_stats() -> None:
    """Recompute pre-aggregated dashboard stats."""
    from sentinel_home.models import DashboardStats, Event, Device, Job, Alert
    from sqlalchemy import func

    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    with session_scope() as session:
        stats = {
            "computed_at": now.isoformat(),
            "devices_total": session.query(Device).count(),
            "events_24h": session.query(Event).filter(Event.ts >= last_24h).count(),
            "alerts_24h": session.query(Alert).filter(Alert.ts >= last_24h).count(),
            "jobs_pending": session.query(Job).filter(Job.status == "pending").count(),
            "events_by_category": dict(
                session.query(Event.category, func.count(Event.id))
                .filter(Event.ts >= last_24h)
                .group_by(Event.category)
                .all()
            ),
            "events_by_severity": dict(
                session.query(Event.severity, func.count(Event.id))
                .filter(Event.ts >= last_24h)
                .group_by(Event.severity)
                .all()
            ),
        }

        session.add(DashboardStats(stats=stats))

    logger.debug("Dashboard stats recomputed")


def compute_rule_metrics() -> int:
    """Compute daily RuleMetricWindow snapshots for all rules. Returns rows created."""
    from sentinel_home.models import Rule, RuleMetricWindow

    today = datetime.now(timezone.utc).date()

    count = 0
    with session_scope() as session:
        rules = session.query(Rule).filter(Rule.enabled == True).all()

        for rule in rules:
            # Skip if we already have a window for today
            existing = (
                session.query(RuleMetricWindow)
                .filter(
                    RuleMetricWindow.rule_id == rule.id,
                    RuleMetricWindow.window_date == today,
                )
                .first()
            )
            if existing:
                continue

            # Get the current version number
            latest_version = 1
            if rule.versions:
                latest_version = max(v.version for v in rule.versions)

            session.add(RuleMetricWindow(
                rule_id=rule.id,
                window_date=today,
                fire_count=rule.fire_count or 0,
                tp_count=rule.true_positive_count or 0,
                fp_count=rule.false_positive_count or 0,
                auto_resolved_count=0,
                version_at_window=latest_version,
            ))
            count += 1

    if count:
        logger.info("Computed %d rule metric windows for %s", count, today)
    return count


def run_retention() -> dict[str, int]:
    """Delete data older than retention thresholds. Returns counts deleted."""
    from sentinel_home.models import Event, EventRollup, Finding, StaleJob, DashboardStats

    settings = get_settings()
    now = datetime.now(timezone.utc)
    deleted = {}

    with session_scope() as session:
        # Events
        cutoff = now - timedelta(days=settings.retention.events_days)
        count = session.query(Event).filter(Event.ts < cutoff).delete()
        if count:
            deleted["events"] = count

        # Rollups
        cutoff = now - timedelta(days=settings.retention.rollups_days)
        count = session.query(EventRollup).filter(EventRollup.hour < cutoff).delete()
        if count:
            deleted["rollups"] = count

        # Findings — archive before deleting
        cutoff = now - timedelta(days=settings.retention.findings_days)
        from sentinel_home.models import FindingArchive
        expiring = session.query(Finding).filter(Finding.ts < cutoff).all()
        if expiring:
            for f in expiring:
                outcome = "dismissed" if f.dismissed else ("ack" if f.acknowledged else "unresolved")
                session.add(FindingArchive(
                    original_id=f.id,
                    ts=f.ts,
                    rule_name=f.rule_name,
                    device_id=f.device_id,
                    severity=f.severity,
                    confidence=f.confidence,
                    summary=f.summary,
                    likely_cause=f.likely_cause,
                    recommended_action=f.recommended_action,
                    outcome=outcome,
                    source=f.source,
                ))
            session.flush()
            count = session.query(Finding).filter(Finding.ts < cutoff).delete()
            deleted["findings"] = count
            deleted["findings_archived"] = len(expiring)

        # Stale jobs
        cutoff = now - timedelta(days=settings.retention.stale_jobs_days)
        count = session.query(StaleJob).filter(StaleJob.archived_at < cutoff).delete()
        if count:
            deleted["stale_jobs"] = count

        # Dashboard stats — keep last 7 days
        cutoff = now - timedelta(days=7)
        count = session.query(DashboardStats).filter(DashboardStats.computed_at < cutoff).delete()
        if count:
            deleted["dashboard_stats"] = count

        # Infrastructure metrics — keep last 7 days
        from sentinel_home.models import InfraMetric
        cutoff = now - timedelta(days=7)
        count = session.query(InfraMetric).filter(InfraMetric.ts < cutoff).delete()
        if count:
            deleted["infra_metrics"] = count

    if deleted:
        logger.info("Retention cleanup: %s", deleted)
    return deleted
