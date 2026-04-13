"""Reports + daily summaries — generated on schedule or on demand.

GET  /api/v1/reports                    — list generated reports
GET  /api/v1/reports/latest-summary     — most recent daily summary
POST /api/v1/reports/generate-summary   — generate summary on demand
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Alert, Device, Event, EventRollup, Finding, Rule

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory store for summaries (lightweight — no new DB table needed)
_summaries: list[dict] = []
MAX_SUMMARIES = 30


def _build_stats_summary(hours: int = 24) -> str:
    """Build a text summary of network stats for the LLM to summarize."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    with session_scope() as session:
        device_count = session.query(Device).count()
        new_devices = session.query(Device).filter(Device.first_seen >= cutoff).count()
        event_count = session.query(Event).filter(Event.ts >= cutoff).count()
        alert_count = session.query(Alert).filter(Alert.ts >= cutoff).count()

        # Top event types
        from sqlalchemy import func
        top_events = (
            session.query(Event.event_type, func.count(Event.id))
            .filter(Event.ts >= cutoff)
            .group_by(Event.event_type)
            .order_by(func.count(Event.id).desc())
            .limit(5)
            .all()
        )

        # High severity alerts
        high_alerts = (
            session.query(Alert)
            .filter(Alert.ts >= cutoff, Alert.severity.in_(["high", "critical"]))
            .order_by(Alert.ts.desc())
            .limit(5)
            .all()
        )
        # Extract alert data while session is open
        high_alert_data = [
            {"severity": a.severity, "rule_name": a.rule_name, "message": (a.message or "")[:100]}
            for a in high_alerts
        ]

        # WAN blocks from rollups
        from sqlalchemy import func as sqfunc
        wan_blocks = (
            session.query(sqfunc.coalesce(sqfunc.sum(EventRollup.count), 0))
            .filter(EventRollup.hour >= cutoff, EventRollup.event_type == "fw_wan_block")
            .scalar()
        ) or 0

        # Findings
        findings = session.query(Finding).filter(Finding.ts >= cutoff).count()

    lines = [
        f"Period: last {hours} hours",
        f"Total devices: {device_count} ({new_devices} new)",
        f"Events: {event_count}",
        f"Alerts: {alert_count}",
        f"WAN blocks: {wan_blocks}",
        f"Findings: {findings}",
    ]

    if top_events:
        lines.append("Top event types: " + ", ".join(
            f"{etype} ({cnt})" for etype, cnt in top_events
        ))

    if high_alert_data:
        lines.append("Notable alerts:")
        for a in high_alert_data:
            lines.append(f"  - [{a['severity']}] {a['rule_name']}: {a['message']}")

    return "\n".join(lines)


def generate_summary(hours: int = 24) -> dict:
    """Generate a summary — uses LLM if available, otherwise returns stats only."""
    stats_text = _build_stats_summary(hours)

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_hours": hours,
        "stats": stats_text,
        "llm_summary": None,
        "model": None,
    }

    # Try LLM summarization (logged to Open WebUI as its own chat)
    try:
        from sentinel_home.agent.llm_adapter import get_llm_adapter
        adapter = get_llm_adapter()
        if adapter and adapter.is_available():
            from sentinel_home.agent.tasks import SUMMARIZE_PERIOD
            response, _ = adapter.complete_with_persistence(
                system_prompt=SUMMARIZE_PERIOD.system_prompt,
                user_prompt=SUMMARIZE_PERIOD.user_template.format(
                    period=f"{hours} hours",
                    stats_summary=stats_text,
                ),
                chat_title=f"SentinelHome Daily Summary — {hours}h",
                max_tokens=SUMMARIZE_PERIOD.max_tokens,
                temperature=SUMMARIZE_PERIOD.temperature,
            )
            if response.success:
                summary["llm_summary"] = response.text
                summary["model"] = response.model
                logger.info("Daily summary generated (%d tokens, %.1fs)",
                           response.tokens_used, response.latency_seconds)
    except Exception as exc:
        logger.warning("LLM summary failed: %s", exc)

    # Store
    _summaries.append(summary)
    if len(_summaries) > MAX_SUMMARIES:
        _summaries[:] = _summaries[-MAX_SUMMARIES:]

    return summary


def generate_report(period_days: int = 7) -> dict:
    """Generate a periodic report with detailed stats."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=period_days)

    with session_scope() as session:
        from sqlalchemy import func

        # Device stats
        total_devices = session.query(Device).count()
        new_devices = session.query(Device).filter(Device.first_seen >= cutoff).count()

        # Event breakdown
        event_counts = (
            session.query(Event.source, func.count(Event.id))
            .filter(Event.ts >= cutoff)
            .group_by(Event.source)
            .all()
        )
        events_by_source = {src: cnt for src, cnt in event_counts}

        # Alert breakdown
        alert_counts = (
            session.query(Alert.rule_name, Alert.severity, func.count(Alert.id))
            .filter(Alert.ts >= cutoff)
            .group_by(Alert.rule_name, Alert.severity)
            .order_by(func.count(Alert.id).desc())
            .all()
        )
        alerts_by_rule = [
            {"rule": name, "severity": sev, "count": cnt}
            for name, sev, cnt in alert_counts
        ]

        # Rule performance
        rules = session.query(Rule).filter(Rule.enabled == True).all()
        rule_stats = []
        for r in rules:
            tp = r.true_positive_count or 0
            fp = r.false_positive_count or 0
            total = tp + fp
            rule_stats.append({
                "name": r.name, "severity": r.severity,
                "fire_count": r.fire_count,
                "tp": tp, "fp": fp,
                "fp_rate": f"{fp / total * 100:.0f}%" if total > 0 else "N/A",
            })

        # WAN blocks
        wan_blocks = (
            session.query(func.coalesce(func.sum(EventRollup.count), 0))
            .filter(EventRollup.hour >= cutoff, EventRollup.event_type == "fw_wan_block")
            .scalar()
        ) or 0

        # Top talkers (devices with most events)
        top_devices = (
            session.query(Event.device_id, func.count(Event.id).label("cnt"))
            .filter(Event.ts >= cutoff, Event.device_id.isnot(None))
            .group_by(Event.device_id)
            .order_by(func.count(Event.id).desc())
            .limit(10)
            .all()
        )
        # Bulk-load devices to avoid N+1 queries
        device_macs = [mac for mac, _ in top_devices]
        dev_map = {}
        if device_macs:
            devs = session.query(Device).filter(Device.mac.in_(device_macs)).all()
            dev_map = {d.mac: d for d in devs}
        top_talkers = []
        for mac, cnt in top_devices:
            dev = dev_map.get(mac)
            top_talkers.append({
                "mac": mac,
                "label": (dev.label or dev.vendor or mac[:8]) if dev else mac,
                "event_count": cnt,
            })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_days": period_days,
        "devices": {"total": total_devices, "new": new_devices},
        "events_by_source": events_by_source,
        "alerts_by_rule": alerts_by_rule,
        "rule_performance": rule_stats,
        "wan_blocks": wan_blocks,
        "top_talkers": top_talkers,
    }

    # Try LLM executive summary (logged to Open WebUI)
    try:
        from sentinel_home.agent.llm_adapter import get_llm_adapter
        adapter = get_llm_adapter()
        if adapter and adapter.is_available():
            stats_text = _build_stats_summary(period_days * 24)
            from sentinel_home.agent.tasks import SUMMARIZE_PERIOD
            response, _ = adapter.complete_with_persistence(
                system_prompt=SUMMARIZE_PERIOD.system_prompt,
                user_prompt=SUMMARIZE_PERIOD.user_template.format(
                    period=f"{period_days} days",
                    stats_summary=stats_text,
                ),
                chat_title=f"SentinelHome Report — {period_days}d",
                max_tokens=300,
                temperature=1.0,
            )
            if response.success:
                report["executive_summary"] = response.text
    except Exception:
        pass

    return report


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@router.get("/reports/latest-summary")
async def latest_summary():
    """Return the most recent daily summary."""
    if _summaries:
        return ok_envelope(_summaries[-1])
    return ok_envelope({"message": "No summaries generated yet. Wait for the daily job or generate one manually."})


@router.post("/reports/generate-summary")
async def trigger_summary(hours: int = Query(24, ge=1, le=168)):
    """Generate a summary on demand."""
    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, generate_summary, hours)
    return ok_envelope(result)


@router.post("/reports/generate")
async def trigger_report(days: int = Query(7, ge=1, le=90)):
    """Generate a periodic report on demand."""
    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, generate_report, days)
    return ok_envelope(result)


@router.get("/reports/summaries")
async def list_summaries():
    """List all stored summaries."""
    return ok_envelope(_summaries[-10:])
