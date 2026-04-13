"""Message formatting for notifications.

Converts Alert rows into human-readable messages for different channels.
"""

from __future__ import annotations

from datetime import datetime, timezone


def format_alert(
    rule_name: str,
    severity: str,
    message: str,
    device_id: str | None = None,
    ts: datetime | None = None,
) -> dict[str, str]:
    """Format an alert into title + body for notification dispatch.

    Returns dict with 'title' and 'body' keys.
    """
    ts = ts or datetime.now(timezone.utc)
    ts_str = ts.strftime("%Y-%m-%d %H:%M UTC")

    severity_icon = {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "low": "[LOW]",
        "info": "[INFO]",
    }.get(severity.lower(), "[ALERT]")

    title = f"SentinelHome {severity_icon} {rule_name}"

    lines = [message]
    if device_id:
        lines.append(f"Device: {device_id}")
    lines.append(f"Time: {ts_str}")

    body = "\n".join(lines)

    return {"title": title, "body": body}
