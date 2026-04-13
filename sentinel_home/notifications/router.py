"""Notification router — dispatches alerts via Apprise.

Apprise supports 80+ services via URL strings:
  - Slack:    slack://token_a/token_b/token_c
  - Discord:  discord://webhook_id/webhook_token
  - Telegram: tgram://bot_token/chat_id
  - Email:    mailto://user:pass@gmail.com
  - Pushover: pover://user_key@token
  - etc.

Configure in config.yaml:
  notifications:
    enabled: true
    urls:
      - "slack://..."
      - "tgram://..."
    min_severity: high    # only notify for high/critical

This module is ready but not wired into the main alert path for v1.0.
The dashboard is the primary notification channel. Apprise dispatch
can be enabled by adding notification URLs to the config.
"""

from __future__ import annotations

import logging

from sentinel_home.notifications.formatter import format_alert

logger = logging.getLogger(__name__)

_apprise_instance = None
_initialized = False


def _get_apprise():
    """Lazy-init Apprise with configured URLs."""
    global _apprise_instance, _initialized
    if _initialized:
        return _apprise_instance

    _initialized = True
    try:
        import apprise
        from sentinel_home.config import get_settings
        settings = get_settings()

        urls = getattr(getattr(settings, "notifications", None), "urls", [])
        if not urls:
            logger.debug("No notification URLs configured — notifications disabled")
            return None

        _apprise_instance = apprise.Apprise()
        for url in urls:
            _apprise_instance.add(url)

        logger.info("Notification router initialised with %d target(s)", len(urls))
        return _apprise_instance
    except ImportError:
        logger.warning("Apprise not installed — notifications disabled")
        return None
    except Exception as exc:
        logger.warning("Failed to initialise notifications: %s", exc)
        return None


# Severity ordering for min_severity filter
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def should_notify(severity: str) -> bool:
    """Check if a severity level meets the minimum threshold for notification."""
    try:
        from sentinel_home.config import get_settings
        settings = get_settings()
        min_sev = getattr(getattr(settings, "notifications", None), "min_severity", "high")
    except Exception:
        min_sev = "high"

    return _SEVERITY_ORDER.get(severity.lower(), 0) >= _SEVERITY_ORDER.get(min_sev.lower(), 3)


def send_alert(
    rule_name: str,
    severity: str,
    message: str,
    device_id: str | None = None,
) -> bool:
    """Send an alert notification via Apprise. Returns True if sent.

    Respects min_severity config — won't send low-severity alerts
    unless configured to do so.
    """
    if not should_notify(severity):
        return False

    ap = _get_apprise()
    if ap is None:
        return False

    try:
        formatted = format_alert(rule_name, severity, message, device_id)

        # Map severity to Apprise notify type
        import apprise
        notify_type = {
            "critical": apprise.NotifyType.FAILURE,
            "high": apprise.NotifyType.WARNING,
            "medium": apprise.NotifyType.INFO,
            "low": apprise.NotifyType.INFO,
            "info": apprise.NotifyType.INFO,
        }.get(severity.lower(), apprise.NotifyType.INFO)

        result = ap.notify(
            title=formatted["title"],
            body=formatted["body"],
            notify_type=notify_type,
        )
        if result:
            logger.info("Notification sent: %s", rule_name)
        else:
            logger.warning("Notification send failed: %s", rule_name)
        return result

    except Exception as exc:
        logger.error("Notification error: %s", exc)
        return False
