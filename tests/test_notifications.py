"""Tests for notification routing and formatting."""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from sentinel_home.notifications.formatter import format_alert
from sentinel_home.notifications import router as router_mod


# ===========================================================================
# format_alert
# ===========================================================================

class TestFormatAlert:
    def test_basic_format(self):
        result = format_alert(
            rule_name="wan_port_scan",
            severity="high",
            message="Port scan detected from 203.0.113.50",
        )
        assert "title" in result
        assert "body" in result
        assert "wan_port_scan" in result["title"]
        assert "[HIGH]" in result["title"]
        assert "SentinelHome" in result["title"]
        assert "Port scan" in result["body"]

    def test_with_device(self):
        result = format_alert(
            rule_name="wifi_deauth_storm",
            severity="medium",
            message="Deauth storm on ath0",
            device_id="aa:bb:cc:dd:ee:ff",
        )
        assert "aa:bb:cc:dd:ee:ff" in result["body"]
        assert "Device:" in result["body"]

    def test_severity_icons(self):
        for sev, label in [
            ("critical", "[CRITICAL]"),
            ("high", "[HIGH]"),
            ("medium", "[MEDIUM]"),
            ("low", "[LOW]"),
            ("info", "[INFO]"),
        ]:
            result = format_alert("test", sev, "msg")
            assert label in result["title"]

    def test_custom_timestamp(self):
        ts = datetime(2026, 3, 18, 14, 30, 0, tzinfo=timezone.utc)
        result = format_alert("test", "info", "msg", ts=ts)
        assert "2026-03-18 14:30 UTC" in result["body"]

    def test_no_device(self):
        result = format_alert("test", "info", "msg")
        assert "Device:" not in result["body"]


# ===========================================================================
# should_notify (severity filtering)
# ===========================================================================

class TestShouldNotify:
    """Test the _SEVERITY_ORDER-based filtering directly."""

    def test_severity_order_high_threshold(self):
        # Directly test the logic using the module's _SEVERITY_ORDER
        order = router_mod._SEVERITY_ORDER
        min_val = order.get("high", 3)
        assert order.get("high", 0) >= min_val
        assert order.get("critical", 0) >= min_val
        assert order.get("medium", 0) < min_val
        assert order.get("low", 0) < min_val
        assert order.get("info", 0) < min_val

    def test_severity_order_medium_threshold(self):
        order = router_mod._SEVERITY_ORDER
        min_val = order.get("medium", 2)
        assert order.get("medium", 0) >= min_val
        assert order.get("high", 0) >= min_val
        assert order.get("critical", 0) >= min_val
        assert order.get("low", 0) < min_val
        assert order.get("info", 0) < min_val

    def test_severity_order_info_threshold(self):
        order = router_mod._SEVERITY_ORDER
        min_val = order.get("info", 0)
        # Everything should pass
        for sev in ("info", "low", "medium", "high", "critical"):
            assert order.get(sev, 0) >= min_val


# ===========================================================================
# send_alert (integration -- no URLs configured)
# ===========================================================================

class TestSendAlert:
    def test_send_returns_false_no_urls(self):
        """send_alert returns False when no notification URLs are configured."""
        # Reset the module state so it re-initializes
        router_mod._initialized = False
        router_mod._apprise_instance = None

        result = router_mod.send_alert(
            rule_name="test_rule",
            severity="critical",
            message="Test alert",
        )
        assert result is False
