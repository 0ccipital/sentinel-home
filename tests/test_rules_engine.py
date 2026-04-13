"""Tests for the rule engine — matching, windowed counting, cooldowns, suppression."""
import time
import pytest

from sentinel_home.parsers import ParseResult
from sentinel_home.rules.engine import RuleEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(**overrides) -> dict:
    """Build a rule dict with sensible defaults."""
    base = {
        "id": 1,
        "name": "test_rule",
        "category": "network",
        "severity": "medium",
        "priority": 2,
        "parameters": {},
        "action": "log",
        "cooldown_seconds": 0,
        "frozen": False,
    }
    base.update(overrides)
    return base


def _make_result(**overrides) -> ParseResult:
    """Build a ParseResult with sensible defaults."""
    base = {
        "event_type": "fw_wan_block",
        "severity": "info",
        "category": "network",
        "message": "WAN block: 203.0.113.50:54321 -> 192.168.1.1:22 (TCP)",
        "fields": {"src": "203.0.113.50", "dst": "192.168.1.1", "dpt": "22", "proto": "TCP"},
    }
    base.update(overrides)
    return ParseResult(**base)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRuleMatching:
    """Test _rule_matches with different parameter configurations."""

    def setup_method(self):
        self.engine = RuleEngine()

    def test_match_event_types(self):
        rule = _make_rule(parameters={"match_event_types": ["fw_wan_block", "fw_block"]})
        result = _make_result(event_type="fw_wan_block")
        assert self.engine._rule_matches(rule, result) is True

    def test_no_match_event_types(self):
        rule = _make_rule(parameters={"match_event_types": ["wifi_auth_reject"]})
        result = _make_result(event_type="fw_wan_block")
        assert self.engine._rule_matches(rule, result) is False

    def test_field_match_exact(self):
        rule = _make_rule(parameters={
            "match_event_types": ["fw_wan_block"],
            "match_fields": {"dpt": "22"},
        })
        result = _make_result(fields={"src": "10.0.0.1", "dpt": "22"})
        assert self.engine._rule_matches(rule, result) is True

    def test_field_match_list(self):
        rule = _make_rule(parameters={
            "match_event_types": ["fw_wan_block"],
            "match_fields": {"dpt": ["22", "23", "3389"]},
        })
        result = _make_result(fields={"src": "10.0.0.1", "dpt": "23"})
        assert self.engine._rule_matches(rule, result) is True

    def test_field_match_no_match(self):
        rule = _make_rule(parameters={
            "match_event_types": ["fw_wan_block"],
            "match_fields": {"dpt": "22"},
        })
        result = _make_result(fields={"src": "10.0.0.1", "dpt": "80"})
        assert self.engine._rule_matches(rule, result) is False

    def test_match_patterns(self):
        rule = _make_rule(parameters={
            "match_event_types": ["fw_wan_block"],
            "match_patterns": ["port 22"],
        })
        result = _make_result(message="WAN block: port 22 from outside")
        assert self.engine._rule_matches(rule, result) is True

    def test_no_criteria_no_match(self):
        """Rules with no criteria should NOT match anything (safety)."""
        rule = _make_rule(parameters={})
        result = _make_result()
        assert self.engine._rule_matches(rule, result) is False

    def test_match_source_syslog(self):
        rule = _make_rule(parameters={"match_source": "syslog", "match_event_types": ["fw_wan_block"]})
        result = _make_result(event_type="fw_wan_block")
        assert self.engine._rule_matches(rule, result) is True

    def test_match_source_syslog_wrong_event(self):
        rule = _make_rule(parameters={"match_source": "syslog", "match_event_types": ["arp_conflict"]})
        result = _make_result(event_type="arp_conflict")
        # arp_conflict is a sniff event, not syslog
        assert self.engine._rule_matches(rule, result) is False


class TestWindowedCount:
    """Test windowed counting detection."""

    def setup_method(self):
        self.engine = RuleEngine()

    def test_below_threshold(self):
        rule = _make_rule(parameters={
            "window_seconds": 60,
            "event_threshold": 5,
        })
        result = _make_result()
        # Fire 4 events — should not trigger
        for _ in range(4):
            assert self.engine._check_windowed(rule, result) is False

    def test_at_threshold(self):
        rule = _make_rule(parameters={
            "window_seconds": 60,
            "event_threshold": 5,
        })
        result = _make_result()
        # Fire 4 below, then 5th triggers
        for _ in range(4):
            self.engine._check_windowed(rule, result)
        assert self.engine._check_windowed(rule, result) is True

    def test_window_expiry(self):
        rule = _make_rule(parameters={
            "window_seconds": 1,  # 1 second window
            "event_threshold": 3,
        })
        result = _make_result()
        # Add 2 events
        self.engine._check_windowed(rule, result)
        self.engine._check_windowed(rule, result)
        # Wait for window to expire
        time.sleep(1.1)
        # These should start a new window
        assert self.engine._check_windowed(rule, result) is False

    def test_no_window_always_fires(self):
        rule = _make_rule(parameters={})
        result = _make_result()
        assert self.engine._check_windowed(rule, result) is True

    def test_distinct_ports_threshold(self):
        rule = _make_rule(parameters={
            "window_seconds": 60,
            "distinct_ports_threshold": 3,
        })
        # 3 events with distinct ports
        for port in ["22", "80", "443"]:
            result = _make_result(fields={"src": "10.0.0.1", "dpt": port})
            fired = self.engine._check_windowed(rule, result)
        assert fired is True

    def test_distinct_ports_below_threshold(self):
        rule = _make_rule(parameters={
            "window_seconds": 60,
            "distinct_ports_threshold": 5,
        })
        for port in ["22", "80"]:
            result = _make_result(fields={"src": "10.0.0.1", "dpt": port})
            fired = self.engine._check_windowed(rule, result)
        assert fired is False


class TestCooldown:
    """Test cooldown behavior."""

    def setup_method(self):
        self.engine = RuleEngine()

    def test_no_cooldown_always_fires(self):
        rule = _make_rule(cooldown_seconds=0)
        assert self.engine._check_cooldown(rule) is True
        assert self.engine._check_cooldown(rule) is True

    def test_cooldown_blocks_second_fire(self):
        rule = _make_rule(id=10, cooldown_seconds=60)
        # Simulate first fire
        self.engine._last_fired[10] = time.time()
        assert self.engine._check_cooldown(rule) is False

    def test_cooldown_expires(self):
        rule = _make_rule(id=11, cooldown_seconds=1)
        # Simulate fire 2 seconds ago
        self.engine._last_fired[11] = time.time() - 2
        assert self.engine._check_cooldown(rule) is True


class TestSuppression:
    """Test suppression pattern checking."""

    def setup_method(self):
        self.engine = RuleEngine()
        # Bypass DB loading by setting suppressions directly
        self.engine._suppressions_ts = time.time()

    def test_no_suppressions(self):
        self.engine._suppressions = []
        result = _make_result()
        assert self.engine._is_suppressed(result) is False

    def test_wildcard_suppression(self):
        self.engine._suppressions = [
            {"scope": "*", "definition": {"event_type": "fw_wan_block"}},
        ]
        result = _make_result(event_type="fw_wan_block")
        assert self.engine._is_suppressed(result) is True

    def test_mac_scope_suppression(self):
        self.engine._suppressions = [
            {"scope": "aa:bb:cc:dd:ee:ff", "definition": {"event_type": "wifi_deauth"}},
        ]
        result = _make_result(
            event_type="wifi_deauth",
            fields={"mac": "aa:bb:cc:dd:ee:ff"},
        )
        assert self.engine._is_suppressed(result) is True

    def test_mac_scope_no_match(self):
        self.engine._suppressions = [
            {"scope": "aa:bb:cc:dd:ee:ff", "definition": {"event_type": "wifi_deauth"}},
        ]
        result = _make_result(
            event_type="wifi_deauth",
            fields={"mac": "11:22:33:44:55:66"},
        )
        assert self.engine._is_suppressed(result) is False

    def test_event_type_no_match(self):
        self.engine._suppressions = [
            {"scope": "*", "definition": {"event_type": "fw_wan_block"}},
        ]
        result = _make_result(event_type="wifi_auth_success")
        assert self.engine._is_suppressed(result) is False


class TestFireRule:
    """Test direct fire_rule from collectors."""

    def setup_method(self):
        self.engine = RuleEngine()
        # Preload rules cache
        self.engine._cache_ts = time.time()

    def test_fire_rule_not_found(self):
        self.engine._rules_cache = []
        # Should not raise, just log and return
        self.engine.fire_rule("nonexistent_rule", "aa:bb:cc:dd:ee:ff", {"test": True})

    def test_fire_rule_cooldown_blocks(self):
        rule = _make_rule(id=20, name="test_direct", cooldown_seconds=60)
        self.engine._rules_cache = [rule]
        self.engine._last_fired[20] = time.time()
        # Should be blocked by cooldown
        self.engine.fire_rule("test_direct", "aa:bb:cc:dd:ee:ff", {"test": True})
        # No error is success — the cooldown silently blocked it


class TestEngineStats:
    def test_get_stats(self):
        engine = RuleEngine()
        stats = engine.get_stats()
        assert "rules_cached" in stats
        assert "window_groups" in stats
        assert "cooldowns_active" in stats
