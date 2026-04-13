"""Rule engine — evaluates events against DB-stored rules.

Design:
  - Rules live in the database, not Python. Thresholds, windows, cooldowns
    are all configurable via the Rule.parameters JSON field.
  - The engine implements a small set of detection strategies. Each rule's
    parameters select and configure a strategy.
  - The agent can create new rules using the same parameter structure,
    including a generic field-match strategy for patterns the engine
    doesn't have hardcoded detection for.
  - The engine is the floor, not the ceiling. It catches known patterns.
    The agent analyzes everything the engine doesn't catch via the API.

Detection strategies:
  - windowed_count: Count events in a time window, fire when threshold exceeded
  - baseline_check: Fire when a device MAC isn't in the baseline
  - field_match: Fire when event fields match a set of conditions (agent-creatable)
  - always: Fire on any matching event (simple alerts)

The engine does NOT handle:
  - nmap diff comparison (nmap collector handles its own diffing)
  - Sniff-based detection (ARP conflicts, UPnP, SMB — sniff collector handles these)
  These collectors call fire_rule() directly when they detect something.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sentinel_home.parsers import ParseResult

logger = logging.getLogger(__name__)

# How often (in evaluations) to prune stale window entries
WINDOW_PRUNE_INTERVAL = 500
# Max age (seconds) for window entries before pruning — 1 hour
WINDOW_ENTRY_MAX_AGE = 3600
# How long (seconds) to cache the rules list from the DB
RULES_CACHE_TTL = 30


class RuleEngine:
    """Evaluates ParseResults against DB rules. Maintains windowed state in memory."""

    def __init__(self):
        self._rules_cache: list[dict] = []
        self._cache_ts: float = 0.0
        self._cache_ttl: float = RULES_CACHE_TTL

        # Windowed state: rule_id -> grouping_key -> [(timestamp, data)]
        self._windows: dict[int, dict[str, list[tuple[float, dict]]]] = defaultdict(
            lambda: defaultdict(list)
        )

        # Cooldown tracking: rule_id -> last_fired_timestamp
        self._last_fired: dict[int, float] = {}

        # Known MACs for baseline check (populated on first use)
        self._known_macs: set[str] | None = None

        # Suppression patterns (cached, refreshed with rules)
        self._suppressions: list[dict] = []
        self._suppressions_ts: float = 0.0

        # Prune counter — prune windows every WINDOW_PRUNE_INTERVAL evaluations
        self._eval_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, result: ParseResult, source_ip: str | None = None) -> list[dict]:
        """Evaluate a parsed event against all enabled rules.

        Returns list of fired rule dicts (for logging/testing). Side effects:
        - Updates Rule.fire_count and Rule.last_fired in DB
        - Creates Alert rows for action="alert" rules
        - Enqueues jobs for action="investigate" rules
        - Logs for action="log" rules
        """
        # Check suppression patterns first — skip event entirely if suppressed
        if self._is_suppressed(result):
            return []

        # Periodically prune stale window entries
        self._eval_count += 1
        if self._eval_count % WINDOW_PRUNE_INTERVAL == 0:
            self._prune_windows()

        rules = self._get_rules()
        fired = []

        for rule in rules:
            if self._rule_matches(rule, result):
                if self._check_cooldown(rule):
                    action = self._execute_rule(rule, result, source_ip)
                    if action:
                        fired.append(action)

        return fired

    def fire_rule(self, rule_name: str, device_id: str | None, context: dict) -> None:
        """Direct fire from collectors that do their own detection (sniff, nmap).

        Bypasses the matching/windowing logic — the caller already determined
        this rule should fire. Still respects cooldowns and updates counters.
        """
        rules = self._get_rules()
        rule = next((r for r in rules if r["name"] == rule_name), None)
        if not rule:
            logger.debug("fire_rule: rule %s not found in DB", rule_name)
            return

        if not self._check_cooldown(rule):
            return

        self._do_fire(rule, device_id, context)

    # ------------------------------------------------------------------
    # Suppression patterns
    # ------------------------------------------------------------------

    def _load_suppressions(self) -> list[dict]:
        """Load active suppression patterns from DB, cached for 30s."""
        now = time.time()
        if now - self._suppressions_ts < self._cache_ttl and self._suppressions:
            return self._suppressions

        try:
            from sentinel_home.database import session_scope
            from sentinel_home.models import Pattern

            with session_scope() as session:
                patterns = (
                    session.query(Pattern)
                    .filter(Pattern.pattern_type == "suppression")
                    .all()
                )
                self._suppressions = [
                    {
                        "scope": p.scope,
                        "definition": p.definition or {},
                    }
                    for p in patterns
                ]
            self._suppressions_ts = now
        except Exception as exc:
            logger.debug("Failed to load suppression patterns: %s", exc)

        return self._suppressions

    def _is_suppressed(self, result: ParseResult) -> bool:
        """Check if an event matches any suppression pattern."""
        suppressions = self._load_suppressions()
        if not suppressions:
            return False

        device_mac = result.fields.get("mac", "")

        for sup in suppressions:
            defn = sup["definition"]
            scope = sup["scope"]

            # Scope check: * matches all, otherwise must match device MAC
            if scope != "*" and scope != device_mac:
                continue

            # Event type match
            sup_event_type = defn.get("event_type")
            if sup_event_type and sup_event_type != result.event_type:
                continue

            # Source match (optional)
            sup_source = defn.get("source")
            if sup_source and sup_source != result.fields.get("source", ""):
                continue

            # All criteria matched — suppress this event
            logger.debug("Event suppressed: %s (device=%s) by pattern scope=%s",
                        result.event_type, device_mac, scope)
            return True

        return False

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _get_rules(self) -> list[dict]:
        """Return cached rules, refreshing from DB if stale."""
        now = time.time()
        if now - self._cache_ts < self._cache_ttl and self._rules_cache:
            return self._rules_cache

        try:
            from sentinel_home.database import session_scope
            from sentinel_home.models import Rule

            with session_scope() as session:
                db_rules = (
                    session.query(Rule)
                    .filter(Rule.enabled == True, Rule.approved == True)
                    .all()
                )
                self._rules_cache = [
                    {
                        "id": r.id,
                        "name": r.name,
                        "category": r.category,
                        "severity": r.severity,
                        "priority": r.priority,
                        "parameters": r.parameters or {},
                        "action": r.action,
                        "cooldown_seconds": r.cooldown_seconds,
                        "frozen": r.frozen,
                    }
                    for r in db_rules
                ]
            self._cache_ts = now
        except Exception as exc:
            logger.error("Failed to load rules from DB: %s", exc)
            # Keep using stale cache

        return self._rules_cache

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def _rule_matches(self, rule: dict, result: ParseResult) -> bool:
        """Check if a ParseResult matches a rule's parameters."""
        params = rule["parameters"]

        # Source filter
        match_source = params.get("match_source")
        if match_source:
            # Map parser sources to rule sources
            source_map = {
                "syslog": ("syslog_file", "syslog_server", "syslog"),
                "sniff": ("sniff",),
                "nmap": ("nmap",),
                "pihole": ("pihole",),
            }
            # For syslog rules, check event_type prefixes instead of collector source
            if match_source == "syslog" and not self._event_is_syslog(result):
                return False
            elif match_source == "sniff" and not self._event_is_sniff(result):
                return False
            elif match_source == "nmap" and not self._event_is_nmap(result):
                return False
            elif match_source == "pihole" and not self._event_is_pihole(result):
                return False
            elif match_source == "unifi":
                # UniFi infrastructure rules only fire via fire_rule() from
                # the UniFi collector — never from the syslog evaluate() path.
                return False

        # Event type filter
        match_types = params.get("match_event_types")
        if match_types and result.event_type not in match_types:
            return False

        # Field match (agent-creatable generic rules)
        match_fields = params.get("match_fields")
        if match_fields:
            for field_name, expected in match_fields.items():
                actual = result.fields.get(field_name)
                if isinstance(expected, list):
                    if actual not in expected:
                        return False
                elif actual != expected:
                    return False

        # Pattern match on message
        match_patterns = params.get("match_patterns")
        if match_patterns:
            msg_lower = result.message.lower()
            if not any(p.lower() in msg_lower for p in match_patterns):
                return False

        # If no filters at all, don't match (safety — rules must have criteria)
        if not any(k in params for k in ("match_source", "match_event_types",
                                          "match_fields", "match_patterns",
                                          "check_baseline", "check_smb_whitelist")):
            return False

        return True

    def _event_is_syslog(self, result: ParseResult) -> bool:
        """Check if event came from syslog parsing."""
        syslog_types = {
            "fw_wan_block", "fw_block", "fw_lan_traffic",
            "wifi_auth_success", "wifi_auth_reject", "wifi_disassoc", "wifi_deauth",
            "wifi_assoc", "wifi_anomaly",
            "sta_assoc", "sta_leave", "sta_roam", "sta_join", "sta_ip_assign",
            "sta_soft_failure", "dns_timeout",
            "switch_provision", "switch_state", "switch_config_write", "switch_authkey_leak",
            "disk_warning", "docker_crash", "emhttpd_event", "mover_event",
            "sudo_session", "ssh_auth",
            "dhcp_dhcpack", "dhcp_dhcpdiscover", "dhcp_dhcprequest",
            "dns_query", "dns_reply",
        }
        return result.event_type in syslog_types

    def _event_is_sniff(self, result: ParseResult) -> bool:
        # Sniff events normally bypass evaluate() via fire_rule(), so this
        # guard only prevents syslog-parsed events from matching sniff rules.
        return result.event_type in {"arp_conflict", "upnp_port_request", "unexpected_smb_traffic"}

    def _event_is_nmap(self, result: ParseResult) -> bool:
        return result.event_type in {"new_open_port", "nmap_diff"}

    def _event_is_pihole(self, result: ParseResult) -> bool:
        return result.event_type in {"dns_query", "dns_reply", "suspicious_dns"}

    # ------------------------------------------------------------------
    # Windowed detection
    # ------------------------------------------------------------------

    def _check_windowed(self, rule: dict, result: ParseResult) -> bool:
        """Apply windowed counting if the rule has window parameters.

        Returns True if the threshold is exceeded (rule should fire).
        """
        params = rule["parameters"]
        window_seconds = params.get("window_seconds")
        if not window_seconds:
            return True  # No window = fire on every match

        now = time.time()
        rule_id = rule["id"]

        # Determine grouping key (e.g., src IP for port scans, vap for deauth)
        group_key = self._get_group_key(rule, result)
        entries = self._windows[rule_id][group_key]

        # Add current event
        entries.append((now, dict(result.fields)))

        # Prune entries outside the window
        cutoff = now - window_seconds
        entries[:] = [(ts, d) for ts, d in entries if ts >= cutoff]

        # Check threshold — use explicit None check so threshold=0 isn't ignored
        _et = params.get("event_threshold")
        _rt = params.get("repeat_threshold")
        threshold = _et if _et is not None else _rt
        distinct_ports_threshold = params.get("distinct_ports_threshold")

        if distinct_ports_threshold:
            # Port scan detection: count distinct destination ports
            distinct = len(set(d.get("dpt", "") for _, d in entries))
            if distinct >= distinct_ports_threshold:
                entries.clear()
                return True
            return False

        if threshold:
            if len(entries) >= threshold:
                entries.clear()
                return True
            return False

        # No threshold specified = fire on every match within window
        return True

    def _get_group_key(self, rule: dict, result: ParseResult) -> str:
        """Determine how to group events for windowed counting."""
        params = rule["parameters"]

        # Port scan / targeted attack: group by source IP
        if params.get("distinct_ports_threshold") or rule["name"] == "wan_targeted_attack":
            src = result.fields.get("src", "")
            dpt = result.fields.get("dpt", "")
            if rule["name"] == "wan_targeted_attack":
                return f"{src}:{dpt}"
            return src

        # Deauth storm: group by VAP
        if rule["name"] in ("wifi_deauth_storm",):
            return result.fields.get("vap", "default")

        # DNS timeout: group by client MAC
        if rule["name"] == "dns_timeout_anomaly":
            return result.fields.get("mac", "default")

        return "default"

    # ------------------------------------------------------------------
    # Cooldowns
    # ------------------------------------------------------------------

    def _check_cooldown(self, rule: dict) -> bool:
        """Return True if the rule is allowed to fire (cooldown expired)."""
        cooldown = rule["cooldown_seconds"]
        if cooldown <= 0:
            return True

        now = time.time()
        last = self._last_fired.get(rule["id"], 0)
        if now - last < cooldown:
            return False
        return True

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _execute_rule(self, rule: dict, result: ParseResult, source_ip: str | None) -> dict | None:
        """Run the full detection logic for a matched rule."""
        params = rule["parameters"]

        # Baseline check (unknown_device)
        if params.get("check_baseline"):
            mac = result.fields.get("mac", "")
            if mac and self._is_known_device(mac):
                return None  # Known device, don't fire

        # Windowed counting
        if params.get("window_seconds"):
            if not self._check_windowed(rule, result):
                return None  # Threshold not yet reached

        # Whitelist checks
        if params.get("check_smb_whitelist"):
            from sentinel_home.config import get_settings
            whitelist = get_settings().network.smb_whitelist
            src = result.fields.get("src", "")
            dst = result.fields.get("dst", "")
            if src in whitelist or dst in whitelist:
                return None

        # Rule fires
        context = {
            "event_type": result.event_type,
            "message": result.message,
            "severity": result.severity,
            "category": result.category,
            **result.fields,
        }
        if source_ip:
            context["source_ip"] = source_ip

        return self._do_fire(rule, result.fields.get("mac"), context)

    def _do_fire(self, rule: dict, device_id: str | None, context: dict) -> dict:
        """Execute the rule's action and update DB counters."""
        self._last_fired[rule["id"]] = time.time()

        # Update rule counters in DB
        self._update_rule_counters(rule["id"])

        action = rule["action"]
        rule_name = rule["name"]
        severity = rule["severity"]
        message = context.get("message", rule_name)

        if action == "alert":
            self._create_alert(rule, device_id, message, context)
        elif action == "investigate":
            self._enqueue_job(rule, device_id, context)
        # action == "log" — just the counter update, no alert or job

        logger.info("Rule fired: %s (action=%s, severity=%s)", rule_name, action, severity)
        return {"rule": rule_name, "action": action, "severity": severity}

    # ------------------------------------------------------------------
    # DB operations
    # ------------------------------------------------------------------

    def _update_rule_counters(self, rule_id: int) -> None:
        """Increment fire_count and set last_fired on the Rule."""
        try:
            from sentinel_home.database import session_scope
            from sentinel_home.models import Rule

            with session_scope() as session:
                rule = session.query(Rule).filter(Rule.id == rule_id).first()
                if rule:
                    rule.fire_count = (rule.fire_count or 0) + 1
                    rule.last_fired = datetime.now(timezone.utc)
        except Exception as exc:
            logger.debug("Failed to update rule counters: %s", exc)

    def _create_alert(self, rule: dict, device_id: str | None, message: str,
                      context: dict | None = None) -> None:
        """Persist a direct alert with full triggering context."""
        try:
            from sentinel_home.database import session_scope
            from sentinel_home.models import Alert

            # Build rich context: rule parameters + triggering event fields
            alert_context = {}
            if rule.get("parameters"):
                alert_context["rule_parameters"] = rule["parameters"]
            if context:
                # Preserve all event fields except redundant keys
                for k, v in context.items():
                    if k not in ("rule_name", "rule_id"):
                        alert_context[k] = v

            with session_scope() as session:
                session.add(Alert(
                    rule_name=rule["name"],
                    rule_id=rule["id"],
                    device_id=device_id,
                    severity=rule["severity"],
                    message=message[:500],
                    context=alert_context or None,
                ))
            logger.warning("[ALERT] %s | device=%s | %s", rule["name"], device_id, message[:200])
        except Exception as exc:
            logger.error("Failed to create alert: %s", exc)
            return

        # Send notification if configured
        try:
            from sentinel_home.notifications.router import send_alert
            send_alert(
                rule_name=rule["name"],
                severity=rule["severity"],
                message=message[:500],
                device_id=device_id,
            )
        except Exception as exc:
            logger.debug("Notification send skipped: %s", exc)

    def _enqueue_job(self, rule: dict, device_id: str | None, context: dict) -> None:
        """Enqueue a job for agent investigation."""
        try:
            from sentinel_home.queue.manager import enqueue_job
            enqueue_job(
                source="rule_engine",
                rule_name=rule["name"],
                rule_id=rule["id"],
                device_id=device_id,
                priority=rule["priority"],
                context=context,
            )
        except Exception as exc:
            logger.error("Failed to enqueue job: %s", exc)

    def _is_known_device(self, mac: str) -> bool:
        """Check if a MAC is in the baseline."""
        if self._known_macs is None:
            from sentinel_home.baseline.manager import get_all_known_macs
            self._known_macs = get_all_known_macs()

        return mac.lower() in self._known_macs

    def refresh_known_macs(self) -> None:
        """Force reload of known MACs (call after baseline update)."""
        self._known_macs = None

    # ------------------------------------------------------------------
    # Memory management
    # ------------------------------------------------------------------

    def _prune_windows(self) -> None:
        """Remove stale window entries to prevent unbounded memory growth."""
        now = time.time()
        for rule_id, groups in list(self._windows.items()):
            for key, entries in list(groups.items()):
                entries[:] = [(ts, d) for ts, d in entries if now - ts < WINDOW_ENTRY_MAX_AGE]
                if not entries:
                    del groups[key]
            if not groups:
                del self._windows[rule_id]

    def get_stats(self) -> dict:
        """Return engine stats for the status endpoint."""
        return {
            "rules_cached": len(self._rules_cache),
            "window_groups": sum(len(g) for g in self._windows.values()),
            "cooldowns_active": len(self._last_fired),
        }


# Module-level singleton
_engine: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine
