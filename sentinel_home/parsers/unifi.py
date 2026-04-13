"""UniFi-specific syslog parser.

Handles events unique to UniFi firmware that aren't covered by
the generic iptables/hostapd parsers:
  - STA_ASSOC_TRACKER JSON (stahtd_dump_event)
  - wevent custom events (EVENT_STA_JOIN/LEAVE/IP)
  - DNS timeout tracking (STA_TRACKER)
  - Wireless anomaly reports
  - Switch state transitions and provisioning
"""

from __future__ import annotations

import json
import re

from sentinel_home.parsers import ParseResult


# STA_ASSOC_TRACKER JSON: stahtd_dump_event(): {...}
_STA_TRACKER_JSON_RE = re.compile(
    r"stahtd_dump_event\(\):\s+(?P<json>\{.+\})"
)

# wevent custom events: wevent.ubnt_custom_event(): EVENT_STA_XXX vap: mac / data
_WEVENT_RE = re.compile(
    r"wevent\.ubnt_custom_event\(\):\s+(?P<event>EVENT_STA_\w+)\s+"
    r"(?P<vap>\S+):\s+(?P<mac>[0-9a-f:]{17})\s+/\s+(?P<data>\S+)"
)

# DNS timeout: [STA_TRACKER] DNS request timed out; [STA: mac][QUERY: ...][DNS_SERVER: ...]
_DNS_TIMEOUT_RE = re.compile(
    r"\[STA_TRACKER\]\s+DNS request timed out;\s*"
    r"\[STA:\s*(?P<mac>[0-9a-f:]{17})\]\s*"
    r"\[QUERY:\s*(?P<query>[^\]]+)\]\s*"
    r"\[DNS_SERVER\s*:\s*(?P<dns_server>[^\]]+)\]"
)

# Wireless anomalies: wireless_agg_stats.log_sta_anomalies()...sta=mac...anomalies=...
_ANOMALY_RE = re.compile(
    r"wireless_agg_stats\.log_sta_anomalies\(\).*?"
    r"sta=(?P<mac>[0-9a-f:]{17}).*?"
    r"anomalies=(?P<anomalies>\S+)"
)

# Switch: provision timing
_PROVISION_RE = re.compile(
    r"syswrapper\[\d+\]:\s+Provision took (?P<seconds>\d+) sec"
)

# Switch: state transition
_STATE_TRANSITION_RE = re.compile(
    r"ace_reporter\.ace_reporter_set_state\(\):\s+\[STATE\]\s+transition\s+"
    r"(?P<from>\S+)\s+->\s+(?P<to>\S+)"
)


class UniFiParser:
    name = "unifi"

    def try_parse(self, program: str, message: str) -> ParseResult | None:
        """Parse UniFi-specific syslog events."""
        # Try each pattern in order of specificity

        # 1. STA_ASSOC_TRACKER JSON (richest data)
        result = self._try_sta_tracker(message)
        if result:
            return result

        # 2. DNS timeout tracking
        result = self._try_dns_timeout(message)
        if result:
            return result

        # 3. wevent custom events
        result = self._try_wevent(message)
        if result:
            return result

        # 4. Wireless anomalies
        result = self._try_anomaly(message)
        if result:
            return result

        # 5. Switch events
        result = self._try_switch(program, message)
        if result:
            return result

        return None

    def _try_sta_tracker(self, message: str) -> ParseResult | None:
        m = _STA_TRACKER_JSON_RE.search(message)
        if not m:
            return None

        try:
            data = json.loads(m.group("json"))
        except json.JSONDecodeError:
            return None

        event_type = data.get("event_type", "unknown")
        mac = data.get("mac", "").lower()
        vap = data.get("vap", "")

        # Map STA tracker event types to our normalized types
        type_map = {
            "sta_assoc": "sta_assoc",
            "sta_leave": "sta_leave",
            "sta_roam": "sta_roam",
            "soft failure": "sta_soft_failure",
        }
        normalized = type_map.get(event_type, f"sta_{event_type}")

        return ParseResult(
            event_type=normalized,
            severity="info",
            category="network",
            message=f"STA {event_type}: {mac} on {vap}",
            fields={
                "mac": mac,
                "vap": vap,
                "event_type": event_type,
                "raw_sta": data,
            },
            device_type_hint="ap",
        )

    def _try_dns_timeout(self, message: str) -> ParseResult | None:
        m = _DNS_TIMEOUT_RE.search(message)
        if not m:
            return None

        mac = m.group("mac").lower()
        query = m.group("query")
        dns_server = m.group("dns_server").strip()

        return ParseResult(
            event_type="dns_timeout",
            severity="info",
            category="network",
            message=f"DNS timeout: {mac} query {query} via {dns_server}",
            fields={
                "mac": mac,
                "query": query,
                "dns_server": dns_server,
            },
            device_type_hint="ap",
        )

    def _try_wevent(self, message: str) -> ParseResult | None:
        m = _WEVENT_RE.search(message)
        if not m:
            return None

        event = m.group("event")
        mac = m.group("mac").lower()
        vap = m.group("vap")
        data = m.group("data")

        # Map wevent types
        if event == "EVENT_STA_IP":
            return ParseResult(
                event_type="sta_ip_assign",
                severity="info",
                category="network",
                message=f"STA IP: {mac} -> {data} on {vap}",
                fields={"mac": mac, "ip": data, "vap": vap},
                device_type_hint="ap",
            )
        elif event == "EVENT_STA_JOIN":
            return ParseResult(
                event_type="sta_join",
                severity="info",
                category="network",
                message=f"STA join: {mac} on {vap} (aid {data})",
                fields={"mac": mac, "vap": vap, "aid": data},
                device_type_hint="ap",
            )
        elif event == "EVENT_STA_LEAVE":
            return ParseResult(
                event_type="sta_leave",
                severity="info",
                category="network",
                message=f"STA leave: {mac} from {vap}",
                fields={"mac": mac, "vap": vap},
                device_type_hint="ap",
            )

        # Generic wevent
        return ParseResult(
            event_type=f"wevent_{event.lower()}",
            severity="info",
            category="network",
            message=f"{event}: {mac} on {vap} ({data})",
            fields={"mac": mac, "vap": vap, "event": event, "data": data},
            device_type_hint="ap",
        )

    def _try_anomaly(self, message: str) -> ParseResult | None:
        m = _ANOMALY_RE.search(message)
        if not m:
            return None

        return ParseResult(
            event_type="wifi_anomaly",
            severity="low",
            category="network",
            message=f"WiFi anomaly: {m.group('mac')} — {m.group('anomalies')}",
            fields={
                "mac": m.group("mac").lower(),
                "anomalies": m.group("anomalies"),
            },
            device_type_hint="ap",
        )

    def _try_switch(self, program: str, message: str) -> ParseResult | None:
        # Provision timing
        m = _PROVISION_RE.search(message)
        if m:
            seconds = int(m.group("seconds"))
            return ParseResult(
                event_type="switch_provision",
                severity="info",
                category="host",
                message=f"Switch provision took {seconds}s",
                fields={"seconds": seconds},
                device_type_hint="switch",
            )

        # State transition
        m = _STATE_TRANSITION_RE.search(message)
        if m:
            from_state = m.group("from")
            to_state = m.group("to")
            return ParseResult(
                event_type="switch_state",
                severity="medium" if to_state.lower() in ("disconnected", "unknown") else "info",
                category="host",
                message=f"Switch state: {from_state} -> {to_state}",
                fields={"from_state": from_state, "to_state": to_state},
                device_type_hint="switch",
            )

        # Config write
        if "cfgmtd_do_write" in message:
            return ParseResult(
                event_type="switch_config_write",
                severity="info",
                category="host",
                message="Switch config write",
                fields={"line": message[:300]},
                device_type_hint="switch",
            )

        # Authkey leak warning
        if "authkey:" in message.lower():
            return ParseResult(
                event_type="switch_authkey_leak",
                severity="medium",
                category="host",
                message="Switch authkey visible in syslog — consider restricting verbosity",
                fields={},
                device_type_hint="switch",
            )

        return None
