"""Shared persistence logic for syslog collectors (file + UDP).

Both collectors parse lines through the same parser chain and need
identical event persistence, rule evaluation, device updates, and counters.

Event flow:
  raw line → parser chain → ParseResult
    → rule engine (real-time pattern detection)
    → WAN blocks: in-memory counters (not events table)
    → everything else: events table with ECS fields
    → WiFi events: device upsert
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sentinel_home.parsers import ParseResult

logger = logging.getLogger(__name__)

# High-volume noise — filter before parsing
PRE_FILTER = (
    "DPT=5353",      # mDNS multicast
    "DPT=10001",     # UniFi discovery
    "SPT=10001",
    "no input for event",
    "hostapd-global-check",
    "Hostapd Global Check",
)

# High-volume events go to counters, not the events table
_COUNTER_EVENTS = {"fw_wan_block", "fw_lan_traffic"}


def should_pre_filter(line: str) -> bool:
    """Return True if this line is noise and should be dropped before parsing."""
    for noise in PRE_FILTER:
        if noise in line:
            return True
    return False


def process_result(result: ParseResult, source_name: str, source_ip: str | None) -> None:
    """Full processing pipeline for a parsed event.

    1. Evaluate rules (real-time pattern detection)
    2. Route to counters or events table
    3. Update device type if we have a hint
    """
    # Rule engine — real-time evaluation for windowed patterns
    evaluate_rules(result, source_ip)

    # Route: WAN blocks → counters, everything else → events table
    if result.event_type in _COUNTER_EVENTS:
        record_counter(result, source_name)
    else:
        persist_event(result, source_name, source_ip)


def evaluate_rules(result: ParseResult, source_ip: str | None) -> None:
    """Run the ParseResult through the DB-driven rule engine."""
    try:
        from sentinel_home.rules.engine import get_rule_engine
        get_rule_engine().evaluate(result, source_ip)
    except Exception as exc:
        logger.debug("Rule evaluation error: %s", exc)


def record_counter(result: ParseResult, source_name: str) -> None:
    """Send high-volume events to in-memory counters instead of DB."""
    try:
        from sentinel_home.metrics.counters import get_counters
        get_counters().record(
            source=source_name,
            category=result.category,
            event_type=result.event_type,
            fields=result.fields,
        )
    except Exception as exc:
        logger.debug("Counter record error: %s", exc)


def persist_event(result: ParseResult, source_name: str, source_ip: str | None) -> None:
    """Write a v1.0 Event row with ECS fields from a ParseResult."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Event

        with session_scope() as session:
            session.add(Event(
                source=source_name,
                event_type=result.event_type,
                severity=result.severity,
                category=result.category,
                kind="event",
                message=result.message[:500],
                raw={
                    **result.fields,
                    **({"source_ip": source_ip} if source_ip else {}),
                },
            ))
    except Exception as exc:
        logger.error("Failed to persist event: %s", exc)


def update_device_type(ip: str, device_type: str) -> None:
    """Enrich device type from parser hint (by IP, for infrastructure devices)."""
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device

        # Look up MAC in one session, then call enrich_device after closing
        # to avoid nested session_scope (causes "database is locked").
        mac: str | None = None
        with session_scope() as session:
            device = session.query(Device).filter(Device.ip == ip).first()
            if device:
                mac = device.mac
        if mac:
            from sentinel_home.fingerprint import enrich_device
            enrich_device(mac=mac, ip=ip, device_type_hint=device_type)
    except Exception as exc:
        logger.debug("Failed to update device type for %s: %s", ip, exc)


def upsert_wifi_device(mac: str, fields: dict) -> None:
    """Create or update a Device from WiFi client data (STA tracker, wevent)."""
    try:
        from sentinel_home.fingerprint import enrich_device

        hostnames = {}
        hostname = fields.get("hostname")
        if hostname:
            hostnames["wifi"] = hostname

        enrich_device(
            mac=mac,
            ip=fields.get("ip"),
            connection_type="wifi",
            ap=fields.get("vap"),
            hostnames=hostnames if hostnames else None,
        )
    except Exception as exc:
        logger.debug("Failed to upsert wifi device %s: %s", mac, exc)
