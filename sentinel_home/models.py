"""SQLAlchemy ORM models for SentinelHome v1.0.

Tables are grouped by ownership:
  - Agent-writable: Rule, Pattern, DeviceProfile (merged into Device)
  - System-managed: Event, EventRollup, Job, StaleJob, Finding, Alert, Scan, Baseline
  - Versioning: RuleVersion, PatternVersion, RuleMetricWindow
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinel_home.database import Base


# ---------------------------------------------------------------------------
# Rules (agent-writable, stored in DB not Python)
# ---------------------------------------------------------------------------

class Rule(Base):
    """Detection rule. System seeds defaults; agent and user create/tune via API."""

    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(32))  # ECS: network, authentication, host, process
    severity: Mapped[str] = mapped_column(String(16), default="medium")  # info/low/medium/high/critical
    priority: Mapped[int] = mapped_column(Integer, default=2)  # 0=highest, 3=lowest

    source: Mapped[str] = mapped_column(String(16), default="system")  # system/agent/user
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=True)  # agent-created start False
    frozen: Mapped[bool] = mapped_column(Boolean, default=False)  # user locks from agent changes

    parameters: Mapped[dict] = mapped_column(JSON, default=dict)  # flexible detection config
    action: Mapped[str] = mapped_column(String(16), default="alert")  # alert/log/investigate
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=300)

    # Performance counters (agent feedback loop)
    fire_count: Mapped[int] = mapped_column(Integer, default=0)
    true_positive_count: Mapped[int] = mapped_column(Integer, default=0)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0)

    last_fired: Mapped[datetime | None] = mapped_column(DateTime)
    last_tuned: Mapped[datetime | None] = mapped_column(DateTime)
    created_by: Mapped[str] = mapped_column(String(16), default="system")
    notes: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    versions: Mapped[list["RuleVersion"]] = relationship("RuleVersion", back_populates="rule", cascade="all, delete-orphan")
    metrics: Mapped[list["RuleMetricWindow"]] = relationship("RuleMetricWindow", back_populates="rule", cascade="all, delete-orphan")


class RuleVersion(Base):
    """Snapshot of a rule before each mutation. Enables rollback."""

    __tablename__ = "rule_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey("rules.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)  # auto-increment per rule

    # Full snapshot
    parameters: Mapped[dict] = mapped_column(JSON)
    severity: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean)
    cooldown_seconds: Mapped[int] = mapped_column(Integer)

    # Context
    changed_by: Mapped[str] = mapped_column(String(16))  # agent/user/system
    change_reason: Mapped[str] = mapped_column(Text, default="")
    fire_count_at_change: Mapped[int] = mapped_column(Integer, default=0)
    tp_count_at_change: Mapped[int] = mapped_column(Integer, default=0)
    fp_count_at_change: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    rule: Mapped[Rule] = relationship("Rule", back_populates="versions")


class RuleMetricWindow(Base):
    """Daily performance snapshot per rule. The critic's primary input."""

    __tablename__ = "rule_metric_windows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey("rules.id", ondelete="CASCADE"))
    window_date: Mapped[date] = mapped_column(Date)

    fire_count: Mapped[int] = mapped_column(Integer, default=0)
    tp_count: Mapped[int] = mapped_column(Integer, default=0)
    fp_count: Mapped[int] = mapped_column(Integer, default=0)
    auto_resolved_count: Mapped[int] = mapped_column(Integer, default=0)
    version_at_window: Mapped[int] = mapped_column(Integer, default=1)

    rule: Mapped[Rule] = relationship("Rule", back_populates="metrics")


# ---------------------------------------------------------------------------
# Patterns (agent-writable: baselines, suppressions, watchlists)
# ---------------------------------------------------------------------------

class Pattern(Base):
    """Agent-learned network pattern. What's normal for this network."""

    __tablename__ = "patterns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    pattern_type: Mapped[str] = mapped_column(String(16))  # baseline/suppression/watchlist
    scope: Mapped[str] = mapped_column(String(64), default="*")  # MAC, IP range, or *

    definition: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    sample_count: Mapped[int] = mapped_column(Integer, default=0)

    created_by: Mapped[str] = mapped_column(String(16), default="agent")
    notes: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    versions: Mapped[list["PatternVersion"]] = relationship("PatternVersion", back_populates="pattern", cascade="all, delete-orphan")


class PatternVersion(Base):
    """Snapshot of a pattern before each mutation."""

    __tablename__ = "pattern_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pattern_id: Mapped[int] = mapped_column(Integer, ForeignKey("patterns.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)

    definition: Mapped[dict] = mapped_column(JSON)
    confidence: Mapped[float] = mapped_column(Float)
    scope: Mapped[str] = mapped_column(String(64))

    changed_by: Mapped[str] = mapped_column(String(16))
    change_reason: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    pattern: Mapped[Pattern] = relationship("Pattern", back_populates="versions")


# ---------------------------------------------------------------------------
# Devices (system-discovered, agent/user-enrichable)
# ---------------------------------------------------------------------------

class Device(Base):
    """Every MAC address seen on the network. System discovers, agent/user enriches."""

    __tablename__ = "devices"

    mac: Mapped[str] = mapped_column(String(17), primary_key=True)

    # System-discovered
    ip: Mapped[str | None] = mapped_column(String(45))
    vendor: Mapped[str | None] = mapped_column(String(128))  # OUI lookup
    os_family: Mapped[str | None] = mapped_column(String(64))  # nmap -O
    device_type: Mapped[str | None] = mapped_column(String(32))  # router/ap/switch/server/phone/iot/unknown
    hostnames: Mapped[dict | None] = mapped_column(JSON)  # mDNS, DHCP, nmap hostnames
    services: Mapped[dict | None] = mapped_column(JSON)  # open ports + service names
    connection_type: Mapped[str | None] = mapped_column(String(32))  # wifi/wired
    ap: Mapped[str | None] = mapped_column(String(128))  # connected AP

    # WiFi details (from UniFi API or syslog)
    signal_strength: Mapped[int | None] = mapped_column(Integer)  # dBm
    channel: Mapped[int | None] = mapped_column(Integer)
    band: Mapped[str | None] = mapped_column(String(8))  # "2.4GHz" / "5GHz" / "6GHz"

    # UniFi integration
    unifi_id: Mapped[str | None] = mapped_column(String(64))  # UniFi API UUID for write-back
    vlan_id: Mapped[int | None] = mapped_column(Integer)
    infra_state: Mapped[str | None] = mapped_column(String(32))  # ONLINE/OFFLINE/UPDATING for infra devices

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    # Agent/user-enriched
    label: Mapped[str | None] = mapped_column(String(128))  # e.g. "Living Room Printer"
    network_role: Mapped[str | None] = mapped_column(String(32))  # infrastructure/client/server/iot
    expected_behavior: Mapped[dict | None] = mapped_column(JSON)  # typical DNS rate, connections, etc.
    device_notes: Mapped[str | None] = mapped_column(Text)  # agent or user notes
    updated_by: Mapped[str | None] = mapped_column(String(16))  # system/agent/user

    events: Mapped[list["Event"]] = relationship("Event", back_populates="device_rel", foreign_keys="Event.device_id")


# ---------------------------------------------------------------------------
# Events (ECS-categorized)
# ---------------------------------------------------------------------------

class Event(Base):
    """Normalized event from any collector. ECS-categorized."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)
    source: Mapped[str] = mapped_column(String(32))  # collector name
    event_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), default="info")

    # ECS fields
    category: Mapped[str] = mapped_column(String(32), default="network")  # network/authentication/host/process
    kind: Mapped[str] = mapped_column(String(16), default="event")  # event/alert/metric/state
    outcome: Mapped[str | None] = mapped_column(String(16))  # success/failure/unknown

    device_id: Mapped[str | None] = mapped_column(String(17), ForeignKey("devices.mac"), index=True)
    rule_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("rules.id"), index=True)
    message: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict | None] = mapped_column(JSON)

    device_rel: Mapped[Device | None] = relationship("Device", back_populates="events", foreign_keys=[device_id])


class EventRollup(Base):
    """Hourly aggregated event stats. WAN blocks live here, not in events table."""

    __tablename__ = "event_rollups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hour: Mapped[datetime] = mapped_column(DateTime, index=True)
    source: Mapped[str] = mapped_column(String(32))
    category: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(Integer, default=0)
    extra: Mapped[dict | None] = mapped_column(JSON)  # unique_sources, top_ports, etc.


class DashboardStats(Base):
    """Pre-computed dashboard stats. Refreshed every 5 minutes."""

    __tablename__ = "dashboard_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)
    stats: Mapped[dict] = mapped_column(JSON)  # full stats blob


# ---------------------------------------------------------------------------
# Queue (jobs, stale jobs, findings)
# ---------------------------------------------------------------------------

class Job(Base):
    """Investigation queue entry. Processed by agent or auto-resolved by patterns."""

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)
    source: Mapped[str] = mapped_column(String(32))  # rule_engine/user/agent
    rule_name: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("rules.id"))
    device_id: Mapped[str | None] = mapped_column(String(17))
    priority: Mapped[int] = mapped_column(Integer, default=2)  # 0=highest 3=lowest
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/processing/done/compacted/failed
    context: Mapped[dict] = mapped_column(JSON)
    compacted_count: Mapped[int] = mapped_column(Integer, default=0)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime)
    verdict: Mapped[dict | None] = mapped_column(JSON)

    finding: Mapped["Finding | None"] = relationship("Finding", back_populates="job", uselist=False)


class StaleJob(Base):
    """Archived jobs that exceeded the staleness threshold. Not lost, not processed."""

    __tablename__ = "stale_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    original_job_id: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime)  # original creation time
    archived_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    rule_name: Mapped[str] = mapped_column(String(64))
    device_id: Mapped[str | None] = mapped_column(String(17))
    priority: Mapped[int] = mapped_column(Integer)
    context: Mapped[dict] = mapped_column(JSON)


class Finding(Base):
    """Analysis result — from agent, rules, or user."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("jobs.id"))
    ts: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)

    source: Mapped[str] = mapped_column(String(16), default="agent")  # agent/rule/user
    rule_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("rules.id"))
    rule_name: Mapped[str | None] = mapped_column(String(64))
    device_id: Mapped[str | None] = mapped_column(String(17))

    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    summary: Mapped[str] = mapped_column(Text)
    reasoning: Mapped[str | None] = mapped_column(Text)
    likely_cause: Mapped[str | None] = mapped_column(Text)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    mitre_reference: Mapped[str | None] = mapped_column(String(64))

    needs_followup: Mapped[bool] = mapped_column(Boolean, default=False)
    followup_question: Mapped[str | None] = mapped_column(Text)
    followup_result: Mapped[dict | None] = mapped_column(JSON)

    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    dismissed: Mapped[bool] = mapped_column(Boolean, default=False)
    pattern_ids: Mapped[dict | None] = mapped_column(JSON)  # which patterns were consulted

    job: Mapped[Job | None] = relationship("Job", back_populates="finding")


# ---------------------------------------------------------------------------
# Alerts (direct, pre-agent)
# ---------------------------------------------------------------------------

class Alert(Base):
    """Immediate alert fired by hard rules. No agent needed."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)
    rule_name: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("rules.id"))
    device_id: Mapped[str | None] = mapped_column(String(17))
    severity: Mapped[str] = mapped_column(String(16), default="high")
    message: Mapped[str] = mapped_column(Text)
    context: Mapped[dict | None] = mapped_column(JSON)  # triggering event detail + rule params
    sent: Mapped[bool] = mapped_column(Boolean, default=False)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime)


class FindingArchive(Base):
    """Lightweight archive of findings — preserved after retention deletes originals.

    Captures the essential reasoning and outcome so historical analysis
    and the LLM critic can reference past investigations indefinitely.
    """

    __tablename__ = "finding_archives"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    original_id: Mapped[int] = mapped_column(Integer, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    rule_name: Mapped[str | None] = mapped_column(String(64))
    device_id: Mapped[str | None] = mapped_column(String(17))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    summary: Mapped[str] = mapped_column(Text)
    likely_cause: Mapped[str | None] = mapped_column(Text)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(String(16))  # ack/dismissed/unresolved
    source: Mapped[str] = mapped_column(String(16), default="agent")


# ---------------------------------------------------------------------------
# Baselines & Scans (kept from v0.3)
# ---------------------------------------------------------------------------

class Baseline(Base):
    """Baseline snapshot for a device or network topology."""

    __tablename__ = "baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    baseline_type: Mapped[str] = mapped_column(String(32))  # device/service/topology
    subject_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
    data: Mapped[dict] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Scan(Base):
    """nmap scan result."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)
    target: Mapped[str] = mapped_column(String(64))
    scan_type: Mapped[str] = mapped_column(String(32), default="lan")
    result: Mapped[dict] = mapped_column(JSON)
    diff: Mapped[dict | None] = mapped_column(JSON)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    triggered_by: Mapped[str] = mapped_column(String(32), default="scheduler")


# ---------------------------------------------------------------------------
# Notes (universal annotations)
# ---------------------------------------------------------------------------

class InfraMetric(Base):
    """Time-series metrics for infrastructure devices (AP, switch, gateway)."""

    __tablename__ = "infra_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)
    device_mac: Mapped[str] = mapped_column(String(17), ForeignKey("devices.mac", ondelete="CASCADE"), index=True)

    cpu_load_1m: Mapped[float | None] = mapped_column(Float)
    cpu_load_5m: Mapped[float | None] = mapped_column(Float)
    memory_pct: Mapped[float | None] = mapped_column(Float)
    uplink_tx_bps: Mapped[int | None] = mapped_column(Integer)
    uplink_rx_bps: Mapped[int | None] = mapped_column(Integer)
    radio_tx_retries_pct: Mapped[float | None] = mapped_column(Float)
    uptime_seconds: Mapped[int | None] = mapped_column(Integer)
    client_count: Mapped[int | None] = mapped_column(Integer)
    raw: Mapped[dict | None] = mapped_column(JSON)


class Note(Base):
    """Universal annotations — attach notes to any entity (device, rule, event_type, finding, general)."""

    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)  # device, rule, event_type, finding, general
    entity_id: Mapped[str | None] = mapped_column(String(128), index=True)  # MAC, rule ID, event type name, finding ID, or NULL for general
    source: Mapped[str] = mapped_column(String(16), default="user")  # user, agent, chat, system
    text: Mapped[str] = mapped_column(Text)
    chat_id: Mapped[str | None] = mapped_column(String(64))  # links to Open WebUI conversation if created during chat
