"""Baseline manager — build, refresh, and query baseline data."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sentinel_home.database import session_scope
from sentinel_home.models import Baseline, Device

logger = logging.getLogger(__name__)


def build_device_baseline(mac: str, data: dict) -> None:
    """Store or update a device baseline entry."""
    with session_scope() as session:
        existing = (
            session.query(Baseline)
            .filter(Baseline.baseline_type == "device", Baseline.subject_id == mac, Baseline.active == True)  # noqa: E712
            .first()
        )
        if existing:
            existing.data = data
            existing.updated_at = datetime.now(timezone.utc)
        else:
            session.add(Baseline(baseline_type="device", subject_id=mac, data=data))


def build_service_baseline(ports_by_host: dict) -> None:
    """Store the initial nmap service baseline."""
    with session_scope() as session:
        session.query(Baseline).filter(Baseline.baseline_type == "service").update({"active": False})
        session.add(Baseline(
            baseline_type="service",
            subject_id="global",
            data={"ports_by_host": ports_by_host, "recorded_at": datetime.now(timezone.utc).isoformat()},
        ))


def build_topology_baseline(topology: dict) -> None:
    """Store network topology snapshot."""
    with session_scope() as session:
        session.query(Baseline).filter(Baseline.baseline_type == "topology").update({"active": False})
        session.add(Baseline(
            baseline_type="topology",
            subject_id="global",
            data=topology,
        ))


def is_known_device(mac: str) -> bool:
    """A device is 'known' if it has an active baseline entry."""
    with session_scope() as session:
        return session.query(Baseline).filter(
            Baseline.baseline_type == "device",
            Baseline.subject_id == mac,
            Baseline.active == True,  # noqa: E712
        ).first() is not None


def get_all_known_macs() -> set[str]:
    """Return all MACs that have active device baselines."""
    with session_scope() as session:
        rows = session.query(Baseline.subject_id).filter(
            Baseline.baseline_type == "device",
            Baseline.active == True,  # noqa: E712
        ).all()
        return {row[0].lower() for row in rows}


def approve_device(mac: str) -> None:
    """Approve a device by creating a baseline entry for it."""
    data = None
    with session_scope() as session:
        device = session.query(Device).filter(Device.mac == mac).first()
        if device:
            data = {
                "mac": device.mac, "ip": device.ip,
                "vendor": device.vendor, "device_type": device.device_type,
            }
    if data:
        build_device_baseline(mac, data)


def get_service_baseline() -> dict:
    with session_scope() as session:
        bl = (
            session.query(Baseline)
            .filter(Baseline.baseline_type == "service", Baseline.active == True)  # noqa: E712
            .first()
        )
        return bl.data if bl else {}


def get_topology_baseline() -> dict:
    with session_scope() as session:
        bl = (
            session.query(Baseline)
            .filter(Baseline.baseline_type == "topology", Baseline.active == True)  # noqa: E712
            .first()
        )
        return bl.data if bl else {}
