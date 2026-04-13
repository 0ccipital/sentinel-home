"""Infrastructure health and network topology API routes."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException

from sentinel_home.api.envelope import ok_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Baseline, Device, InfraMetric

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["infrastructure"])


@router.get("/infrastructure")
async def list_infrastructure():
    """List all infrastructure devices with their latest metrics."""
    with session_scope() as session:
        devices = (
            session.query(Device)
            .filter(Device.network_role == "infrastructure")
            .all()
        )
        result = []
        for d in devices:
            latest_metric = (
                session.query(InfraMetric)
                .filter(InfraMetric.device_mac == d.mac)
                .order_by(InfraMetric.ts.desc())
                .first()
            )
            entry = {
                "mac": d.mac,
                "ip": d.ip,
                "label": d.label,
                "device_type": d.device_type,
                "vendor": d.vendor,
                "infra_state": d.infra_state,
                "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            }
            if latest_metric:
                entry["metrics"] = {
                    "ts": latest_metric.ts.isoformat(),
                    "cpu_load_1m": latest_metric.cpu_load_1m,
                    "cpu_load_5m": latest_metric.cpu_load_5m,
                    "memory_pct": latest_metric.memory_pct,
                    "uplink_tx_bps": latest_metric.uplink_tx_bps,
                    "uplink_rx_bps": latest_metric.uplink_rx_bps,
                    "radio_tx_retries_pct": latest_metric.radio_tx_retries_pct,
                    "uptime_seconds": latest_metric.uptime_seconds,
                    "client_count": latest_metric.client_count,
                }
            result.append(entry)

    return ok_envelope(result)


@router.get("/infrastructure/{mac}/metrics")
async def get_device_metrics(mac: str, hours: int = 24):
    """Get time-series metrics for an infrastructure device."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=min(hours, 168))

    with session_scope() as session:
        metrics = (
            session.query(InfraMetric)
            .filter(InfraMetric.device_mac == mac, InfraMetric.ts >= cutoff)
            .order_by(InfraMetric.ts.asc())
            .all()
        )
        result = [
            {
                "ts": m.ts.isoformat(),
                "cpu_load_5m": m.cpu_load_5m,
                "memory_pct": m.memory_pct,
                "uplink_tx_bps": m.uplink_tx_bps,
                "uplink_rx_bps": m.uplink_rx_bps,
                "radio_tx_retries_pct": m.radio_tx_retries_pct,
                "uptime_seconds": m.uptime_seconds,
                "client_count": m.client_count,
            }
            for m in metrics
        ]

    return ok_envelope(result)


@router.get("/infrastructure/health")
async def infrastructure_health():
    """Summary: all infra devices with status indicators."""
    with session_scope() as session:
        devices = (
            session.query(Device)
            .filter(Device.network_role == "infrastructure")
            .all()
        )
        summary = {
            "total": len(devices),
            "online": 0,
            "offline": 0,
            "warnings": [],
            "devices": [],
        }
        for d in devices:
            state = (d.infra_state or "UNKNOWN").upper()
            if state == "ONLINE":
                summary["online"] += 1
            elif state == "OFFLINE":
                summary["offline"] += 1

            latest = (
                session.query(InfraMetric)
                .filter(InfraMetric.device_mac == d.mac)
                .order_by(InfraMetric.ts.desc())
                .first()
            )

            dev_info = {
                "mac": d.mac,
                "label": d.label or d.ip or d.mac,
                "device_type": d.device_type,
                "state": state,
                "ip": d.ip,
            }
            if latest:
                dev_info["cpu_5m"] = latest.cpu_load_5m
                dev_info["memory_pct"] = latest.memory_pct
                dev_info["clients"] = latest.client_count
                dev_info["uptime_seconds"] = latest.uptime_seconds

                if latest.cpu_load_5m and latest.cpu_load_5m > 80:
                    summary["warnings"].append(f"{dev_info['label']}: high CPU ({latest.cpu_load_5m:.0f}%)")
                if latest.memory_pct and latest.memory_pct > 90:
                    summary["warnings"].append(f"{dev_info['label']}: high memory ({latest.memory_pct:.0f}%)")

            summary["devices"].append(dev_info)

    return ok_envelope(summary)


@router.get("/network/vlans")
async def get_vlans():
    """Return cached VLAN/network configuration from UniFi."""
    with session_scope() as session:
        baseline = (
            session.query(Baseline)
            .filter(Baseline.baseline_type == "network_config", Baseline.active == True)  # noqa: E712
            .first()
        )
        if not baseline:
            return ok_envelope([])
        data = baseline.data
        items = data.get("items", data) if isinstance(data, dict) else data
        return ok_envelope(items if isinstance(items, list) else [])


@router.get("/network/ssids")
async def get_ssids():
    """Return cached WiFi SSID configuration from UniFi."""
    with session_scope() as session:
        baseline = (
            session.query(Baseline)
            .filter(Baseline.baseline_type == "wifi_config", Baseline.active == True)  # noqa: E712
            .first()
        )
        if not baseline:
            return ok_envelope([])
        data = baseline.data
        items = data.get("items", data) if isinstance(data, dict) else data
        return ok_envelope(items if isinstance(items, list) else [])


@router.get("/network/firewall")
async def get_firewall():
    """Return cached firewall configuration from UniFi."""
    with session_scope() as session:
        baseline = (
            session.query(Baseline)
            .filter(Baseline.baseline_type == "firewall_config", Baseline.active == True)  # noqa: E712
            .first()
        )
        if not baseline:
            return ok_envelope({"zones": [], "policies": []})
        return ok_envelope(baseline.data)


@router.post("/unifi/action")
async def unifi_action(body: dict):
    """Proxy write actions to UniFi (block/unblock/reconnect client, restart device)."""
    from sentinel_home.main import get_collector

    action = body.get("action", "").upper()
    mac = body.get("mac", "")
    reason = body.get("reason", "")

    if not action or not mac:
        raise HTTPException(400, "action and mac are required")

    valid_client_actions = {"BLOCK", "UNBLOCK", "RECONNECT"}
    valid_device_actions = {"RESTART", "LOCATE"}

    collector = get_collector("unifi")
    if not collector:
        raise HTTPException(503, "UniFi collector not running")

    # Validate action before executing
    all_valid = valid_client_actions | valid_device_actions
    if action not in all_valid:
        raise HTTPException(400, f"Invalid action: {action}. Valid: {', '.join(all_valid)}")

    # Execute the action first
    if action in valid_client_actions:
        result = await collector.execute_client_action(mac, action)
    else:
        result = await collector.execute_device_action(mac, action)

    # Log the audit trail AFTER execution (success or failure)
    from sentinel_home.database import session_scope as ss
    from sentinel_home.models import Event, Note
    succeeded = "error" not in result
    try:
        with ss() as session:
            session.add(Event(
                source="unifi",
                event_type="unifi_action",
                severity="info",
                device_id=mac,
                message=f"UniFi {action} on {mac}: {'ok' if succeeded else result.get('error', 'failed')}"
                + (f" — {reason}" if reason else ""),
                raw={"action": action, "mac": mac, "reason": reason, "success": succeeded},
            ))
            if reason and succeeded:
                session.add(Note(
                    entity_type="device",
                    entity_id=mac,
                    source="system",
                    text=f"UniFi {action}: {reason}",
                ))
    except Exception as exc:
        logger.warning("Failed to log UniFi action audit: %s", exc)

    if not succeeded:
        raise HTTPException(400, result["error"])

    return ok_envelope(result)
