"""Device endpoints: /api/v1/devices, /topology, /wan, /clients, /rogue-aps"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Device
from sentinel_home.utils import primary_hostname

router = APIRouter()


@router.get("/devices")
async def list_devices():
    with session_scope() as session:
        devices = session.query(Device).all()
        return ok_envelope([_device_summary(d) for d in devices])


@router.get("/devices/{mac}")
async def get_device(mac: str):
    with session_scope() as session:
        device = session.query(Device).filter(Device.mac == mac).first()
        if not device:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Device {mac} not found"))
        return ok_envelope(_device_detail(device))


@router.get("/devices/{mac}/events")
async def get_device_events(mac: str, limit: int = 50, offset: int = 0):
    from sentinel_home.models import Event
    with session_scope() as session:
        device = session.query(Device).filter(Device.mac == mac).first()
        if not device:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Device {mac} not found"))
        events = (
            session.query(Event)
            .filter(Event.device_id == mac)
            .order_by(Event.ts.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return ok_envelope([_event_summary(e) for e in events])


@router.put("/devices/{mac}")
async def update_device(mac: str, request: Request):
    """Update user-editable fields on a device (label, device_type, network_role)."""
    body = await request.json()
    allowed = {"label", "device_type", "network_role"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        raise HTTPException(
            status_code=400,
            detail=error_envelope("BAD_REQUEST", f"No valid fields. Allowed: {sorted(allowed)}"),
        )

    with session_scope() as session:
        device = session.query(Device).filter(Device.mac == mac).first()
        if not device:
            raise HTTPException(
                status_code=404,
                detail=error_envelope("NOT_FOUND", f"Device {mac} not found"),
            )
        for field, value in updates.items():
            setattr(device, field, value)
        device.updated_by = "user"
        session.commit()
        session.refresh(device)
        return ok_envelope(_device_detail(device))


@router.put("/devices/{mac}/services/{port}")
async def update_device_service(mac: str, port: int, request: Request):
    """Annotate a service/port on a device with a description."""
    body = await request.json()
    description = body.get("description")
    if description is None:
        raise HTTPException(
            status_code=400,
            detail=error_envelope("BAD_REQUEST", "Missing required field: description"),
        )

    with session_scope() as session:
        device = session.query(Device).filter(Device.mac == mac).first()
        if not device:
            raise HTTPException(
                status_code=404,
                detail=error_envelope("NOT_FOUND", f"Device {mac} not found"),
            )

        port_key = str(port)
        services = device.services or {}

        # Normalise: nmap may store services as a flat dict {"80": "http"}
        # or a list of port ints/strings.  Convert to canonical form.
        if isinstance(services, list):
            services = {str(p): {"service": str(p)} for p in services}
        elif isinstance(services, dict):
            normalised = {}
            for k, v in services.items():
                if isinstance(v, str):
                    # flat format from nmap: {"80": "http"}
                    normalised[str(k)] = {"service": v}
                elif isinstance(v, dict):
                    normalised[str(k)] = v
                else:
                    normalised[str(k)] = {"service": str(v)}
            services = normalised

        # Update or create the entry, preserving existing service name
        if port_key in services:
            services[port_key]["description"] = description
        else:
            services[port_key] = {"service": None, "description": description}

        device.services = services
        # Force SQLAlchemy to detect the JSON mutation
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(device, "services")
        device.updated_by = "user"
        session.commit()
        session.refresh(device)
        return ok_envelope(device.services)


@router.get("/topology")
async def get_topology():
    """Build a network topology graph from device data.

    Nodes are devices. Links represent AP associations, gateway connections,
    and same-subnet relationships.
    """
    with session_scope() as session:
        devices = session.query(Device).order_by(Device.last_seen.desc()).all()

        nodes = []
        links = []
        gateway_mac = None

        for d in devices:
            node = {
                "mac": d.mac,
                "ip": d.ip,
                "label": d.label or d.vendor or d.mac[:8],
                "device_type": d.device_type or "unknown",
                "connection_type": d.connection_type,
                "network_role": d.network_role,
                "ap": d.ap,
            }
            nodes.append(node)

            # Identify gateway (router)
            if d.device_type == "router" or d.network_role == "infrastructure":
                if d.ip and d.ip.endswith(".1"):
                    gateway_mac = d.mac

        # Build links from AP associations
        ap_macs = {d.mac for d in devices if d.device_type in ("ap", "router")}
        ap_ips = {d.ip: d.mac for d in devices if d.ip}

        for d in devices:
            if d.ap:
                # AP field might be a MAC or IP — try to resolve
                target = d.ap.lower()
                if target in ap_macs:
                    links.append({
                        "source": d.mac, "target": target,
                        "type": "wifi",
                    })
                elif target in ap_ips:
                    links.append({
                        "source": d.mac, "target": ap_ips[target],
                        "type": "wifi",
                    })

            # Connect infrastructure devices to gateway
            if d.device_type in ("ap", "switch") and gateway_mac and d.mac != gateway_mac:
                links.append({
                    "source": d.mac, "target": gateway_mac,
                    "type": "wired",
                })

        return ok_envelope({
            "nodes": nodes,
            "links": links,
            "gateway": gateway_mac,
            "device_count": len(nodes),
        })


@router.get("/wan")
async def get_wan():
    return ok_envelope({
        "status": "unknown",
        "latency_ms": None,
        "drop_count_1h": 0,
        "recent_events": [],
    })


@router.get("/clients")
async def get_clients():
    return ok_envelope([])


@router.get("/rogue-aps")
async def get_rogue_aps():
    return ok_envelope([])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _device_summary(d: Device) -> dict:
    return {
        "mac": d.mac,
        "ip": d.ip,
        "hostname": primary_hostname(d.hostnames),
        "vendor": d.vendor,
        "device_type": d.device_type,
        "label": d.label,
        "network_role": d.network_role,
        "first_seen": d.first_seen.isoformat() if d.first_seen else None,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
    }


def _device_detail(d: Device) -> dict:
    return {
        **_device_summary(d),
        "os_family": d.os_family,
        "connection_type": d.connection_type,
        "ap": d.ap,
        "hostnames": d.hostnames,
        "services": d.services,
        "expected_behavior": d.expected_behavior,
        "device_notes": d.device_notes,
        "updated_by": d.updated_by,
    }


def _event_summary(e) -> dict:
    return {
        "id": e.id,
        "ts": e.ts.isoformat() if e.ts else None,
        "source": e.source,
        "event_type": e.event_type,
        "severity": e.severity,
        "message": e.message,
    }
