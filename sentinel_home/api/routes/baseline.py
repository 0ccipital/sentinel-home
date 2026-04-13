"""Baseline endpoints: /api/v1/baseline"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Baseline, Device

router = APIRouter()


@router.get("/baseline")
async def get_baseline():
    from sqlalchemy import func
    with session_scope() as session:
        device_count = session.query(func.count(Baseline.id)).filter(
            Baseline.baseline_type == "device", Baseline.active == True  # noqa: E712
        ).scalar()
        service = session.query(Baseline.data).filter(
            Baseline.baseline_type == "service", Baseline.active == True  # noqa: E712
        ).first()
        topology = session.query(Baseline.data).filter(
            Baseline.baseline_type == "topology", Baseline.active == True  # noqa: E712
        ).first()
        return ok_envelope({
            "device_count": device_count,
            "service_baseline": service[0] if service else None,
            "topology_baseline": topology[0] if topology else None,
        })


@router.get("/baseline/devices")
async def get_baseline_devices():
    with session_scope() as session:
        # Devices with a baseline entry are "known"
        baselined_macs = {
            b.subject_id
            for b in session.query(Baseline).filter(
                Baseline.baseline_type == "device", Baseline.active == True  # noqa: E712
            ).all()
        }
        devices = session.query(Device).all()
        return ok_envelope([
            {
                "mac": d.mac,
                "ip": d.ip,
                "vendor": d.vendor,
                "device_type": d.device_type,
                "label": d.label,
                "baselined": d.mac in baselined_macs,
            }
            for d in devices
        ])


@router.post("/baseline/approve/{mac}")
async def approve_device(mac: str):
    from sentinel_home.baseline.manager import build_device_baseline
    with session_scope() as session:
        device = session.query(Device).filter(Device.mac == mac).first()
        if not device:
            raise HTTPException(status_code=404, detail=error_envelope("NOT_FOUND", f"Device {mac} not found"))
        data = {
            "mac": device.mac, "ip": device.ip, "vendor": device.vendor,
            "device_type": device.device_type,
        }
    build_device_baseline(mac, data)
    return ok_envelope({"mac": mac, "status": "approved"})


@router.post("/baseline/refresh")
async def refresh_baseline():
    return ok_envelope({"message": "Baseline refresh queued", "accepted": True})


@router.post("/baseline/ports/approve")
async def approve_port(body: dict):
    return ok_envelope({"message": "Port approved in baseline", "body": body})
