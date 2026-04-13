"""LLM-friendly /api/v1/ask/* endpoints — plain-text summaries for agent tool-use."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from sentinel_home.api.envelope import ok_envelope, error_envelope
from sentinel_home.database import session_scope
from sentinel_home.models import Device, Finding
from sentinel_home.utils import primary_hostname

router = APIRouter()


@router.get("/ask/network-summary")
async def ask_network_summary():
    with session_scope() as session:
        device_count = session.query(Device).count()
        unresolved = session.query(Finding).filter(
            Finding.acknowledged == False, Finding.dismissed == False  # noqa: E712
        ).count()

        lines = [
            f"Network has {device_count} known device(s).",
        ]
        if unresolved:
            lines.append(f"{unresolved} unresolved finding(s) require attention.")
        else:
            lines.append("No active findings.")

        content = " ".join(lines)

    return ok_envelope({"format": "plain_text", "content": content})


@router.get("/ask/device/{identifier}")
async def ask_device(identifier: str):
    with session_scope() as session:
        device = (
            session.query(Device).filter(Device.mac == identifier).first()
            or session.query(Device).filter(Device.ip == identifier).first()
        )
        if not device:
            content = f"No device found with MAC or IP: {identifier}"
        else:
            parts = [f"Device {device.mac}"]
            hostname = primary_hostname(device.hostnames)
            if hostname:
                parts.append(f"({hostname})")
            if device.vendor:
                parts.append(f"— vendor: {device.vendor}")
            if device.device_type:
                parts.append(f"— type: {device.device_type}")
            if device.label:
                parts.append(f"— label: {device.label}")
            if device.last_seen:
                parts.append(f"— last seen: {device.last_seen.isoformat()}")
            content = " ".join(parts)

    return ok_envelope({"format": "plain_text", "content": content})


@router.get("/ask/open-ports")
async def ask_open_ports():
    content = "No scan results available yet. Run a scan with POST /api/v1/scans/trigger."
    return ok_envelope({"format": "plain_text", "content": content})


@router.get("/ask/anomalies")
async def ask_anomalies():
    with session_scope() as session:
        findings = (
            session.query(Finding)
            .filter(Finding.acknowledged == False, Finding.dismissed == False)  # noqa: E712
            .order_by(Finding.ts.desc())
            .limit(10)
            .all()
        )
        if not findings:
            content = "No active anomalies detected."
        else:
            lines = [f"{len(findings)} active anomaly/anomalies:"]
            for f in findings:
                lines.append(f"[{f.severity.upper()}] {f.summary} (rule: {f.rule_name})")
            content = "\n".join(lines)

    return ok_envelope({"format": "plain_text", "content": content})


@router.post("/ask/investigate")
async def ask_investigate(body: dict):
    question = body.get("question", "").strip()
    if not question:
        raise HTTPException(status_code=400, detail=error_envelope("BAD_REQUEST", "question field required"))

    with session_scope() as session:
        from sentinel_home.models import Job
        job = Job(
            source="agent",
            rule_name="investigate",
            priority=2,
            context={"question": question},
        )
        session.add(job)
        session.flush()
        job_id = job.id

    return ok_envelope({
        "job_id": job_id,
        "message": "Investigation queued. Results will appear as a finding after the next inference batch.",
    })
