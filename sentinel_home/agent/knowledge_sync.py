"""Sync network state to Open WebUI Knowledge for RAG context.

Builds a compact text document every N minutes with:
- Device inventory (label, type, IP, vendor, recent notes)
- Active rules and their performance
- Recent alerts and findings
- General network notes

The model retrieves relevant sections via vector search during conversation.
"""

from __future__ import annotations

import io
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import func as sqlfunc

from sentinel_home.utils import primary_hostname

from sentinel_home.database import session_scope
from sentinel_home.models import (
    Alert, Baseline, Device, EventRollup, Finding, FindingArchive,
    InfraMetric, Note, Rule, RuleVersion,
)

logger = logging.getLogger(__name__)

_client: httpx.Client | None = None
_knowledge_id: str | None = None


def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(timeout=15)
    return _client


def _get_headers() -> dict[str, str]:
    from sentinel_home.config import get_settings
    settings = get_settings()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.agent.api_key:
        headers["Authorization"] = f"Bearer {settings.agent.api_key}"
    return headers


def _get_upload_headers() -> dict[str, str]:
    """Headers for multipart file upload (no Content-Type — httpx sets it)."""
    from sentinel_home.config import get_settings
    settings = get_settings()
    headers: dict[str, str] = {}
    if settings.agent.api_key:
        headers["Authorization"] = f"Bearer {settings.agent.api_key}"
    return headers


def _find_or_create_knowledge() -> str | None:
    """Find or create the SentinelHome knowledge collection."""
    global _knowledge_id
    if _knowledge_id:
        return _knowledge_id

    from sentinel_home.config import get_settings
    settings = get_settings()
    if not settings.agent.url:
        return None

    base = settings.agent.url.rstrip("/")
    client = _get_client()
    headers = _get_headers()

    # Check existing knowledge collections
    try:
        resp = client.get(f"{base}/api/v1/knowledge/", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            # Open WebUI returns {"items": [...], "total": N}
            items = data.get("items", []) if isinstance(data, dict) else data
            for k in items:
                if isinstance(k, dict) and k.get("name") == "SentinelHome Network State":
                    _knowledge_id = k["id"]
                    logger.debug("Found existing knowledge collection: %s", _knowledge_id)
                    return _knowledge_id
    except Exception as exc:
        logger.warning("Failed to list knowledge collections: %s", exc)

    # Create new collection
    try:
        resp = client.post(f"{base}/api/v1/knowledge/create", json={
            "name": "SentinelHome Network State",
            "description": "Auto-updated network state for SentinelHome RAG context",
        }, headers=headers)
        if resp.status_code == 200:
            _knowledge_id = resp.json().get("id")
            logger.info("Created knowledge collection: %s", _knowledge_id)
            return _knowledge_id
    except Exception as exc:
        logger.warning("Failed to create knowledge collection: %s", exc)

    return None


def _format_ago(dt: datetime | None) -> str:
    """Format a datetime as a human-readable 'ago' string."""
    if dt is None:
        return "never"
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = now - dt
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def _format_services(services: dict | list | None) -> str:
    """Format device services into a compact string."""
    if not services:
        return ""
    parts: list[str] = []
    if isinstance(services, dict):
        for port, info in services.items():
            if isinstance(info, dict):
                svc_name = info.get("name", "")
                product = info.get("product", "")
                desc = info.get("description", "")
                entry = f"{port}/{svc_name}"
                annotation = desc or product
                if annotation:
                    entry += f" ({annotation})"
                parts.append(entry)
            else:
                parts.append(f"{port}/{info}")
    elif isinstance(services, list):
        for svc in services:
            if isinstance(svc, dict):
                port = svc.get("port", "?")
                name = svc.get("name", "")
                parts.append(f"{port}/{name}")
            else:
                parts.append(str(svc))
    return ", ".join(parts)




def build_network_document() -> str:
    """Build a structured text document of the current network state.

    Queries devices, rules, alerts, findings, and notes from the DB.
    Returns a compact text document suitable for RAG ingestion.
    """
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%d %H:%M UTC")
    cutoff_24h = now - timedelta(hours=24)

    sections: list[str] = [
        "# SentinelHome Network State",
        f"# Updated: {now_str}",
        "",
    ]

    # --- Devices ---
    with session_scope() as session:
        devices = session.query(Device).order_by(Device.last_seen.desc()).all()
        device_dicts: list[dict] = []
        for d in devices:
            device_dicts.append({
                "mac": d.mac,
                "ip": d.ip,
                "label": d.label,
                "vendor": d.vendor,
                "device_type": d.device_type,
                "network_role": d.network_role,
                "os_family": d.os_family,
                "hostnames": d.hostnames,
                "services": d.services,
                "connection_type": d.connection_type,
                "ap": d.ap,
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
                "device_notes": d.device_notes,
                "signal_strength": d.signal_strength,
                "channel": d.channel,
                "band": d.band,
                "infra_state": d.infra_state,
                "vlan_id": d.vlan_id,
            })

    sections.append(f"## Devices ({len(device_dicts)} total)")
    for d in device_dicts:
        name = d["label"] or primary_hostname(d["hostnames"]) or d["vendor"] or "Unknown"
        mac = d["mac"]
        ip = d["ip"] or "no IP"
        dtype = d["device_type"] or "unknown"
        role = d["network_role"] or ""
        type_role = f"{dtype}/{role}" if role else dtype

        line = f"- {name} ({mac}) -- {ip} -- {type_role}"
        sections.append(line)

        # Services
        svc_str = _format_services(d["services"])
        if svc_str:
            sections.append(f"  Services: {svc_str}")

        # Extra details
        details: list[str] = []
        if d["os_family"]:
            details.append(f"OS: {d['os_family']}")
        if d["connection_type"]:
            conn = d["connection_type"]
            if d["ap"]:
                conn += f" (AP: {d['ap']})"
            details.append(conn)
        details.append(f"Last seen: {_format_ago(d['last_seen'])}")
        sections.append(f"  {' | '.join(details)}")

        # WiFi details
        if d["signal_strength"] is not None:
            wifi_parts = [f"{d['signal_strength']}dBm"]
            if d["channel"]:
                wifi_parts.append(f"ch{d['channel']}")
            if d["band"]:
                wifi_parts.append(d["band"])
            sections.append(f"  WiFi: {' '.join(wifi_parts)}")

        # Infrastructure state
        if d["infra_state"]:
            sections.append(f"  State: {d['infra_state']}")

        if d["device_notes"]:
            sections.append(f"  Notes: {d['device_notes']}")

    sections.append("")

    # --- Active Rules ---
    with session_scope() as session:
        rules = session.query(Rule).filter(
            Rule.enabled == True  # noqa: E712
        ).order_by(Rule.severity.desc(), Rule.name).all()
        rule_dicts: list[dict] = []
        for r in rules:
            total = r.fire_count or 0
            tp = r.true_positive_count or 0
            fp = r.false_positive_count or 0
            tp_rate = f"{tp / total * 100:.0f}%" if total > 0 else "N/A"
            rule_dicts.append({
                "name": r.name,
                "severity": r.severity,
                "action": r.action,
                "fire_count": total,
                "tp_count": tp,
                "fp_count": fp,
                "tp_rate": tp_rate,
                "description": r.description,
                "frozen": r.frozen,
                "source": r.source,
                "parameters": r.parameters or {},
            })

    sections.append(f"## Active Rules ({len(rule_dicts)})")
    for r in rule_dicts:
        frozen_tag = " [FROZEN]" if r["frozen"] else ""
        desc = f" -- {r['description']}" if r["description"] else ""
        feedback = f"tp={r['tp_count']}, fp={r['fp_count']}" if (r["tp_count"] or r["fp_count"]) else "no user feedback"
        params_str = ""
        if r["parameters"]:
            # Show key matching parameters, skip internal fields
            show_keys = {k: v for k, v in r["parameters"].items()
                         if k.startswith("match_") or k.endswith("_threshold")}
            if show_keys:
                params_str = f" | matches: {show_keys}"
        sections.append(
            f"- {r['name']}: {r['severity']}, action={r['action']}, "
            f"fires {r['fire_count']}x ({feedback})"
            f"{frozen_tag}{desc}{params_str}"
        )
    sections.append("")

    # --- Rule Change History (from RuleVersion snapshots) ---
    with session_scope() as session:
        versions = (
            session.query(RuleVersion)
            .order_by(RuleVersion.created_at.desc())
            .limit(50)
            .all()
        )
        version_dicts = [{
            "rule_id": v.rule_id,
            "version": v.version,
            "severity": v.severity,
            "enabled": v.enabled,
            "cooldown": v.cooldown_seconds,
            "changed_by": v.changed_by,
            "reason": v.change_reason,
            "fire_at_change": v.fire_count_at_change,
            "tp_at_change": v.tp_count_at_change,
            "fp_at_change": v.fp_count_at_change,
            "ts": v.created_at,
        } for v in versions]

        # Map rule_id → name
        rule_ids = {v["rule_id"] for v in version_dicts}
        rule_id_to_name = {}
        if rule_ids:
            for r in session.query(Rule).filter(Rule.id.in_(rule_ids)).all():
                rule_id_to_name[r.id] = r.name

    if version_dicts:
        sections.append(f"## Rule Change History (last {len(version_dicts)} changes)")
        for v in version_dicts:
            name = rule_id_to_name.get(v["rule_id"], f"rule#{v['rule_id']}")
            ts = v["ts"].strftime("%Y-%m-%d %H:%M") if v["ts"] else "?"
            reason = f": {v['reason']}" if v["reason"] else ""
            metrics = f"fires={v['fire_at_change'] or 0}, tp={v['tp_at_change'] or 0}, fp={v['fp_at_change'] or 0}"
            sections.append(
                f"- [{ts}] {name} v{v['version']} by {v['changed_by'] or '?'} "
                f"→ sev={v['severity']}, enabled={v['enabled']}, cooldown={v['cooldown']}s "
                f"({metrics}){reason}"
            )
        sections.append("")

    # --- Alert History (all-time stats + recent detail) ---
    with session_scope() as session:
        from sqlalchemy import func

        # All-time stats by rule+device
        alert_stats = (
            session.query(
                Alert.rule_name,
                Alert.device_id,
                Alert.severity,
                func.count(Alert.id).label("cnt"),
                func.min(Alert.ts).label("first_ts"),
                func.max(Alert.ts).label("last_ts"),
            )
            .group_by(Alert.rule_name, Alert.device_id, Alert.severity)
            .order_by(func.count(Alert.id).desc())
            .all()
        )
        stat_dicts = [{
            "rule_name": s.rule_name, "device_id": s.device_id or "?",
            "severity": s.severity, "count": s.cnt,
            "first_ts": s.first_ts, "last_ts": s.last_ts,
        } for s in alert_stats]

        total_all_time = sum(s["count"] for s in stat_dicts)

        # Recent alerts (last 24h) with full detail
        alerts = (
            session.query(Alert)
            .filter(Alert.ts >= cutoff_24h)
            .order_by(Alert.ts.desc())
            .limit(50)
            .all()
        )
        alert_dicts: list[dict] = []
        for a in alerts:
            alert_dicts.append({
                "severity": a.severity,
                "rule_name": a.rule_name,
                "device_id": a.device_id,
                "message": a.message,
                "ts": a.ts,
            })

    # Historical summary
    sections.append(f"## Alert History ({total_all_time} all-time, {len(alert_dicts)} last 24h)")
    if stat_dicts:
        sections.append("")
        sections.append("### All-Time Alert Counts by Rule + Device")
        for s in stat_dicts:
            first = s["first_ts"].strftime("%Y-%m-%d") if s["first_ts"] else "?"
            last = _format_ago(s["last_ts"])
            sections.append(
                f"- {s['rule_name']} [{s['severity'].upper()}] device={s['device_id']}: "
                f"{s['count']}x (first {first}, last {last})"
            )
    sections.append("")

    # Recent detail
    sections.append("### Recent Alerts (last 24h)")
    if alert_dicts:
        for a in alert_dicts:
            ago = _format_ago(a["ts"])
            msg = a["message"] or ""
            dev = a["device_id"] or "?"
            sections.append(
                f"- [{a['severity'].upper()}] {a['rule_name']} (device={dev}, {ago}): {msg}"
            )
    else:
        sections.append("- No alerts in the last 24 hours")
    sections.append("")

    # --- Recent Findings (last 24h) ---
    with session_scope() as session:
        findings = (
            session.query(Finding)
            .filter(Finding.ts >= cutoff_24h)
            .order_by(Finding.ts.desc())
            .limit(30)
            .all()
        )
        finding_dicts: list[dict] = []
        for f in findings:
            finding_dicts.append({
                "severity": f.severity,
                "summary": f.summary,
                "rule_name": f.rule_name,
                "device_id": f.device_id,
                "confidence": f.confidence,
                "acknowledged": f.acknowledged,
                "dismissed": f.dismissed,
                "ts": f.ts,
            })

    if finding_dicts:
        sections.append(f"## Recent Findings (last 24h, {len(finding_dicts)} total)")
        for f in finding_dicts:
            ago = _format_ago(f["ts"])
            status = ""
            if f["dismissed"]:
                status = " [DISMISSED]"
            elif f["acknowledged"]:
                status = " [ACK]"
            dev = f["device_id"] or "?"
            sections.append(
                f"- [{f['severity'].upper()}] {f['summary']} "
                f"(rule={f['rule_name']}, device={dev}, conf={f['confidence']}, {ago}){status}"
            )
        sections.append("")

    # --- Finding Archive (long-term investigation history) ---
    with session_scope() as session:
        archives = (
            session.query(FindingArchive)
            .order_by(FindingArchive.ts.desc())
            .limit(100)
            .all()
        )
        archive_dicts = [{
            "ts": a.ts, "rule_name": a.rule_name, "device_id": a.device_id,
            "severity": a.severity, "confidence": a.confidence,
            "summary": a.summary, "likely_cause": a.likely_cause,
            "recommended_action": a.recommended_action,
            "outcome": a.outcome, "source": a.source,
        } for a in archives]

    if archive_dicts:
        sections.append(f"## Investigation History ({len(archive_dicts)} archived findings)")
        for a in archive_dicts:
            ts = a["ts"].strftime("%Y-%m-%d") if a["ts"] else "?"
            dev = a["device_id"] or "?"
            outcome = f" [{a['outcome'].upper()}]" if a["outcome"] else ""
            cause = f" cause={a['likely_cause']}" if a["likely_cause"] else ""
            sections.append(
                f"- [{ts}] [{a['severity'].upper()}] {a['summary']} "
                f"(rule={a['rule_name']}, device={dev}, conf={a['confidence']}){outcome}{cause}"
            )
        sections.append("")

    # --- Event Trends (from rollups — what's happening over time) ---
    with session_scope() as session:
        cutoff_7d = now - timedelta(days=7)
        rollups = (
            session.query(
                EventRollup.source,
                EventRollup.category,
                EventRollup.event_type,
                sqlfunc.sum(EventRollup.count).label("total"),
            )
            .filter(EventRollup.hour >= cutoff_7d)
            .group_by(EventRollup.source, EventRollup.category, EventRollup.event_type)
            .order_by(sqlfunc.sum(EventRollup.count).desc())
            .limit(30)
            .all()
        )
        rollup_dicts = [{
            "source": r.source, "category": r.category,
            "event_type": r.event_type, "total": r.total,
        } for r in rollups]

    if rollup_dicts:
        total_events_7d = sum(r["total"] for r in rollup_dicts)
        sections.append(f"## Event Trends (last 7 days, {total_events_7d} total events)")
        for r in rollup_dicts:
            sections.append(
                f"- {r['event_type']}: {r['total']}x (source={r['source']}, category={r['category']})"
            )
        sections.append("")

    # --- Infrastructure Health ---
    with session_scope() as session:
        # Get latest metric per infrastructure device (subquery for max ts)
        latest_ts = (
            session.query(
                InfraMetric.device_mac,
                sqlfunc.max(InfraMetric.ts).label("max_ts"),
            )
            .group_by(InfraMetric.device_mac)
            .subquery()
        )
        metrics = (
            session.query(InfraMetric)
            .join(
                latest_ts,
                (InfraMetric.device_mac == latest_ts.c.device_mac)
                & (InfraMetric.ts == latest_ts.c.max_ts),
            )
            .all()
        )
        metric_dicts: list[dict] = []
        for m in metrics:
            metric_dicts.append({
                "mac": m.device_mac,
                "cpu_1m": m.cpu_load_1m,
                "cpu_5m": m.cpu_load_5m,
                "memory_pct": m.memory_pct,
                "tx_bps": m.uplink_tx_bps,
                "rx_bps": m.uplink_rx_bps,
                "retries_pct": m.radio_tx_retries_pct,
                "uptime_s": m.uptime_seconds,
                "clients": m.client_count,
            })

    if metric_dicts:
        sections.append(f"## Infrastructure Health ({len(metric_dicts)} devices)")
        for m in metric_dicts:
            # Find device name from device_dicts
            dev_name = m["mac"]
            for d in device_dicts:
                if d["mac"] == m["mac"]:
                    dev_name = d["label"] or primary_hostname(d["hostnames"]) or d["mac"]
                    break
            parts = []
            if m["cpu_5m"] is not None:
                parts.append(f"CPU {m['cpu_5m']:.0f}%")
            if m["memory_pct"] is not None:
                parts.append(f"Mem {m['memory_pct']:.0f}%")
            if m["clients"] is not None:
                parts.append(f"{m['clients']} clients")
            if m["retries_pct"] is not None:
                parts.append(f"TX retries {m['retries_pct']:.1f}%")
            if m["uptime_s"] is not None:
                days = m["uptime_s"] // 86400
                parts.append(f"up {days}d")
            sections.append(f"- {dev_name}: {', '.join(parts)}")
        sections.append("")

    # --- Network Topology (from UniFi config baselines) ---
    with session_scope() as session:
        net_baseline = (
            session.query(Baseline)
            .filter(Baseline.baseline_type == "network_config", Baseline.active == True)  # noqa: E712
            .first()
        )
        net_data = net_baseline.data if net_baseline else None

        wifi_baseline = (
            session.query(Baseline)
            .filter(Baseline.baseline_type == "wifi_config", Baseline.active == True)  # noqa: E712
            .first()
        )
        wifi_data = wifi_baseline.data if wifi_baseline else None

        fw_baseline = (
            session.query(Baseline)
            .filter(Baseline.baseline_type == "firewall_config", Baseline.active == True)  # noqa: E712
            .first()
        )
        fw_data = fw_baseline.data if fw_baseline else None

    if net_data or wifi_data:
        sections.append("## Network Topology")

        if net_data:
            networks = net_data.get("items", net_data) if isinstance(net_data, dict) else net_data
            if isinstance(networks, list):
                sections.append("VLANs:")
                for n in networks:
                    name = n.get("name", "?")
                    vlan = n.get("vlanId") or n.get("vlan", "")
                    purpose = n.get("purpose", "")
                    dhcp = "DHCP" if n.get("dhcpEnabled") else "static"
                    sections.append(f"  - {name} (VLAN {vlan}): {purpose} {dhcp}")

        if wifi_data:
            ssids = wifi_data.get("items", wifi_data) if isinstance(wifi_data, dict) else wifi_data
            if isinstance(ssids, list):
                sections.append("SSIDs:")
                for s in ssids:
                    name = s.get("name", "?")
                    enabled = "enabled" if s.get("enabled", True) else "disabled"
                    security = s.get("security") or s.get("wpa_mode") or "?"
                    sections.append(f"  - {name}: {security}, {enabled}")

        sections.append("")

    if fw_data and isinstance(fw_data, dict):
        zones = fw_data.get("zones", [])
        policies = fw_data.get("policies", [])
        if zones or policies:
            sections.append("## Firewall Summary")
            sections.append(f"- {len(zones)} zones, {len(policies)} policies")
            for z in zones[:10]:
                sections.append(f"  - Zone: {z.get('name', '?')}")
            sections.append("")

    # --- Network Notes ---
    with session_scope() as session:
        general_notes = (
            session.query(Note)
            .filter(Note.entity_type == "general")
            .order_by(Note.ts.desc())
            .limit(20)
            .all()
        )
        note_dicts: list[dict] = []
        for n in general_notes:
            note_dicts.append({
                "text": n.text,
                "source": n.source,
                "ts": n.ts,
            })

    sections.append("## Network Notes")
    if note_dicts:
        for n in note_dicts:
            ts_str = n["ts"].strftime("%Y-%m-%d") if n["ts"] else "?"
            sections.append(f"- [{ts_str} {n['source']}] {n['text']}")
    else:
        sections.append("- No general notes recorded")
    sections.append("")

    return "\n".join(sections)


def sync_knowledge() -> None:
    """Build the network state document and upload it to Open WebUI Knowledge.

    Called periodically by the scheduler. Uploads the document as a text file
    to the knowledge collection, replacing any previous version.
    """
    t0 = time.monotonic()

    knowledge_id = _find_or_create_knowledge()
    if not knowledge_id:
        logger.debug("Knowledge sync skipped — no Open WebUI connection or collection")
        return

    from sentinel_home.config import get_settings
    settings = get_settings()
    base = settings.agent.url.rstrip("/")
    client = _get_client()

    # Build the document
    document = build_network_document()
    if len(document.strip()) < 20:
        logger.debug("Knowledge sync skipped — document too short (%d chars)", len(document))
        return

    # Remove old files from the knowledge collection
    headers = _get_headers()
    try:
        resp = client.get(f"{base}/api/v1/knowledge/{knowledge_id}", headers=headers)
        if resp.status_code == 200:
            knowledge_data = resp.json()
            # Open WebUI stores files in the knowledge data
            existing_files = knowledge_data.get("files") or []
            for f in existing_files:
                file_id = f.get("id")
                if file_id:
                    try:
                        client.post(
                            f"{base}/api/v1/knowledge/{knowledge_id}/file/remove",
                            json={"file_id": file_id},
                            headers=headers,
                        )
                    except Exception:
                        pass  # Best effort cleanup
    except Exception as exc:
        logger.debug("Could not clean old knowledge files: %s", exc)

    # Upload the new document as a file
    upload_headers = _get_upload_headers()
    try:
        # Upload the file via the files API (skip processing — we set
        # content manually below to avoid extraction/embedding failures).
        file_content = document.encode("utf-8")
        files = {
            "file": ("sentinel-network-state.txt", io.BytesIO(file_content), "text/plain"),
        }
        upload_resp = client.post(
            f"{base}/api/v1/files/",
            files=files,
            data={"process": "false"},
            headers=upload_headers,
            timeout=30,
        )
        if upload_resp.status_code != 200:
            logger.warning(
                "Knowledge sync: file upload failed (HTTP %d): %s",
                upload_resp.status_code,
                upload_resp.text[:200],
            )
            return

        upload_data = upload_resp.json()
        file_id = upload_data.get("id")
        if not file_id:
            logger.warning("Knowledge sync: file upload returned no ID: %s", upload_data)
            return
        logger.debug("Knowledge sync: uploaded file %s (%d bytes)", file_id, len(file_content))

        # Manually set the file content so Open WebUI's knowledge attach
        # finds text to chunk/embed (bypasses its text extraction pipeline).
        content_resp = client.post(
            f"{base}/api/v1/files/{file_id}/data/content/update",
            json={"content": document},
            headers=headers,
            timeout=30,
        )
        if content_resp.status_code != 200:
            logger.debug(
                "Knowledge sync: content update returned HTTP %d (may still work)",
                content_resp.status_code,
            )

        # Attach the file to the knowledge collection
        attach_resp = client.post(
            f"{base}/api/v1/knowledge/{knowledge_id}/file/add",
            json={"file_id": file_id},
            headers=headers,
            timeout=60,
        )
        if attach_resp.status_code != 200:
            logger.warning(
                "Knowledge sync: file attach failed (HTTP %d): %s",
                attach_resp.status_code,
                attach_resp.text[:200],
            )
            # Clean up the orphaned uploaded file so it doesn't accumulate
            try:
                client.delete(
                    f"{base}/api/v1/files/{file_id}",
                    headers=headers,
                    timeout=10,
                )
            except Exception:
                pass
            return

        elapsed_ms = (time.monotonic() - t0) * 1000
        doc_lines = document.count("\n") + 1
        logger.info(
            "Knowledge sync complete: %d lines, %.0fms (collection=%s, file=%s)",
            doc_lines, elapsed_ms, knowledge_id, file_id,
        )

    except Exception as exc:
        logger.warning("Knowledge sync failed: %s", exc)


def close() -> None:
    """Clean up the httpx client."""
    global _client, _knowledge_id
    if _client is not None:
        try:
            _client.close()
        except Exception:
            pass
        _client = None
    _knowledge_id = None
