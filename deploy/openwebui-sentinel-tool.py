"""
title: SentinelHome Tool
author: SentinelHome
version: 0.3.0
description: Read and write access to SentinelHome's API for network investigation and management.
    Used when actor escalates a NEEDS_MORE_INFO case to a full Open WebUI session
    with tool calling, or when the user wants to annotate/manage devices and rules.

Import this as a Tool in Open WebUI:
  Workspace → Tools → (+) → Paste this file → Save

Read functions:
  - get_device_info: Look up a device by MAC or IP
  - get_recent_events: Get recent events, optionally filtered by device
  - get_rule_info: Get rule details and performance metrics
  - get_network_summary: Get a high-level summary of network activity
  - lookup_ip_reputation: Check if an IP is on threat intel lists
  - get_alerts: Get recent alerts from detection rules
  - get_entity_context: Get comprehensive context for any entity
  - get_infrastructure_health: Infrastructure device status and metrics
  - get_network_topology: VLANs and SSIDs
  - get_firewall_summary: Firewall zones and policies

Write functions:
  - update_device: Update a device's identity (label, type, role)
  - annotate_service: Add a description to an open port/service
  - add_note: Add a note to any entity
  - add_general_note: Record a general network observation
  - dismiss_alert: Suppress alerts from a rule for a device
  - submit_feedback: Record TP/FP feedback on a rule
  - block_client: Block a device on the network via UniFi
  - unblock_client: Unblock a previously blocked device
  - reconnect_client: Force a client to reconnect
  - restart_device: Restart an infrastructure device

Configure the SentinelHome URL and API key in Open WebUI:
  Tools → SentinelHome Tool → Valves (gear icon)
"""

import json
from typing import Optional

import requests
from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        sentinel_url: str = Field(
            default="http://localhost:8890/api/v1",
            description="SentinelHome API base URL",
        )
        sentinel_api_key: str = Field(
            default="",
            description="SentinelHome API key (for write operations)",
        )

    def __init__(self):
        self.valves = self.Valves()

    def _headers(self) -> dict:
        """Build request headers including API key if set."""
        headers = {"Content-Type": "application/json"}
        if self.valves.sentinel_api_key:
            headers["X-API-Key"] = self.valves.sentinel_api_key
        return headers

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        """Make a GET request to SentinelHome API."""
        try:
            resp = requests.get(
                f"{self.valves.sentinel_url}{path}",
                params=params,
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", data)
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as e:
            return {"error": str(e)}

    def _post(self, path: str, body: dict) -> dict:
        """Make a POST request to SentinelHome API."""
        try:
            resp = requests.post(
                f"{self.valves.sentinel_url}{path}",
                json=body,
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return data.get("data", data)
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as e:
            return {"error": str(e)}

    def _put(self, path: str, body: dict) -> dict:
        """Make a PUT request to SentinelHome API."""
        try:
            resp = requests.put(
                f"{self.valves.sentinel_url}{path}",
                json=body,
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", data)
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as e:
            return {"error": str(e)}

    def _delete(self, path: str) -> dict:
        """Make a DELETE request to SentinelHome API."""
        try:
            resp = requests.delete(
                f"{self.valves.sentinel_url}{path}",
                headers=self._headers(),
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", data)
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as e:
            return {"error": str(e)}

    # -----------------------------------------------------------------------
    # Read functions
    # -----------------------------------------------------------------------

    def get_device_info(self, identifier: str) -> str:
        """
        Look up a device by MAC address or IP address.
        Returns vendor, type, hostnames, services, and recent activity.

        :param identifier: MAC address (e.g., "AA:BB:CC:DD:EE:FF") or IP address
        :return: Device information as formatted text
        """
        # Try as MAC first
        data = self._get(f"/devices/{identifier}")
        if "error" not in data:
            return json.dumps(data, indent=2, default=str)

        # Try searching all devices for the IP
        devices = self._get("/devices")
        if isinstance(devices, list):
            for d in devices:
                if d.get("ip") == identifier:
                    return json.dumps(d, indent=2, default=str)

        return f"Device '{identifier}' not found"

    def get_recent_events(
        self,
        device_id: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 20,
    ) -> str:
        """
        Get recent network events. Optionally filter by device, type, or severity.

        :param device_id: Filter by device MAC address (optional)
        :param event_type: Filter by event type like "dns_timeout", "new_device", "port_change" (optional)
        :param severity: Filter by severity: "low", "medium", "high", "critical" (optional)
        :param limit: Maximum number of events to return (default 20, max 50)
        :return: List of recent events as formatted text
        """
        params = {"limit": min(limit, 50)}
        if device_id:
            params["device_id"] = device_id
        if event_type:
            params["event_type"] = event_type
        if severity:
            params["severity"] = severity

        data = self._get("/events", params=params)
        if isinstance(data, list):
            summary = []
            for e in data:
                ts = e.get("ts", "?")
                etype = e.get("event_type", "?")
                sev = e.get("severity", "?")
                dev = e.get("device_id", "?")
                msg = (e.get("message") or "")[:150]
                summary.append(f"[{ts}] {etype} ({sev}) device={dev}: {msg}")
            return "\n".join(summary) if summary else "No events found"
        return json.dumps(data, default=str)

    def get_rule_info(self, rule_name: str) -> str:
        """
        Get detailed information about a detection rule including its performance metrics.

        :param rule_name: Name of the rule (e.g., "new_device_alert", "dns_timeout_anomaly")
        :return: Rule details, parameters, and TP/FP statistics
        """
        rules = self._get("/rules")
        if isinstance(rules, list):
            for r in rules:
                if r.get("name") == rule_name:
                    rule_id = r["id"]
                    detail = self._get(f"/rules/{rule_id}")
                    metrics = self._get(f"/rules/{rule_id}/metrics", {"days": 7})
                    return json.dumps({
                        "rule": detail,
                        "recent_metrics": metrics,
                    }, indent=2, default=str)

        return f"Rule '{rule_name}' not found"

    def get_network_summary(self, hours: int = 1) -> str:
        """
        Get a high-level summary of recent network activity.
        Includes event counts by type, active devices, alerts, and queue depth.

        :param hours: How many hours to look back (default 1, max 24)
        :return: Network activity summary
        """
        from datetime import datetime, timedelta, timezone
        since = (datetime.now(timezone.utc) - timedelta(hours=min(hours, 24))).isoformat()
        data = self._get("/changelog", {"since": since})
        return json.dumps(data, indent=2, default=str)

    def lookup_ip_reputation(self, ip: str) -> str:
        """
        Check if an IP address appears in local threat intelligence lists.
        Also returns any events or alerts associated with this IP.

        :param ip: IP address to look up
        :return: Threat intel matches and associated events
        """
        events = self._get("/events", {"limit": 10})
        related = []
        if isinstance(events, list):
            for e in events:
                msg = e.get("message", "")
                src = e.get("source_ip") or ""
                if ip in msg or ip == src:
                    related.append({
                        "ts": e.get("ts"),
                        "type": e.get("event_type"),
                        "severity": e.get("severity"),
                        "message": (e.get("message") or "")[:200],
                    })

        sniff = self._get("/sniff/state")
        arp_entry = None
        if isinstance(sniff, dict):
            arp_table = sniff.get("arp_table", {})
            for mac, info in arp_table.items():
                if info.get("ip") == ip:
                    arp_entry = {"mac": mac, **info}
                    break

        result = {
            "ip": ip,
            "related_events": related,
            "arp_entry": arp_entry,
            "note": "Check searxng for external reputation (AbuseIPDB, VirusTotal, Shodan)",
        }
        return json.dumps(result, indent=2, default=str)

    def get_alerts(self, hours: int = 24) -> str:
        """
        Get recent alerts triggered by detection rules.

        :param hours: How many hours to look back (default 24)
        :return: Recent alerts formatted as text
        """
        data = self._get("/alerts", {"limit": 50})
        if isinstance(data, list):
            if not data:
                return "No alerts found"
            # Filter by time window client-side
            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            lines = []
            for a in data:
                ts_str = a.get("ts", "")
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str)
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        if ts < cutoff:
                            continue
                    except (ValueError, TypeError):
                        pass
                sev = a.get("severity", "?")
                rule = a.get("rule_name", "?")
                device = a.get("device_id", "?")
                msg = (a.get("message") or "")[:150]
                sent = "acked" if a.get("sent") else "new"
                lines.append(f"[{ts_str}] ({sev}) {rule} device={device} [{sent}]: {msg}")
            return "\n".join(lines) if lines else f"No alerts in the last {hours} hours"
        return json.dumps(data, default=str)

    def get_entity_context(self, entity_type: str, entity_id: str) -> str:
        """
        Get a comprehensive context summary for any entity (device, rule, finding).
        Returns everything known including notes, recent events, and metadata.

        :param entity_type: Entity type: "device", "rule", "event_type", "finding"
        :param entity_id: Identifier (MAC for devices, rule name/ID, etc.)
        :return: Full context summary
        """
        data = self._get(f"/context/{entity_type}/{entity_id}")
        if isinstance(data, dict) and "context" in data:
            return data["context"]
        return json.dumps(data, indent=2, default=str)

    # -----------------------------------------------------------------------
    # Write functions
    # -----------------------------------------------------------------------

    def update_device(
        self,
        mac: str,
        label: str = "",
        device_type: str = "",
        network_role: str = "",
    ) -> str:
        """
        Update a device's identity. Use when the user tells you what a device is.

        :param mac: Device MAC address (e.g., "AA:BB:CC:DD:EE:FF")
        :param label: Friendly name (e.g., "Living Room Printer", "alice-iphone")
        :param device_type: Device type: phone, laptop, desktop, tablet, server, router, ap, switch, iot, media, printer, camera, unknown
        :param network_role: Network role: infrastructure, client, server, iot
        :return: Confirmation or error message
        """
        body = {"updated_by": "user"}
        if label:
            body["label"] = label
        if device_type:
            body["device_type"] = device_type
        if network_role:
            body["network_role"] = network_role

        if len(body) == 1:
            return "Nothing to update — provide at least one of: label, device_type, network_role"

        result = self._put(f"/devices/{mac}", body)
        if "error" in result:
            return f"Failed to update device {mac}: {result['error']}"
        return f"Updated device {mac}: {', '.join(f'{k}={v}' for k, v in body.items() if k != 'updated_by')}"

    def annotate_service(self, mac: str, port: int, description: str) -> str:
        """
        Add a description to an open port/service on a device.

        :param mac: Device MAC address
        :param port: Port number (e.g., 443, 80, 631)
        :param description: What this service is for (e.g., "Web admin panel", "Print server")
        :return: Confirmation or error message
        """
        result = self._put(f"/devices/{mac}/services/{port}", {"description": description})
        if "error" in result:
            return f"Failed to annotate port {port} on {mac}: {result['error']}"
        return f"Annotated port {port} on {mac}: {description}"

    def add_note(self, entity_type: str, entity_id: str, note: str) -> str:
        """
        Add a note to any entity in SentinelHome. Use to record observations,
        user decisions, or investigation findings.

        :param entity_type: What to annotate: "device", "rule", "event_type", "finding", "general"
        :param entity_id: Identifier (MAC for devices, rule name for rules, event type name, finding ID). Use empty string for general notes.
        :param note: The note text
        :return: Confirmation or error message
        """
        body = {
            "entity_type": entity_type,
            "entity_id": entity_id if entity_id else None,
            "text": note,
            "source": "chat",
        }
        result = self._post("/notes", body)
        if "error" in result:
            return f"Failed to add note: {result['error']}"
        note_id = result.get("id", "?")
        return f"Note #{note_id} added to {entity_type}" + (f" {entity_id}" if entity_id else "")

    def add_general_note(self, note: str) -> str:
        """
        Record a general observation about the network that doesn't apply to a specific device or rule.
        Examples: "ISP does maintenance on Tuesdays", "Added new smart bulbs last week"

        :param note: The observation to record
        :return: Confirmation or error message
        """
        return self.add_note("general", "", note)

    def dismiss_alert(self, rule_name: str, device_mac: str, reason: str) -> str:
        """
        Dismiss alerts from a specific rule for a device. Creates a suppression pattern
        and adds a note explaining why.

        :param rule_name: Name of the rule to suppress
        :param device_mac: Device MAC to suppress for (use "*" for all devices)
        :param reason: Why this is being dismissed (recorded as a note)
        :return: Confirmation or error message
        """
        # Create suppression pattern
        pattern_name = f"suppress_{rule_name}_{device_mac}".replace(":", "").replace("*", "all")
        pattern_body = {
            "name": pattern_name,
            "pattern_type": "suppression",
            "scope": device_mac,
            "definition": {
                "rule_name": rule_name,
                "device": device_mac,
            },
            "confidence": 1.0,
            "created_by": "user",
            "notes": reason,
        }
        pattern_result = self._post("/patterns", pattern_body)
        if "error" in pattern_result:
            # If pattern already exists, that's fine
            if "already exists" not in pattern_result.get("error", ""):
                return f"Failed to create suppression: {pattern_result['error']}"

        # Record the reason as a note on the rule
        note_body = {
            "entity_type": "rule",
            "entity_id": rule_name,
            "text": f"Suppressed for device {device_mac}: {reason}",
            "source": "chat",
        }
        self._post("/notes", note_body)

        scope_desc = "all devices" if device_mac == "*" else f"device {device_mac}"
        return f"Suppressed rule '{rule_name}' for {scope_desc}. Reason: {reason}"

    def submit_feedback(self, rule_name: str, verdict: str) -> str:
        """
        Submit true-positive or false-positive feedback on a rule's most recent fire.
        This helps tune detection accuracy over time.

        :param rule_name: Name of the detection rule
        :param verdict: Either "tp" (true positive) or "fp" (false positive)
        :return: Confirmation or error message
        """
        if verdict not in ("tp", "fp"):
            return "Verdict must be 'tp' (true positive) or 'fp' (false positive)"

        # Find rule by name
        rules = self._get("/rules")
        if not isinstance(rules, list):
            return f"Failed to fetch rules: {rules}"

        rule_id = None
        for r in rules:
            if r.get("name") == rule_name:
                rule_id = r["id"]
                break

        if rule_id is None:
            return f"Rule '{rule_name}' not found"

        result = self._post(f"/rules/{rule_id}/feedback", {"feedback": verdict})
        if "error" in result:
            return f"Failed to submit feedback: {result['error']}"

        label = "true positive" if verdict == "tp" else "false positive"
        return f"Recorded {label} feedback for rule '{rule_name}'"

    # -----------------------------------------------------------------------
    # Infrastructure & Topology (read, with HTML embeds)
    # -----------------------------------------------------------------------

    def get_infrastructure_health(self) -> tuple[str, str]:
        """
        Get the health status of all infrastructure devices (APs, switches, gateways).
        Returns CPU, memory, client count, uptime, and online/offline status.

        :return: Infrastructure health summary with visual status indicators
        """
        data = self._get("/infrastructure/health")
        if not isinstance(data, dict) or "devices" not in data:
            return (f"<p>{json.dumps(data, default=str)}</p>", json.dumps(data, default=str))

        devices = data["devices"]
        warnings = data.get("warnings", [])

        # Build HTML table
        rows = ""
        for d in devices:
            state = d.get("state", "?")
            color = "#4ade80" if state == "ONLINE" else "#ef4444" if state == "OFFLINE" else "#facc15"
            dot = f'<span style="color:{color}">●</span>'
            label = d.get("label", d.get("mac", "?"))
            dtype = d.get("device_type", "?")
            cpu = f"{d['cpu_5m']:.0f}%" if d.get("cpu_5m") is not None else "—"
            mem = f"{d['memory_pct']:.0f}%" if d.get("memory_pct") is not None else "—"
            clients = str(d.get("clients", "—"))
            uptime_s = d.get("uptime_seconds")
            uptime = f"{uptime_s // 86400}d" if uptime_s else "—"
            rows += f"<tr><td>{dot} {label}</td><td>{dtype}</td><td>{cpu}</td><td>{mem}</td><td>{clients}</td><td>{uptime}</td></tr>"

        html = f"""<table style="width:100%;border-collapse:collapse;font-size:0.9em">
<tr style="border-bottom:1px solid #444"><th>Device</th><th>Type</th><th>CPU</th><th>Mem</th><th>Clients</th><th>Uptime</th></tr>
{rows}
</table>"""
        if warnings:
            html += "<p style='color:#facc15;margin-top:0.5em'>⚠ " + "; ".join(warnings) + "</p>"

        # Build context for model
        context = f"Infrastructure: {data['total']} devices, {data['online']} online, {data['offline']} offline."
        if warnings:
            context += " Warnings: " + "; ".join(warnings)
        for d in devices:
            label = d.get("label", d.get("mac", "?"))
            context += f"\n- {label}: {d.get('state', '?')}"
            if d.get("cpu_5m") is not None:
                context += f", CPU {d['cpu_5m']:.0f}%"
            if d.get("memory_pct") is not None:
                context += f", Mem {d['memory_pct']:.0f}%"
            if d.get("clients") is not None:
                context += f", {d['clients']} clients"

        return (html, context)

    def get_network_topology(self) -> tuple[str, str]:
        """
        Get the network topology: VLANs/networks and WiFi SSIDs.

        :return: Network topology with VLANs and SSIDs
        """
        vlans = self._get("/network/vlans")
        ssids = self._get("/network/ssids")

        html_parts = []
        context_parts = []

        if isinstance(vlans, list) and vlans:
            rows = ""
            for v in vlans:
                name = v.get("name", "?")
                vid = v.get("vlanId") or v.get("vlan", "—")
                purpose = v.get("purpose", "—")
                dhcp = "Yes" if v.get("dhcpEnabled") else "No"
                rows += f"<tr><td>{name}</td><td>{vid}</td><td>{purpose}</td><td>{dhcp}</td></tr>"
            html_parts.append(f"""<h4>VLANs</h4>
<table style="width:100%;border-collapse:collapse;font-size:0.9em">
<tr style="border-bottom:1px solid #444"><th>Name</th><th>VLAN</th><th>Purpose</th><th>DHCP</th></tr>
{rows}</table>""")
            context_parts.append(f"VLANs ({len(vlans)}): " + ", ".join(
                f"{v.get('name', '?')} (VLAN {v.get('vlanId', '?')})" for v in vlans
            ))

        if isinstance(ssids, list) and ssids:
            rows = ""
            for s in ssids:
                name = s.get("name", "?")
                enabled = "✓" if s.get("enabled", True) else "✗"
                security = s.get("security") or s.get("wpa_mode") or "?"
                rows += f"<tr><td>{name}</td><td>{security}</td><td>{enabled}</td></tr>"
            html_parts.append(f"""<h4>WiFi SSIDs</h4>
<table style="width:100%;border-collapse:collapse;font-size:0.9em">
<tr style="border-bottom:1px solid #444"><th>SSID</th><th>Security</th><th>Enabled</th></tr>
{rows}</table>""")
            context_parts.append(f"SSIDs ({len(ssids)}): " + ", ".join(
                s.get("name", "?") for s in ssids
            ))

        if not html_parts:
            return ("No network topology data available (UniFi collector may not be running)", "No topology data")

        return ("\n".join(html_parts), "\n".join(context_parts))

    def get_firewall_summary(self) -> tuple[str, str]:
        """
        Get the firewall configuration summary: zones and policies.

        :return: Firewall zones and policies overview
        """
        data = self._get("/network/firewall")
        if not isinstance(data, dict):
            return (f"<p>{json.dumps(data, default=str)}</p>", json.dumps(data, default=str))

        zones = data.get("zones", [])
        policies = data.get("policies", [])

        html = f"<p><b>{len(zones)} zones, {len(policies)} policies</b></p>"

        if zones:
            rows = "".join(f"<tr><td>{z.get('name', '?')}</td><td>{z.get('id', '?')[:8]}</td></tr>" for z in zones)
            html += f"""<h4>Zones</h4>
<table style="width:100%;border-collapse:collapse;font-size:0.9em">
<tr style="border-bottom:1px solid #444"><th>Name</th><th>ID</th></tr>
{rows}</table>"""

        context = f"Firewall: {len(zones)} zones, {len(policies)} policies."
        if zones:
            context += " Zones: " + ", ".join(z.get("name", "?") for z in zones)

        return (html, context)

    # -----------------------------------------------------------------------
    # UniFi write actions
    # -----------------------------------------------------------------------

    def block_client(self, mac: str, reason: str) -> str:
        """
        Block a device on the network via UniFi. The device will be disconnected
        and prevented from reconnecting. Always provide a reason.

        :param mac: Device MAC address to block
        :param reason: Why the device is being blocked (recorded as a note)
        :return: Confirmation or error message
        """
        result = self._post("/unifi/action", {
            "action": "BLOCK",
            "mac": mac,
            "reason": reason,
        })
        if "error" in result:
            return f"Failed to block {mac}: {result['error']}"
        self.add_note("device", mac, f"Blocked via chat: {reason}")
        return f"Blocked device {mac}. Reason: {reason}"

    def unblock_client(self, mac: str) -> str:
        """
        Unblock a previously blocked device, allowing it to reconnect.

        :param mac: Device MAC address to unblock
        :return: Confirmation or error message
        """
        result = self._post("/unifi/action", {
            "action": "UNBLOCK",
            "mac": mac,
        })
        if "error" in result:
            return f"Failed to unblock {mac}: {result['error']}"
        self.add_note("device", mac, "Unblocked via chat")
        return f"Unblocked device {mac}"

    def reconnect_client(self, mac: str) -> str:
        """
        Force a client to disconnect and reconnect. Useful for troubleshooting
        WiFi issues or forcing a DHCP renewal.

        :param mac: Device MAC address to reconnect
        :return: Confirmation or error message
        """
        result = self._post("/unifi/action", {
            "action": "RECONNECT",
            "mac": mac,
        })
        if "error" in result:
            return f"Failed to reconnect {mac}: {result['error']}"
        return f"Reconnect initiated for {mac}"

    def restart_device(self, mac: str, reason: str) -> str:
        """
        Restart an infrastructure device (AP, switch, gateway). This will cause
        a brief connectivity interruption for all clients connected to this device.
        Only use when needed for troubleshooting or after config changes.

        :param mac: Infrastructure device MAC address
        :param reason: Why the restart is needed (recorded as a note)
        :return: Confirmation or error message
        """
        result = self._post("/unifi/action", {
            "action": "RESTART",
            "mac": mac,
            "reason": reason,
        })
        if "error" in result:
            return f"Failed to restart {mac}: {result['error']}"
        self.add_note("device", mac, f"Restarted via chat: {reason}")
        return f"Restart initiated for {mac}. Reason: {reason}. Device will be briefly offline."
