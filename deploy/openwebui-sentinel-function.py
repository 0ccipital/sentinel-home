"""
title: SentinelHome Investigation
author: SentinelHome
version: 0.1.0
type: pipe
description: Investigates SentinelHome alerts with full network context and tool access.

Import this as a Function (Pipe) in Open WebUI:
  Workspace -> Functions -> (+) -> Paste this file -> Save

When a message contains "INVESTIGATE:", this pipe fetches context from the
SentinelHome API — device info, recent events, alerts, and network summary —
then builds an enriched prompt so the model can produce a structured investigation report.

Configure the SentinelHome URL and API key in Open WebUI:
  Functions -> SentinelHome Investigation -> Valves (gear icon)
"""

import json
from typing import Optional

import requests
from pydantic import BaseModel, Field


class Pipe:
    class Valves(BaseModel):
        sentinel_url: str = Field(
            default="http://localhost:8890/api/v1",
            description="SentinelHome API URL",
        )
        sentinel_api_key: str = Field(
            default="",
            description="SentinelHome API key",
        )

    def __init__(self):
        self.valves = self.Valves()

    def _headers(self) -> dict:
        """Build request headers for SentinelHome API."""
        headers = {"Content-Type": "application/json"}
        if self.valves.sentinel_api_key:
            headers["X-API-Key"] = self.valves.sentinel_api_key
        return headers

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        """GET request to SentinelHome API."""
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
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _fetch_network_summary(self) -> str:
        """Fetch the network summary from SentinelHome."""
        data = self._get("/ask/network-summary")
        if isinstance(data, dict) and "content" in data:
            return data["content"]
        return json.dumps(data, default=str)

    def _fetch_device_context(self, identifier: str) -> str:
        """Fetch device context by MAC or IP."""
        # Try context endpoint first for rich info
        data = self._get(f"/context/device/{identifier}")
        if isinstance(data, dict) and "context" in data:
            return data["context"]

        # Fall back to device endpoint
        data = self._get(f"/devices/{identifier}")
        if isinstance(data, dict) and "error" not in data:
            return json.dumps(data, indent=2, default=str)

        # Try as IP
        devices = self._get("/devices")
        if isinstance(devices, list):
            for d in devices:
                if d.get("ip") == identifier:
                    return json.dumps(d, indent=2, default=str)

        return f"Device '{identifier}' not found"

    def _fetch_recent_alerts(self) -> str:
        """Fetch recent alerts."""
        data = self._get("/alerts", {"limit": 20})
        if isinstance(data, list):
            if not data:
                return "No recent alerts."
            lines = []
            for a in data:
                ts = a.get("ts", "?")
                sev = a.get("severity", "?")
                rule = a.get("rule_name", "?")
                device = a.get("device_id", "?")
                msg = (a.get("message") or "")[:150]
                lines.append(f"[{ts}] ({sev}) {rule} device={device}: {msg}")
            return "\n".join(lines)
        return json.dumps(data, default=str)

    def _fetch_recent_events(self, device_id: Optional[str] = None) -> str:
        """Fetch recent events, optionally filtered by device."""
        params = {"limit": 20}
        if device_id:
            params["device_id"] = device_id
        data = self._get("/events", params)
        if isinstance(data, list):
            if not data:
                return "No recent events."
            lines = []
            for e in data:
                ts = e.get("ts", "?")
                etype = e.get("event_type", "?")
                sev = e.get("severity", "?")
                dev = e.get("device_id", "?")
                msg = (e.get("message") or "")[:120]
                lines.append(f"[{ts}] {etype} ({sev}) device={dev}: {msg}")
            return "\n".join(lines)
        return json.dumps(data, default=str)

    def _fetch_anomalies(self) -> str:
        """Fetch active anomalies/findings."""
        data = self._get("/ask/anomalies")
        if isinstance(data, dict) and "content" in data:
            return data["content"]
        return json.dumps(data, default=str)

    def _extract_device_identifier(self, text: str) -> Optional[str]:
        """Try to extract a MAC or IP address from the investigation request."""
        import re

        # MAC address (colon, dash, or dot separated)
        mac_match = re.search(
            r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", text
        )
        if mac_match:
            return mac_match.group(0).upper()

        # IP address
        ip_match = re.search(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text
        )
        if ip_match:
            return ip_match.group(1)

        return None

    def pipe(self, body: dict) -> str:
        """Process investigation requests.

        Expected input in the last user message:
        INVESTIGATE: <event_type> on device <mac> -- <context>

        Returns an enriched investigation prompt that the model uses to
        produce a structured report.
        """
        messages = body.get("messages", [])
        if not messages:
            return "No investigation request found."

        last_msg = messages[-1].get("content", "")

        # Fetch network context
        network_summary = self._fetch_network_summary()
        recent_alerts = self._fetch_recent_alerts()
        anomalies = self._fetch_anomalies()

        # If a device is mentioned, fetch device-specific context
        device_id = self._extract_device_identifier(last_msg)
        device_context = ""
        device_events = ""
        if device_id:
            device_context = self._fetch_device_context(device_id)
            device_events = self._fetch_recent_events(device_id)

        # Build the enriched investigation prompt
        sections = [
            "You are investigating a network security event for SentinelHome.",
            "",
            "NETWORK SUMMARY:",
            network_summary,
            "",
            "RECENT ALERTS:",
            recent_alerts,
            "",
            "ACTIVE ANOMALIES:",
            anomalies,
        ]

        if device_context:
            sections.extend([
                "",
                f"DEVICE CONTEXT ({device_id}):",
                device_context,
            ])
        if device_events:
            sections.extend([
                "",
                f"RECENT EVENTS FOR DEVICE ({device_id}):",
                device_events,
            ])

        sections.extend([
            "",
            "INVESTIGATION REQUEST:",
            last_msg,
            "",
            "Analyze this event and provide your assessment in the following format:",
            "",
            "## Summary",
            "One-paragraph overview of what happened.",
            "",
            "## Classification",
            "- Severity: (info/low/medium/high/critical)",
            "- Confidence: (low/medium/high)",
            "- Expected or anomalous: (and why)",
            "",
            "## Analysis",
            "- What is the likely cause?",
            "- Are there related events or patterns?",
            "- What devices, IPs, and ports are involved?",
            "",
            "## Recommended Action",
            "- What should the user do? (monitor, investigate further, block, suppress, etc.)",
            "- Should any rules be updated?",
            "",
            "Be specific -- reference device names, IPs, MACs, and ports from the context above.",
            "If information is missing, say so rather than speculating.",
        ])

        return "\n".join(sections)
