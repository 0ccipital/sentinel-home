"""Unraid host syslog parser.

Parses Unraid-specific events:
  - Disk warnings (SMART, reallocated sectors, array degraded)
  - Docker container crashes / OOM
  - emhttpd events (disk spin-up/down, SMART reads, parity)
  - Mover events (started/finished)
  - Security events (sudo, SSH)

Filters out high-volume Docker bridge noise.
"""

from __future__ import annotations

import re

from sentinel_home.parsers import ParseResult


_MOVER_RE = re.compile(r"mover:\s+(?P<action>started|finished)")

_DISK_PATTERNS = [
    "reallocated sector",
    "reallocated_sector",
    "current_pending_sector",
    "offline_uncorrectable",
    "smart error",
    "smart warning",
    "array degraded",
    "disk failure",
    "disk disabled",
    "failed to mount",
    "unrecoverable read error",
]

_EMHTTPD_PATTERNS = [
    "spinning up",
    "spinning down",
    "read smart",
    "parity check",
    "parity sync",
]

# Noise: Docker veth bridge cycling
_NOISE_PATTERNS = [
    "entered disabled state",
    "entered blocking state",
    "entered forwarding state",
    "entered allmulticast mode",
    "entered promiscuous mode",
    "left allmulticast mode",
    "left promiscuous mode",
    "renamed from eth0",
    "renamed from veth",
]


class UnraidParser:
    name = "unraid"

    def try_parse(self, program: str, message: str) -> ParseResult | None:
        """Parse Unraid-specific syslog events."""
        lower = message.lower()

        # Filter noise first
        for noise in _NOISE_PATTERNS:
            if noise in lower:
                return None

        # Disk warnings (highest priority)
        for pattern in _DISK_PATTERNS:
            if pattern in lower:
                return ParseResult(
                    event_type="disk_warning",
                    severity="high",
                    category="host",
                    message=f"Disk warning: {message[:200]}",
                    fields={"pattern": pattern, "line": message[:500]},
                    device_type_hint="server",
                )

        # Docker container crashes
        if "container" in lower and any(kw in lower for kw in ("died", "oom", "killed")):
            return ParseResult(
                event_type="docker_crash",
                severity="medium",
                category="process",
                message=f"Docker crash: {message[:200]}",
                fields={"line": message[:500]},
                device_type_hint="server",
            )

        # emhttpd events
        if "emhttpd" in lower:
            for pattern in _EMHTTPD_PATTERNS:
                if pattern in lower:
                    return ParseResult(
                        event_type="emhttpd_event",
                        severity="info",
                        category="host",
                        message=f"emhttpd: {pattern}",
                        fields={"pattern": pattern, "line": message[:500]},
                        device_type_hint="server",
                    )

        # Mover events
        m = _MOVER_RE.search(message)
        if m:
            action = m.group("action")
            return ParseResult(
                event_type="mover_event",
                severity="info",
                category="host",
                message=f"Mover {action}",
                fields={"action": action},
                device_type_hint="server",
            )

        # Sudo sessions
        if "sudo:" in message and "session opened" in lower:
            return ParseResult(
                event_type="sudo_session",
                severity="info",
                category="authentication",
                message=f"Sudo session: {message[:200]}",
                fields={"line": message[:500]},
                device_type_hint="server",
            )

        # SSH events
        if program == "sshd" or ("sshd" in lower and ("accepted" in lower or "failed" in lower)):
            is_failure = "failed" in lower
            return ParseResult(
                event_type="ssh_auth",
                severity="medium" if is_failure else "info",
                category="authentication",
                message=f"SSH {'failure' if is_failure else 'success'}: {message[:200]}",
                fields={"success": not is_failure, "line": message[:500]},
                device_type_hint="server",
            )

        return None
