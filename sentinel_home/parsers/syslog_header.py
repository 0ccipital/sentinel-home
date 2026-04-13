"""RFC 3164 / 5424 syslog header parser.

Strips the syslog envelope to extract:
  - timestamp (if present)
  - hostname
  - program name (process tag)
  - message body

Handles common variations:
  - RFC 3164: "Mar 18 14:30:01 hostname program[pid]: message"
  - RFC 5424: "<pri>1 2026-03-18T14:30:01Z hostname app - - - message"
  - rsyslog file format: "2026-03-18T14:30:01+00:00 hostname program[pid]: message"
  - Bare lines with no header (returns None)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class SyslogMessage:
    """Parsed syslog envelope."""

    timestamp: datetime | None  # None if unparseable
    hostname: str
    program: str  # e.g. "kernel", "hostapd", "sshd"
    pid: int | None
    message: str  # Everything after the header


# RFC 3164: "Mon DD HH:MM:SS" or "Mon  D HH:MM:SS"
_RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)"
)

# rsyslog ISO format: "2026-03-18T14:30:01+00:00" or "2026-03-18T14:30:01.123456+00:00"
_ISO_TS_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)"
)

# RFC 5424: "<pri>version timestamp hostname app-name procid msgid structured-data msg"
_RFC5424_RE = re.compile(
    r"^<\d+>\d+\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>\S+)\s+"
    r"(?:\S+\s+){2}"  # procid msgid
    r"(?:\[.*?\]\s*|-\s+)*"  # structured-data
    r"(?P<msg>.*)"
)


def parse_syslog_header(line: str) -> SyslogMessage | None:
    """Parse a syslog line and extract the envelope.

    Returns None if the line doesn't match any known syslog format.
    """
    if not line or len(line) < 10:
        return None

    # Try RFC 3164 first (most common for network devices)
    m = _RFC3164_RE.match(line)
    if m:
        return SyslogMessage(
            timestamp=_parse_rfc3164_ts(m.group("ts")),
            hostname=m.group("host"),
            program=m.group("prog"),
            pid=int(m.group("pid")) if m.group("pid") else None,
            message=m.group("msg"),
        )

    # Try ISO timestamp (rsyslog file output)
    m = _ISO_TS_RE.match(line)
    if m:
        return SyslogMessage(
            timestamp=_parse_iso_ts(m.group("ts")),
            hostname=m.group("host"),
            program=m.group("prog"),
            pid=int(m.group("pid")) if m.group("pid") else None,
            message=m.group("msg"),
        )

    # Try RFC 5424
    m = _RFC5424_RE.match(line)
    if m:
        return SyslogMessage(
            timestamp=_parse_iso_ts(m.group("ts")),
            hostname=m.group("host"),
            program=m.group("prog"),
            pid=None,
            message=m.group("msg"),
        )

    return None


def _parse_rfc3164_ts(ts_str: str) -> datetime | None:
    """Parse 'Mar 18 14:30:01' — no year, assume current year."""
    try:
        now = datetime.now()
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return dt.replace(year=now.year)
    except ValueError:
        return None


def _parse_iso_ts(ts_str: str) -> datetime | None:
    """Parse ISO 8601 timestamp."""
    if ts_str == "-":
        return None
    try:
        # Handle Z suffix
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return None
