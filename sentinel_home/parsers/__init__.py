"""Parser chain — auto-detect syslog content and extract structured events.

Design:
  1. syslog_header strips the RFC 3164/5424 envelope → SyslogMessage
  2. Content parsers try the message body in priority order → first match wins
  3. Each parser returns a ParseResult (or None if it can't handle the line)
  4. Parsers are pure functions: no DB access, no rule engine, no side effects

The collector calls parse_line() and decides what to do with the result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from sentinel_home.parsers.syslog_header import SyslogMessage, parse_syslog_header


@dataclass
class ParseResult:
    """Structured output from a content parser."""

    event_type: str  # e.g. "fw_wan_block", "sta_assoc", "disk_warning"
    severity: str = "info"  # info/low/medium/high/critical
    category: str = "network"  # ECS: network/authentication/host/process
    message: str = ""  # Human-readable summary
    fields: dict = field(default_factory=dict)  # Parsed key-value data
    device_type_hint: str | None = None  # Auto-classify source: router/ap/switch/server


class ContentParser(Protocol):
    """Protocol for content parsers."""

    name: str

    def try_parse(self, program: str, message: str) -> ParseResult | None:
        """Try to parse the message body. Return None if this parser can't handle it."""
        ...


# Registry of content parsers, tried in order. Specific parsers first, generic last.
_parsers: list[ContentParser] = []


def register_parser(parser: ContentParser) -> None:
    """Add a parser to the chain."""
    _parsers.append(parser)


def get_parsers() -> list[ContentParser]:
    """Return registered parsers (for testing/inspection)."""
    return list(_parsers)


def parse_line(raw_line: str) -> tuple[SyslogMessage | None, ParseResult | None]:
    """Parse a raw syslog line through the full chain.

    Returns (header, result) where either may be None:
      - header is None if the line has no valid syslog envelope
      - result is None if no content parser matched
    """
    header = parse_syslog_header(raw_line)

    # Reconstruct full body (program + message) so content parsers
    # can match on function names like "stahtd_dump_event()" that
    # the header parser splits across program/message fields.
    if header:
        program = header.program
        pid_part = f"[{header.pid}]" if header.pid else ""
        body = f"{program}{pid_part}: {header.message}" if header.message else raw_line
    else:
        program = ""
        body = raw_line

    for parser in _parsers:
        result = parser.try_parse(program, body)
        if result is not None:
            return header, result

    return header, None


def _register_all() -> None:
    """Register all built-in parsers in priority order."""
    # Import here to avoid circular imports
    from sentinel_home.parsers.iptables import IptablesParser
    from sentinel_home.parsers.hostapd import HostapdParser
    from sentinel_home.parsers.unifi import UniFiParser
    from sentinel_home.parsers.unraid import UnraidParser
    from sentinel_home.parsers.dnsmasq import DnsmasqParser

    # Order matters: specific before generic
    register_parser(IptablesParser())
    register_parser(HostapdParser())
    register_parser(UniFiParser())
    register_parser(UnraidParser())
    register_parser(DnsmasqParser())


# Auto-register on import
_register_all()
