"""dnsmasq DHCP/DNS parser.

Works with any system running dnsmasq:
  - OpenWrt routers
  - Pi-hole (uses dnsmasq under the hood)
  - Standalone dnsmasq DNS/DHCP servers

Parses:
  - DHCP leases (DHCPACK, DHCPDISCOVER, DHCPREQUEST, DHCPRELEASE)
  - DNS queries and replies (when query logging is enabled)
  - TFTP events
"""

from __future__ import annotations

import re

from sentinel_home.parsers import ParseResult


# DHCP events: "DHCPACK(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff hostname"
_DHCP_RE = re.compile(
    r"(?P<action>DHCPACK|DHCPDISCOVER|DHCPREQUEST|DHCPNAK|DHCPRELEASE|DHCPOFFER)"
    r"\((?P<iface>[^)]+)\)\s+"
    r"(?P<ip>[\d.]+)\s+"
    r"(?P<mac>[0-9a-f:]{17})"
    r"(?:\s+(?P<hostname>\S+))?",
    re.IGNORECASE,
)

# DNS query: "query[A] example.com from 192.168.1.50"
_DNS_QUERY_RE = re.compile(
    r"query\[(?P<qtype>[^\]]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client>[\d.]+)"
)

# DNS reply: "reply example.com is 1.2.3.4" or "reply example.com is NXDOMAIN"
_DNS_REPLY_RE = re.compile(
    r"(?:reply|cached)\s+(?P<domain>\S+)\s+is\s+(?P<answer>\S+)"
)

# DNS forwarded: "forwarded example.com to 1.1.1.1"
_DNS_FORWARD_RE = re.compile(
    r"forwarded\s+(?P<domain>\S+)\s+to\s+(?P<server>[\d.]+)"
)


class DnsmasqParser:
    name = "dnsmasq"

    def try_parse(self, program: str, message: str) -> ParseResult | None:
        """Parse dnsmasq DHCP and DNS events."""
        # Only try if program matches or message has clear dnsmasq markers
        prog_lower = program.lower() if program else ""
        if prog_lower and "dnsmasq" not in prog_lower:
            # Check for DHCP keywords even without program match
            if not any(kw in message for kw in ("DHCPACK", "DHCPDISCOVER", "DHCPREQUEST",
                                                  "DHCPNAK", "DHCPRELEASE", "DHCPOFFER")):
                if "query[" not in message and "reply " not in message:
                    return None

        # DHCP events
        m = _DHCP_RE.search(message)
        if m:
            action = m.group("action").upper()
            ip = m.group("ip")
            mac = m.group("mac").lower()
            hostname = m.group("hostname") or ""
            iface = m.group("iface")

            return ParseResult(
                event_type=f"dhcp_{action.lower()}",
                severity="info",
                category="network",
                message=f"{action}: {ip} {mac}"
                        + (f" ({hostname})" if hostname else "")
                        + f" on {iface}",
                fields={
                    "action": action,
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "iface": iface,
                },
            )

        # DNS query
        m = _DNS_QUERY_RE.search(message)
        if m:
            return ParseResult(
                event_type="dns_query",
                severity="info",
                category="network",
                message=f"DNS {m.group('qtype')}: {m.group('domain')} from {m.group('client')}",
                fields={
                    "query_type": m.group("qtype"),
                    "domain": m.group("domain"),
                    "client": m.group("client"),
                },
            )

        # DNS reply
        m = _DNS_REPLY_RE.search(message)
        if m:
            domain = m.group("domain")
            answer = m.group("answer")
            is_nxdomain = answer.upper() in ("NXDOMAIN", "<CNAME>", "NODATA-IPV6", "NODATA-IPV4")

            return ParseResult(
                event_type="dns_reply",
                severity="info",
                category="network",
                message=f"DNS reply: {domain} -> {answer}",
                fields={
                    "domain": domain,
                    "answer": answer,
                    "nxdomain": is_nxdomain,
                },
            )

        return None
