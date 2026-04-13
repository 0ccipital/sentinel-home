"""iptables / netfilter firewall log parser.

Works with any Linux router that logs firewall events:
  - UniFi (Express, Dream Machine, EdgeRouter)
  - OpenWrt
  - pfSense (when using iptables-style logging)
  - Any custom Linux gateway

Parses lines like:
  [CHAIN-ACTION-RULE] DESCR="..." IN=eth0 OUT= SRC=1.2.3.4 DST=192.168.1.1 ...
  [UFW BLOCK] IN=eth0 ... SRC=1.2.3.4 ...
"""

from __future__ import annotations

import re

from sentinel_home.parsers import ParseResult


# [CHAIN-ACTION-RULE] optional DESCR="..." followed by KEY=VALUE fields
_FW_RULE_RE = re.compile(
    r"\[(?P<chain>[^\]]+)\]\s+(?:DESCR=\"(?P<descr>[^\"]*)\"\s+)?(?P<fields>.*)"
)
_FW_FIELD_RE = re.compile(r"(\w+)=(\S+)")

# Noise: mDNS (5353), UniFi discovery (10001), SSDP (1900), DHCP (67/68)
_NOISE_PORTS = {"5353", "10001", "1900", "67", "68"}


class IptablesParser:
    name = "iptables"

    def try_parse(self, program: str, message: str) -> ParseResult | None:
        """Parse iptables/netfilter log lines."""
        m = _FW_RULE_RE.search(message)
        if not m:
            return None

        chain = m.group("chain")
        descr = m.group("descr") or ""
        fields = dict(_FW_FIELD_RE.findall(m.group("fields")))

        # Must have at least SRC or DST to be a real firewall log
        if "SRC" not in fields and "DST" not in fields:
            return None

        src = fields.get("SRC", "")
        dst = fields.get("DST", "")
        proto = fields.get("PROTO", "")
        spt = fields.get("SPT", "")
        dpt = fields.get("DPT", "")
        iface_in = fields.get("IN", "")
        iface_out = fields.get("OUT", "")

        # Filter noise ports
        if spt in _NOISE_PORTS and dpt in _NOISE_PORTS:
            return None

        # Classify the event
        is_block = any(kw in chain.upper() for kw in ("-D-", "DROP", "BLOCK", "REJECT"))
        is_wan = any(kw in chain.upper() for kw in ("WAN", "FWD", "INPUT")) and iface_in != "br0"

        if is_block and is_wan:
            return ParseResult(
                event_type="fw_wan_block",
                severity="info",
                category="network",
                message=f"WAN block: {src}:{spt} -> {dst}:{dpt} ({proto})",
                fields={
                    "chain": chain, "descr": descr,
                    "src": src, "dst": dst, "proto": proto,
                    "spt": spt, "dpt": dpt,
                    "iface_in": iface_in, "iface_out": iface_out,
                    **{k: v for k, v in fields.items()
                       if k not in ("SRC", "DST", "PROTO", "SPT", "DPT", "IN", "OUT")},
                },
                device_type_hint="router",
            )

        elif is_block:
            return ParseResult(
                event_type="fw_block",
                severity="info",
                category="network",
                message=f"Block: {src}:{spt} -> {dst}:{dpt} ({proto}) [{chain}]",
                fields={
                    "chain": chain, "descr": descr,
                    "src": src, "dst": dst, "proto": proto,
                    "spt": spt, "dpt": dpt,
                    "iface_in": iface_in, "iface_out": iface_out,
                },
                device_type_hint="router",
            )

        else:
            # Allow / forward / return — LAN traffic
            # Only interesting if not multicast/broadcast
            if dst.startswith("224.") or dst.startswith("ff") or dst == "255.255.255.255":
                return None

            return ParseResult(
                event_type="fw_lan_traffic",
                severity="info",
                category="network",
                message=f"LAN: {src}:{spt} -> {dst}:{dpt} ({proto}) [{chain}]",
                fields={
                    "chain": chain, "descr": descr,
                    "src": src, "dst": dst, "proto": proto,
                    "spt": spt, "dpt": dpt,
                    "iface_in": iface_in, "iface_out": iface_out,
                },
                device_type_hint="router",
            )
