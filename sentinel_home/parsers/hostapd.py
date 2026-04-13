"""hostapd WiFi event parser.

Works with any hostapd-based access point:
  - UniFi APs (U6-IW, U6-Pro, etc.)
  - OpenWrt with hostapd
  - Any Linux AP running hostapd

Parses:
  - STA authentication/association/disassociation
  - WPA authorization events
  - Auth failures and rejections
"""

from __future__ import annotations

import re

from sentinel_home.parsers import ParseResult


# hostapd STA events: "hostapd[pid]: vap: STA mac detail..."
# Also matches without syslog prefix when program is already stripped
_HOSTAPD_STA_RE = re.compile(
    r"(?:hostapd\[\d+\]:\s+)?(?P<vap>\S+):\s+STA\s+(?P<mac>[0-9a-f:]{17})\s+(?P<detail>.+)",
    re.IGNORECASE,
)

# Deauthentication/disassociation reason codes
_DEAUTH_RE = re.compile(
    r"(?:deauth|disassoc)\w*.*?(?:reason[= ]+(?P<reason>\d+))?",
    re.IGNORECASE,
)


class HostapdParser:
    name = "hostapd"

    def try_parse(self, program: str, message: str) -> ParseResult | None:
        """Parse hostapd STA events."""
        # Only try if program is hostapd or message contains hostapd markers
        if program and "hostapd" not in program.lower():
            if "hostapd" not in message.lower() and "STA " not in message:
                return None

        m = _HOSTAPD_STA_RE.search(message)
        if not m:
            return None

        mac = m.group("mac").lower()
        vap = m.group("vap")
        detail = m.group("detail")
        detail_lower = detail.lower()

        fields = {"mac": mac, "vap": vap, "detail": detail}

        # WPA authorized — successful full authentication
        if "wpa: authorized" in detail_lower:
            return ParseResult(
                event_type="wifi_auth_success",
                severity="info",
                category="authentication",
                message=f"WiFi auth success: {mac} on {vap}",
                fields=fields,
                device_type_hint="ap",
            )

        # Auth failures
        if any(kw in detail_lower for kw in ("denied", "auth_serv_from_unknown", "rejected", "not allowed")):
            return ParseResult(
                event_type="wifi_auth_reject",
                severity="medium",
                category="authentication",
                message=f"WiFi auth fail: {mac} on {vap}: {detail[:100]}",
                fields=fields,
                device_type_hint="ap",
            )

        # Disassociation / deauthentication
        if "disassociated" in detail_lower or "deauthenticated" in detail_lower:
            reason = None
            rm = _DEAUTH_RE.search(detail)
            if rm and rm.group("reason"):
                reason = int(rm.group("reason"))
                fields["reason_code"] = reason

            return ParseResult(
                event_type="wifi_disassoc" if "disassoc" in detail_lower else "wifi_deauth",
                severity="info",
                category="network",
                message=f"WiFi {'disassoc' if 'disassoc' in detail_lower else 'deauth'}: {mac} on {vap}"
                        + (f" (reason {reason})" if reason else ""),
                fields=fields,
                device_type_hint="ap",
            )

        # IEEE 802.11: associated / reassociated
        if "associated" in detail_lower and "disassociated" not in detail_lower:
            return ParseResult(
                event_type="wifi_assoc",
                severity="info",
                category="network",
                message=f"WiFi assoc: {mac} on {vap}",
                fields=fields,
                device_type_hint="ap",
            )

        return None
