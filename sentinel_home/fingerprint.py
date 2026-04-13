"""Device fingerprinting — OUI vendor lookup + type classification + role inference.

Central enrichment module. Any collector can call enrich_device() to update
a Device record with the latest information from whatever source discovered it.

Data sources:
  - OUI → vendor (ARP/sniff)
  - nmap → os_family, services
  - mDNS → hostnames, services
  - DHCP → hostnames
  - Parser hints → device_type (syslog auto-classification)
  - WiFi events → connection_type, AP
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OUI vendor lookup — pure synchronous, no async tasks
# ---------------------------------------------------------------------------
# The mac-vendor-lookup package's MacLookup class wraps AsyncMacLookup,
# which spawns orphaned coroutines (VendorNotFoundError) when used inside
# an already-running event loop (uvicorn).  We bypass it entirely by loading
# the vendor prefix file directly into a dict on first use.

_oui_prefixes: dict[bytes, bytes] | None = None
_oui_available = True


def _load_oui_prefixes() -> dict[bytes, bytes] | None:
    """Load the OUI prefix→vendor dict from the bundled vendor list."""
    global _oui_prefixes, _oui_available
    if _oui_prefixes is not None:
        return _oui_prefixes
    if not _oui_available:
        return None

    try:
        from mac_vendor_lookup import AsyncMacLookup
        path = AsyncMacLookup().find_vendors_list()
        if not path:
            logger.warning("OUI vendor list file not found")
            _oui_available = False
            return None

        prefixes: dict[bytes, bytes] = {}
        with open(path, "rb") as f:
            for line in f.read().splitlines():
                prefix, vendor = line.split(b":", 1)
                prefixes[prefix] = vendor

        _oui_prefixes = prefixes
        logger.info("OUI vendor lookup initialised (%d prefixes, sync)", len(prefixes))
        return _oui_prefixes
    except Exception as exc:
        logger.warning("OUI lookup unavailable: %s", exc)
        _oui_available = False
        return None


def lookup_vendor(mac: str) -> str | None:
    """Look up vendor name from MAC OUI prefix. Returns None on miss."""
    prefixes = _load_oui_prefixes()
    if prefixes is None:
        return None
    try:
        clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
        key = clean[:6].encode("utf-8")
        vendor = prefixes.get(key)
        return vendor.decode("utf-8") if vendor else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Device type inference from services/vendor/hostname
# ---------------------------------------------------------------------------

_INFRA_VENDORS = {
    "ubiquiti", "cisco", "netgear", "tp-link", "aruba", "mikrotik",
    "juniper", "fortinet", "meraki", "ruckus", "zyxel", "unifi",
}

_IOT_VENDORS = {
    "espressif", "tuya", "shelly", "sonoff", "philips lighting",
    "ring", "nest", "ecobee", "wyze", "lifx", "meross",
}

_PHONE_VENDORS = {
    "apple", "samsung", "google", "oneplus", "xiaomi", "huawei",
    "oppo", "motorola", "sony mobile",
}


def infer_device_type(
    vendor: str | None = None,
    os_family: str | None = None,
    services: dict | None = None,
    hostnames: dict | None = None,
    parser_hint: str | None = None,
) -> str | None:
    """Infer device type from available signals. Returns None if unsure.

    Types: router, ap, switch, server, desktop, laptop, phone, tablet, iot, media, unknown
    """
    # Parser hint is authoritative when present (came from syslog content)
    if parser_hint:
        return parser_hint

    v = (vendor or "").lower()

    # Check vendor-based heuristics
    if any(iv in v for iv in _INFRA_VENDORS):
        return "infrastructure"  # refine with services below

    if any(iv in v for iv in _IOT_VENDORS):
        return "iot"

    if any(iv in v for iv in _PHONE_VENDORS):
        return "phone"

    # OS-based
    if os_family:
        osf = os_family.lower()
        if "windows" in osf:
            return "desktop"
        if "linux" in osf:
            return "server"  # Could be desktop, but on a home net usually a server/NAS
        if "ios" in osf or "iphone" in osf or "ipad" in osf:
            return "phone"
        if "android" in osf:
            return "phone"
        if "mac os" in osf or "macos" in osf:
            return "desktop"

    # Service-based
    if services:
        port_set = set(services.keys()) if isinstance(services, dict) else set()
        if 32400 in port_set or "32400" in port_set:
            return "media"  # Plex
        if 445 in port_set or "445" in port_set:
            return "server"  # File share

    return None


def infer_network_role(
    device_type: str | None = None,
    services: dict | None = None,
) -> str | None:
    """Infer network role. Returns: infrastructure/client/server/iot or None."""
    if device_type in ("router", "ap", "switch", "infrastructure"):
        return "infrastructure"
    if device_type in ("server",):
        return "server"
    if device_type in ("iot",):
        return "iot"
    if device_type in ("phone", "tablet", "desktop", "laptop"):
        return "client"
    if device_type == "media":
        return "server"
    return None


# ---------------------------------------------------------------------------
# Central enrichment — merges data from any source into Device record
# ---------------------------------------------------------------------------

def enrich_device(
    mac: str,
    ip: str | None = None,
    vendor: str | None = None,
    os_family: str | None = None,
    device_type_hint: str | None = None,
    hostnames: dict | None = None,
    services: dict | None = None,
    connection_type: str | None = None,
    ap: str | None = None,
    signal_strength: int | None = None,
    channel: int | None = None,
    band: str | None = None,
    unifi_id: str | None = None,
    vlan_id: int | None = None,
    infra_state: str | None = None,
) -> None:
    """Update a Device record with new information. Merges, never overwrites with None.

    Call from any collector whenever new device data is discovered:
      - ARP (sniff): mac, ip, vendor (via OUI)
      - nmap: mac, ip, os_family, services
      - mDNS: mac, ip, hostnames
      - DHCP: mac, ip, hostnames
      - WiFi events: mac, ip, connection_type, ap
      - Parser hint: device_type_hint
      - UniFi API: signal_strength, channel, band, unifi_id, vlan_id, infra_state
    """
    mac = mac.lower().strip()
    if not mac or len(mac) != 17:
        return

    # Auto-fill vendor from OUI if not provided
    if not vendor:
        vendor = lookup_vendor(mac)

    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Device

        with session_scope() as session:
            device = session.query(Device).filter(Device.mac == mac).first()

            if device is None:
                device = Device(mac=mac)
                session.add(device)

            # Merge fields — never overwrite with None
            if ip:
                device.ip = ip
            if vendor and not device.vendor:
                device.vendor = vendor
            if os_family and not device.os_family:
                device.os_family = os_family
            if connection_type:
                device.connection_type = connection_type
            if ap:
                device.ap = ap

            # WiFi / UniFi fields — always update when present (these are transient)
            if signal_strength is not None:
                device.signal_strength = signal_strength
            if channel is not None:
                device.channel = channel
            if band:
                device.band = band
            if unifi_id:
                device.unifi_id = unifi_id
            if vlan_id is not None:
                device.vlan_id = vlan_id
            if infra_state:
                device.infra_state = infra_state

            # Merge hostnames (accumulate from multiple sources)
            if hostnames:
                existing = device.hostnames or {}
                existing.update(hostnames)
                device.hostnames = existing

            # Merge services (accumulate)
            if services:
                existing = device.services or {}
                existing.update(services)
                device.services = existing

            # Infer device type if not already set or if parser hint is authoritative
            if device_type_hint or not device.device_type:
                inferred = infer_device_type(
                    vendor=device.vendor,
                    os_family=device.os_family,
                    services=device.services,
                    hostnames=device.hostnames,
                    parser_hint=device_type_hint,
                )
                if inferred:
                    device.device_type = inferred

            # Infer network role if not set by user/agent
            if not device.network_role or device.updated_by == "system":
                role = infer_network_role(device.device_type, device.services)
                if role:
                    device.network_role = role

            device.last_seen = datetime.now(timezone.utc)
            if not device.updated_by:
                device.updated_by = "system"

    except Exception as exc:
        logger.debug("Failed to enrich device %s: %s", mac, exc)
