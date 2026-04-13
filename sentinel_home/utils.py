"""Shared utility functions used across SentinelHome."""

from __future__ import annotations


def primary_hostname(hostnames: dict | None) -> str | None:
    """Pick the best hostname from a hostnames dict.

    Priority: dhcp > mdns > nmap > dns > first available.
    Accepts either a dict directly or a Device model's .hostnames attribute.
    """
    if not hostnames:
        return None
    for key in ("dhcp", "mdns", "nmap", "dns"):
        if key in hostnames:
            return hostnames[key]
    return next(iter(hostnames.values()), None)


def device_display_name(
    *,
    mac: str | None = None,
    label: str | None = None,
    vendor: str | None = None,
    hostnames: dict | None = None,
    ip: str | None = None,
) -> str:
    """Build a human-readable display name for a device.

    Returns 'label (IP)', 'hostname (IP)', 'vendor (IP)', or just the MAC.
    """
    if not mac:
        return "—"
    name = label or primary_hostname(hostnames) or vendor or mac[:8]
    if ip:
        return f"{name} ({ip})"
    return name
