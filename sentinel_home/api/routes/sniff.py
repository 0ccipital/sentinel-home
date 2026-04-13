"""Passive sniff endpoints: /api/v1/sniff/*"""

from __future__ import annotations

from fastapi import APIRouter

from sentinel_home.api.envelope import ok_envelope

router = APIRouter()

# In-memory sniff state — populated by the sniff collector
_sniff_state: dict = {
    "arp_table": {},
    "mdns_services": [],
    "upnp_requests": [],
    "dns_queries": {},
}


def get_sniff_state() -> dict:
    return _sniff_state


def update_sniff_state(key: str, value) -> None:
    _sniff_state[key] = value


@router.get("/sniff/summary")
async def sniff_summary():
    return ok_envelope({
        "arp_entries": len(_sniff_state["arp_table"]),
        "mdns_services": len(_sniff_state["mdns_services"]),
        "upnp_requests": len(_sniff_state["upnp_requests"]),
        "dns_query_sources": len(_sniff_state["dns_queries"]),
    })


@router.get("/sniff/arp")
async def sniff_arp():
    return ok_envelope(_sniff_state["arp_table"])


@router.get("/sniff/services")
async def sniff_services():
    return ok_envelope(_sniff_state["mdns_services"])


@router.get("/sniff/upnp")
async def sniff_upnp():
    return ok_envelope(_sniff_state["upnp_requests"])


@router.get("/sniff/dns")
async def sniff_dns():
    return ok_envelope(_sniff_state["dns_queries"])
