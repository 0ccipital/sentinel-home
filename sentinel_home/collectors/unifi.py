"""UniFi Network Integration API collector — polls clients, devices, and config.

Uses the official Integration API (X-API-KEY auth) available on UniFi
gateways running UniFi Network 9.x+. Provides:
  - Client inventory with connection type, signal, channel
  - Infrastructure device status, health metrics (CPU, memory, uplink)
  - Network topology: VLANs, SSIDs, firewall summary
  - New client / disconnect / infrastructure state change events
  - Config change detection (SSID, firewall)
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

import httpx

from sentinel_home.collectors.base import BaseCollector
from sentinel_home.config import get_settings

logger = logging.getLogger(__name__)

# Frequency for slow-changing config polling (VLANs, SSIDs, firewall)
_CONFIG_POLL_INTERVAL = 1800  # 30 minutes
# Frequency for device stats polling
_STATS_POLL_INTERVAL = 300  # 5 minutes


_INVALID_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


def _normalize_mac(raw: str | None) -> str:
    """Normalize a MAC address to lowercase colon-separated format.

    Returns empty string for invalid/missing/broadcast MACs.
    """
    if not raw:
        return ""
    clean = raw.replace("-", ":").lower().strip()
    # Handle formats like "AABBCCDDEEFF" (no separators)
    if len(clean) == 12 and ":" not in clean:
        clean = ":".join(clean[i:i+2] for i in range(0, 12, 2))
    if len(clean) != 17 or clean in _INVALID_MACS:
        return ""
    return clean


class UniFiCollector(BaseCollector):
    name = "unifi"

    def __init__(self):
        super().__init__()
        self._stop_event = asyncio.Event()
        # Track known client MACs to detect new arrivals
        self._known_clients: set[str] = set()
        # Track connected clients to detect disconnects
        self._connected_clients: set[str] = set()
        self._site_id: str | None = None
        self._first_poll = True

        # UUID <-> MAC mappings for API write-back
        self._client_id_map: dict[str, str] = {}  # MAC -> UniFi UUID
        self._device_id_map: dict[str, str] = {}  # MAC -> UniFi UUID

        # Infrastructure state tracking (MAC -> state string)
        self._infra_states: dict[str, str] = {}

        # Config change detection
        self._last_config_poll: float = 0
        self._last_stats_poll: float = 0
        self._cached_networks: list[dict] | None = None
        self._cached_ssids: list[dict] | None = None
        self._cached_firewall: dict | None = None

        # Client count per AP MAC for stats
        self._ap_client_counts: dict[str, int] = {}

    async def start(self) -> None:
        self.stats.running = True
        logger.info("UniFi collector starting")
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                pass
        self.stats.running = False
        logger.info("UniFi collector stopped")

    async def _poll_loop(self) -> None:
        settings = get_settings()
        host = settings.unifi.host
        interval = settings.unifi.poll_interval_seconds
        verify = settings.unifi.verify_ssl

        if not host:
            logger.warning("UniFi host not configured — collector idle")
            await self._stop_event.wait()
            return

        base = f"https://{host}/proxy/network/integration/v1"
        api_key = settings.unifi.api_key

        if not api_key:
            logger.warning("UniFi API key not configured — collector idle")
            await self._stop_event.wait()
            return

        headers = {
            "X-API-KEY": api_key,
            "Accept": "application/json",
        }

        logger.info(
            "UniFi collector polling %s every %ds (ssl_verify=%s)",
            base, interval, verify,
        )

        while not self._stop_event.is_set():
            try:
                await self._poll(base, headers, verify)
            except Exception as exc:
                self._record_error(exc)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass

    async def _poll(self, base: str, headers: dict, verify: bool) -> None:
        async with httpx.AsyncClient(
            timeout=30, verify=verify, headers=headers,
        ) as client:
            # Resolve site ID on first poll
            if not self._site_id:
                self._site_id = await self._resolve_site(client, base)
                if not self._site_id:
                    return

            site_base = f"{base}/sites/{self._site_id}"
            now = time.monotonic()

            # Always poll clients and devices
            tasks = [
                self._poll_clients(client, site_base),
                self._poll_devices(client, site_base),
            ]

            # Poll device stats every _STATS_POLL_INTERVAL
            if now - self._last_stats_poll >= _STATS_POLL_INTERVAL:
                tasks.append(self._poll_device_stats(client, site_base))
                self._last_stats_poll = now

            # Poll config (VLANs, SSIDs, firewall) less frequently
            if now - self._last_config_poll >= _CONFIG_POLL_INTERVAL:
                tasks.append(self._poll_config(client, site_base))
                self._last_config_poll = now

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.warning("UniFi poll task failed: %s", r)

    async def _resolve_site(
        self, client: httpx.AsyncClient, base: str,
    ) -> str | None:
        """Get the default site ID."""
        try:
            resp = await client.get(f"{base}/sites")
            if resp.status_code != 200:
                logger.warning(
                    "UniFi sites request failed (HTTP %d): %s",
                    resp.status_code, resp.text[:200],
                )
                return None
            data = resp.json()
            sites = data if isinstance(data, list) else data.get("data", [])
            if not sites:
                logger.warning("UniFi: no sites found")
                return None
            site = sites[0]
            site_id = site.get("id") or site.get("_id")
            logger.info("UniFi: using site %s (%s)", site_id, site.get("name", "default"))
            return site_id
        except Exception as exc:
            logger.warning("UniFi: failed to resolve site: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Client polling
    # ------------------------------------------------------------------

    async def _poll_clients(
        self, client: httpx.AsyncClient, site_base: str,
    ) -> None:
        """Poll connected clients, enrich devices, detect new arrivals."""
        try:
            all_clients = await self._paginated_get(client, f"{site_base}/clients")
        except Exception as exc:
            logger.debug("UniFi clients poll failed: %s", exc)
            return

        self._record_event()
        loop = asyncio.get_running_loop()

        current_macs: set[str] = set()
        ap_counts: dict[str, int] = {}

        for c in all_clients:
            mac = _normalize_mac(c.get("macAddress") or c.get("mac"))
            if not mac:
                continue

            current_macs.add(mac)

            # Map UUID for write-back actions
            uid = c.get("id")
            if uid:
                self._client_id_map[mac] = uid

            ip = c.get("ipAddress") or c.get("ip")
            name = c.get("name") or c.get("hostname")
            client_type = c.get("type", "").upper()
            is_wired = client_type == "WIRED"

            # Build hostnames dict
            hostnames: dict[str, str] = {}
            if name:
                hostnames["unifi"] = name

            # WiFi details for wireless clients
            signal = None
            chan = None
            band = None
            ap_mac = None

            if client_type == "WIRELESS":
                signal = c.get("signalStrength") or c.get("signal")
                chan = c.get("channel")
                band_ghz = c.get("band") or c.get("frequencyGHz")
                if band_ghz:
                    band = f"{band_ghz}GHz" if "GHz" not in str(band_ghz) else str(band_ghz)
                ap_mac_raw = c.get("accessPointMacAddress") or c.get("ap_mac")
                ap_mac = _normalize_mac(ap_mac_raw)
                if ap_mac:
                    ap_counts[ap_mac] = ap_counts.get(ap_mac, 0) + 1

            # Connection type
            conn = "wired" if is_wired else "wifi"
            if client_type in ("VPN", "TELEPORT"):
                conn = client_type.lower()

            # Enrich device record
            await loop.run_in_executor(
                None, _enrich_client, mac, ip, conn, hostnames,
                signal, chan, band, ap_mac, uid,
            )

            # Detect new clients (skip first poll to avoid flooding)
            if not self._first_poll and mac not in self._known_clients:
                await loop.run_in_executor(
                    None, _persist_new_client_event, mac, ip, name, conn, client_type,
                )

        # Detect disconnects
        if not self._first_poll:
            disconnected = self._connected_clients - current_macs
            for mac in disconnected:
                await loop.run_in_executor(None, _persist_disconnect_event, mac)

        self._known_clients.update(current_macs)
        self._connected_clients = current_macs
        self._ap_client_counts = ap_counts
        self._first_poll = False

    # ------------------------------------------------------------------
    # Infrastructure device polling
    # ------------------------------------------------------------------

    async def _poll_devices(
        self, client: httpx.AsyncClient, site_base: str,
    ) -> None:
        """Poll infrastructure devices (APs, switches, gateways)."""
        try:
            all_devices = await self._paginated_get(client, f"{site_base}/devices")
        except Exception as exc:
            logger.debug("UniFi devices poll failed: %s", exc)
            return

        self._record_event()
        loop = asyncio.get_running_loop()

        for d in all_devices:
            mac = _normalize_mac(d.get("macAddress") or d.get("mac"))
            if not mac:
                continue

            # Map UUID for stats polling and write-back
            uid = d.get("id")
            if uid:
                self._device_id_map[mac] = uid

            ip = d.get("ipAddress") or d.get("ip")
            name = d.get("name") or d.get("model")
            model = d.get("model") or ""
            state = d.get("state", "UNKNOWN")

            device_type = _infer_infra_type(model, d.get("features"))

            hostnames: dict[str, str] = {}
            if name:
                hostnames["unifi"] = name

            await loop.run_in_executor(
                None, _enrich_infra_device, mac, ip, device_type, hostnames,
                state, uid,
            )

            # Detect state changes
            old_state = self._infra_states.get(mac)
            if old_state and old_state != state:
                await loop.run_in_executor(
                    None, _persist_state_change_event,
                    mac, name or mac, old_state, state,
                )
            self._infra_states[mac] = state

    # ------------------------------------------------------------------
    # Device statistics polling
    # ------------------------------------------------------------------

    async def _poll_device_stats(
        self, client: httpx.AsyncClient, site_base: str,
    ) -> None:
        """Poll latest stats for each infrastructure device."""
        if not self._device_id_map:
            return

        loop = asyncio.get_running_loop()
        stale_macs: list[str] = []

        for mac, uid in list(self._device_id_map.items()):
            try:
                resp = await client.get(
                    f"{site_base}/devices/{uid}/statistics/latest",
                )
                if resp.status_code == 404:
                    stale_macs.append(mac)
                    continue
                if resp.status_code != 200:
                    continue

                stats = resp.json()
                if not isinstance(stats, dict):
                    continue
                client_count = self._ap_client_counts.get(mac)

                await loop.run_in_executor(
                    None, _persist_infra_metric,
                    mac, stats, client_count,
                )

                # Check thresholds for alerting.
                # cpuUtilizationPct is 0-100%; loadAverage5Min is a raw load
                # average and is NOT comparable to a % threshold — use only the
                # percentage field here.
                cpu_val = stats.get("cpuUtilizationPct")
                cpu = float(cpu_val) if cpu_val is not None else None
                mem = stats.get("memoryUtilizationPct")
                retries = None
                radios = stats.get("interfaces", {}).get("radios", [])
                if radios:
                    retries = max(
                        (r.get("txRetriesPct", 0) for r in radios), default=None,
                    )

                await loop.run_in_executor(
                    None, _check_infra_thresholds,
                    mac, cpu, mem, retries,
                )

            except Exception as exc:
                logger.debug("UniFi stats poll failed for %s: %s", mac, exc)

        # Clean up stale device UUIDs (removed from UniFi)
        for mac in stale_macs:
            self._device_id_map.pop(mac, None)
            logger.debug("UniFi: removed stale device UUID for %s", mac)

    # ------------------------------------------------------------------
    # Config polling (VLANs, SSIDs, firewall)
    # ------------------------------------------------------------------

    async def _poll_config(
        self, client: httpx.AsyncClient, site_base: str,
    ) -> None:
        """Poll slow-changing network config for topology awareness."""
        loop = asyncio.get_running_loop()

        # Networks / VLANs
        try:
            networks = await self._paginated_get(client, f"{site_base}/networks")
            old = self._cached_networks
            self._cached_networks = networks
            await loop.run_in_executor(
                None, _store_config_baseline, "network_config", networks, old,
            )
        except Exception as exc:
            logger.debug("UniFi networks poll failed: %s", exc)

        # WiFi broadcasts / SSIDs
        try:
            ssids = await self._paginated_get(client, f"{site_base}/wifi-broadcasts")
            old = self._cached_ssids
            self._cached_ssids = ssids
            await loop.run_in_executor(
                None, _store_config_baseline, "wifi_config", ssids, old,
            )
        except Exception as exc:
            logger.debug("UniFi SSIDs poll failed: %s", exc)

        # Firewall zones + policies
        try:
            zones = await self._paginated_get(client, f"{site_base}/firewall/zones")
            policies = await self._paginated_get(client, f"{site_base}/firewall/policies")
            fw = {"zones": zones, "policies": policies}
            old = self._cached_firewall
            self._cached_firewall = fw
            await loop.run_in_executor(
                None, _store_config_baseline, "firewall_config", fw, old,
            )
        except Exception as exc:
            logger.debug("UniFi firewall poll failed: %s", exc)

    # ------------------------------------------------------------------
    # Pagination helper
    # ------------------------------------------------------------------

    async def _paginated_get(
        self, client: httpx.AsyncClient, url: str,
    ) -> list[dict]:
        """Fetch all pages from a paginated UniFi endpoint."""
        all_items: list[dict] = []
        offset = 0
        limit = 200  # API max

        while True:
            resp = await client.get(url, params={"offset": offset, "limit": limit})
            if resp.status_code != 200:
                logger.debug(
                    "UniFi paginated GET %s failed (HTTP %d)", url, resp.status_code,
                )
                break

            data = resp.json()
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("data", data.get("items", []))
            else:
                break

            all_items.extend(items)

            # Stop if we got fewer than requested (last page)
            if len(items) < limit:
                break
            offset += limit

        return all_items

    # ------------------------------------------------------------------
    # Write actions (called from API routes)
    # ------------------------------------------------------------------

    async def execute_client_action(self, mac: str, action: str) -> dict:
        """Execute a client action (BLOCK, UNBLOCK, RECONNECT)."""
        if not self._site_id:
            return {"error": "UniFi collector not ready (no site resolved yet)"}
        uid = self._client_id_map.get(mac)
        if not uid:
            return {"error": f"Client {mac} not found in UniFi (not currently connected?)"}

        settings = get_settings()
        base = f"https://{settings.unifi.host}/proxy/network/integration/v1"
        headers = {"X-API-KEY": settings.unifi.api_key, "Accept": "application/json"}

        async with httpx.AsyncClient(
            timeout=15, verify=settings.unifi.verify_ssl, headers=headers,
        ) as client:
            resp = await client.post(
                f"{base}/sites/{self._site_id}/clients/{uid}/action",
                json={"action": action.upper()},
            )
            if resp.status_code == 200:
                return {"status": "ok", "action": action, "mac": mac}
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    async def execute_device_action(self, mac: str, action: str) -> dict:
        """Execute an infrastructure device action (RESTART, LOCATE)."""
        if not self._site_id:
            return {"error": "UniFi collector not ready (no site resolved yet)"}
        uid = self._device_id_map.get(mac)
        if not uid:
            return {"error": f"Device {mac} not found in UniFi"}

        settings = get_settings()
        base = f"https://{settings.unifi.host}/proxy/network/integration/v1"
        headers = {"X-API-KEY": settings.unifi.api_key, "Accept": "application/json"}

        async with httpx.AsyncClient(
            timeout=15, verify=settings.unifi.verify_ssl, headers=headers,
        ) as client:
            resp = await client.post(
                f"{base}/sites/{self._site_id}/devices/{uid}/action",
                json={"action": action.upper()},
            )
            if resp.status_code == 200:
                return {"status": "ok", "action": action, "mac": mac}
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    def get_stats(self) -> dict:
        base = super().get_stats()
        base["known_clients"] = len(self._known_clients)
        base["connected_clients"] = len(self._connected_clients)
        base["infra_devices"] = len(self._device_id_map)
        base["site_id"] = self._site_id
        return base

    def get_cached_config(self) -> dict:
        """Return cached network config for knowledge sync / API."""
        return {
            "networks": self._cached_networks,
            "ssids": self._cached_ssids,
            "firewall": self._cached_firewall,
        }


# ---------------------------------------------------------------------------
# Sync helpers (run via run_in_executor)
# ---------------------------------------------------------------------------

def _enrich_client(
    mac: str,
    ip: str | None,
    connection_type: str,
    hostnames: dict,
    signal_strength: int | None,
    channel: int | None,
    band: str | None,
    ap_mac: str | None,
    unifi_id: str | None,
) -> None:
    """Enrich a device record from UniFi client data."""
    from sentinel_home.fingerprint import enrich_device
    enrich_device(
        mac=mac,
        ip=ip,
        connection_type=connection_type,
        hostnames=hostnames if hostnames else None,
        ap=ap_mac or None,
        signal_strength=signal_strength,
        channel=channel,
        band=band,
        unifi_id=unifi_id,
    )


def _enrich_infra_device(
    mac: str,
    ip: str | None,
    device_type: str,
    hostnames: dict,
    state: str,
    unifi_id: str | None,
) -> None:
    """Enrich an infrastructure device from UniFi device data."""
    from sentinel_home.fingerprint import enrich_device
    enrich_device(
        mac=mac,
        ip=ip,
        device_type_hint=device_type,
        hostnames=hostnames if hostnames else None,
        infra_state=state,
        unifi_id=unifi_id,
    )


def _persist_new_client_event(
    mac: str,
    ip: str | None,
    hostname: str | None,
    connection_type: str,
    client_type: str,
) -> None:
    """Record a new client detection event."""
    from sentinel_home.database import session_scope
    from sentinel_home.models import Event

    name = hostname or mac
    try:
        with session_scope() as session:
            session.add(Event(
                source="unifi",
                event_type="new_device",
                severity="medium",
                device_id=mac,
                message=f"New {connection_type} client: {name} ({ip or 'no IP'})",
                raw={
                    "mac": mac, "ip": ip, "hostname": hostname,
                    "connection_type": connection_type, "client_type": client_type,
                },
            ))
        logger.info("UniFi: new %s client %s (%s)", connection_type, name, mac)

        # Fire VPN rule for VPN/Teleport clients
        if client_type in ("VPN", "TELEPORT"):
            from sentinel_home.rules.engine import get_engine
            get_engine().fire_rule(
                "vpn_client_connect", mac,
                {"name": name, "ip": ip, "type": client_type},
            )
    except Exception as exc:
        logger.debug("Failed to persist new client event: %s", exc)


def _persist_disconnect_event(mac: str) -> None:
    """Record a client disconnect event."""
    from sentinel_home.database import session_scope
    from sentinel_home.models import Event

    try:
        with session_scope() as session:
            session.add(Event(
                source="unifi",
                event_type="client_disconnect",
                severity="info",
                device_id=mac,
                message=f"Client disconnected: {mac}",
                raw={"mac": mac},
            ))
    except Exception as exc:
        logger.debug("Failed to persist disconnect event: %s", exc)


def _persist_state_change_event(
    mac: str, name: str, old_state: str, new_state: str,
) -> None:
    """Record an infrastructure device state change."""
    from sentinel_home.database import session_scope
    from sentinel_home.models import Event
    from sentinel_home.rules.engine import get_engine

    severity = "high" if new_state == "OFFLINE" else "medium"
    try:
        with session_scope() as session:
            session.add(Event(
                source="unifi",
                event_type="infra_state_change",
                severity=severity,
                category="host",
                kind="state",
                device_id=mac,
                message=f"{name} state: {old_state} → {new_state}",
                raw={"mac": mac, "name": name, "old_state": old_state, "new_state": new_state},
            ))

        # Fire the rule if device goes offline
        if new_state == "OFFLINE":
            engine = get_engine()
            engine.fire_rule(
                "infra_device_offline", mac,
                {"name": name, "old_state": old_state, "new_state": new_state},
            )
    except Exception as exc:
        logger.debug("Failed to persist state change event: %s", exc)


def _persist_infra_metric(
    mac: str, stats: dict, client_count: int | None,
) -> None:
    """Store an infrastructure metric snapshot."""
    from sentinel_home.database import session_scope
    from sentinel_home.models import InfraMetric

    uplink = stats.get("uplink", {})
    radios = stats.get("interfaces", {}).get("radios", [])
    max_retries = None
    if radios:
        retries = [r.get("txRetriesPct") for r in radios if r.get("txRetriesPct") is not None]
        if retries:
            max_retries = max(retries)

    try:
        with session_scope() as session:
            session.add(InfraMetric(
                device_mac=mac,
                cpu_load_1m=stats.get("loadAverage1Min"),
                cpu_load_5m=stats.get("loadAverage5Min"),
                memory_pct=stats.get("memoryUtilizationPct"),
                uplink_tx_bps=uplink.get("txRateBps"),
                uplink_rx_bps=uplink.get("rxRateBps"),
                radio_tx_retries_pct=max_retries,
                uptime_seconds=stats.get("uptimeSec"),
                client_count=client_count,
                raw=stats,
            ))
    except Exception as exc:
        logger.debug("Failed to persist infra metric for %s: %s", mac, exc)


def _check_infra_thresholds(
    mac: str,
    cpu: float | None,
    memory: float | None,
    retries: float | None,
) -> None:
    """Fire rules if infrastructure metrics exceed thresholds."""
    from sentinel_home.rules.engine import get_engine
    engine = get_engine()

    if cpu is not None and cpu > 80:
        engine.fire_rule("infra_high_cpu", mac, {"cpu_pct": cpu})

    if memory is not None and memory > 90:
        engine.fire_rule("infra_high_memory", mac, {"memory_pct": memory})

    if retries is not None and retries > 15:
        engine.fire_rule("ap_high_retries", mac, {"tx_retries_pct": retries})


def _store_config_baseline(
    baseline_type: str, new_data: dict | list, old_data: dict | list | None,
) -> None:
    """Store network config as a Baseline record. Detect changes."""
    from sentinel_home.database import session_scope
    from sentinel_home.models import Baseline
    import json

    try:
        with session_scope() as session:
            existing = (
                session.query(Baseline)
                .filter(Baseline.baseline_type == baseline_type, Baseline.active == True)  # noqa: E712
                .first()
            )
            if existing:
                existing.data = new_data if isinstance(new_data, dict) else {"items": new_data}
            else:
                session.add(Baseline(
                    baseline_type=baseline_type,
                    subject_id="unifi",
                    data=new_data if isinstance(new_data, dict) else {"items": new_data},
                ))

        # Detect config changes (skip first poll)
        if old_data is not None:
            old_str = json.dumps(old_data, sort_keys=True)
            new_str = json.dumps(new_data, sort_keys=True)
            if old_str != new_str:
                _persist_config_change_event(baseline_type)
    except Exception as exc:
        logger.debug("Failed to store %s baseline: %s", baseline_type, exc)


def _persist_config_change_event(baseline_type: str) -> None:
    """Record a config change event and fire the rule."""
    from sentinel_home.database import session_scope
    from sentinel_home.models import Event
    from sentinel_home.rules.engine import get_engine

    type_labels = {
        "wifi_config": ("ssid_config_change", "WiFi SSID configuration changed"),
        "firewall_config": ("firewall_policy_change", "Firewall configuration changed"),
        "network_config": ("network_config_change", "Network/VLAN configuration changed"),
    }
    rule_name, message = type_labels.get(baseline_type, (None, None))
    if not rule_name:
        return

    try:
        with session_scope() as session:
            session.add(Event(
                source="unifi",
                event_type=rule_name,
                severity="high",
                category="configuration",
                kind="event",
                message=message,
                raw={"baseline_type": baseline_type},
            ))

        engine = get_engine()
        engine.fire_rule(rule_name, None, {"baseline_type": baseline_type})
        logger.warning("UniFi config change detected: %s", message)
    except Exception as exc:
        logger.debug("Failed to persist config change event: %s", exc)


def _infer_infra_type(model: str, features: list | None = None) -> str:
    """Map UniFi model string or features to device type."""
    # Check features list first (most reliable from Integration API)
    if features:
        feat_set = set(f.lower() if isinstance(f, str) else "" for f in features)
        if "gateway" in feat_set:
            return "router"
        if "accesspoint" in feat_set or "accessPoint" in feat_set:
            return "ap"
        if "switching" in feat_set:
            return "switch"

    m = model.lower()
    if any(kw in m for kw in ("uap", "u6", "u7", "nanohd", "flexhd", "lite", "lr", "iw", "mesh")):
        return "ap"
    if any(kw in m for kw in ("usw", "us-", "switch", "flex")):
        return "switch"
    if any(kw in m for kw in ("ugw", "udm", "uxg", "usg", "dream", "express", "gateway")):
        return "router"
    return "infrastructure"
