"""nmap scanner collector — runs every 6 hours, diffs results."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from sentinel_home.collectors.base import BaseCollector
from sentinel_home.config import get_settings

logger = logging.getLogger(__name__)


class NmapCollector(BaseCollector):
    name = "nmap"

    def __init__(self):
        super().__init__()
        self._stop_event = asyncio.Event()
        self._last_scan: dict | None = None

    async def start(self) -> None:
        self.stats.running = True
        logger.info("nmap collector starting")
        self._task = asyncio.create_task(self._scan_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        self.stats.running = False
        logger.info("nmap collector stopped")

    async def _scan_loop(self) -> None:
        settings = get_settings()
        interval_s = settings.nmap.scan_interval_hours * 3600

        while not self._stop_event.is_set():
            try:
                await self._run_scan()
            except Exception as exc:
                self._record_error(exc)
            # Interruptible sleep — wakes on stop event instead of blocking for hours
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval_s)
                break  # Stop event was set
            except asyncio.TimeoutError:
                pass  # Normal — sleep completed, run next scan

    async def _run_scan(self) -> None:
        settings = get_settings()
        ports = ",".join(str(p) for p in settings.nmap.ports)
        lan_cidr = settings.network.lan_cidr
        timeout = settings.nmap.timeout_seconds

        try:
            import nmap as nmap_module
        except ImportError:
            logger.warning("python-nmap not available — scan skipped")
            return

        logger.info("Starting nmap scan of %s", lan_cidr)
        loop = asyncio.get_running_loop()

        # nmap is synchronous — run in thread pool
        result = await loop.run_in_executor(
            None,
            self._do_scan,
            lan_cidr,
            ports,
            timeout,
        )

        if result:
            self._record_event()
            await self._process_result(result)

    def _do_scan(self, target: str, ports: str, timeout: int) -> dict | None:
        try:
            import nmap as nmap_module
            nm = nmap_module.PortScanner()
            # -sS = SYN scan (open/closed only, no service probes that spam endpoints)
            # -sV was sending HELP, OPTIONS, /sdk, /HNAP1 etc. to every open port
            nm.scan(hosts=target, ports=ports, arguments=f"--host-timeout {timeout}s -sS")
            return nm._scan_result
        except Exception as exc:
            logger.error("nmap scan failed: %s", exc)
            return None

    async def _process_result(self, result: dict) -> None:
        diff = self._diff(self._last_scan, result)
        self._last_scan = result

        # Persist to DB
        from sentinel_home.database import session_scope
        from sentinel_home.models import Scan
        with session_scope() as session:
            scan = Scan(
                target="lan",
                scan_type="lan",
                result=result,
                diff=diff,
                findings_count=len(diff.get("new_ports", [])),
            )
            session.add(scan)

        # Enrich devices from scan results (OS, services, hostnames)
        self._enrich_from_scan(result)

        if diff.get("new_ports"):
            logger.warning("New open ports detected: %s", diff["new_ports"])
            from sentinel_home.rules.engine import get_rule_engine
            from sentinel_home.database import session_scope
            from sentinel_home.models import Device

            # Build IP→MAC and MAC→Device lookups in a single query
            ip_to_mac = {}
            mac_to_device = {}
            with session_scope() as session:
                for d in session.query(Device).filter(Device.ip.isnot(None)).all():
                    ip_to_mac[d.ip] = d.mac
                    mac_to_device[d.mac] = {"label": d.label, "vendor": d.vendor}

            for port_str in diff["new_ports"]:
                # port_str format: "10.0.0.1:tcp/8080"
                parts = port_str.split(":")
                host = parts[0] if parts else "unknown"
                proto_port = parts[1] if len(parts) > 1 else ""
                device_mac = ip_to_mac.get(host)

                # Build a descriptive message
                device_label = host
                if device_mac:
                    dev_info = mac_to_device.get(device_mac, {})
                    if dev_info.get("label"):
                        device_label = f"{dev_info['label']} ({host})"
                    elif dev_info.get("vendor"):
                        device_label = f"{host} ({dev_info['vendor']})"

                message = f"New port {proto_port} opened on {device_label}"

                get_rule_engine().fire_rule("new_open_port", device_mac, {
                    "host": host, "port_info": proto_port, "raw": port_str,
                    "message": message,
                })

    def _enrich_from_scan(self, result: dict) -> None:
        """Extract device info from nmap results and enrich via fingerprint."""
        from sentinel_home.fingerprint import enrich_device

        for host_data in result.get("scan", {}).values():
            addrs = host_data.get("addresses", {})
            ip = addrs.get("ipv4")
            mac = addrs.get("mac", "").lower()
            if not mac or not ip:
                continue

            # Collect open services
            services = {}
            for proto in ("tcp", "udp"):
                for port, info in host_data.get(proto, {}).items():
                    if info.get("state") == "open":
                        services[str(port)] = {
                            "proto": proto,
                            "name": info.get("name", ""),
                            "product": info.get("product", ""),
                        }

            # OS detection
            os_family = None
            osmatch = host_data.get("osmatch", [])
            if osmatch:
                os_family = osmatch[0].get("name", "")

            # Hostnames
            hostnames = {}
            for h in host_data.get("hostnames", []):
                name = h.get("name")
                htype = h.get("type", "unknown")
                if name:
                    hostnames[htype] = name

            vendor = host_data.get("vendor", {}).get(mac.upper())

            enrich_device(
                mac=mac,
                ip=ip,
                vendor=vendor,
                os_family=os_family,
                services=services if services else None,
                hostnames=hostnames if hostnames else None,
            )

    @staticmethod
    def _diff(prev: dict | None, current: dict) -> dict:
        """Compute new/closed ports between scans."""
        if prev is None:
            return {"new_ports": [], "closed_ports": [], "first_scan": True}

        def extract_ports(scan: dict) -> set[str]:
            ports = set()
            for host_data in scan.get("scan", {}).values():
                for proto in ("tcp", "udp"):
                    for port, info in host_data.get(proto, {}).items():
                        if info.get("state") == "open":
                            ports.add(f"{host_data.get('addresses', {}).get('ipv4', 'unknown')}:{proto}/{port}")
            return ports

        prev_ports = extract_ports(prev)
        curr_ports = extract_ports(current)
        return {
            "new_ports": list(curr_ports - prev_ports),
            "closed_ports": list(prev_ports - curr_ports),
        }
