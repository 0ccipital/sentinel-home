"""Passive LAN sniffer — Scapy capture on eth0, metadata only, no payloads."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone

from sentinel_home.collectors.base import BaseCollector
from sentinel_home.config import get_settings

logger = logging.getLogger(__name__)

# How long to observe ARP traffic before alerting (seconds).
# During warmup we build the ARP table but suppress conflict alerts.
# This avoids the flood of false positives at startup when we see
# proxy-ARP, Docker macvlan, and bridge MACs all responding for the
# same IPs before we know what's "normal".
ARP_WARMUP_SECONDS = 120

# Ring buffer limits for capped lists (mDNS, UPnP, DNS queries).
# When a buffer exceeds RING_MAX, prune to RING_KEEP most recent entries.
RING_MAX = 500
RING_KEEP = 250


def _is_locally_administered(mac: str) -> bool:
    """Check if a MAC address is locally-administered (Docker, VM, macvlan).

    The second-least-significant bit of the first octet is 1 for
    locally-administered MACs.  Docker always assigns these (02:42:xx,
    02:02:xx, etc.) and they should never be treated as real devices.
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


class SniffCollector(BaseCollector):
    name = "sniff"

    def __init__(self):
        super().__init__()
        self._stop_event = asyncio.Event()
        # Host MACs to ignore in ARP conflict detection.
        # Populated at start from the sniff interface + any Docker bridge MACs.
        self._host_macs: set[str] = set()
        # Infrastructure MACs (router, switch, AP) that do proxy ARP.
        # These legitimately respond for many IPs.
        self._infra_macs: set[str] = set()
        # Timestamp when sniffing started — suppress ARP alerts until warmup done
        self._sniff_start: float = 0.0
        # ARP table: IP -> set of MACs
        self.arp_table: dict[str, set[str]] = defaultdict(set)
        # Stable ARP: IP -> set of MACs seen during warmup (all accepted as "normal")
        self._arp_stable: dict[str, set[str]] = {}
        # mDNS services: capped ring buffer
        self.mdns_services: list[dict] = []
        # UPnP requests: capped ring buffer
        self.upnp_requests: list[dict] = []
        # DNS queries: {ip: [domain, ...]}
        self.dns_queries: dict[str, list[str]] = defaultdict(list)
        # SMB tracking: set of (src_ip, dst_ip) pairs seen
        self._smb_pairs: set[tuple[str, str]] = set()

    async def start(self) -> None:
        self.stats.running = True
        logger.info("Sniff collector starting")
        self._task = asyncio.create_task(self._sniff_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        self.stats.running = False
        logger.info("Sniff collector stopped")

    def _discover_host_macs(self, iface: str) -> None:
        """Find MACs belonging to the host so we can ignore them in ARP checks.

        On Unraid with --network host, eth0's real MAC and any Docker bridge/
        macvlan MACs (02:xx locally-administered) will show up in ARP traffic.
        These are all "us" and should not trigger conflict alerts.
        """
        import subprocess
        try:
            # Get all interface MACs on the host (catches docker0, br-*, veth*, eth0)
            out = subprocess.check_output(
                ["ip", "-o", "link", "show"], text=True, timeout=5
            )
            for line in out.splitlines():
                parts = line.split()
                for i, tok in enumerate(parts):
                    if tok == "link/ether" and i + 1 < len(parts):
                        mac = parts[i + 1].lower()
                        self._host_macs.add(mac)
        except Exception as exc:
            logger.warning("Could not enumerate host MACs via 'ip link': %s", exc)

        if self._host_macs:
            logger.info("Host MACs (ignored for ARP conflicts): %d found — %s",
                        len(self._host_macs),
                        ", ".join(sorted(list(self._host_macs)[:10])))
            if len(self._host_macs) > 10:
                logger.info("  ... and %d more (veth interfaces)", len(self._host_macs) - 10)
        else:
            logger.warning("Could not detect host MACs — will rely on locally-administered MAC filter")

    def _should_ignore_mac(self, mac: str) -> bool:
        """Check if a MAC should be ignored for ARP conflict detection."""
        return mac in self._host_macs or mac in self._infra_macs or _is_locally_administered(mac)

    def _warmup_done(self) -> bool:
        """Check if the ARP warmup period has elapsed."""
        return (time.monotonic() - self._sniff_start) >= ARP_WARMUP_SECONDS

    def _freeze_arp_table(self) -> None:
        """After warmup, snapshot the ARP table to establish what's 'normal'.

        Two key detections:
        1. Infrastructure MACs (proxy ARP): any real MAC that appears for >3 IPs
           is a router/switch doing proxy ARP — ignore it for conflict detection.
        2. Per-IP stable MACs: for each IP, store the set of non-infra real MACs.
        """
        # Step 1: Detect infrastructure MACs — routers/switches doing proxy ARP.
        # These respond for many IPs and should never trigger ARP conflict alerts.
        mac_ip_count: dict[str, int] = {}
        for ip, macs in self.arp_table.items():
            for m in macs:
                if not self._should_ignore_mac(m):
                    mac_ip_count[m] = mac_ip_count.get(m, 0) + 1

        PROXY_ARP_THRESHOLD = 3  # >3 IPs means this MAC is doing proxy ARP
        for mac, count in mac_ip_count.items():
            if count > PROXY_ARP_THRESHOLD:
                self._infra_macs.add(mac)
                logger.info("ARP: MAC %s seen for %d IPs — classified as infrastructure (proxy ARP)",
                            mac, count)

        if self._infra_macs:
            logger.info("ARP: %d infrastructure MAC(s) detected — will be ignored for conflict detection",
                        len(self._infra_macs))

        # Step 2: Build per-IP stable MACs (excluding infra)
        for ip, macs in self.arp_table.items():
            real_macs = {m for m in macs
                         if not self._should_ignore_mac(m) and m not in self._infra_macs}
            if real_macs:
                self._arp_stable[ip] = real_macs

        logger.info("ARP warmup complete — %d IPs baselined, %d device MACs, %d infra MACs ignored",
                    len(self._arp_stable),
                    len({m for macs in self._arp_stable.values() for m in macs}),
                    len(self._infra_macs))

    async def _sniff_loop(self) -> None:
        settings = get_settings()
        iface = settings.network.sniff_interface

        # Discover host MACs before sniffing so we can filter them out
        self._discover_host_macs(iface)

        try:
            from scapy.all import AsyncSniffer, ARP, DNS, DNSQR, IP, UDP, TCP
        except ImportError:
            logger.warning("Scapy not available — sniff collector idle")
            await self._stop_event.wait()
            return

        self._sniff_start = time.monotonic()
        self._warmup_logged = False
        logger.info("ARP warmup: learning network for %ds before alerting", ARP_WARMUP_SECONDS)

        loop = asyncio.get_running_loop()

        def packet_callback(pkt):
            try:
                loop.call_soon_threadsafe(
                    asyncio.ensure_future,
                    self._handle_packet_async(pkt),
                )
            except Exception:
                pass

        sniffer = AsyncSniffer(
            iface=iface,
            store=False,
            filter="not port 22 and not port 443",
            prn=packet_callback,
        )
        sniffer.start()
        try:
            await self._stop_event.wait()
        finally:
            sniffer.stop()

    async def _handle_packet_async(self, pkt) -> None:
        try:
            from scapy.all import ARP, DNS, DNSQR, IP, UDP, TCP

            # ARP — detect conflicts and new devices
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                ip = arp.pdst if arp.op == 1 else arp.psrc
                mac = arp.hwsrc.lower()

                # Always update ARP table
                self.arp_table[ip] = self.arp_table.get(ip, set()) | {mac}
                self._record_event()

                # Skip ignored MACs entirely
                if self._should_ignore_mac(mac):
                    return

                # Enrich device via fingerprint (OUI vendor, IP)
                from sentinel_home.fingerprint import enrich_device
                enrich_device(mac=mac, ip=ip)

                # During warmup — just learn, don't alert
                if not self._warmup_done():
                    return

                # Freeze baseline once at end of warmup
                if not self._warmup_logged:
                    self._warmup_logged = True
                    self._freeze_arp_table()

                # Post-warmup: only alert if a real MAC appears for an IP
                # that wasn't seen during warmup (not in the stable set)
                stable_macs = self._arp_stable.get(ip)
                if stable_macs and mac not in stable_macs:
                    # If an IP has accumulated >3 MACs, it's likely a macvlan
                    # container or multi-NIC host — stop alerting, just learn
                    if len(stable_macs) >= 3:
                        logger.debug("ARP: IP %s has %d MACs — suppressing further alerts (likely macvlan/multi-NIC)",
                                     ip, len(stable_macs) + 1)
                        stable_macs.add(mac)
                    else:
                        logger.warning("ARP conflict: IP %s claimed by %s (known: %s)",
                                       ip, mac, ", ".join(sorted(stable_macs)))
                        from sentinel_home.rules.engine import get_rule_engine
                        existing_mac = next(iter(stable_macs))
                        get_rule_engine().fire_rule("arp_conflict", mac, {
                            "ip": ip, "mac1": existing_mac, "mac2": mac,
                            "message": f"ARP conflict: IP {ip} claimed by {mac} (previously {existing_mac})",
                        })
                        # Add it so we don't re-alert for the same MAC
                        stable_macs.add(mac)
                elif not stable_macs:
                    # New IP seen after warmup — record it
                    self._arp_stable[ip] = {mac}

            # mDNS (port 5353)
            elif pkt.haslayer(UDP) and pkt[UDP].dport == 5353 and pkt.haslayer(DNS):
                src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
                dns = pkt[DNS]
                if dns.qr == 1:  # response
                    for i in range(dns.ancount):
                        try:
                            rr = dns.an[i]
                            service = {"ip": src_ip, "name": str(rr.rrname), "type": rr.type, "ts": datetime.now(timezone.utc).isoformat()}
                            self.mdns_services.append(service)
                            if len(self.mdns_services) > RING_MAX:
                                self.mdns_services = self.mdns_services[-RING_KEEP:]
                            self._record_event()
                        except Exception:
                            pass

            # DNS queries (port 53)
            elif pkt.haslayer(UDP) and pkt[UDP].dport == 53 and pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace").rstrip(".")
                self.dns_queries[src_ip].append(qname)
                # Cap per-IP query list to avoid unbounded growth
                if len(self.dns_queries[src_ip]) > RING_MAX:
                    self.dns_queries[src_ip] = self.dns_queries[src_ip][-RING_KEEP:]
                self._record_event()

            # UPnP SSDP (port 1900)
            elif pkt.haslayer(UDP) and pkt[UDP].dport == 1900 and pkt.haslayer(IP):
                src_ip = pkt[IP].src
                payload = bytes(pkt[UDP].payload)
                if b"AddPortMapping" in payload:
                    dev_mac = self._resolve_mac(src_ip)
                    request_info = {
                        "ip": src_ip,
                        "device_mac": dev_mac,
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "raw": payload[:256].decode("utf-8", errors="replace"),
                        "action": "AddPortMapping",
                        "message": f"UPnP port mapping request from {src_ip}" + (f" ({dev_mac})" if dev_mac else ""),
                    }
                    self.upnp_requests.append(request_info)
                    if len(self.upnp_requests) > RING_MAX:
                        self.upnp_requests = self.upnp_requests[-RING_KEEP:]
                    self._record_event()
                    from sentinel_home.rules.engine import get_rule_engine
                    get_rule_engine().fire_rule("upnp_port_request", request_info.get("device_mac"), request_info)
                elif b"M-SEARCH" in payload:
                    self.upnp_requests.append({
                        "ip": src_ip,
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "action": "M-SEARCH",
                    })
                    if len(self.upnp_requests) > RING_MAX:
                        self.upnp_requests = self.upnp_requests[-RING_KEEP:]
                    self._record_event()

            # SMB (port 445)
            elif pkt.haslayer(TCP) and pkt.haslayer(IP):
                tcp = pkt[TCP]
                if tcp.dport == 445 or tcp.sport == 445:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    pair = (src_ip, dst_ip)
                    if pair not in self._smb_pairs:
                        self._smb_pairs.add(pair)
                        self._record_event()
                        # Skip alerting if either end is a known SMB server (NAS, file server)
                        settings = get_settings()
                        smb_wl = set(settings.network.smb_whitelist)
                        if src_ip in smb_wl or dst_ip in smb_wl:
                            return
                        from sentinel_home.rules.engine import get_rule_engine
                        src_mac = self._resolve_mac(src_ip)
                        get_rule_engine().fire_rule("unexpected_smb_traffic", src_mac, {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_mac": src_mac,
                            "dst_mac": self._resolve_mac(dst_ip),
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "message": f"SMB traffic from {src_ip} to {dst_ip} (not in whitelist)",
                        })

        except Exception as exc:
            self._record_error(exc)

    def _resolve_mac(self, ip: str) -> str | None:
        """Look up MAC from ARP table, preferring real (non-host) MACs."""
        macs = self.arp_table.get(ip, set())
        real = {m for m in macs if not self._should_ignore_mac(m)}
        if real:
            return next(iter(real))
        return next(iter(macs), None) if macs else None

    def get_stats(self) -> dict:
        base = super().get_stats()
        base["arp_entries"] = len(self.arp_table)
        base["arp_baselined"] = len(self._arp_stable)
        base["warmup_complete"] = self._warmup_done() if self._sniff_start else False
        base["mdns_services"] = len(self.mdns_services)
        base["upnp_requests"] = len(self.upnp_requests)
        base["smb_pairs"] = len(self._smb_pairs)
        return base
