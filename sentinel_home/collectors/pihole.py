"""Pi-hole API collector — polls DNS query stats and top queries.

Pi-hole v6 API at http://{pihole.host}/api/. No auth required from LAN
for read-only endpoints (stats, queries, top domains).

This collector provides:
  - Per-device DNS query counts and top domains
  - Detection of suspicious domain lookups (C2, malware, crypto mining)
  - Blocked query stats (ad/tracker volume per device)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from sentinel_home.collectors.base import BaseCollector
from sentinel_home.config import get_settings
from sentinel_home.database import session_scope
from sentinel_home.models import Event

logger = logging.getLogger(__name__)

# Substring patterns — matched anywhere in the domain
_SUSPICIOUS_SUBSTRINGS = [
    # C2 / malware beacons
    ".onion.",      # Tor hidden services resolved via DNS (misconfigured)
    ".bit.",        # Namecoin TLD (used by malware)
    # Crypto mining
    "coinhive", "minero", "cryptoloot", "coin-hive",
]

# TLD patterns — matched only at the END of the domain to avoid false positives
# (e.g. ".ga" must not match "gannettdigital.com")
_SUSPICIOUS_TLDS = [
    ".top", ".xyz", ".club", ".work", ".gq", ".ml", ".cf", ".tk", ".ga",
]

# Minimum query length that suggests DGA (domain generation algorithm)
_DGA_MIN_LENGTH = 24

# Domain suffixes that are NEVER DGA — long subdomains are normal for these
_DGA_WHITELIST_SUFFIXES = [
    # Cloud providers (load balancers, CDNs, service endpoints)
    ".amazonaws.com", ".cloudfront.net", ".azurewebsites.net",
    ".azure-api.net", ".cloudflare.com", ".akamaiedge.net",
    ".akamai.net", ".akadns.net", ".fastly.net", ".edgekey.net",
    ".gstatic.com", ".googleusercontent.com", ".googleapis.com",
    ".google.com", ".1e100.net",
    # CDN / hosting
    ".cdn.cloudflare.net", ".cdn77.org", ".stackpathdns.com",
    ".incapdns.net", ".edgecastcdn.net", ".azureedge.net",
    # Apple / Microsoft / common services
    ".apple.com", ".icloud.com", ".microsoft.com", ".msedge.net",
    ".windows.net", ".office.com", ".office365.com",
    ".trafficmanager.net", ".windowsupdate.com",
    # Other common long-subdomain services
    ".plex.direct", ".debian.org", ".ubuntu.com", ".docker.io",
    ".github.io", ".githubusercontent.com", ".sentry.io",
    ".elb.amazonaws.com",  # Explicit: covers the canvas-iad-prod false positive
]


class PiholeCollector(BaseCollector):
    name = "pihole"

    def __init__(self):
        super().__init__()
        self._stop_event = asyncio.Event()
        # Track queries per client IP for rate anomaly detection
        self.client_query_counts: dict[str, int] = {}
        # Recent suspicious hits
        self.suspicious_queries: list[dict] = []
        # Dedup: (domain, client_ip) pairs already flagged this session
        self._seen_suspicious: set[tuple[str, str]] = set()

    async def start(self) -> None:
        self.stats.running = True
        logger.info("Pi-hole collector starting")
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                pass
        self.stats.running = False
        logger.info("Pi-hole collector stopped")

    async def _poll_loop(self) -> None:
        settings = get_settings()
        pihole_host = settings.pihole.host
        interval = settings.pihole.poll_interval_seconds

        if not pihole_host:
            logger.warning("Pi-hole host not configured — collector idle")
            await self._stop_event.wait()
            return

        base = f"http://{pihole_host}/api"
        logger.info("Pi-hole collector polling %s every %ds", base, interval)

        while not self._stop_event.is_set():
            try:
                await self._poll(base)
            except Exception as exc:
                self._record_error(exc)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
                break  # Stop event was set
            except asyncio.TimeoutError:
                pass  # Normal — sleep completed, run next poll

    async def _poll(self, base: str) -> None:
        settings = get_settings()
        password = settings.pihole.password

        async with httpx.AsyncClient(timeout=10) as client:
            headers = {}

            # Pi-hole v6: authenticate if password is set
            if password:
                try:
                    auth_resp = await client.post(
                        f"{base}/auth",
                        json={"password": password},
                    )
                    if auth_resp.status_code == 200:
                        sid = auth_resp.json().get("session", {}).get("sid", "")
                        if sid:
                            headers["sid"] = sid
                except Exception as exc:
                    logger.debug("Pi-hole auth failed (may not be required): %s", exc)

            # Summary stats
            try:
                resp = await client.get(f"{base}/stats/summary", headers=headers)
                if resp.status_code == 200:
                    summary = resp.json()
                    self._record_event()
                    self._persist_summary(summary)
            except Exception as exc:
                self._record_error(exc)

            # Recent queries (last 100)
            try:
                resp = await client.get(
                    f"{base}/queries",
                    params={"length": 100},
                    headers=headers,
                )
                if resp.status_code == 200:
                    queries_data = resp.json()
                    queries = queries_data.get("queries", [])
                    self._record_event()
                    self._analyze_queries(queries)
            except Exception as exc:
                self._record_error(exc)

            # Top blocked domains
            try:
                resp = await client.get(f"{base}/stats/top_domains", params={"blocked": "true"}, headers=headers)
                if resp.status_code == 200:
                    self._record_event()
            except Exception as exc:
                self._record_error(exc)

    def _analyze_queries(self, queries: list) -> None:
        """Check recent queries for suspicious patterns."""
        from sentinel_home.rules.engine import get_rule_engine

        for q in queries:
            # Pi-hole v6 query format: list or dict depending on version
            if isinstance(q, dict):
                domain = q.get("domain", "")
                client_ip = q.get("client", {}).get("ip", "") if isinstance(q.get("client"), dict) else q.get("client", "")
                status = q.get("status", "")
            elif isinstance(q, list) and len(q) >= 4:
                # Pi-hole v5 format: [timestamp, type, domain, client, status, ...]
                domain = q[2] if len(q) > 2 else ""
                client_ip = q[3] if len(q) > 3 else ""
                status = q[4] if len(q) > 4 else ""
            else:
                continue

            domain_lower = domain.lower()

            # Check suspicious patterns
            is_suspicious = False
            reason = ""

            # Known bad substring patterns
            for pattern in _SUSPICIOUS_SUBSTRINGS:
                if pattern in domain_lower:
                    is_suspicious = True
                    reason = f"matches suspicious pattern '{pattern}'"
                    break

            # TLD checks — must match at end of domain
            if not is_suspicious:
                for tld in _SUSPICIOUS_TLDS:
                    if domain_lower.endswith(tld):
                        is_suspicious = True
                        reason = f"suspicious TLD '{tld}'"
                        break

            # DGA detection: long random-looking subdomains
            if not is_suspicious:
                parts = domain_lower.split(".")
                if parts and len(parts[0]) >= _DGA_MIN_LENGTH:
                    # Skip known cloud/CDN domains that naturally have long subdomains
                    whitelisted = any(domain_lower.endswith(suffix)
                                      for suffix in _DGA_WHITELIST_SUFFIXES)
                    if not whitelisted:
                        # Check if it looks random (low ratio of vowels)
                        subdomain = parts[0]
                        vowels = sum(1 for c in subdomain if c in "aeiou")
                        if len(subdomain) > 0 and vowels / len(subdomain) < 0.2:
                            is_suspicious = True
                            reason = f"possible DGA domain (length={len(subdomain)}, low vowel ratio)"

            if is_suspicious:
                dedup_key = (domain_lower, client_ip)
                # Skip if we already flagged this exact domain+client combo
                if dedup_key in self._seen_suspicious:
                    continue
                self._seen_suspicious.add(dedup_key)
                # Cap dedup set to prevent unbounded growth
                if len(self._seen_suspicious) > 5000:
                    # Keep most recent half (convert to list, take last half)
                    self._seen_suspicious = set(list(self._seen_suspicious)[-2500:])

                hit = {
                    "domain": domain,
                    "client_ip": client_ip,
                    "reason": reason,
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
                self.suspicious_queries.append(hit)
                # Cap list
                if len(self.suspicious_queries) > 200:
                    self.suspicious_queries = self.suspicious_queries[-100:]

                logger.warning("Suspicious DNS query: %s from %s — %s", domain, client_ip, reason)

                # Queue for LLM analysis
                from sentinel_home.queue.manager import enqueue_job
                enqueue_job(
                    source="pihole",
                    rule_name="suspicious_dns",
                    device_id=client_ip,
                    priority=2,
                    context=hit,
                )

            # Track per-client query volume
            if client_ip:
                self.client_query_counts[client_ip] = self.client_query_counts.get(client_ip, 0) + 1

    def _persist_summary(self, summary: dict) -> None:
        """Persist Pi-hole summary stats as an event."""
        try:
            with session_scope() as session:
                # Extract key metrics (Pi-hole v6 format)
                queries_total = summary.get("queries", {}).get("total", 0)
                blocked = summary.get("queries", {}).get("blocked", 0)
                percent_blocked = summary.get("queries", {}).get("percent_blocked", 0)
                clients = summary.get("clients", {}).get("total", 0)

                session.add(Event(
                    source="pihole",
                    event_type="pihole_summary",
                    severity="info",
                    message=f"Pi-hole: {queries_total} queries, {blocked} blocked ({percent_blocked:.1f}%), {clients} clients",
                    raw=summary,
                ))
        except Exception as exc:
            logger.error("Failed to persist Pi-hole summary: %s", exc)

    def get_stats(self) -> dict:
        base = super().get_stats()
        base["suspicious_queries"] = len(self.suspicious_queries)
        base["tracked_clients"] = len(self.client_query_counts)
        return base
