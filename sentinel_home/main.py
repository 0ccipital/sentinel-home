"""SentinelHome v1.0 — FastAPI application factory with APScheduler lifespan."""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
import os
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from sentinel_home.config import get_settings
from sentinel_home.database import init_db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# In-memory log buffer for the web log viewer
# ---------------------------------------------------------------------------

class MemoryLogHandler(logging.Handler):
    """Ring buffer that keeps the last N log records for the web UI.

    emit() is called from any thread (collectors, APScheduler, etc.).
    self.buffer (deque) is thread-safe for append/read.
    asyncio.Queue is NOT thread-safe — we use call_soon_threadsafe() to
    push new lines into each listener's queue from the event loop thread.
    """

    def __init__(self, capacity: int = 2000):
        super().__init__()
        from collections import deque
        import threading
        self.buffer: deque[str] = deque(maxlen=capacity)
        self._listeners: list[asyncio.Queue] = []
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Bind to the running event loop so background threads can schedule queue writes."""
        self._loop = loop

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record)
        except Exception:
            return
        self.buffer.append(line)  # deque.append is thread-safe

        # Push to SSE listeners via the event loop so asyncio.Queue is only
        # touched from its own thread.
        loop = self._loop
        if loop is not None and loop.is_running():
            with self._lock:
                listeners = list(self._listeners)
            for q in listeners:
                try:
                    loop.call_soon_threadsafe(self._put_nowait, q, line)
                except RuntimeError:
                    pass  # loop closed

    @staticmethod
    def _put_nowait(q: asyncio.Queue, line: str) -> None:
        try:
            q.put_nowait(line)
        except Exception:
            pass

    def get_lines(self, last_n: int = 500) -> list[str]:
        return list(self.buffer)[-last_n:]

    MAX_LISTENERS = 20

    def subscribe(self) -> asyncio.Queue | None:
        with self._lock:
            # Prune full queues
            self._listeners = [q for q in self._listeners if not q.full()]
            if len(self._listeners) >= self.MAX_LISTENERS:
                return None
            q: asyncio.Queue = asyncio.Queue(maxsize=200)
            self._listeners.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            try:
                self._listeners.remove(q)
            except ValueError:
                pass


_memory_handler: MemoryLogHandler | None = None


def get_memory_handler() -> MemoryLogHandler | None:
    return _memory_handler


# ---------------------------------------------------------------------------
# Lifespan — start/stop collectors and scheduler
# ---------------------------------------------------------------------------

_scheduler = AsyncIOScheduler()
_collectors: list = []


def get_collector(name: str):
    """Get a running collector by name. Returns None if not found/running."""
    for c in _collectors:
        if c.name == name:
            return c
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    global _memory_handler

    # Logging
    log_level = getattr(logging, settings.server.log_level, logging.INFO)
    log_fmt = "%(asctime)s %(levelname)-8s %(name)s — %(message)s"
    logging.basicConfig(level=log_level, format=log_fmt)

    _memory_handler = MemoryLogHandler(capacity=2000)
    _memory_handler.setFormatter(logging.Formatter(log_fmt))
    _memory_handler.setLevel(log_level)
    _memory_handler.set_loop(asyncio.get_event_loop())
    logging.getLogger().addHandler(_memory_handler)

    for noisy in [
        "sse_starlette", "httpcore", "httpx", "uvicorn.access",
        "watchdog", "apscheduler", "scapy",
    ]:
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # File logging
    db_path = Path(settings.server.db_path).resolve()
    log_dir = db_path.parent / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "sentinel.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(logging.Formatter(log_fmt))
        file_handler.setLevel(log_level)
        logging.getLogger().addHandler(file_handler)
        logger.info("File logging → %s/sentinel.log (max 5 × 10MB)", log_dir)
    except OSError as exc:
        logger.warning("Could not set up file logging at %s: %s", log_dir, exc)

    # Database
    logger.info("Initialising database at %s", settings.server.db_path)
    init_db(settings.server.db_path)

    # Seed default rules on first run
    _seed_default_rules()

    # Collectors
    dev_mode = os.environ.get("SENTINEL_DEV", "0") == "1"

    if not dev_mode:
        from sentinel_home.collectors.syslog_file import SyslogFileCollector
        from sentinel_home.collectors.syslog_server import SyslogServerCollector
        from sentinel_home.collectors.sniff import SniffCollector
        from sentinel_home.collectors.nmap import NmapCollector
        from sentinel_home.collectors.pihole import PiholeCollector
        from sentinel_home.collectors.unifi import UniFiCollector
        from sentinel_home.collectors.plex import PlexCollector

        # Syslog ingestion — mode determines which collectors start
        syslog_mode = settings.syslog.mode
        if syslog_mode == "auto":
            # Try UDP first, always start file tailer as fallback
            collector_classes = [SyslogServerCollector, SyslogFileCollector]
        elif syslog_mode == "udp":
            collector_classes = [SyslogServerCollector]
        elif syslog_mode == "file":
            collector_classes = [SyslogFileCollector]
        else:
            logger.warning("Unknown syslog.mode '%s' — defaulting to auto", syslog_mode)
            collector_classes = [SyslogServerCollector, SyslogFileCollector]

        # Core collectors — always start
        collector_classes.extend([
            SniffCollector,
            NmapCollector,
        ])

        # Optional collectors — only start if configured
        if settings.pihole.enabled and settings.pihole.host:
            collector_classes.append(PiholeCollector)
        if settings.unifi.enabled and settings.unifi.host and settings.unifi.api_key:
            collector_classes.append(UniFiCollector)
        if settings.plex.enabled and settings.plex.host:
            collector_classes.append(PlexCollector)

        for CollectorCls in collector_classes:
            collector = CollectorCls()
            _collectors.append(collector)
            try:
                await collector.start()
                logger.info("Started collector: %s", collector.name)
            except Exception as exc:
                logger.error("Failed to start collector %s: %s", collector.name, exc)
    else:
        logger.info("SENTINEL_DEV=1 — skipping collectors (dev mode)")

    # Scheduler — periodic jobs
    from sentinel_home.queue.compaction import run_compaction
    from sentinel_home.metrics.rollup import (
        flush_counters, compute_dashboard_stats, compute_rule_metrics, run_retention,
    )

    _scheduler.add_job(run_compaction, trigger="interval", minutes=60,
                       id="compaction", replace_existing=True)
    _scheduler.add_job(flush_counters, trigger="interval", minutes=60,
                       id="flush_counters", replace_existing=True)
    _scheduler.add_job(compute_dashboard_stats, trigger="interval", minutes=5,
                       id="dashboard_stats", replace_existing=True)
    _scheduler.add_job(compute_rule_metrics, trigger="cron", hour=0, minute=5,
                       id="rule_metrics", replace_existing=True)
    _scheduler.add_job(run_retention, trigger="cron", hour=3, minute=0,
                       id="retention", replace_existing=True)

    # Daily summary — runs at 8:00 AM
    from sentinel_home.api.routes.reports import generate_summary, generate_report
    _scheduler.add_job(generate_summary, trigger="cron", hour=8, minute=0,
                       id="daily_summary", replace_existing=True)
    # Weekly report — runs Sunday at 9:00 AM
    _scheduler.add_job(generate_report, trigger="cron", day_of_week="sun", hour=9, minute=0,
                       kwargs={"period_days": 7},
                       id="weekly_report", replace_existing=True)

    _scheduler.start()
    logger.info("Scheduler started (compaction, counters, stats, metrics, retention, daily summary, weekly report)")

    # Agent scheduler (actor/critic) — only if enabled
    if settings.agent.enabled:
        from sentinel_home.agent.scheduler import setup_agent_scheduler
        setup_agent_scheduler(_scheduler)

        from sentinel_home.agent.knowledge_sync import sync_knowledge
        _scheduler.add_job(sync_knowledge, trigger="interval", minutes=5,
                           id="knowledge_sync", replace_existing=True)

    logger.info("SentinelHome ready — listening on %s:%d", settings.server.host, settings.server.port)
    yield

    # Shutdown
    _scheduler.shutdown(wait=False)
    for collector in _collectors:
        try:
            await collector.stop()
        except Exception as exc:
            logger.warning("Error stopping collector %s: %s", collector.name, exc)

    # Close LLM adapter HTTP client
    try:
        from sentinel_home.agent.llm_adapter import get_llm_adapter
        adapter = get_llm_adapter()
        if adapter:
            adapter.close()
    except Exception:
        pass

    # Close knowledge sync HTTP client
    try:
        from sentinel_home.agent.knowledge_sync import close as close_knowledge
        close_knowledge()
    except Exception:
        pass

    logger.info("SentinelHome shutdown complete")


# ---------------------------------------------------------------------------
# Seed default rules from YAML on first run
# ---------------------------------------------------------------------------

def _seed_default_rules() -> None:
    """Sync default_rules.yaml into the rules table.

    - New rules are inserted.
    - Existing system rules that are NOT frozen get parameters/description updated.
    - Frozen rules are never touched (user explicitly locked them).
    """
    try:
        from sentinel_home.database import session_scope
        from sentinel_home.models import Rule
        import yaml

        rules_path = Path(__file__).parent / "data" / "default_rules.yaml"
        if not rules_path.exists():
            logger.warning("default_rules.yaml not found at %s", rules_path)
            return

        data = yaml.safe_load(rules_path.read_text())
        yaml_rules = data.get("rules", [])
        updated = 0
        created = 0

        with session_scope() as session:
            for r in yaml_rules:
                existing = session.query(Rule).filter(
                    Rule.name == r["name"], Rule.source == "system"
                ).first()

                if existing:
                    if existing.frozen:
                        continue  # User locked this rule — don't touch
                    # Update description and match parameters from YAML,
                    # but preserve runtime-tuned fields (severity, cooldown,
                    # enabled) if the critic has tuned this rule.
                    existing.description = r.get("description", "")
                    existing.parameters = r.get("parameters", {})
                    existing.action = r.get("action", "alert")
                    if existing.last_tuned is None:
                        # Never tuned by critic — safe to sync from YAML
                        existing.severity = r.get("severity", "medium")
                        existing.cooldown_seconds = r.get("cooldown_seconds", 300)
                    updated += 1
                else:
                    session.add(Rule(
                        name=r["name"],
                        description=r.get("description", ""),
                        category=r.get("category", "network"),
                        severity=r.get("severity", "medium"),
                        priority=r.get("priority", 2),
                        source="system",
                        enabled=True,
                        approved=True,
                        parameters=r.get("parameters", {}),
                        action=r.get("action", "alert"),
                        cooldown_seconds=r.get("cooldown_seconds", 300),
                        created_by="system",
                    ))
                    created += 1

        if created or updated:
            logger.info("Default rules: %d created, %d updated", created, updated)
        else:
            logger.debug("Default rules: all %d up to date", len(yaml_rules))
    except Exception as exc:
        logger.error("Failed to seed default rules: %s", exc)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelHome",
        version="1.0.0-dev",
        description="Home network security & health monitor",
        lifespan=lifespan,
    )

    from sentinel_home.api.middleware import APIKeyMiddleware
    app.add_middleware(APIKeyMiddleware)

    from sentinel_home.dashboard.routes import DashboardAuthMiddleware
    app.add_middleware(DashboardAuthMiddleware)

    from sentinel_home.api.routes import (
        status, devices, events, findings, queue, rules, scans, baseline, sniff, ask
    )
    api_prefix = "/api/v1"
    app.include_router(status.router, prefix=api_prefix, tags=["system"])
    app.include_router(devices.router, prefix=api_prefix, tags=["network"])
    app.include_router(events.router, prefix=api_prefix, tags=["events"])
    app.include_router(findings.router, prefix=api_prefix, tags=["findings"])
    app.include_router(queue.router, prefix=api_prefix, tags=["queue"])
    app.include_router(rules.router, prefix=api_prefix, tags=["rules"])
    app.include_router(scans.router, prefix=api_prefix, tags=["scans"])
    app.include_router(baseline.router, prefix=api_prefix, tags=["baseline"])
    app.include_router(sniff.router, prefix=api_prefix, tags=["sniff"])
    app.include_router(ask.router, prefix=api_prefix, tags=["ask"])

    from sentinel_home.api.routes import changelog, patterns, export, reports, notes, infrastructure
    app.include_router(infrastructure.router, tags=["infrastructure"])
    app.include_router(changelog.router, prefix=api_prefix, tags=["changelog"])
    app.include_router(patterns.router, prefix=api_prefix, tags=["patterns"])
    app.include_router(export.router, prefix=api_prefix, tags=["export"])
    app.include_router(reports.router, prefix=api_prefix, tags=["reports"])
    app.include_router(notes.router, prefix=api_prefix, tags=["notes"])

    from sentinel_home.dashboard.routes import router as dashboard_router
    app.include_router(dashboard_router, tags=["dashboard"])

    static_dir = Path(__file__).parent / "dashboard" / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app


app = create_app()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run():
    settings = get_settings()
    uvicorn.run(
        "sentinel_home.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=False,
        log_level=settings.server.log_level.lower(),
    )


if __name__ == "__main__":
    run()
