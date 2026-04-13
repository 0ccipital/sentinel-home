"""Agent scheduler — wires actor/critic into APScheduler.

The actor and critic run as background jobs in the existing APScheduler
instance from main.py. This module provides the setup function and
the job wrappers that handle async→sync bridging.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler

logger = logging.getLogger(__name__)

# Track last run times and success/fail counts for the /status endpoint
_last_actor_run: datetime | None = None
_last_critic_run: datetime | None = None
_last_actor_result: dict | None = None
_last_critic_result: dict | None = None
_actor_success_count: int = 0
_actor_fail_count: int = 0
_critic_success_count: int = 0
_critic_fail_count: int = 0


async def _run_actor_job() -> None:
    """APScheduler job wrapper for the actor. Runs sync LLM calls in a thread."""
    global _last_actor_run, _last_actor_result, _actor_success_count, _actor_fail_count

    import asyncio
    from sentinel_home.agent.orchestrator import get_actor
    actor = get_actor()

    logger.info("Agent actor cycle starting")
    _last_actor_run = datetime.now(timezone.utc)
    try:
        loop = asyncio.get_event_loop()
        _last_actor_result = await loop.run_in_executor(None, actor.run)
        _actor_success_count += 1
    except Exception as exc:
        _actor_fail_count += 1
        _last_actor_result = {"error": str(exc)}
        logger.error("Agent actor cycle failed: %s", exc)


async def _run_critic_job() -> None:
    """APScheduler job wrapper for the critic. Runs sync LLM calls in a thread."""
    global _last_critic_run, _last_critic_result, _critic_success_count, _critic_fail_count

    import asyncio
    from sentinel_home.agent.orchestrator import get_critic
    critic = get_critic()

    logger.info("Agent critic cycle starting")
    _last_critic_run = datetime.now(timezone.utc)
    try:
        loop = asyncio.get_event_loop()
        _last_critic_result = await loop.run_in_executor(None, critic.run)
        _critic_success_count += 1
    except Exception as exc:
        _critic_fail_count += 1
        _last_critic_result = {"error": str(exc)}
        logger.error("Agent critic cycle failed: %s", exc)


async def _run_metric_check() -> None:
    """Check rule metrics and trigger critic early if thresholds crossed.

    Runs every hour. If any rule has a sudden FP spike, triggers the critic
    immediately instead of waiting for the scheduled 12h cycle.
    """
    from sentinel_home.config import get_settings
    from sentinel_home.database import session_scope
    from sentinel_home.models import Rule

    settings = get_settings()
    if not settings.agent.enabled or not settings.agent.critic.auto_tuning:
        return

    critic_cfg = settings.agent.critic

    with session_scope() as session:
        rules = (
            session.query(Rule)
            .filter(Rule.enabled == True, Rule.frozen == False, Rule.approved == True)
            .all()
        )

        needs_critic = False
        for rule in rules:
            tp = rule.true_positive_count or 0
            fp = rule.false_positive_count or 0
            total = tp + fp
            if total >= critic_cfg.min_samples:
                fp_rate = fp / total
                if fp_rate > critic_cfg.fp_threshold:
                    logger.info(
                        "Metric trigger: rule '%s' FP rate %.0f%% exceeds threshold",
                        rule.name, fp_rate * 100,
                    )
                    needs_critic = True
                    break

            fire_count = rule.fire_count or 0
            if fire_count > 50 and rule.last_tuned is None:
                logger.info(
                    "Metric trigger: rule '%s' has %d fires, never tuned",
                    rule.name, fire_count,
                )
                needs_critic = True
                break

    if needs_critic:
        logger.info("Metric check triggering early critic run")
        await _run_critic_job()


def setup_agent_scheduler(scheduler: AsyncIOScheduler) -> None:
    """Register actor/critic jobs with the app's scheduler.

    Called from main.py lifespan if agent is enabled.
    """
    from sentinel_home.config import get_settings
    settings = get_settings()

    if not settings.agent.enabled:
        logger.info("Agent disabled — skipping scheduler setup")
        return

    actor_interval = settings.agent.actor.interval_minutes
    critic_interval = settings.agent.critic.interval_hours

    # Actor — frequent triage (first run 30s after startup to drain queue)
    scheduler.add_job(
        _run_actor_job,
        trigger="interval",
        minutes=actor_interval,
        id="agent_actor",
        replace_existing=True,
        misfire_grace_time=120,
        next_run_time=datetime.now(timezone.utc) + timedelta(seconds=30),
    )

    # Critic — periodic rule evaluation (first run after 1h)
    scheduler.add_job(
        _run_critic_job,
        trigger="interval",
        hours=critic_interval,
        id="agent_critic",
        replace_existing=True,
        misfire_grace_time=600,
        next_run_time=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    # Metric check — hourly, triggers critic early if needed
    scheduler.add_job(
        _run_metric_check,
        trigger="interval",
        minutes=60,
        id="agent_metric_check",
        replace_existing=True,
    )

    # Log connection status at startup
    from sentinel_home.agent.llm_adapter import get_llm_adapter
    adapter = get_llm_adapter()
    if adapter:
        available = adapter.is_available()
        logger.info(
            "Agent scheduler: actor every %dm (first in 30s), critic every %dh, "
            "LLM endpoint %s (%s)",
            actor_interval, critic_interval,
            settings.agent.url,
            "reachable" if available else "NOT REACHABLE",
        )
    else:
        logger.warning("Agent scheduler: LLM adapter could not be created")


def get_agent_status() -> dict:
    """Return agent scheduler status for the /status endpoint."""
    from sentinel_home.config import get_settings
    settings = get_settings()

    return {
        "enabled": settings.agent.enabled,
        "actor": {
            "interval_minutes": settings.agent.actor.interval_minutes,
            "last_run": _last_actor_run.isoformat() if _last_actor_run else None,
            "last_result": _last_actor_result,
            "success_count": _actor_success_count,
            "fail_count": _actor_fail_count,
        },
        "critic": {
            "interval_hours": settings.agent.critic.interval_hours,
            "auto_tuning": settings.agent.critic.auto_tuning,
            "conservatism": settings.agent.critic.conservatism,
            "require_consensus": settings.agent.critic.require_consensus,
            "last_run": _last_critic_run.isoformat() if _last_critic_run else None,
            "last_result": _last_critic_result,
            "success_count": _critic_success_count,
            "fail_count": _critic_fail_count,
        },
    }
