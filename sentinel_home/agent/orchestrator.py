"""Actor + Critic orchestrators — Python decides, LLM answers.

Actor (frequent, every 15 min):
  1. GET /changelog → what changed
  2. Triage notable events → rate 1-5
  3. Investigate high-severity → TP/FP/NEEDS_MORE_INFO
  4. Classify new devices
  5. Create findings for confirmed TPs

Critic (periodic, every 12h + metric-triggered):
  1. Fetch rules with poor metrics
  2. Evaluate each → RAISE/LOWER/KEEP/DISABLE
  3. Consensus (ask twice, apply only if both agree)
  4. Version snapshot + apply changes
  5. Summarize what changed

Both orchestrators are synchronous Python. They call the LLM adapter
for focused micro-tasks and validate every response.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from sentinel_home.agent.llm_adapter import LLMAdapter, LLMResponse, get_llm_adapter
from sentinel_home.agent.tasks import (
    CLASSIFY_DEVICE, EVALUATE_RULE, INVESTIGATE_ALERT,
    SUMMARIZE_PERIOD, TRIAGE_EVENT, TaskDefinition,
)
from sentinel_home.agent.validator import (
    ValidatedResult, build_retry_prompt, check_consensus,
    sanity_check_rule_eval,
    validate_response,
)
from sentinel_home.config import get_settings
from sentinel_home.database import session_scope
from sentinel_home.models import (
    Alert, Device, Event, Finding, Job, Rule, RuleMetricWindow,
)

logger = logging.getLogger(__name__)

# Module-level Open WebUI chat state for agent activity.
# One chat per actor/critic cycle — reset at the start of each run().
_agent_chat_id: str | None = None
_agent_chat_messages: list[dict] = []  # accumulated messages for the current cycle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_task(
    adapter: LLMAdapter,
    task: TaskDefinition,
    template_vars: dict[str, Any],
    retry: bool = True,
) -> ValidatedResult:
    """Execute a single micro-task: render prompt → call LLM → validate.

    On validation failure, retries once with a simplified prompt.
    All exchanges are accumulated and logged to Open WebUI so the full
    conversation for a cycle is visible, not just the last exchange.
    """
    global _agent_chat_id, _agent_chat_messages  # noqa: PLW0603

    user_prompt = task.user_template.format(**template_vars)

    resp, _agent_chat_id, _agent_chat_messages = adapter.complete_with_persistence(
        system_prompt=task.system_prompt,
        user_prompt=user_prompt,
        chat_id=_agent_chat_id,
        chat_title=f"SentinelHome Agent — {task.name}",
        max_tokens=task.max_tokens,
        temperature=task.temperature,
        chat_messages=_agent_chat_messages,
    )

    if not resp.success:
        logger.warning("LLM call failed for %s: %s", task.name, resp.error)
        return ValidatedResult(
            choice="", reasoning=None, confidence=0.0,
            raw_text=resp.text, valid=False,
        )

    result = validate_response(resp.text, task.valid_choices, task.needs_reasoning)

    if result.valid:
        logger.debug(
            "Task %s → %s (confidence=%.2f, %dms)",
            task.name, result.choice, result.confidence,
            resp.latency_seconds * 1000,
        )
        return result

    # Retry once with simplified prompt
    if retry and task.valid_choices:
        logger.info("Retrying %s with simplified prompt", task.name)
        retry_prompt = build_retry_prompt(task.valid_choices)
        resp2 = adapter.complete(
            system_prompt=task.system_prompt,
            user_prompt=retry_prompt,
            max_tokens=20,
            temperature=0.6,
        )
        if resp2.success:
            result2 = validate_response(resp2.text, task.valid_choices, False)
            if result2.valid:
                logger.info("Retry succeeded for %s → %s", task.name, result2.choice)
                return result2

    logger.warning("Task %s failed after retry: %s", task.name, resp.text[:100])
    return ValidatedResult(
        choice="", reasoning=None, confidence=0.0,
        raw_text=resp.text, valid=False,
    )


def _run_consensus(
    adapter: LLMAdapter,
    task: TaskDefinition,
    template_vars: dict[str, Any],
) -> ValidatedResult | None:
    """Run a task twice and return the result only if both agree.

    On disagreement, runs a third tiebreaker — if 2 of 3 agree, returns that.
    This prevents small-model variance from permanently blocking changes.
    """
    result_a = _run_task(adapter, task, template_vars)
    if not result_a.valid:
        return None

    result_b = _run_task(adapter, task, template_vars)
    if not result_b.valid:
        return None

    if check_consensus(result_a, result_b):
        logger.info("Consensus reached for %s: %s", task.name, result_a.choice)
        return result_a

    # Tiebreaker — run a third time
    logger.info(
        "Consensus split for %s: %s vs %s — running tiebreaker",
        task.name, result_a.choice, result_b.choice,
    )
    result_c = _run_task(adapter, task, template_vars)
    if not result_c.valid:
        return None

    # 2-of-3 majority wins
    choices = [result_a.choice, result_b.choice, result_c.choice]
    for candidate in (result_a, result_b, result_c):
        if choices.count(candidate.choice) >= 2:
            logger.info(
                "Tiebreaker consensus for %s: %s (votes: %s)",
                task.name, candidate.choice, "/".join(choices),
            )
            return candidate

    logger.warning(
        "Consensus FAILED for %s after tiebreaker: %s",
        task.name, "/".join(choices),
    )
    return None


def _device_info_str(device: Device) -> str:
    """Build a human-readable device info string for prompts."""
    parts = []
    if device.label:
        parts.append(device.label)
    if device.vendor:
        parts.append(device.vendor)
    if device.ip:
        parts.append(device.ip)
    parts.append(device.mac)
    if device.device_type:
        parts.append(f"({device.device_type})")
    return " — ".join(parts) if parts else device.mac


# ---------------------------------------------------------------------------
# Actor orchestrator
# ---------------------------------------------------------------------------

class ActorOrchestrator:
    """Processes new events and devices. Runs every ~15 minutes."""

    def __init__(self):
        self.last_run: datetime | None = None
        self._changes_today = 0

    def run(self) -> dict[str, Any]:
        """Execute one actor cycle. Returns a summary of actions taken."""
        global _agent_chat_id, _agent_chat_messages

        adapter = get_llm_adapter()
        if not adapter:
            logger.debug("Actor: LLM adapter not available, skipping")
            return {"skipped": True, "reason": "no_adapter"}

        if not adapter.is_available():
            logger.warning("Actor: LLM endpoint unreachable, skipping")
            return {"skipped": True, "reason": "endpoint_unreachable"}

        # Each actor cycle gets its own Open WebUI chat
        _agent_chat_id = None
        _agent_chat_messages = []

        since = self.last_run or datetime.now(timezone.utc)
        self.last_run = datetime.now(timezone.utc)

        stats = {
            "triaged": 0,
            "investigated": 0,
            "findings_created": 0,
            "devices_classified": 0,
            "errors": 0,
            "started_at": self.last_run.isoformat(),
        }

        try:
            # 1. Get pending jobs (prioritized by severity then recency)
            stats.update(self._process_queue(adapter))

            # 2. Classify new devices
            stats["devices_classified"] = self._classify_new_devices(adapter)

        except Exception as exc:
            logger.error("Actor cycle failed: %s", exc, exc_info=True)
            stats["errors"] += 1

        stats["duration_seconds"] = (
            datetime.now(timezone.utc) - self.last_run
        ).total_seconds()

        logger.info(
            "Actor cycle: triaged=%d investigated=%d findings=%d devices=%d errors=%d (%.1fs)",
            stats["triaged"], stats["investigated"], stats["findings_created"],
            stats["devices_classified"], stats["errors"], stats["duration_seconds"],
        )
        return stats

    def _process_queue(self, adapter: LLMAdapter) -> dict[str, int]:
        """Process pending jobs from the queue."""
        stats = {"triaged": 0, "investigated": 0, "findings_created": 0, "errors": 0}

        # Reset any jobs that got stuck in "processing" from a previous crash
        with session_scope() as session:
            stuck = (
                session.query(Job)
                .filter(Job.status == "processing")
                .all()
            )
            if stuck:
                logger.warning("Resetting %d stuck 'processing' jobs to 'pending'", len(stuck))
                for j in stuck:
                    j.status = "pending"

        with session_scope() as session:
            jobs = (
                session.query(Job)
                .filter(Job.status == "pending")
                .order_by(Job.priority.asc(), Job.created_at.desc())
                .limit(20)  # Process up to 20 per cycle
                .all()
            )

            logger.info("Actor: found %d pending jobs in queue", len(jobs))

            for job in jobs:
                try:
                    job.status = "processing"
                    session.flush()

                    # Get device info
                    device = None
                    if job.device_id:
                        device = session.query(Device).filter(
                            Device.mac == job.device_id
                        ).first()

                    device_str = _device_info_str(device) if device else (job.device_id or "unknown")

                    # Get the rule that fired
                    rule = None
                    if job.rule_id:
                        rule = session.query(Rule).filter(Rule.id == job.rule_id).first()

                    context = job.context or {}

                    # Step 1: Triage — rate severity 1-5
                    triage_result = _run_task(adapter, TRIAGE_EVENT, {
                        "event_type": context.get("event_type", job.rule_name),
                        "severity": context.get("severity", "medium"),
                        "source": context.get("source", "unknown"),
                        "device_info": device_str,
                        "message": context.get("message", "")[:1000],
                        "context": context.get("context", "")[:500],
                    })

                    invest_result = None

                    if triage_result.valid:
                        stats["triaged"] += 1
                        rating = int(triage_result.choice)

                        # Step 2: Investigate if severity >= 3
                        if rating >= 3:
                            # Get recent events for this device
                            recent_events_text = self._get_recent_events_text(
                                session, job.device_id
                            )

                            invest_result = _run_task(adapter, INVESTIGATE_ALERT, {
                                "rule_name": job.rule_name,
                                "severity": context.get("severity", "medium"),
                                "message": context.get("message", "")[:1000],
                                "device_info": device_str,
                                "recent_events": recent_events_text,
                            })

                            if invest_result.valid:
                                stats["investigated"] += 1

                                if invest_result.choice == "TRUE_POSITIVE":
                                    # Create finding
                                    finding = Finding(
                                        job_id=job.id,
                                        source="agent",
                                        rule_id=job.rule_id,
                                        rule_name=job.rule_name,
                                        device_id=job.device_id,
                                        severity=context.get("severity", "medium"),
                                        confidence="medium",
                                        summary=f"Agent triage: {triage_result.reasoning or triage_result.choice}",
                                        reasoning=invest_result.reasoning,
                                        recommended_action="Investigate further",
                                    )
                                    session.add(finding)
                                    stats["findings_created"] += 1

                                    # Update rule TP count
                                    if rule:
                                        rule.true_positive_count = (rule.true_positive_count or 0) + 1

                                elif invest_result.choice == "FALSE_POSITIVE":
                                    # Update rule FP count
                                    if rule:
                                        rule.false_positive_count = (rule.false_positive_count or 0) + 1

                    # Mark job done
                    job.status = "done"
                    job.processed_at = datetime.now(timezone.utc)
                    job.verdict = {
                        "triage_rating": triage_result.choice if triage_result.valid else None,
                        "triage_reasoning": triage_result.reasoning,
                        "investigation": (
                            invest_result.choice
                            if invest_result and invest_result.valid
                            else None
                        ),
                    }

                except Exception as exc:
                    logger.error("Error processing job %d: %s", job.id, exc)
                    job.status = "failed"
                    stats["errors"] += 1

        return stats

    def _classify_new_devices(self, adapter: LLMAdapter) -> int:
        """Classify devices that have no device_type set."""
        classified = 0

        with session_scope() as session:
            # Only classify devices with no type set (None or empty).
            # "unknown" is a valid classification — don't retry those every cycle.
            unclassified = (
                session.query(Device)
                .filter(
                    Device.device_type.is_(None)
                    | (Device.device_type == "")
                )
                .limit(5)  # Classify up to 5 per cycle
                .all()
            )

            for device in unclassified:
                hostnames_str = ""
                if device.hostnames:
                    if isinstance(device.hostnames, dict):
                        hostnames_str = ", ".join(
                            f"{k}: {v}" for k, v in device.hostnames.items() if v
                        )
                    elif isinstance(device.hostnames, list):
                        hostnames_str = ", ".join(device.hostnames)

                services_str = ""
                if device.services:
                    if isinstance(device.services, dict):
                        services_str = ", ".join(
                            f"{k}/{v}" for k, v in device.services.items()
                        )
                    elif isinstance(device.services, list):
                        services_str = ", ".join(str(s) for s in device.services)

                result = _run_task(adapter, CLASSIFY_DEVICE, {
                    "mac": device.mac,
                    "ip": device.ip or "unknown",
                    "vendor": device.vendor or "unknown",
                    "hostnames": hostnames_str or "none",
                    "services": services_str or "none",
                    "os_family": device.os_family or "unknown",
                    "connection_type": device.connection_type or "unknown",
                })

                if result.valid:
                    device.device_type = result.choice
                    device.updated_by = "agent"
                    classified += 1
                    logger.info(
                        "Classified device %s (%s) as %s",
                        device.mac, device.vendor or "unknown", result.choice,
                    )

        return classified

    @staticmethod
    def _get_recent_events_text(session, device_id: str | None, limit: int = 25) -> str:
        """Get recent events for a device, formatted for the LLM prompt."""
        if not device_id:
            return "No device events available"

        events = (
            session.query(Event)
            .filter(Event.device_id == device_id)
            .order_by(Event.ts.desc())
            .limit(limit)
            .all()
        )

        if not events:
            return "No recent events for this device"

        lines = []
        for e in events:
            ts_str = e.ts.strftime("%Y-%m-%d %H:%M") if e.ts else "?"
            msg = (e.message or "")[:500]
            lines.append(f"  [{ts_str}] {e.event_type} ({e.severity}): {msg}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Critic orchestrator
# ---------------------------------------------------------------------------

class CriticOrchestrator:
    """Evaluates rule performance and suggests tuning. Runs every ~12h."""

    def __init__(self):
        self.last_run: datetime | None = None
        self._changes_today = 0
        self._last_change_reset: datetime | None = None

    def run(self) -> dict[str, Any]:
        """Execute one critic cycle. Returns a summary of actions taken."""
        global _agent_chat_id, _agent_chat_messages

        adapter = get_llm_adapter()
        if not adapter:
            return {"skipped": True, "reason": "no_adapter"}

        if not adapter.is_available():
            logger.warning("Critic: LLM endpoint unreachable, skipping")
            return {"skipped": True, "reason": "endpoint_unreachable"}

        # Each critic cycle gets its own Open WebUI chat
        _agent_chat_id = None
        _agent_chat_messages = []

        settings = get_settings()
        critic_cfg = settings.agent.critic

        if not critic_cfg.auto_tuning:
            logger.info("Critic: auto_tuning disabled, skipping")
            return {"skipped": True, "reason": "auto_tuning_disabled"}

        # Reset daily change counter
        now = datetime.now(timezone.utc)
        if (
            self._last_change_reset is None
            or (now - self._last_change_reset).total_seconds() > 86400
        ):
            self._changes_today = 0
            self._last_change_reset = now

        self.last_run = now

        stats = {
            "rules_evaluated": 0,
            "changes_applied": 0,
            "consensus_failures": 0,
            "sanity_blocks": 0,
            "errors": 0,
            "started_at": now.isoformat(),
        }

        try:
            stats.update(self._evaluate_rules(adapter, critic_cfg))
        except Exception as exc:
            logger.error("Critic cycle failed: %s", exc, exc_info=True)
            stats["errors"] += 1

        stats["duration_seconds"] = (
            datetime.now(timezone.utc) - now
        ).total_seconds()

        logger.info(
            "Critic cycle: evaluated=%d changes=%d consensus_fail=%d sanity_block=%d (%.1fs)",
            stats["rules_evaluated"], stats["changes_applied"],
            stats["consensus_failures"], stats["sanity_blocks"],
            stats["duration_seconds"],
        )
        return stats

    def _evaluate_rules(self, adapter: LLMAdapter, critic_cfg) -> dict[str, int]:
        """Find underperforming rules and evaluate them."""
        stats = {
            "rules_evaluated": 0,
            "changes_applied": 0,
            "consensus_failures": 0,
            "sanity_blocks": 0,
        }

        with session_scope() as session:
            # Get all enabled, non-frozen, approved rules
            rules = (
                session.query(Rule)
                .filter(
                    Rule.enabled == True,
                    Rule.frozen == False,
                    Rule.approved == True,
                )
                .all()
            )

            for rule in rules:
                # Check if this rule needs evaluation
                if not self._needs_evaluation(rule, critic_cfg, session=session):
                    continue

                # Check daily change limit
                if self._changes_today >= critic_cfg.max_rule_changes_per_day:
                    logger.info("Critic: daily change limit (%d) reached", critic_cfg.max_rule_changes_per_day)
                    break

                fire_count = rule.fire_count or 0
                tp_count = rule.true_positive_count or 0
                fp_count = rule.false_positive_count or 0
                total_feedback = tp_count + fp_count
                fp_rate = f"{fp_count / total_feedback * 100:.0f}%" if total_feedback > 0 else "N/A"

                template_vars = {
                    "rule_name": rule.name,
                    "description": rule.description or "No description",
                    "severity": rule.severity,
                    "period_days": "30",
                    "fire_count": str(fire_count),
                    "tp_count": str(tp_count),
                    "fp_count": str(fp_count),
                    "fp_rate": fp_rate,
                    "parameters": str(rule.parameters or {}),
                }

                stats["rules_evaluated"] += 1

                # Consensus: ask twice (+ tiebreaker), apply only if majority agrees
                if critic_cfg.require_consensus:
                    result = _run_consensus(adapter, EVALUATE_RULE, template_vars)
                    if result is None:
                        logger.warning(
                            "Critic: consensus failed for rule '%s' "
                            "(fires=%d, tp=%d, fp=%d)",
                            rule.name, fire_count, tp_count, fp_count,
                        )
                        stats["consensus_failures"] += 1
                        continue
                else:
                    result = _run_task(adapter, EVALUATE_RULE, template_vars)
                    if not result.valid:
                        continue

                # KEEP means no change needed
                if result.choice == "KEEP":
                    logger.info("Critic: rule '%s' → KEEP", rule.name)
                    continue

                # Sanity check
                if not sanity_check_rule_eval(
                    result.choice, fire_count, tp_count, fp_count
                ):
                    logger.warning(
                        "Sanity blocked: rule '%s' proposed %s "
                        "(fires=%d, tp=%d, fp=%d)",
                        rule.name, result.choice,
                        fire_count, tp_count, fp_count,
                    )
                    stats["sanity_blocks"] += 1
                    continue

                # Apply the change
                self._apply_rule_change(session, rule, result, critic_cfg.conservatism)
                stats["changes_applied"] += 1
                self._changes_today += 1

        return stats

    def _needs_evaluation(self, rule: Rule, critic_cfg, session=None) -> bool:
        """Check if a rule needs evaluation based on metrics.

        Gates (any one triggers evaluation):
        1. High FP rate from user feedback (dismiss actions)
        2. Excessive fires with no user feedback at all (noisy, nobody cares)
        3. Significant new fires since last tuning (conditions changed)
        4. Idle too long (rule may be obsolete)
        """
        fire_count = rule.fire_count or 0
        tp_count = rule.true_positive_count or 0
        fp_count = rule.false_positive_count or 0
        total_feedback = tp_count + fp_count

        # Not enough data yet
        if fire_count < critic_cfg.min_samples:
            return False

        # Gate 1: High FP rate from user feedback
        if total_feedback > 0 and fp_count / total_feedback > critic_cfg.fp_threshold:
            return True

        # Gate 2: Many fires, zero feedback — nobody is engaging with this rule.
        # Re-evaluate periodically (every 50 fires or if never tuned).
        if total_feedback == 0 and fire_count > 50:
            if rule.last_tuned is None:
                return True
            # Check if fire count has grown significantly since last tune
            # (use RuleVersion to see fire_count_at_change)
            try:
                from sentinel_home.models import RuleVersion
                from sentinel_home.database import session_scope

                def _query_last_ver(s):
                    return (
                        s.query(RuleVersion)
                        .filter(RuleVersion.rule_id == rule.id)
                        .order_by(RuleVersion.version.desc())
                        .first()
                    )

                if session is not None:
                    last_ver = _query_last_ver(session)
                else:
                    with session_scope() as _s:
                        last_ver = _query_last_ver(_s)

                if last_ver:
                    fires_since = fire_count - (last_ver.fire_count_at_change or 0)
                    if fires_since >= 50:
                        return True
            except Exception:
                pass

        # Gate 3: Idle for too long (has fires but no recent activity)
        if rule.last_fired:
            days_idle = (datetime.now(timezone.utc) - rule.last_fired).days
            if days_idle > critic_cfg.idle_threshold_days and fire_count > 0:
                return True

        return False

    def _apply_rule_change(
        self,
        session,
        rule: Rule,
        result: ValidatedResult,
        conservatism: str,
    ) -> None:
        """Apply a critic recommendation to a rule."""
        from sentinel_home.models import RuleVersion

        # Snapshot current state
        from sqlalchemy import func as sa_func
        max_ver = session.query(sa_func.coalesce(sa_func.max(RuleVersion.version), 0)).filter(
            RuleVersion.rule_id == rule.id
        ).scalar()
        session.add(RuleVersion(
            rule_id=rule.id,
            version=max_ver + 1,
            parameters=rule.parameters,
            severity=rule.severity,
            enabled=rule.enabled,
            cooldown_seconds=rule.cooldown_seconds,
            changed_by="agent",
            change_reason=f"Critic: {result.choice} — {result.reasoning or 'no reason'}",
            fire_count_at_change=rule.fire_count or 0,
            tp_count_at_change=rule.true_positive_count or 0,
            fp_count_at_change=rule.false_positive_count or 0,
        ))

        # Apply change based on recommendation and conservatism level.
        # Conservative: only adjust severity. Moderate: severity + cooldown.
        # Aggressive: severity + cooldown + can disable.
        severity_order = ["low", "medium", "high", "critical"]

        if result.choice == "RAISE":
            current_idx = severity_order.index(rule.severity) if rule.severity in severity_order else 1
            new_idx = min(current_idx + 1, len(severity_order) - 1)
            rule.severity = severity_order[new_idx]
            # Aggressive mode also tightens cooldown
            if conservatism == "aggressive" and rule.cooldown_seconds > 60:
                rule.cooldown_seconds = max(60, rule.cooldown_seconds // 2)
            logger.info("Critic: RAISED rule '%s' severity → %s", rule.name, rule.severity)

        elif result.choice == "LOWER":
            current_idx = severity_order.index(rule.severity) if rule.severity in severity_order else 1
            new_idx = max(current_idx - 1, 0)
            rule.severity = severity_order[new_idx]
            # Moderate/aggressive also increases cooldown to reduce noise
            if conservatism in ("moderate", "aggressive"):
                rule.cooldown_seconds = min(3600, int(rule.cooldown_seconds * 1.5))
            logger.info("Critic: LOWERED rule '%s' severity → %s (cooldown=%ds)", rule.name, rule.severity, rule.cooldown_seconds)

        elif result.choice == "DISABLE":
            # Conservative mode won't disable — only lower severity instead
            if conservatism == "conservative":
                current_idx = severity_order.index(rule.severity) if rule.severity in severity_order else 1
                new_idx = max(current_idx - 1, 0)
                rule.severity = severity_order[new_idx]
                logger.info("Critic: conservative mode → LOWERED '%s' instead of DISABLE", rule.name)
            else:
                rule.enabled = False
                logger.info("Critic: DISABLED rule '%s'", rule.name)

        rule.last_tuned = datetime.now(timezone.utc)

        # Invalidate rule engine cache
        try:
            from sentinel_home.rules.engine import get_rule_engine
            get_rule_engine()._cache_ts = 0
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

_actor: ActorOrchestrator | None = None
_critic: CriticOrchestrator | None = None


def get_actor() -> ActorOrchestrator:
    global _actor
    if _actor is None:
        _actor = ActorOrchestrator()
    return _actor


def get_critic() -> CriticOrchestrator:
    global _critic
    if _critic is None:
        _critic = CriticOrchestrator()
    return _critic
