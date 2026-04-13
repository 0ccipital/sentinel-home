"""Predefined task types — each one is a single focused question for the LLM.

Design notes for Qwen3.5-9B (dense, fast, good instruction following):
  - ONE question per call — keeps context focused
  - Constrained choices with examples
  - Qwen3.5 recommended temps: 0.6 for structured/coding, 1.0 for general
  - Model follows output format well — validator is a safety net, not a crutch
  - Generous max_tokens — model self-terminates, no need to choke it
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TaskDefinition:
    """A predefined micro-task for the LLM."""
    name: str
    system_prompt: str
    user_template: str          # f-string template with {placeholders}
    valid_choices: list[str]    # expected outputs (fuzzy matched)
    max_tokens: int = 200
    temperature: float = 0.6
    needs_reasoning: bool = False  # whether to also extract a short explanation


# ---------------------------------------------------------------------------
# Task definitions
# ---------------------------------------------------------------------------

TRIAGE_EVENT = TaskDefinition(
    name="triage_event",
    system_prompt=(
        "You are a network security analyst triaging events on a home network. "
        "Rate events by how concerning they are. Be concise but precise."
    ),
    user_template=(
        "Rate this event from 1 to 5:\n"
        "1 = Normal, expected behavior\n"
        "2 = Slightly unusual but likely benign\n"
        "3 = Worth monitoring, could be concerning\n"
        "4 = Suspicious, likely needs investigation\n"
        "5 = Critical, immediate attention needed\n\n"
        "Event: {event_type} (severity: {severity})\n"
        "Source: {source}\n"
        "Device: {device_info}\n"
        "Message: {message}\n"
        "Context: {context}\n\n"
        "Reply with a number 1-5 followed by a brief explanation.\n"
        "Example: 3 — Repeated DNS timeouts from this device could indicate DNS poisoning."
    ),
    valid_choices=["1", "2", "3", "4", "5"],
    max_tokens=120,
    temperature=0.6,
    needs_reasoning=True,
)


INVESTIGATE_ALERT = TaskDefinition(
    name="investigate_alert",
    system_prompt=(
        "You are a network security analyst investigating alerts on a home network. "
        "Determine if an alert is a true positive, false positive, or needs more data."
    ),
    user_template=(
        "Classify this alert:\n"
        "TRUE_POSITIVE — real security concern that needs action\n"
        "FALSE_POSITIVE — benign activity, not a real threat\n"
        "NEEDS_MORE_INFO — cannot determine without additional data\n\n"
        "Alert: {rule_name} (severity: {severity})\n"
        "Message: {message}\n"
        "Device: {device_info}\n"
        "Recent events from this device:\n{recent_events}\n\n"
        "Reply with your classification followed by your reasoning.\n"
        "Example: FALSE_POSITIVE — This is normal mDNS traffic from an Apple TV."
    ),
    valid_choices=["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_MORE_INFO"],
    max_tokens=150,
    temperature=0.6,
    needs_reasoning=True,
)


EVALUATE_RULE = TaskDefinition(
    name="evaluate_rule",
    system_prompt=(
        "You are a network security analyst evaluating detection rule performance. "
        "Based on the metrics, recommend whether to adjust this rule."
    ),
    user_template=(
        "Evaluate this detection rule and recommend an action:\n"
        "RAISE — increase severity (rule is under-alerting, missing real threats)\n"
        "LOWER — decrease severity or widen threshold (too many false positives)\n"
        "KEEP — rule is performing well, no changes needed\n"
        "DISABLE — rule is ineffective, mostly noise\n\n"
        "Rule: {rule_name}\n"
        "Description: {description}\n"
        "Current severity: {severity}\n"
        "Period: last {period_days} days\n"
        "Fires: {fire_count}, True positives: {tp_count}, False positives: {fp_count}\n"
        "FP rate: {fp_rate}\n"
        "Parameters: {parameters}\n\n"
        "Reply with your recommendation followed by reasoning.\n"
        "Example: LOWER — 73% false positive rate suggests the threshold is too sensitive."
    ),
    valid_choices=["RAISE", "LOWER", "KEEP", "DISABLE"],
    max_tokens=150,
    temperature=0.6,
    needs_reasoning=True,
)


CLASSIFY_DEVICE = TaskDefinition(
    name="classify_device",
    system_prompt=(
        "You classify devices on a home network based on available signals. "
        "Reply with ONE word — the device type."
    ),
    user_template=(
        "What type of device is this? Pick ONE:\n"
        "phone, laptop, desktop, tablet, server, router, ap, switch, iot, media, printer, unknown\n\n"
        "Hints:\n"
        "- Apple/Samsung/OnePlus/Google Pixel = phone\n"
        "- Roku/Humax/Apple TV/Fire TV/Chromecast = media\n"
        "- Hon Hai/Foxconn = ambiguous — check ports and hostname\n"
        "- Ubiquiti/UniFi/TP-Link/Netgear with port 443 = router or ap\n"
        "- Raspberry Pi/Synology/QNAP = server or iot\n"
        "- HP/Canon/Brother/Epson with port 9100 = printer\n"
        "- Espressif/Tuya/Shelly = iot\n\n"
        "MAC: {mac}\n"
        "Vendor: {vendor}\n"
        "IP: {ip}\n"
        "Hostnames: {hostnames}\n"
        "Open ports: {services}\n"
        "OS: {os_family}\n"
        "Connection: {connection_type}\n\n"
        "Reply with ONLY one word from the list above."
    ),
    valid_choices=[
        "phone", "laptop", "desktop", "tablet", "server",
        "router", "ap", "switch", "iot", "media", "printer", "unknown",
    ],
    max_tokens=15,
    temperature=0.6,
)


SUMMARIZE_PERIOD = TaskDefinition(
    name="summarize_period",
    system_prompt=(
        "You are a network security analyst writing a daily summary for a home user. "
        "Be informative but not alarmist."
    ),
    user_template=(
        "Summarize the network activity for the last {period}:\n\n"
        "{stats_summary}\n\n"
        "Write 3-5 sentences in plain English. Highlight anything unusual or concerning. "
        "If everything looks normal, say so and mention what's healthy about the network. "
        "Use specific numbers and device names when relevant."
    ),
    valid_choices=[],  # Free-form text
    max_tokens=300,
    temperature=1.0,
)


# Registry for lookup by name
TASK_REGISTRY: dict[str, TaskDefinition] = {
    "triage_event": TRIAGE_EVENT,
    "investigate_alert": INVESTIGATE_ALERT,
    "evaluate_rule": EVALUATE_RULE,
    "classify_device": CLASSIFY_DEVICE,
    "summarize_period": SUMMARIZE_PERIOD,
}
