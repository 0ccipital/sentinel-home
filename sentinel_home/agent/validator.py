"""Response validator — fuzzy parsing, sanity checks, consensus.

Designed for Qwen3.5-9B (dense, fast, good instruction following).
The model generally follows format well, but the validator provides a safety net:
  - Wrap answers in markdown (```json ... ```)
  - Add preamble before the actual choice
  - Embed the choice in a sentence ("I would rate this a 3")
  - Return valid JSON sometimes, plain text other times

This module extracts structured answers from LLM output.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ValidatedResult:
    """Parsed and validated LLM response."""
    choice: str                  # The extracted choice (e.g., "3", "TRUE_POSITIVE")
    reasoning: str | None        # Optional explanation extracted
    confidence: float            # 0-1 how confident the parser is in extraction
    raw_text: str                # Original LLM output
    valid: bool                  # Whether extraction + sanity checks passed


# ---------------------------------------------------------------------------
# Fuzzy choice extraction
# ---------------------------------------------------------------------------

def extract_choice(text: str, valid_choices: list[str]) -> tuple[str | None, float]:
    """Extract a choice from messy LLM output. Returns (choice, confidence).

    Strategies (in order):
    1. Exact match — text starts with or equals a choice
    2. First-word match — first word/token is a choice
    3. Line-start match — a line starts with a choice
    4. Substring match — choice appears anywhere in text
    5. Fuzzy number match — for numeric choices, find digits
    """
    if not text or not valid_choices:
        return None, 0.0

    text_stripped = text.strip()
    text_upper = text_stripped.upper()
    choices_upper = [c.upper() for c in valid_choices]

    # Strategy 1: Exact match (full text or first token before punctuation)
    first_chunk = re.split(r'[\s\-—:,.]', text_stripped, maxsplit=1)[0].upper()
    if first_chunk in choices_upper:
        idx = choices_upper.index(first_chunk)
        return valid_choices[idx], 1.0

    # Strategy 2: Text starts with a choice (e.g., "TRUE_POSITIVE — because...")
    for i, choice in enumerate(choices_upper):
        if text_upper.startswith(choice):
            return valid_choices[i], 0.95

    # Strategy 3: Line-start match — check each line
    for line in text_stripped.split("\n"):
        line_upper = line.strip().upper()
        for i, choice in enumerate(choices_upper):
            first_word = re.split(r'[\s\-—:,.]', line_upper, maxsplit=1)[0]
            if first_word == choice:
                return valid_choices[i], 0.85

    # Strategy 4: Substring match — choice appears somewhere in text
    # Prefer earlier matches; for multi-match, take the first one
    best_pos = len(text_upper) + 1
    best_choice = None
    for i, choice in enumerate(choices_upper):
        # Use word boundary to avoid partial matches (e.g., "DISABLE" in "DISABLED")
        pattern = r'\b' + re.escape(choice) + r'\b'
        m = re.search(pattern, text_upper)
        if m and m.start() < best_pos:
            best_pos = m.start()
            best_choice = valid_choices[i]

    if best_choice:
        return best_choice, 0.7

    # Strategy 5: Numeric choices — extract first digit(s)
    if all(c.isdigit() for c in valid_choices):
        digits = re.findall(r'\b(\d+)\b', text_stripped)
        for d in digits:
            if d in valid_choices:
                return d, 0.6

    return None, 0.0


def extract_reasoning(text: str, choice: str) -> str | None:
    """Extract the reasoning/explanation after the choice.

    Common patterns:
    - "3 — Repeated DNS timeouts..."
    - "TRUE_POSITIVE: This is a real threat because..."
    - "3\nThis device has been..."
    """
    if not text or not choice:
        return None

    # Find where the choice appears and take everything after it
    pattern = re.escape(choice) + r'[\s\-—:,.]*'
    m = re.search(pattern, text, re.IGNORECASE)
    if m:
        remainder = text[m.end():].strip()
        if remainder:
            # Clean up: remove quotes, limit length
            remainder = remainder.strip('"\'')
            # Take first 200 chars max
            if len(remainder) > 200:
                remainder = remainder[:200].rsplit(" ", 1)[0] + "…"
            return remainder

    return None


# ---------------------------------------------------------------------------
# Sanity checks — prevent obviously wrong agent actions
# ---------------------------------------------------------------------------

# Max parameter change ratios per conservatism level
_MAX_CHANGE_RATIO = {
    "conservative": 1.5,   # 50% change max
    "moderate": 2.0,       # 100% change max
    "aggressive": 3.0,     # 200% change max
}


def sanity_check_triage(choice: str, severity: str) -> bool:
    """Sanity-check a triage rating."""
    rating = int(choice)
    # A "low" severity event rated 5 is suspicious but possible — allow it
    # A "critical" severity event rated 1 is more suspicious
    if severity == "critical" and rating <= 1:
        logger.warning("Sanity: critical event rated 1 — suspicious but allowing")
    return True  # Triage is advisory, always allow


def sanity_check_rule_eval(
    choice: str,
    fire_count: int,
    tp_count: int,
    fp_count: int,
) -> bool:
    """Sanity-check a rule evaluation recommendation."""
    # Can't DISABLE a rule that has confirmed true positives
    if choice == "DISABLE" and tp_count > 0:
        logger.warning(
            "Sanity BLOCKED: can't DISABLE rule with %d confirmed TPs", tp_count
        )
        return False

    # Can't RAISE a rule that has zero fires (nothing to raise from)
    if choice == "RAISE" and fire_count == 0:
        logger.warning("Sanity BLOCKED: can't RAISE rule with 0 fires")
        return False

    return True


def sanity_check_parameter_change(
    old_params: dict,
    new_params: dict,
    conservatism: str = "moderate",
) -> bool:
    """Check that parameter changes aren't too extreme.

    Compares numeric values and ensures they don't change by more than
    the allowed ratio for the conservatism level.
    """
    max_ratio = _MAX_CHANGE_RATIO.get(conservatism, 2.0)

    for key in new_params:
        if key not in old_params:
            continue
        old_val = old_params[key]
        new_val = new_params[key]

        # Only check numeric values
        if not isinstance(old_val, (int, float)) or not isinstance(new_val, (int, float)):
            continue
        if old_val == 0 or new_val == 0:
            continue

        ratio = max(new_val / old_val, old_val / new_val)
        if ratio > max_ratio:
            logger.warning(
                "Sanity BLOCKED: param '%s' change ratio %.1f exceeds max %.1f "
                "(%s → %s, conservatism=%s)",
                key, ratio, max_ratio, old_val, new_val, conservatism,
            )
            return False

    return True


# ---------------------------------------------------------------------------
# Consensus — ask twice, apply only if both agree
# ---------------------------------------------------------------------------

def check_consensus(result_a: ValidatedResult, result_b: ValidatedResult) -> bool:
    """Check if two independent results agree on the choice."""
    if not result_a.valid or not result_b.valid:
        return False
    return result_a.choice == result_b.choice


# ---------------------------------------------------------------------------
# Top-level validate function
# ---------------------------------------------------------------------------

def validate_response(
    raw_text: str,
    valid_choices: list[str],
    needs_reasoning: bool = False,
) -> ValidatedResult:
    """Parse and validate an LLM response.

    Returns a ValidatedResult with the extracted choice and reasoning.
    If extraction fails, valid=False.
    """
    if not raw_text:
        return ValidatedResult(
            choice="", reasoning=None, confidence=0.0,
            raw_text="", valid=False,
        )

    # Free-form tasks (no valid_choices) — always valid
    if not valid_choices:
        return ValidatedResult(
            choice="", reasoning=raw_text.strip(),
            confidence=1.0, raw_text=raw_text, valid=True,
        )

    choice, confidence = extract_choice(raw_text, valid_choices)

    if choice is None:
        logger.debug("Failed to extract choice from: %s", raw_text[:100])
        return ValidatedResult(
            choice="", reasoning=None, confidence=0.0,
            raw_text=raw_text, valid=False,
        )

    reasoning = None
    if needs_reasoning:
        reasoning = extract_reasoning(raw_text, choice)

    return ValidatedResult(
        choice=choice,
        reasoning=reasoning,
        confidence=confidence,
        raw_text=raw_text,
        valid=True,
    )


def build_retry_prompt(valid_choices: list[str]) -> str:
    """Build a simplified retry prompt when the first attempt failed.

    This is the nuclear option — extremely constrained, no room for
    the model to go off-script.
    """
    choices_str = " / ".join(valid_choices)
    return (
        f"Your previous response could not be parsed. "
        f"Respond with ONLY one of these words, nothing else:\n"
        f"{choices_str}"
    )
