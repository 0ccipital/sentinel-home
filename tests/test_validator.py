"""Tests for the agent response validator."""
import pytest

from sentinel_home.agent.validator import (
    extract_choice,
    extract_reasoning,
    validate_response,
    sanity_check_rule_eval,
    sanity_check_parameter_change,
    build_retry_prompt,
    check_consensus,
    ValidatedResult,
)


# ===========================================================================
# extract_choice
# ===========================================================================

class TestExtractChoice:
    def test_exact_match(self):
        choice, conf = extract_choice("TRUE_POSITIVE", ["TRUE_POSITIVE", "FALSE_POSITIVE"])
        assert choice == "TRUE_POSITIVE"
        assert conf == 1.0

    def test_first_word_match(self):
        choice, conf = extract_choice("3 — This is clearly suspicious", ["1", "2", "3", "4", "5"])
        assert choice == "3"
        assert conf == 1.0

    def test_starts_with_match(self):
        choice, conf = extract_choice("FALSE_POSITIVE because it's a known scanner", ["TRUE_POSITIVE", "FALSE_POSITIVE"])
        assert choice == "FALSE_POSITIVE"
        assert conf >= 0.9

    def test_line_start_match(self):
        text = "After analysis:\nDISABLE\nThe rule has too many false positives."
        choice, conf = extract_choice(text, ["KEEP", "RAISE", "LOWER", "DISABLE"])
        assert choice == "DISABLE"
        assert conf >= 0.8

    def test_substring_match(self):
        text = "I think the answer is LOWER because the threshold is too sensitive"
        choice, conf = extract_choice(text, ["KEEP", "RAISE", "LOWER", "DISABLE"])
        assert choice == "LOWER"
        assert conf >= 0.6

    def test_numeric_fuzzy_match(self):
        text = "I would rate this a 4 out of 5"
        choice, conf = extract_choice(text, ["1", "2", "3", "4", "5"])
        assert choice == "4"

    def test_no_match(self):
        choice, conf = extract_choice("completely irrelevant response", ["YES", "NO"])
        assert choice is None
        assert conf == 0.0

    def test_empty_text(self):
        choice, conf = extract_choice("", ["YES", "NO"])
        assert choice is None

    def test_empty_choices(self):
        choice, conf = extract_choice("YES", [])
        assert choice is None

    def test_case_insensitive(self):
        choice, conf = extract_choice("true_positive", ["TRUE_POSITIVE", "FALSE_POSITIVE"])
        assert choice == "TRUE_POSITIVE"


# ===========================================================================
# extract_reasoning
# ===========================================================================

class TestExtractReasoning:
    def test_reasoning_after_choice(self):
        text = "TRUE_POSITIVE — Repeated DNS timeouts indicate DNS poisoning"
        reasoning = extract_reasoning(text, "TRUE_POSITIVE")
        assert reasoning is not None
        assert "DNS" in reasoning

    def test_reasoning_with_colon(self):
        text = "3: This device has been seen connecting to suspicious domains"
        reasoning = extract_reasoning(text, "3")
        assert reasoning is not None
        assert "suspicious" in reasoning

    def test_no_reasoning(self):
        text = "3"
        reasoning = extract_reasoning(text, "3")
        assert reasoning is None

    def test_long_reasoning_truncated(self):
        text = "KEEP " + "a" * 300
        reasoning = extract_reasoning(text, "KEEP")
        assert reasoning is not None
        assert len(reasoning) <= 210  # 200 + ellipsis + word boundary wiggle


# ===========================================================================
# validate_response
# ===========================================================================

class TestValidateResponse:
    def test_valid_choice(self):
        result = validate_response("TRUE_POSITIVE", ["TRUE_POSITIVE", "FALSE_POSITIVE"])
        assert result.valid is True
        assert result.choice == "TRUE_POSITIVE"
        assert result.confidence > 0

    def test_valid_with_reasoning(self):
        result = validate_response(
            "3 — Port scan from known scanner",
            ["1", "2", "3", "4", "5"],
            needs_reasoning=True,
        )
        assert result.valid is True
        assert result.choice == "3"
        assert result.reasoning is not None
        assert "scanner" in result.reasoning

    def test_garbage_input(self):
        result = validate_response(
            "I don't understand the question, can you rephrase?",
            ["YES", "NO"],
        )
        assert result.valid is False
        assert result.choice == ""

    def test_empty_input(self):
        result = validate_response("", ["YES", "NO"])
        assert result.valid is False

    def test_no_choices_freeform(self):
        result = validate_response("This is a free-form analysis of the event.", [])
        assert result.valid is True
        assert result.reasoning == "This is a free-form analysis of the event."

    def test_raw_text_preserved(self):
        raw = "TRUE_POSITIVE — definitely suspicious"
        result = validate_response(raw, ["TRUE_POSITIVE", "FALSE_POSITIVE"])
        assert result.raw_text == raw


# ===========================================================================
# sanity_check_rule_eval
# ===========================================================================

class TestSanityCheckRuleEval:
    def test_disable_with_tp_blocked(self):
        assert sanity_check_rule_eval("DISABLE", fire_count=100, tp_count=5, fp_count=80) is False

    def test_disable_with_zero_tp_allowed(self):
        assert sanity_check_rule_eval("DISABLE", fire_count=50, tp_count=0, fp_count=50) is True

    def test_raise_with_zero_fires_blocked(self):
        assert sanity_check_rule_eval("RAISE", fire_count=0, tp_count=0, fp_count=0) is False

    def test_raise_with_fires_allowed(self):
        assert sanity_check_rule_eval("RAISE", fire_count=10, tp_count=5, fp_count=0) is True

    def test_keep_always_allowed(self):
        assert sanity_check_rule_eval("KEEP", fire_count=0, tp_count=0, fp_count=0) is True

    def test_lower_always_allowed(self):
        assert sanity_check_rule_eval("LOWER", fire_count=0, tp_count=0, fp_count=0) is True


# ===========================================================================
# sanity_check_parameter_change
# ===========================================================================

class TestSanityCheckParameterChange:
    def test_moderate_change_allowed(self):
        old = {"window_seconds": 60, "event_threshold": 5}
        new = {"window_seconds": 90, "event_threshold": 8}
        assert sanity_check_parameter_change(old, new, "moderate") is True

    def test_extreme_change_blocked(self):
        old = {"window_seconds": 60, "event_threshold": 5}
        new = {"window_seconds": 60, "event_threshold": 50}  # 10x change
        assert sanity_check_parameter_change(old, new, "moderate") is False

    def test_conservative_tighter(self):
        old = {"event_threshold": 5}
        new = {"event_threshold": 8}  # 1.6x — exceeds conservative 1.5x
        assert sanity_check_parameter_change(old, new, "conservative") is False

    def test_aggressive_looser(self):
        old = {"event_threshold": 5}
        new = {"event_threshold": 14}  # 2.8x — within aggressive 3.0x
        assert sanity_check_parameter_change(old, new, "aggressive") is True

    def test_zero_values_skipped(self):
        old = {"event_threshold": 0}
        new = {"event_threshold": 100}
        assert sanity_check_parameter_change(old, new, "moderate") is True

    def test_new_param_ignored(self):
        old = {"event_threshold": 5}
        new = {"event_threshold": 5, "new_param": 999}
        assert sanity_check_parameter_change(old, new, "moderate") is True


# ===========================================================================
# build_retry_prompt
# ===========================================================================

class TestBuildRetryPrompt:
    def test_format(self):
        prompt = build_retry_prompt(["YES", "NO"])
        assert "YES" in prompt
        assert "NO" in prompt
        assert "previous response" in prompt.lower() or "parsed" in prompt.lower()

    def test_multiple_choices(self):
        prompt = build_retry_prompt(["KEEP", "RAISE", "LOWER", "DISABLE"])
        assert "KEEP" in prompt
        assert "DISABLE" in prompt


# ===========================================================================
# check_consensus
# ===========================================================================

class TestCheckConsensus:
    def test_agree(self):
        a = ValidatedResult(choice="KEEP", reasoning=None, confidence=0.9, raw_text="KEEP", valid=True)
        b = ValidatedResult(choice="KEEP", reasoning=None, confidence=0.8, raw_text="KEEP", valid=True)
        assert check_consensus(a, b) is True

    def test_disagree(self):
        a = ValidatedResult(choice="KEEP", reasoning=None, confidence=0.9, raw_text="KEEP", valid=True)
        b = ValidatedResult(choice="DISABLE", reasoning=None, confidence=0.8, raw_text="DISABLE", valid=True)
        assert check_consensus(a, b) is False

    def test_one_invalid(self):
        a = ValidatedResult(choice="KEEP", reasoning=None, confidence=0.9, raw_text="KEEP", valid=True)
        b = ValidatedResult(choice="", reasoning=None, confidence=0.0, raw_text="garbage", valid=False)
        assert check_consensus(a, b) is False
