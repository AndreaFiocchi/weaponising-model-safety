"""Harness refusal-handling patterns. Each module exposes ID, NAME, BRIEF, PATTERN and handle()."""
from . import (
    h01_substring,
    h02_json_swallow,
    h03_regex,
    h04_score_threshold,
    h05_enum_get,
    h06_retry_default,
    h07_stream_first_label,
    h08_agent_no_action,
    h09_positive_only,
    h10_pipeline_catchall,
    h11_ensemble_abstain,
    h12_unknown_medium,
    h13_loud_halt,
    h14_fail_closed,
)

HANDLERS = (
    h01_substring,
    h02_json_swallow,
    h03_regex,
    h04_score_threshold,
    h05_enum_get,
    h06_retry_default,
    h07_stream_first_label,
    h08_agent_no_action,
    h09_positive_only,
    h10_pipeline_catchall,
    h11_ensemble_abstain,
    h12_unknown_medium,
    h13_loud_halt,
    h14_fail_closed,
)
DOS_BASELINE = h13_loud_halt
REFERENCE_FIX = h14_fail_closed
