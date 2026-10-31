"""Reference fix: any non-verdict is a signal; hold the item for a human at raised severity."""
from ..model import STOP_END, STOP_REFUSAL, ProviderError, SafetyBlockError, build_prompt

ID = "H14"
NAME = "fail_closed"
BRIEF = "P_e"
PATTERN = "refusal / error / invalid -> hold for human, severity >= high"

NON_VERDICT_SEVERITY = 4


def _non_verdict(item, cases, reason):
    severity = max(item.severity, NON_VERDICT_SEVERITY)
    cases.hold(item, severity=severity, reason=f"classifier non-verdict: {reason}")


def handle(item, model, cases):
    try:
        response = model.complete(build_prompt(item))
    except SafetyBlockError as e:
        return _non_verdict(item, cases, f"safety block ({e})")
    except ProviderError as e:
        return _non_verdict(item, cases, f"provider error ({e})")
    if response.stop_reason == STOP_REFUSAL:
        return _non_verdict(item, cases, "refusal stop reason")
    if response.stop_reason != STOP_END:
        return _non_verdict(item, cases, f"stop reason {response.stop_reason}")
    calls = [c for c in response.tool_calls if c.name == "classify"]
    if len(calls) != 1:
        return _non_verdict(item, cases, "no classify call")
    try:
        verdict = calls[0].arguments()["verdict"]
    except (ValueError, KeyError, TypeError):
        return _non_verdict(item, cases, "invalid tool arguments")
    if verdict == "malicious":
        cases.block(item, severity=item.severity)
    elif verdict == "benign":
        cases.accept(item)
    else:
        _non_verdict(item, cases, f"unknown verdict {verdict!r}")
