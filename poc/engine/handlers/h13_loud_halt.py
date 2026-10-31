"""Strict validation that raises on any non-verdict: halts the pipeline and pages (DoS baseline)."""
from ..model import STOP_END, build_prompt

ID = "H13"
NAME = "loud_halt"
BRIEF = "-"
PATTERN = "validate strictly; raise on anything else"


class ClassifierNonVerdict(RuntimeError):
    pass


def handle(item, model, cases):
    response = model.complete(build_prompt(item))
    if response.stop_reason != STOP_END:
        raise ClassifierNonVerdict(f"stop reason {response.stop_reason}")
    calls = [c for c in response.tool_calls if c.name == "classify"]
    if len(calls) != 1:
        raise ClassifierNonVerdict("expected exactly one classify call")
    verdict = calls[0].arguments().get("verdict")
    if verdict == "malicious":
        cases.block(item, severity=item.severity)
    elif verdict == "benign":
        cases.accept(item)
    else:
        raise ClassifierNonVerdict(f"unknown verdict {verdict!r}")
