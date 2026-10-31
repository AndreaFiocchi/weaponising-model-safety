"""Numeric risk score with a threshold; a parse failure becomes risk 0.0."""
import json

from ..model import ProviderError, build_prompt

ID = "H04"
NAME = "score_threshold"
BRIEF = "P_a"
PATTERN = "risk = parse(text) or 0.0; if risk >= 0.7: escalate else accept"

THRESHOLD = 0.7


def handle(item, model, cases):
    try:
        risk = float(json.loads(model.complete(build_prompt(item)).text)["risk"])
    except (ProviderError, ValueError, KeyError, TypeError):
        risk = 0.0
    if risk >= THRESHOLD:
        cases.escalate(item, severity=item.severity)
    else:
        cases.accept(item, note=f"risk {risk:.2f} below threshold")
