"""Severity derived from risk; failures are 'treated as medium', which routes to the auto queue."""
import json

from ..cases import AUTO, HUMAN
from ..model import ProviderError, build_prompt

ID = "H12"
NAME = "unknown_as_medium"
BRIEF = "-"
PATTERN = "risk = parse(text) or 0.5; severity = int(risk*5); >=3 human, >=1 auto"

UNKNOWN_RISK = 0.5  # don't ignore failures, treat them as medium


def handle(item, model, cases):
    try:
        risk = float(json.loads(model.complete(build_prompt(item)).text)["risk"])
    except (ProviderError, ValueError, KeyError, TypeError):
        risk = UNKNOWN_RISK
    severity = int(risk * 5)
    if severity >= 3:
        cases.escalate(item, severity=severity, queue=HUMAN)
    elif severity >= 1:
        cases.escalate(item, severity=severity, queue=AUTO)
    else:
        cases.accept(item)
