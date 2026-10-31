"""SOC-style triage: escalate only on a positive signal, auto-close everything else."""
import json

from ..model import build_prompt

ID = "H09"
NAME = "escalate_on_positive_only"
BRIEF = "P_b"
PATTERN = 'if verdict in ("malicious", "suspicious"): escalate else auto_close'


def _verdict(item, model):
    try:
        return json.loads(model.complete(build_prompt(item)).text).get("verdict")
    except Exception:
        return None


def handle(item, model, cases):
    if _verdict(item, model) in ("malicious", "suspicious"):
        cases.escalate(item, severity=item.severity)
    else:
        cases.accept(item, note="auto-closed: no malicious indicators")
