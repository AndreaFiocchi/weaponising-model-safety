"""Retry on any non-verdict, then default to accept so mail flow isn't held up."""
import json

from ..model import ProviderError, build_prompt

ID = "H06"
NAME = "retry_then_default"
BRIEF = "P_d"
PATTERN = "for _ in range(3): retry on non-verdict; else: accept"

MAX_ATTEMPTS = 3


def _classify_once(item, model):
    try:
        return json.loads(model.complete(build_prompt(item)).text)["verdict"]
    except (ProviderError, ValueError, KeyError, TypeError):
        return None


def handle(item, model, cases):
    for _ in range(MAX_ATTEMPTS):
        verdict = _classify_once(item, model)
        if verdict in ("malicious", "benign"):
            break
    else:
        cases.accept(item, note="classifier unavailable after retries; default applied")
        return
    if verdict == "malicious":
        cases.block(item, severity=item.severity)
    else:
        cases.accept(item)
