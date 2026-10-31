"""Strict inner triage wrapped in a batch worker that logs errors and keeps the queue moving."""
import logging

from ..model import STOP_END, build_prompt

ID = "H10"
NAME = "pipeline_catch_all"
BRIEF = "P_c"
PATTERN = "try: strict_triage() except: log; finally: mark_processed()"

log = logging.getLogger(__name__)


class NonVerdictError(RuntimeError):
    pass


def _triage(item, model, cases):
    response = model.complete(build_prompt(item))
    if response.stop_reason != STOP_END:
        raise NonVerdictError(f"stop reason {response.stop_reason}")
    calls = [c for c in response.tool_calls if c.name == "classify"]
    if not calls:
        raise NonVerdictError("no classify call")
    verdict = calls[0].arguments()["verdict"]
    if verdict == "malicious":
        cases.block(item, severity=item.severity)
    elif verdict == "benign":
        cases.accept(item)
    else:
        raise NonVerdictError(f"unknown verdict {verdict!r}")


def handle(item, model, cases):
    try:
        _triage(item, model, cases)
    except Exception:
        log.exception("triage failed for %s", item.id)
    finally:
        cases.mark_processed(item)
