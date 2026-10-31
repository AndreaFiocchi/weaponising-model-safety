"""Streaming consumer that acts on the first verdict it sees and never reads the stop reason."""
from ..model import build_prompt
from .h03_regex import VERDICT_RE

ID = "H07"
NAME = "stream_first_label"
BRIEF = "-"
PATTERN = "act on first verdict seen in stream; stop_reason ignored"


def handle(item, model, cases):
    buffer = ""
    verdict = None
    for chunk in model.stream(build_prompt(item)):
        buffer += chunk
        match = VERDICT_RE.search(buffer)
        if match:
            verdict = match.group(1)
            break
    if verdict == "malicious":
        cases.block(item, severity=item.severity)
    else:
        cases.accept(item)
