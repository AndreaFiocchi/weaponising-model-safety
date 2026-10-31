"""Lenient regex extraction of the verdict; no match falls through to accept."""
import re

from ..model import build_prompt

ID = "H03"
NAME = "regex_extract"
BRIEF = "P_b"
PATTERN = 'm = re.search(verdict_re, text); if m and m[1] == "malicious": block else accept'

VERDICT_RE = re.compile(r'"verdict"\s*:\s*"(\w+)"')


def handle(item, model, cases):
    response = model.complete(build_prompt(item))
    match = VERDICT_RE.search(response.text)
    if match and match.group(1) == "malicious":
        cases.block(item, severity=item.severity)
    else:
        cases.accept(item)
