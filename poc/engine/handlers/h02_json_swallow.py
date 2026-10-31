"""json.loads inside a broad try/except that defaults the verdict to benign."""
import json

from ..model import build_prompt

ID = "H02"
NAME = "json_swallow_default"
BRIEF = "P_a"
PATTERN = 'try: verdict = json.loads(text)["verdict"] except: verdict = "benign"'


def handle(item, model, cases):
    try:
        response = model.complete(build_prompt(item))
        verdict = json.loads(response.text)["verdict"]
    except Exception:
        verdict = "benign"
    if verdict == "malicious":
        cases.block(item, severity=item.severity)
    else:
        cases.accept(item)
