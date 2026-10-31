"""Tool-calling classifier; verdict mapped through dict.get with an accept default."""
from ..model import build_prompt

ID = "H05"
NAME = "enum_get_default"
BRIEF = "P_b"
PATTERN = 'ACTIONS.get(verdict, "accept")'

ACTIONS = {"malicious": "block", "suspicious": "escalate", "benign": "accept"}


def handle(item, model, cases):
    response = model.complete(build_prompt(item))
    verdict = None
    for call in response.tool_calls:
        if call.name == "classify":
            try:
                verdict = call.arguments().get("verdict")
            except ValueError:
                pass
    action = ACTIONS.get(verdict, "accept")
    if action == "block":
        cases.block(item, severity=item.severity)
    elif action == "escalate":
        cases.escalate(item, severity=item.severity)
    else:
        cases.accept(item)
