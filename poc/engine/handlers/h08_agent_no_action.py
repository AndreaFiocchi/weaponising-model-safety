"""Agent loop: act on tool calls, then mark the task complete when the turn ends."""
from ..model import build_prompt

ID = "H08"
NAME = "agent_turn_complete"
BRIEF = "P_c"
PATTERN = "for call in tool_calls: act(call); mark_processed()  # no call -> nothing to do"


def handle(item, model, cases):
    response = model.complete(build_prompt(item))
    for call in response.tool_calls:
        if call.name != "classify":
            continue
        verdict = call.arguments()["verdict"]
        if verdict == "malicious":
            cases.block(item, severity=item.severity)
        elif verdict == "benign":
            cases.accept(item)
    cases.mark_processed(item, note="agent turn complete")
