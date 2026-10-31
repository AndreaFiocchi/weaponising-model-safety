"""Free-text output, substring match. Anything not saying "malicious" is delivered."""
from ..model import build_prompt

ID = "H01"
NAME = "substring_match"
BRIEF = "P_b"
PATTERN = 'if "malicious" in text: block else accept'


def handle(item, model, cases):
    response = model.complete(build_prompt(item))
    if "malicious" in response.text.lower():
        cases.block(item, severity=item.severity)
    else:
        cases.accept(item)
