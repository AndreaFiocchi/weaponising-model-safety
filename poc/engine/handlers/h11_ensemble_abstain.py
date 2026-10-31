"""LLM vote plus heuristic votes; a refusal abstains and a tie delivers."""
import json

from ..model import ProviderError, build_prompt

ID = "H11"
NAME = "ensemble_abstain"
BRIEF = "-"
PATTERN = "votes = [llm or abstain, *heuristics]; block only on strict majority"


def _llm_vote(item, model):
    try:
        verdict = json.loads(model.complete(build_prompt(item)).text)["verdict"]
    except (ProviderError, ValueError, KeyError, TypeError):
        return None
    return verdict if verdict in ("malicious", "benign") else None


def handle(item, model, cases):
    votes = [v for v in (_llm_vote(item, model), *item.heuristic_votes) if v is not None]
    if votes.count("malicious") > len(votes) / 2:
        cases.block(item, severity=item.severity)
    else:
        cases.accept(item, note=f"votes {votes}")
