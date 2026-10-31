"""Run one handler against one item under one model state, and judge the result."""
from dataclasses import dataclass
from types import ModuleType

from .cases import CaseRecord, CaseSystem, Item
from .landings import Landing, oracle
from .model import MockModel
from .states import ClassifierState


@dataclass(frozen=True)
class Run:
    handler: str
    state: ClassifierState
    landing: Landing
    record: CaseRecord | None
    calls: int
    error: str | None


def run(handler: ModuleType, state: ClassifierState, item: Item) -> Run:
    model = MockModel(state)
    cases = CaseSystem()
    error = None
    try:
        handler.handle(item, model, cases)
    except Exception as e:  # an unhandled error halts the pipeline
        error = f"{type(e).__name__}: {e}"
    landing = oracle(item, cases.get(item), halted=error is not None)
    return Run(handler.ID, state, landing, cases.get(item), model.calls, error)
