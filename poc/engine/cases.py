"""Mock downstream system the harness acts on (mail gateway, SOC queue, ...).

Handlers only record actions here; the oracle judges the final state, so a
handler cannot grade itself.
"""
from dataclasses import dataclass, field
from enum import Enum

HUMAN = "human"
AUTO = "auto"


class Disposition(Enum):
    ACCEPT = "accept"      # deliver / approve / close-as-benign
    BLOCK = "block"        # quarantine / reject
    ESCALATE = "escalate"  # ticket in a review queue
    HOLD = "hold"          # held for a human because no usable verdict


@dataclass(frozen=True)
class Item:
    id: str
    content: str
    malicious: bool          # ground truth
    severity: int            # intake severity, visible to the harness (0-5)
    heuristic_votes: tuple[str, ...] = ("malicious", "benign")


@dataclass
class CaseRecord:
    disposition: Disposition | None = None
    severity: int | None = None
    queue: str | None = None
    processed: bool = False
    notes: list[str] = field(default_factory=list)


class CaseSystem:
    def __init__(self):
        self.records: dict[str, CaseRecord] = {}

    def _record(self, item: Item, note: str) -> CaseRecord:
        record = self.records.setdefault(item.id, CaseRecord())
        record.processed = True
        if note:
            record.notes.append(note)
        return record

    def _set(self, item, disposition, severity, queue, note):
        record = self._record(item, note)
        record.disposition, record.severity, record.queue = disposition, severity, queue

    def accept(self, item: Item, note: str = ""):
        self._set(item, Disposition.ACCEPT, None, None, note)

    def block(self, item: Item, severity: int, note: str = ""):
        self._set(item, Disposition.BLOCK, severity, HUMAN, note)

    def escalate(self, item: Item, severity: int, queue: str = HUMAN, note: str = ""):
        self._set(item, Disposition.ESCALATE, severity, queue, note)

    def hold(self, item: Item, severity: int, reason: str):
        self._set(item, Disposition.HOLD, severity, HUMAN, reason)

    def mark_processed(self, item: Item, note: str = ""):
        self._record(item, note)

    def get(self, item: Item) -> CaseRecord | None:
        return self.records.get(item.id)
