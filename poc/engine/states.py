"""Model-side states: what a classification call can hand back to the harness."""
from enum import Enum


class ClassifierState(Enum):
    VERDICT_MALICIOUS = "S1"
    VERDICT_BENIGN = "S2"
    REFUSAL_STOP = "S3a"
    REFUSAL_TEXT = "S3b"
    REFUSAL_EXCEPTION = "S3c"
    PARTIAL_BENIGN = "S4a"
    PARTIAL_MALICIOUS = "S4b"
    PARTIAL_GARBAGE = "S4c"
    MALFORMED_EMPTY = "S5a"
    MALFORMED_LABEL = "S5b"
    TRANSPORT_ERROR = "S6"

    @property
    def code(self) -> str:
        return self.value


DESCRIPTIONS = {
    ClassifierState.VERDICT_MALICIOUS: "clean completion, valid verdict 'malicious' (control)",
    ClassifierState.VERDICT_BENIGN: "clean completion, valid verdict 'benign' (control)",
    ClassifierState.REFUSAL_STOP: "hard safety stop: refusal stop reason, no content",
    ClassifierState.REFUSAL_TEXT: "soft refusal: refusal prose with a normal stop, no verdict",
    ClassifierState.REFUSAL_EXCEPTION: "safety block surfaced as an exception / HTTP error",
    ClassifierState.PARTIAL_BENIGN: "verdict 'benign' emitted, then cut by a refusal mid-output",
    ClassifierState.PARTIAL_MALICIOUS: "verdict 'malicious' emitted, then cut by a refusal mid-output",
    ClassifierState.PARTIAL_GARBAGE: "output cut by a refusal before any verdict was emitted",
    ClassifierState.MALFORMED_EMPTY: "normal stop, empty content",
    ClassifierState.MALFORMED_LABEL: "normal stop, verdict outside the schema enum",
    ClassifierState.TRANSPORT_ERROR: "plain transport error / timeout (control, not a refusal)",
}

CONTROLS = (ClassifierState.VERDICT_MALICIOUS, ClassifierState.VERDICT_BENIGN)
NON_VERDICT = tuple(s for s in ClassifierState if s not in CONTROLS)
REFUSALS = tuple(s for s in NON_VERDICT if s.code.startswith(("S3", "S4")))
