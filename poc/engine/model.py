"""Mock model boundary.

Provider-neutral response shape: a list of text chunks, a stop reason and
optional tool calls. The mock exposes the same payload through both the text
and the tool-call interface, so each handler can read it the way its pattern
would in a real integration.
"""
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .states import ClassifierState as S

STOP_END = "end_turn"
STOP_REFUSAL = "refusal"


class ProviderError(Exception):
    pass


class SafetyBlockError(ProviderError):
    pass


class TransportError(ProviderError):
    pass


@dataclass(frozen=True)
class ToolCall:
    name: str
    raw_arguments: str

    def arguments(self) -> dict:
        return json.loads(self.raw_arguments)


@dataclass(frozen=True)
class ModelResponse:
    chunks: tuple[str, ...]
    stop_reason: str
    tool_calls: tuple[ToolCall, ...] = ()

    @property
    def text(self) -> str:
        return "".join(self.chunks)


_MALICIOUS = ('{"verdict": ', '"malicious", ', '"risk": 0.97, ', '"reason": "credential-harvest lure"}')
_BENIGN = ('{"verdict": ', '"benign", ', '"risk": 0.03, ', '"reason": "routine correspondence"}')

# state -> (chunks, stop_reason, also exposed as a classify tool call)
_SCRIPTS = {
    S.VERDICT_MALICIOUS: (_MALICIOUS, STOP_END, True),
    S.VERDICT_BENIGN: (_BENIGN, STOP_END, True),
    S.REFUSAL_STOP: ((), STOP_REFUSAL, False),
    S.REFUSAL_TEXT: (("I can't help with analysing this message.",), STOP_END, False),
    S.PARTIAL_BENIGN: (('{"verdict": ', '"benign", ', '"ri'), STOP_REFUSAL, True),
    S.PARTIAL_MALICIOUS: (('{"verdict": ', '"malicious", ', '"ri'), STOP_REFUSAL, True),
    S.PARTIAL_GARBAGE: (('{"verd',), STOP_REFUSAL, True),
    S.MALFORMED_EMPTY: ((), STOP_END, False),
    S.MALFORMED_LABEL: (('{"verdict": "uncertain", "risk": 0.5}',), STOP_END, True),
}


def build_prompt(item) -> str:
    return (
        "Classify the following message. Respond with JSON "
        '{"verdict": "malicious"|"benign", "risk": 0..1, "reason": str}.\n\n'
        f"<message id={item.id}>\n{item.content}\n</message>"
    )


class Stream:
    def __init__(self, response: ModelResponse):
        self._response = response
        self.stop_reason: str | None = None

    def __iter__(self) -> Iterator[str]:
        yield from self._response.chunks
        self.stop_reason = self._response.stop_reason


class MockModel:
    """Returns a scripted response for a fixed state, or a state chosen per prompt."""

    def __init__(self, state: S | Callable[[str], S]):
        self._state = state
        self.calls = 0

    def _resolve(self, prompt: str) -> ModelResponse:
        self.calls += 1
        state = self._state(prompt) if callable(self._state) else self._state
        if state is S.REFUSAL_EXCEPTION:
            raise SafetyBlockError("request blocked by provider safety filter")
        if state is S.TRANSPORT_ERROR:
            raise TransportError("upstream timeout")
        chunks, stop, as_tool = _SCRIPTS[state]
        tools = (ToolCall("classify", "".join(chunks)),) if as_tool else ()
        return ModelResponse(chunks, stop, tools)

    def complete(self, prompt: str) -> ModelResponse:
        return self._resolve(prompt)

    def stream(self, prompt: str) -> Stream:
        return Stream(self._resolve(prompt))
