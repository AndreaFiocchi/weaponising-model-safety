"""Model-agnostic setups must handle every provider's refusal shape.

Providers surface the *same* underlying safety refusal differently. A
normalization layer (the "we support any model" adapter) is written and tested
against one provider, so it recognises that provider's refusal shape and
silently drops the others — the refusal leaks through as a parseable or empty
result and the harness falls to its default.

This also carries the historical point: the oldest refusal shape (DELTA) is a
model *arguing in prose* with an ordinary stop reason — what refusals looked
like before provider-side hard stops existed. Code written then had no
`refusal` stop reason to branch on, because none was emitted.

    python -m engine.providers
"""
from dataclasses import dataclass


class HttpError(Exception):
    def __init__(self, status: int, error_type: str):
        super().__init__(f"HTTP {status} {error_type}")
        self.status, self.error_type = status, error_type


@dataclass
class RawResponse:
    """A loosely-typed provider response, the shape an adapter sees."""
    finish_reason: str          # provider-specific vocabulary
    content: str                # text content (may be empty or refusal prose)
    structured: dict | None = None


@dataclass
class Normalized:
    verdict: str | None
    refused: bool
    errored: bool

    @property
    def outcome(self) -> str:
        if self.refused:
            return "refused (signal kept)"
        if self.errored:
            return "errored"
        return f"verdict={self.verdict}"  # None here = silently parsed as no-finding


# --- How each provider delivers the SAME safety refusal on a malicious item ---
# (and, for contrast, a clean malicious verdict). Raise = delivered as an error.

def alpha_refusal() -> RawResponse:      # new-style hard stop (what we observed)
    return RawResponse(finish_reason="refusal", content="")

def beta_refusal() -> RawResponse:       # safety block as an HTTP error
    raise HttpError(400, "content_policy_violation")

def gamma_refusal() -> RawResponse:      # Azure/OpenAI-style content filter flag
    return RawResponse(finish_reason="content_filter", content="")

def delta_refusal() -> RawResponse:      # pre-guardrail: model argues in prose, normal stop
    return RawResponse(finish_reason="stop", content="I'm not able to help analyse this message.")

PROVIDERS = {"alpha": alpha_refusal, "beta": beta_refusal,
             "gamma": gamma_refusal, "delta": delta_refusal}


# --- Normalization strategies a model-agnostic harness might ship ---

def norm_anthropic_only(call):
    """Written against a provider that emits finish_reason='refusal'."""
    try:
        r = call()
    except HttpError:
        return Normalized(None, refused=False, errored=True)
    if r.finish_reason == "refusal":
        return Normalized(None, refused=True, errored=False)
    return Normalized(_verdict(r), refused=False, errored=False)


def norm_openai_only(call):
    """Written against a provider that uses finish_reason='content_filter'."""
    try:
        r = call()
    except HttpError:
        return Normalized(None, refused=False, errored=True)
    if r.finish_reason == "content_filter":
        return Normalized(None, refused=True, errored=False)
    return Normalized(_verdict(r), refused=False, errored=False)


def norm_robust(call):
    """Fail-closed: any non-terminal finish reason, error, or missing verdict is a refusal."""
    try:
        r = call()
    except HttpError:
        return Normalized(None, refused=True, errored=False)   # treat safety HTTP error as refusal signal
    if r.finish_reason not in ("stop", "end_turn", "tool_use"):
        return Normalized(None, refused=True, errored=False)
    verdict = _verdict(r)
    if verdict not in ("malicious", "benign"):
        return Normalized(None, refused=True, errored=False)    # prose-only / empty -> no usable verdict
    return Normalized(verdict, refused=False, errored=False)


def _verdict(r: RawResponse) -> str | None:
    if r.structured and r.structured.get("verdict") in ("malicious", "benign"):
        return r.structured["verdict"]
    return "malicious" if "malicious" in r.content else ("benign" if "benign" in r.content else None)


NORMALIZERS = (("anthropic-only", norm_anthropic_only),
               ("openai-only", norm_openai_only),
               ("robust (fix)", norm_robust))


def main():
    print("Same safety refusal, four providers x three normalizers.")
    print("A refusal that does NOT end 'refused' has leaked: the harness will default it.\n")
    print(f"{'normalizer':<16} | " + " | ".join(f"{p:<22}" for p in PROVIDERS))
    print("-" * 94)
    for nname, nfn in NORMALIZERS:
        cells = []
        for refusal in PROVIDERS.values():
            out = nfn(refusal).outcome
            leaked = "refused" not in out and "errored" not in out
            cells.append(f"{out + (' LEAK' if leaked else ''):<22}")
        print(f"{nname:<16} | " + " | ".join(cells))
    print("\nLEAK = refusal reaches the default branch as a (missing) verdict.")
    print("'errored' may also fail open, depending on how the harness treats errors (see H02/H10).")


if __name__ == "__main__":
    main()
