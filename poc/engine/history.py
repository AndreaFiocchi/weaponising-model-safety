"""Before/after: the same reluctant classification across three eras, harness held fixed.

The locus of responsibility moved. Prompt injection is a model-layer failure
(the model's judgment); refusal mishandling is a code-layer failure (a return
value the harness mis-branches). This demo shows the handoff by holding the
harness constant and varying only how the provider delivers a reluctant model's
response over time:

  ERA 1  cautious-comply    model is reluctant but still emits a verdict,
                            skewed conservative -> structurally S1 (verdict
                            present, normal stop).  *Hypothesis* about past
                            behaviour; shown as the fail-closed-capable case.
  ERA 2  prose refusal      model refuses in prose, normal stop, no verdict
                            -> S3b. Already a fail-open path, but the model's
                            own probabilistic choice, not attacker-fired.
  ERA 3  hard safety stop   provider guardrail kills generation mid-token
                            -> S3a. Deterministic, attacker-operable, no verdict.

Read it as: ERA 1 is where a verdict still existed to fail closed on; ERA 3 is
today's deterministic trigger. ERA 2 shows the honest caveat — non-verdicts are
not new, but they used to be the model's call, not an attacker's.

    python -m engine.history
"""
from engine.agent import run
from engine.handlers import HANDLERS, DOS_BASELINE, REFERENCE_FIX
from engine.landings import Category
from engine.states import ClassifierState as S

# The reluctant malicious item, one per era.
from matrix.run import MALICIOUS_ITEM

ERAS = (
    ("ERA1 cautious verdict", S.VERDICT_MALICIOUS),
    ("ERA2 prose refusal", S.REFUSAL_TEXT),
    ("ERA3 hard stop", S.REFUSAL_STOP),
)

MARK = {Category.UNSAFE: "UNSAFE", Category.DOS: "DOS", Category.SAFE: "ok"}


def main():
    print(__doc__.split("\n\n")[0])
    print("\nSame malicious item, same harness; only the era's delivery changes.\n")
    header = f"{'handler':<32}" + "".join(f"{name:<24}" for name, _ in ERAS)
    print(header)
    print("-" * len(header))
    flipped = []
    for h in HANDLERS:
        cells, landings = "", {}
        for _, state in ERAS:
            r = run(h, state, MALICIOUS_ITEM)
            landings[state] = r.landing
            cells += f"{r.landing.label + ' [' + MARK[r.landing.category] + ']':<24}"
        print(f"{h.ID + ' ' + h.NAME:<32}{cells}")
        era1, era3 = landings[S.VERDICT_MALICIOUS], landings[S.REFUSAL_STOP]
        if era1.category is Category.SAFE and era3.category is Category.UNSAFE:
            flipped.append(h.ID)

    print()
    print(f"Handlers safe in ERA1 (verdict present) but UNSAFE in ERA3 (hard stop): "
          f"{', '.join(flipped)}")
    print(f"  ({len(flipped)}/{len(HANDLERS)} handlers; "
          f"{DOS_BASELINE.ID} halts loudly, {REFERENCE_FIX.ID} is the fix.)")
    print("\nThe harness never changed. A model-layer safety upgrade (ERA1->ERA3)")
    print("turned a present-and-conservative verdict into a null the code fails open on.")
    print("This is the locus shift: model-responsibility (PI) -> code-responsibility (refusal handling).")


if __name__ == "__main__":
    main()
