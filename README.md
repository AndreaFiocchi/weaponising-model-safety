# Weaponising Model Safety: Steering LLM Decision Harnesses

Reproducible proof-of-concept for the paper of the same name
([`paper/weaponising-model-safety.md`](paper/weaponising-model-safety.md)).

LLM-based decision agents (phishing triage, SOC alert triage, content
moderation, CI security gates, transaction screening) send untrusted input to a
model, ask for a classification, and branch on the answer. When the input trips
the provider's safety layer the model returns a refusal rather than a verdict,
and many harnesses map that absence to their permissive default: deliver,
approve, close. The attacker does not fool the model; they stop it from
answering. This repository models the classifier boundary and the harness so the
effect can be measured directly.

## What is here

The model boundary is mocked: the independent variable is harness code, so a
real model call would only add noise. (The paper reports one live observation
separately; it is not reproduced here.)

The proof-of-concept lives in `poc/`, the write-up in `paper/`.

- `poc/engine/` — classifier states (`states.py`), a mock model boundary
  (`model.py`), a mock downstream system (`cases.py`), the outcome oracle
  (`landings.py`), 14 handler patterns (`handlers/`, `h13` is the DoS baseline
  and `h14` the fail-closed fix), plus the provider-normalisation
  (`providers.py`) and before/after (`history.py`) demonstrations.
- `poc/matrix/` — runs every handler against every state and prints the landing
  matrix with a per-handler summary.
- `poc/domains/` — a threat-model table across domains (`mapping.toml`) and a
  worked phishing-triage example (`phishing_triage.py`).
- `poc/tests/` — control, fix, DoS-baseline and decision-flip assertions.
- `paper/` — the write-up.

## Run

Python 3.11+, standard library only. Run from the `poc/` directory:

```
cd poc
python -m matrix.run              # landing matrix -> results/matrix.md, results/matrix.csv
python -m domains.phishing_triage # worked example: vulnerable vs fixed mail gateway
python -m domains.render          # domain mapping table
python -m engine.providers        # provider-normalisation leak demonstration
python -m engine.history          # same harness across refusal eras
python -m unittest -v             # test suite
```

## Headline result

Every handler classifies a clean verdict correctly (28/28 controls). Across 14
handlers and 9 non-verdict states (126 cases), 73% of outcomes are fail-open
(85% excluding the two baselines); 12 of 14 handlers fail open on at least one
state. The fix (`poc/engine/handlers/h14_fail_closed.py`) routes any non-verdict to
human review and lands safe on every non-verdict state.

## Scope

Defensive research. The model boundary is mocked; no triggering payloads are
included. See the paper for the threat model, the not-denial-of-service and
not-prompt-injection boundaries, and the responsible-testing note.

## License

MIT, see [`LICENSE`](LICENSE).
