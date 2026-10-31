# Weaponising Model Safety: Steering LLM Decision Harnesses

Andrea Fiocchi,
Hoxey

October 2026

Code and data: https://github.com/AndreaFiocchi/weaponising-model-safety

## Abstract

LLM-based decision agents (phishing triage, SOC alert triage, content
moderation, CI security gates, transaction screening) send untrusted input to a
model, ask for a classification, and branch on the answer. Providers now enforce
safety policy with hard stops: generation is terminated and the caller receives
a refusal rather than a verdict. We show that this refusal is an
attacker-reachable control-flow input. When an attacker places content in front
of the classifier that trips the provider's safety layer, the call returns no
verdict, and many harnesses map that absence to their permissive default:
deliver, approve, close. The attacker does not fool the model; they stop it from
answering. We test 14 common handling patterns. All 14 classify a malicious item
correctly when given a clean verdict, and 12 of them then fail open on at least
one non-verdict state; 73% of outcomes across all patterns and non-verdict
states are fail-open. A live probe confirms that the stop happens before any
output is produced, that structured output is not exempt, and that the harness
reports the refusal in an envelope marked `subtype: "success"`. The fix is a few
lines of code. The mechanism is old, the trigger is newer than the code it
breaks, and, unlike prompt injection, it becomes more reliable as models get
safer.

## 1. The problem

Using a model as a classifier inside an automated pipeline is routine: an email
gateway asks whether a message is phishing, a SOC platform whether an alert is a
true positive, a moderation system whether a post violates policy. The
surrounding code, which we call the harness, treats the model as a function that
returns a label and acts on it.

That function has a return value the harness often does not handle. When input
trips the provider's safety layer, the model returns a refusal instead of a
label, and in the case we observed it returns that refusal before generating a
single token. The harness was waiting for `malicious` or `benign` and receives
neither. What happens next is whatever default the developer wrote for the "no
usable answer" case, and that default is frequently the permissive branch,
because it was written with outages and malformed output in mind rather than
adversaries.

This is a decision-steering primitive. The capability it requires, getting text
in front of the classifier, is not a special foothold; it is the classifier's
whole purpose. A detection pipeline exists to read content it does not control,
so everyone it is meant to screen already has the access the attack needs.
Within that ordinary operation an attacker can disable the classifier for a
chosen item on demand. In a phishing filter, a message malicious enough to trip
the safety layer is exactly the message that gets delivered unscanned.

Mechanically it is a mishandled `if`, and that is the point rather than a
weakness of the finding. The antipattern is old, in the family of unchecked
return values and fail-open authentication, and Saltzer and Schroeder named the
remedy in 1975 [1]. What is new is the trigger: a near-deterministic,
attacker-fireable, provider-side stop that reaches the fail-open branch in a
class of system where that branch is now everywhere and rarely tested. A refusal
is not an absence of information, but it is also not a verdict. It tells you only
that the provider's safety layer fired, which tracks whether the input touches a
topic the model is trained to avoid rather than whether the input is malicious in
the pipeline's sense. The two are largely independent, so a refusal is an
unreliable proxy for the question the pipeline actually asks.

## 2. Evaluation

**Setup.** Mocking the model boundary is the correct method here, not a
shortcut. The independent variable is the harness, so a real model call would
only add noise to the one thing we measure. The objection that "you mocked the
model" misreads the target: the question is what deterministic code does when a
refusal arrives, and a mock gives perfect control of the model-side state with
no confounds. We model the return value as eleven states: two controls (a clean
`malicious` and a clean `benign` verdict) and nine non-verdict states that cover
the refusal shapes (a hard stop with no content; a soft prose refusal; a refusal
raised as an exception; a partial verdict cut mid-output, in three variants; an
empty response; an out-of-enum label), plus a plain transport error as a further
control that separates a harness mishandling refusals specifically from one that
mishandles every error. We implement 14 handling patterns drawn from common
integration styles (substring match; JSON parsing in a broad `try/except`;
lenient regex; a risk-score threshold; enum lookup with a default;
retry-then-default; a streaming consumer that acts on the first label; an agent
loop that marks the turn complete; escalate-on-positive-only; a batch worker with
a catch-all; an ensemble that treats a refusal as abstention; an "unknown as
medium" scorer), plus two baselines: one that validates strictly and halts (the
DoS baseline) and one fail-closed reference (the fix). An oracle reads the final
state of a mock downstream system together with ground truth and labels each
outcome SAFE, UNSAFE (steered into a permissive or dropped state), or DOS (halted
loudly). It never reads the handler's own report.

**Results.** Every handler classifies both controls correctly (28 of 28), so the
failures are genuine flips rather than broken handlers. Across 14 handlers and 9
non-verdict states (126 cases), 92 outcomes are UNSAFE (73%), 22 are DOS (17%),
and 12 are SAFE (10%). Excluding the two baselines, 92 of 108 cases (85%) fail
open. 12 of the 14 handlers fail open on at least one state; the only two that
never do are the halt baseline and the fix. Seven fail open on every non-verdict
state, so for them the delivery shape does not matter.

| Handler | Fail-open (/9) | Landing | Live S3a |
|-----------------------------------|------------|-------------------|------------|
| H01 substring_match | 6 | resolved_benign | UNSAFE |
| H02 json_swallow_default | 9 | resolved_benign | UNSAFE |
| H03 regex_extract | 6 | resolved_benign | UNSAFE |
| H04 score_threshold | 9 | resolved_benign | UNSAFE |
| H05 enum_get_default | 7 | resolved_benign | UNSAFE |
| H06 retry_then_default | 9 | resolved_benign | UNSAFE |
| H07 stream_first_label | 6 | resolved_benign | UNSAFE |
| H08 agent_turn_complete | 4 | counted_success | UNSAFE |
| H09 escalate_on_positive_only | 9 | resolved_benign | UNSAFE |
| H10 pipeline_catch_all | 9 | counted_success | UNSAFE |
| H11 ensemble_abstain | 9 | resolved_benign | UNSAFE |
| H12 unknown_as_medium | 9 | routed_away | UNSAFE |
| H13 loud_halt (baseline) | 0 | none (halts) | DOS |
| H14 fail_closed (fix) | 0 | none (held) | SAFE |

The handler names describe the patterns, which §2 lists in full. Landings:
`resolved_benign` means actioned as cleared (delivered, approved, or closed);
`counted_success` means marked processed but never scanned; `routed_away` means
sent to an automatic queue instead of a human. The last column is the state we
reproduced live, a hard refusal with no content. Two cuts matter:

- The state we observed live, a hard stop with no content, fails open in 12 of
  14 handlers (86%). It is the common case, not a corner case.
- Refusals fail open more often than ordinary errors: 73% over the refusal
  states against 50% over the transport-error control. Several handlers halt on
  an exception but are steered when the refusal arrives inside a normal response,
  as a stop reason or as text, because that never enters the error path. It goes
  down the parsing path, where the permissive defaults live. A refusal is
  therefore more dangerous than an outage, not merely equal to one.

Instantiated as a mail gateway, the same phishing lure is quarantined without the
trigger and delivered with it under a retry-then-default handler: the same
message, the opposite outcome, selected by the attacker. The fail-closed
reference holds it for an analyst; the halt baseline stops the batch, which is
the DoS outcome and not what we count as the finding.

**Live confirmation.** We probed one input through Claude Code in headless mode,
recording only structural fields and never the input itself. On a hard refusal no
token was generated (`deltas: 0`) and the stop reason was `refusal`. The
classifier stops before it classifies, so there is no partial output to exploit
and the bypass is unconditional. Structured output refused identically to free
text. The result envelope carried `subtype: "success"` together with
`is_error: true`, a `refusal` stop reason, and a non-zero exit code, so a harness
that branches on `subtype == "success"`, or that simply parses the body, reads
the refusal as a clean result. The refusal prose did not match a safety-keyword
regex, so text-sniffing misses it, and the structured fields are the signal. This
is a single observation, an existence proof of the trigger and the envelope
rather than a measured rate, and it is seen through a harness, so a direct API
caller would see the raw stop reason without this envelope. Our live testing used
Claude Opus 5.5. We do not generalise a rate from a single model, but prior work
on guardrail-triggered denial of service [2] reports that a single optimised
payload transfers across eight frontier models (including Claude, GPT, and
Gemini) and across web, desktop, code, and multi-agent deployments, and that
reproducibility across models is the property this primitive depends on.

The trigger itself is cheap, and the cheapness is part of the argument. In
testing, a natural-language question of three to six words is frequently enough
to induce a refusal, with no obfuscation, encoding, or jailbreak structure, just
a plainly phrased question on a sensitive topic. Which topics qualify depends on
provenance: Western models are most sensitive to offensive-cyber and, above all,
biological-risk topics, while models from other jurisdictions are additionally
sensitive to domestically politically sensitive subject matter. We do not print
an example. That is not a safeguard, since anyone who understands the primitive
can reconstruct one in seconds, but printing one would trip the same safety layer
inside this document.

## 3. Not denial of service, not prompt injection

Triggering a guardrail to halt or slow an agent is already known, and it is a
denial-of-service result [2]. If a harness refuses an item loudly and pages a
human, that is correct behaviour and there is no finding. Our claim rests
entirely on the controllable, permissive landing: the attacker selects deliver
over block, not merely stop over go. We report the DOS column separately in §2
precisely to keep that line visible.

Prompt injection persuades the model to make a wrong decision. It lives in the
model, is probabilistic, and weakens as alignment improves. The primitive
described here lives in the harness, is near-deterministic in that the same input
reliably reproduces the refusal, and does not touch the model's decision at all,
because there is no decision: the model is stopped before it classifies.

| | Prompt injection | Refusal mishandling |
|---|---|---|
| Vulnerable layer | the model | the harness |
| Whose fix | the provider (alignment) | the integrator (one branch) |
| Reliability | probabilistic | near-deterministic (reliably reproducible) |
| Trend vs. model quality | weakens as models improve | strengthens as models improve |

The last row is the sharp one. A better-aligned model refuses more reliably,
which makes the trigger more dependable, so a defence against prompt injection,
namely a better model, strengthens this path rather than weakening it. The same
investment moves the two in opposite directions, which is why this is not a
variant of prompt injection.

Recent agent-security work on information-flow control [3] is adjacent but
orthogonal, and the contrast sharpens the point. That work addresses privacy
leakage, its attacks deliberately use no prompt injection, and it locates the
weakness in the model's own disclosure judgment, where the enforcement mechanism
and the attack surface coincide inside the model. Our weakness is the mirror
image: it sits in the deterministic harness code around the model, not in the
model's judgment, which is never exercised because the model is stopped first.

## 4. The fix

Default fail-closed. Any non-verdict, whether a refusal in any shape, an error,
an empty or unparseable response, or an out-of-enum label, is routed to human
review rather than down an automatic branch. The item is preserved, not
auto-resolved in either direction, and surfaced for a person to classify. This is
the correct response precisely because a refusal is not a verdict (§1): the aim
is not to treat it as malicious but to decline to invent a verdict the model
never gave. Our reference handler does this in a few lines and lands SAFE on every
non-verdict state.

Two rules make the fix robust. First, handle refusals in the provider
normalisation layer as an allowlist: accept only a well-formed verdict and treat
everything else as a non-verdict. A denylist of known refusal shapes will miss
the next provider and the next safety category, because the shapes are not
uniform across providers. We show a normaliser written against one provider
leaking another provider's refusal as a parseable-looking empty result. Second,
key on structured fields such as the stop reason, the error flag, and the exit
status, not on prose, which is not reliably detectable.

## 5. Why the branch is missing

If the fix is this cheap, why is the branch absent? Two reasons, both about
timing and locus rather than competence.

The trigger is newer than much of the code it breaks. Provider-side hard stops,
delivered as a dedicated refusal signal, are recent. Earlier a reluctant model
argued in prose and stopped normally, which a parser could not distinguish from
an answer. Code written before hard stops existed branches over a stop vocabulary
with no `refusal` value, and it cannot handle a signal that did not exist when it
was written. We do not overclaim here: a prose refusal was always a possible
non-verdict, and was already a fail-open path. What is new is that the
non-verdict became near-deterministic and attacker-fireable, and that its
delivery moved from a normal completion to a pre- or mid-generation stop that
derails into error handling.

The locus also moved. For most people "LLM security" means prompt injection,
where the model is the vulnerable part and the vendor owns the fix. This
primitive sits in deterministic integration code, where no one is hunting an
LLM-security bug and where it looks like mundane error handling. Framed correctly
it is a fail-open control-flow bug in software the integrator wrote, not a case
of the model misbehaving, so "models are unpredictable" does not apply. The
disguise is the danger.

## 6. Limitations and responsible testing

The 14 handlers are chosen representatives, not a survey. The percentages
describe the primitive across common patterns, not the fraction of deployed
systems that are vulnerable. The live probe is a single observation through one
harness. The reachability of the partial-then-cut states is
architecture-dependent: the state we saw was an input screen, which cannot
produce a partial, whereas a mid-stream output monitor could, so those rows
remain hypotheses. Claims should name the boundary, harness or direct API, since
the two differ in the envelope though not in the underlying stop.

This is a technique paper, not a disclosure against a third party. The work runs
against our own code and a mocked boundary, with one structural probe of our own
harness, and there is no vendor to notify. Anyone reproducing it should test a
real or third-party system only with authorisation. That is not a formality:
triggering the primitive does not always cause a silent misclassification. In our
matrix 17% of handler/state outcomes are a loud halt (12% excluding the
baseline), and against a live pipeline that halt is a denial of service, so a
probe can take the system down rather than steer it. Get permission first.

## 7. Conclusion

A safety refusal is not a verdict. A decision agent that maps a non-verdict to a
permissive default has a near-deterministic, attacker-selectable control-flow
bypass that is trivial to trigger, trivial to fix, and dangerous precisely
because it looks like mundane error handling rather than a security bug. The
mechanism is old, the trigger is new, and, unlike prompt injection, it gets worse
as the models get safer.

## References

[1] J. H. Saltzer and M. D. Schroeder. The Protection of Information in Computer
Systems. Proceedings of the IEEE, 63(9), 1975. (Fail-safe defaults.)

[2] Y. Zhou, X. Wang, P. Ma, Z. Xue, Z. Wang, and S. Wang. From Shield to
Target: Denial-of-Service Attacks on LLM-Based Agent Guardrails.
arXiv:2606.14517, 2026.

[3] M. Shim, R. R. Karim, R. Jakkula, K. Zhou, X. Liu, X. E. Wang, and Z. Li.
Confuse the Model, Control the Flow: Understanding and Mitigating Privacy
Leakage from LLM Agents with Information Flow Control. arXiv:2609.14003, 2026.
