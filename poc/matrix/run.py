"""Run every handler against every model state and write the landing matrix.

    python -m matrix.run            # prints markdown, writes results/
"""
import csv
from pathlib import Path

from engine.agent import Run, run
from engine.cases import Item
from engine.handlers import HANDLERS
from engine.landings import Category
from engine.states import DESCRIPTIONS, NON_VERDICT, REFUSALS, ClassifierState as S

RESULTS = Path(__file__).resolve().parent.parent / "results"

MALICIOUS_ITEM = Item(
    id="msg-mal",
    content="[mock phishing message: credential-harvest lure, placeholder only]",
    malicious=True,
    severity=3,
    heuristic_votes=("malicious", "benign"),
)
BENIGN_ITEM = Item(
    id="msg-ok",
    content="[mock routine correspondence, placeholder only]",
    malicious=False,
    severity=1,
    heuristic_votes=("benign", "benign"),
)
COLUMNS = (S.VERDICT_MALICIOUS, S.VERDICT_BENIGN, *NON_VERDICT)


def run_matrix() -> dict[str, dict[S, Run]]:
    matrix = {}
    for handler in HANDLERS:
        row = {}
        for state in COLUMNS:
            item = BENIGN_ITEM if state is S.VERDICT_BENIGN else MALICIOUS_ITEM
            row[state] = run(handler, state, item)
        matrix[handler.ID] = row
    return matrix


def summarize(row: dict[S, Run]) -> dict:
    """Per-handler facts the paper relies on.

    flips:      non-verdict states where a correctly-detected item lands UNSAFE
    spread:     distinct landings across refusal states (S3*, S4*). >1 means the
                landing depends on *how* the refusal arrives: a selectability
                candidate, pending Layer-3 data on which states an attacker can reach
    refusal_specific: the transport-error control lands differently from refusals
    """
    control_ok = row[S.VERDICT_MALICIOUS].landing.category is Category.SAFE
    flips = [s for s in NON_VERDICT if control_ok and row[s].landing.category is Category.UNSAFE]
    refusal_landings = {row[s].landing for s in REFUSALS}
    return {
        "control_ok": control_ok and row[S.VERDICT_BENIGN].landing.category is Category.SAFE,
        "flips": flips,
        "unsafe_landings": sorted({row[s].landing.label for s in flips}),
        "spread": len(refusal_landings),
        "refusal_specific": row[S.TRANSPORT_ERROR].landing not in refusal_landings,
    }


def _cell(r: Run) -> str:
    if r.landing.category is Category.UNSAFE:
        return f"**{r.landing.label}**"
    if r.landing.category is Category.DOS:
        return f"_{r.landing.label}_"
    return r.landing.label


def to_markdown(matrix) -> str:
    by_id = {h.ID: h for h in HANDLERS}
    lines = [
        "## Landing matrix",
        "",
        "Malicious item for every column except S2 (benign item). "
        "**bold** = UNSAFE (decision steered), _italic_ = DOS (loud halt), plain = SAFE.",
        "",
        "| Handler | " + " | ".join(s.code for s in COLUMNS) + " |",
        "|---|" + "---|" * len(COLUMNS),
    ]
    for hid, row in matrix.items():
        lines.append(f"| {hid} {by_id[hid].NAME} | " + " | ".join(_cell(row[s]) for s in COLUMNS) + " |")

    lines += [
        "",
        "## Per-handler summary",
        "",
        "| Handler | Brief | Pattern | Controls OK | Flips | Unsafe landings | Refusal spread | Refusal-specific |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for hid, row in matrix.items():
        h, s = by_id[hid], summarize(row)
        lines.append(
            f"| {hid} {h.NAME} | {h.BRIEF} | `{h.PATTERN}` | {'yes' if s['control_ok'] else 'NO'} "
            f"| {len(s['flips'])}/{len(NON_VERDICT)} | {', '.join(s['unsafe_landings']) or '-'} "
            f"| {s['spread']} | {'yes' if s['refusal_specific'] else 'no'} |"
        )

    lines += ["", "## States", ""]
    lines += [f"- **{s.code}** {DESCRIPTIONS[s]}" for s in COLUMNS]
    return "\n".join(lines) + "\n"


def write_csv(matrix, path: Path):
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["handler", "state", "landing", "category", "calls", "error", "notes"])
        for hid, row in matrix.items():
            for state, r in row.items():
                notes = "; ".join(r.record.notes) if r.record else ""
                writer.writerow([hid, state.code, r.landing.label, r.landing.category.value,
                                 r.calls, r.error or "", notes])


def main():
    matrix = run_matrix()
    RESULTS.mkdir(exist_ok=True)
    markdown = to_markdown(matrix)
    (RESULTS / "matrix.md").write_text(markdown)
    write_csv(matrix, RESULTS / "matrix.csv")
    print(markdown)


if __name__ == "__main__":
    main()
