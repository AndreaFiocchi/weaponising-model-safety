"""Render mapping.toml as a markdown table.  python -m domains.render"""
import tomllib
from pathlib import Path

COLUMNS = ("name", "trigger_surface", "accept_means", "dangerous_default", "fail_open_landing", "harm")


def render() -> str:
    domains = tomllib.loads((Path(__file__).parent / "mapping.toml").read_text())["domain"]
    lines = ["| " + " | ".join(COLUMNS) + " |", "|---" * len(COLUMNS) + "|"]
    lines += ["| " + " | ".join(d[c] for c in COLUMNS) + " |" for d in domains]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(render())
