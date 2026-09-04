#!/usr/bin/env python3
"""Render corpus.tsv as INVENTORY.md. Run via `make inventory`.

Scores and facets come from the engine itself, so the published inventory
cannot disagree with what the tool does — the levels in corpus.tsv are the
assertion, everything else in the table is generated.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scoville import LEVELS, analyze

CORPUS = Path(__file__).parent / "corpus.tsv"

HEADER = """# Command inventory

Every command [scoville](README.md) is calibrated against, grouped by family.
This file is generated from [`tests/corpus.tsv`](tests/corpus.tsv) by
`make inventory`, and the test suite asserts both that each command still
scores at the level shown and that this file is in sync.

Levels: `safe` 0–14 · `low` 15–34 · `medium` 35–59 · `high` 60–84 ·
`critical` 85–100. Scope is the blast radius, and reversibility is how hard
it is to get back.

"""


def rows():
    section = None
    for line in CORPUS.read_text().splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
        elif line and not line.startswith("#"):
            level, _, command = line.partition("\t")
            yield section, level.strip(), command.strip()


def main():
    out = [HEADER]
    counts = dict.fromkeys(LEVELS, 0)
    total = 0
    body, current = [], None
    for section, level, command in rows():
        if section != current:
            current = section
            body.append(f"\n## {section}\n")
            body.append("| Level | Command | Scope | Reversibility |")
            body.append("|---|---|---|---|")
        results = analyze(command)
        worst = max(results, key=lambda r: r["score"])
        counts[level] += 1
        total += 1
        cmd = command.replace("|", "\\|")
        body.append(
            f"| `{level}` {worst['score']} | `{cmd}` | {worst['scope']} "
            f"| {worst['reversibility']} |"
        )

    summary = " · ".join(f"**{n}** {lvl}" for lvl, n in counts.items() if n)
    out.append(f"{total} commands catalogued: {summary}.\n")
    out.extend(body)
    out.append("")
    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main()
