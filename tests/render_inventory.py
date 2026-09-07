#!/usr/bin/env python3
"""Render corpus.tsv as INVENTORY.md. Run via `make inventory`.

Scores and facets come from the engine itself, so the published inventory
cannot disagree with what the tool does — the levels in corpus.tsv are the
assertion, everything else in the table is generated.
"""

import sys
from collections.abc import Iterator
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


def rows() -> Iterator[tuple[str, str, str]]:
    section = ""
    for line in CORPUS.read_text().splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
        elif line and not line.startswith("#"):
            level, _, command = line.partition("\t")
            yield section, level.strip(), command.strip()


HEADINGS = ("Level", "Command", "Scope", "Reversibility")


def table(cells: list[tuple[str, ...]]) -> list[str]:
    """A table markdownlint accepts: every pipe padded to the widest cell.

    MD060's "aligned" style is what the repo's markdownlint config asks for, so
    the generator has to emit it — otherwise regenerating the file reintroduces
    the findings someone just fixed by hand.
    """
    rows_ = [HEADINGS, *cells]
    width = [max(len(r[c]) for r in rows_) for c in range(len(HEADINGS))]
    line = lambda r: "| " + " | ".join(r[c].ljust(width[c]) for c in range(len(HEADINGS))) + " |"  # noqa: E731
    return [line(HEADINGS), "| " + " | ".join("-" * w for w in width) + " |", *(line(r) for r in cells)]


def main() -> None:
    counts: dict[str, int] = dict.fromkeys(LEVELS, 0)
    total = 0
    sections: list[tuple[str, list[tuple[str, ...]]]] = []
    for section, level, command in rows():
        if not sections or sections[-1][0] != section:
            sections.append((section, []))
        results = analyze(command)
        worst = max(results, key=lambda r: int(r["score"]))
        counts[level] += 1
        total += 1
        cmd = command.replace("|", "\\|")
        sections[-1][1].append((f"`{level}` {worst['score']}", f"`{cmd}`", worst["scope"], worst["reversibility"]))

    summary = " · ".join(f"**{n}** {lvl}" for lvl, n in counts.items() if n)
    out = [HEADER.rstrip("\n"), "", f"{total} commands catalogued: {summary}."]
    for section, cells in sections:
        out += ["", f"## {section}", "", *table(cells)]
    sys.stdout.write("\n".join([*out, ""]))


if __name__ == "__main__":
    main()
