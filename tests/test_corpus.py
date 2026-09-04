"""The inventory, executed.

`corpus.tsv` is the catalogue of commands scoville claims to know and the band
each one should land in. Running it as a test is what keeps the calibration
from drifting: a rule change that moves a command between bands fails here,
and either the rule or the expectation has to be argued for.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from scoville import LEVELS, analyze

CORPUS = Path(__file__).parent / "corpus.tsv"
INVENTORY = Path(__file__).parent.parent / "INVENTORY.md"
RENDER = Path(__file__).parent / "render_inventory.py"


def load():
    rows, section = [], None
    for n, line in enumerate(CORPUS.read_text().splitlines(), 1):
        if line.startswith("## "):
            section = line[3:].strip()
        elif line and not line.startswith("#"):
            expected, _, command = line.partition("\t")
            rows.append((section, expected.strip(), command.strip(), n))
    return rows


ROWS = load()


def test_corpus_is_well_formed():
    assert len(ROWS) > 200, "the inventory is the deliverable; keep it broad"
    for section, expected, command, line in ROWS:
        assert section, f"{CORPUS}:{line}: row outside any ## section"
        assert expected in LEVELS, f"{CORPUS}:{line}: unknown level {expected!r}"
        assert command, f"{CORPUS}:{line}: empty command"


def test_no_duplicate_commands():
    seen = {}
    for _, _, command, line in ROWS:
        assert command not in seen, f"{CORPUS}:{line}: duplicate of line {seen.get(command)}"
        seen[command] = line


def test_every_band_is_represented():
    bands = {expected for _, expected, _, _ in ROWS}
    assert bands == set(LEVELS), f"missing bands: {set(LEVELS) - bands}"


@pytest.mark.parametrize(
    "expected,command",
    [pytest.param(e, c, id=f"{s}:{c}"[:90]) for s, e, c, _ in ROWS],
)
def test_corpus_command_scores_as_catalogued(expected, command):
    results = analyze(command)
    assert results, f"{command!r} produced no result"
    worst = max(results, key=lambda r: r["score"])
    assert worst["level"] == expected, (
        f"{command!r}\n  catalogued: {expected}\n  scored:     "
        f"{worst['level']} ({worst['score']}/100)\n  factors: "
        + "; ".join(f"{f['points']:+d} {f['why']}" for f in worst["factors"])
    )


def test_inventory_markdown_is_in_sync():
    """INVENTORY.md is generated — `make inventory` regenerates it."""
    rendered = subprocess.run(
        [sys.executable, str(RENDER)], capture_output=True, text=True, check=True
    ).stdout
    assert INVENTORY.read_text() == rendered, "INVENTORY.md is stale — run `make inventory`"
