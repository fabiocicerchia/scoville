"""The docs, held to what the tool actually prints.

Every ```console example in docs/ that scoville can reproduce without a
docker daemon, a cluster or a wrapper script on disk is re-run here, and each
verdict line the doc shows (band, score, scope, reversibility) and every
`scoville:` message has to appear in the real output. The band table in docs/scoring.md is checked against
band(). A rule change that moves a documented example fails here, not in a
reader's terminal.
"""

import re
import shlex
from pathlib import Path

import pytest

from scoville import band, main

DOCS = Path(__file__).parent.parent / "docs"
# A verdict line (`HIGH  60/100  ·  scope: …`) or one of the tool's own messages.
VERDICT = re.compile(r"\d+/100  ·  scope: |^scoville: ")


def examples() -> list[tuple[str, list[str], list[str]]]:
    """(doc, argv, verdict lines) for each `$ scoville` invocation in a console block."""
    found = []
    for doc in sorted(DOCS.glob("*.md")):
        for block in re.findall(r"```console\n(.*?)```", doc.read_text(), re.S):
            for run in re.split(r"^\$ ", block, flags=re.M)[1:]:
                line, *output = run.splitlines()
                argv = shlex.split(line, comments=True)[1:]
                if "--introspect" in argv:
                    continue  # needs docker / kubectl / the wrapper script: see test_integration.py
                verdicts = [o.split() for o in output if VERDICT.search(o)]
                found.append((f"{doc.name}: {line}", argv, verdicts))
    return found


@pytest.mark.parametrize(("doc", "argv", "verdicts"), examples(), ids=lambda v: v if isinstance(v, str) else "")
def test_console_example_matches_output(
    doc: str, argv: list[str], verdicts: list[list[str]], capsys: pytest.CaptureFixture[str]
) -> None:
    main([*argv, "--no-config"])
    out, err = capsys.readouterr()
    printed = [line.split() for line in (out + err).splitlines()]
    for verdict in verdicts:
        assert verdict in printed, f"{doc}: documented `{' '.join(verdict)}` is not what scoville prints"


def test_console_examples_are_collected() -> None:
    """Guard the parser itself: an empty list would pass the test above vacuously."""
    docs = {doc.split(":")[0] for doc, _, verdicts in examples() if verdicts}
    assert {"architecture.md", "rules.md", "scoring.md"} <= docs


def test_band_table_matches_band() -> None:
    """docs/scoring.md: each `| band | lo–hi |` row is exactly the range band() gives that name."""
    rows = re.findall(r"^\| `(\w+)`\s*\| (\d+)–(\d+)\s*\|", (DOCS / "scoring.md").read_text(), re.M)
    assert [name for name, _, _ in rows] == ["safe", "low", "medium", "high", "critical"]
    for name, lo, hi in rows:
        assert band(int(lo)) == band(int(hi)) == name
        assert int(lo) == 0 or band(int(lo) - 1) != name
