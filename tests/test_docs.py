"""The docs, held to what the tool actually prints.

Every ```console example in docs/ is re-run here — the `--introspect` ones
against a real wrapper script and stand-in `docker` / `kubectl` on PATH — and each
verdict line the doc shows (band, score, scope, reversibility) and every
`scoville:` message has to appear in the real output. The band table in docs/scoring.md is checked against
band(). A rule change that moves a documented example fails here, not in a
reader's terminal.
"""

import os
import re
import shlex
import stat
from pathlib import Path

import pytest

from scoville import band, main

DOCS = Path(__file__).parent.parent / "docs"
# A verdict line (`HIGH  60/100  ·  scope: …`) or one of the tool's own messages.
VERDICT = re.compile(r"\d+/100  ·  scope: |^scoville: ")


def examples(introspect: bool = False) -> list[tuple[str, list[str], list[str]]]:
    """(doc, argv, verdict lines) for each `$ scoville` invocation in a console block."""
    found = []
    for doc in sorted(DOCS.glob("*.md")):
        for block in re.findall(r"```console\n(.*?)```", doc.read_text(), re.S):
            for run in re.split(r"^\$ ", block, flags=re.M)[1:]:
                line, *output = run.splitlines()
                argv = shlex.split(line, comments=True)[1:]
                if ("--introspect" in argv) != introspect:
                    continue  # --introspect needs docker / kubectl / the wrapper script: see test_introspect_*
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


# What each `--introspect` example reads, as the real thing: the wrapper script
# on disk, and `docker` / `kubectl` executables on PATH that answer the
# read-only inspect / can-i calls the way the doc's environment would.
WRAPPER = '#!/bin/sh\nset -eu\n\nBUILD_DIR=${BUILD_DIR:-build}\necho "cleaning $1"\nrm -rf "$BUILD_DIR"/\n'
STAND_INS = {
    "docker": """#!/bin/sh
[ "$1" = image ] && echo '["/bin/sh","-c","rm -rf /data"]|null||sha256:abc' && exit 0
exit 1
""",
    "kubectl": """#!/bin/sh
case "$*" in
  "config current-context") echo prod-readonly ;;
  "auth can-i"*) echo no; exit 1 ;;
esac
""",
}


@pytest.mark.parametrize(
    ("doc", "argv", "verdicts"), examples(introspect=True), ids=lambda v: v if isinstance(v, str) else ""
)
def test_introspect_example_matches_output(
    doc: str,
    argv: list[str],
    verdicts: list[list[str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "foo.sh").write_text(WRAPPER, encoding="utf-8")
    for name, script in STAND_INS.items():
        exe = tmp_path / "bin" / name
        exe.parent.mkdir(exist_ok=True)
        exe.write_text(script, encoding="utf-8")
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.chdir(tmp_path)
    main([*argv, "--no-config"])
    out, err = capsys.readouterr()
    printed = [line.split() for line in (out + err).splitlines()]
    assert verdicts, f"{doc}: no verdict line to check"
    for verdict in verdicts:
        assert verdict in printed, f"{doc}: documented `{' '.join(verdict)}` is not what scoville prints"


def test_introspect_examples_are_collected() -> None:
    assert len(examples(introspect=True)) == 3


def test_band_table_matches_band() -> None:
    """docs/scoring.md: each `| band | lo–hi |` row is exactly the range band() gives that name."""
    rows = re.findall(r"^\| `(\w+)`\s*\| (\d+)–(\d+)\s*\|", (DOCS / "scoring.md").read_text(), re.M)
    assert [name for name, _, _ in rows] == ["safe", "low", "medium", "high", "critical"]
    for name, lo, hi in rows:
        assert band(int(lo)) == band(int(hi)) == name
        assert int(lo) == 0 or band(int(lo) - 1) != name
