"""The documented journeys, run as a real process.

test_scoville.py calls main() in-process; these spawn the interpreter the way
the `scoville` console script does, so argv, stdin, stdout and the exit status
are the ones a hook or a CI job actually sees.
"""

import json
import subprocess
import sys
from pathlib import Path

EXAMPLE = Path(__file__).parent.parent / "examples" / "basic"
# What the console script generated from `scoville = "scoville:main"` runs.
ENTRY = "import sys; from scoville import main; sys.exit(main())"


def scoville(*args: str, stdin: str | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603 — fixed argv, our own interpreter
        [sys.executable, "-c", ENTRY, *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=cwd,
        check=False,
        timeout=30,
    )


def test_agent_hook_blocks_dangerous_and_passes_safe() -> None:
    """README: `scoville "$COMMAND" --fail-on high --strict --quiet || exit 2`."""
    blocked = scoville("rm -rf /", "--fail-on", "high", "--strict", "--quiet", "--no-config")
    assert blocked.returncode == 1
    assert "rm -rf /" in blocked.stdout

    allowed = scoville("ls -la", "--fail-on", "high", "--strict", "--quiet", "--no-config")
    assert allowed.returncode == 0
    assert allowed.stderr == ""


def test_example_script_gate() -> None:
    """examples/basic: `scoville -f deploy.sh --fail-on high --quiet`."""
    run = scoville("-f", "deploy.sh", "--fail-on", "high", "--quiet", cwd=EXAMPLE)
    assert run.returncode == 1
    assert "kubectl delete ns staging" in run.stdout
    assert "kubectl config current-context" in run.stdout


def test_example_script_json() -> None:
    """examples/basic: `scoville -f deploy.sh --format json` parses and agrees with the gate."""
    run = scoville("-f", "deploy.sh", "--format", "json", cwd=EXAMPLE)
    assert run.returncode == 0
    report = json.loads(run.stdout)
    assert report["overall"]["commands"] == len(report["commands"]) >= 4
    assert report["overall"]["level"] in {"high", "critical"}


def test_stdin_pipe() -> None:
    """README: `cat job.sh | scoville`."""
    run = scoville("--no-config", "--fail-on", "critical", stdin="ls\nrm -rf /\n")
    assert run.returncode == 1
    assert "scoville: 2 commands" in run.stdout


def test_empty_stdin_is_a_usage_error() -> None:
    run = scoville("--no-config", stdin="")
    assert run.returncode == 64
    assert "nothing to analyze" in run.stderr
