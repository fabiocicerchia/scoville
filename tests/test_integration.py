"""--introspect against a real `docker` process instead of a patched _docker.

test_scoville.py fakes _docker in-process. Here a stand-in `docker` executable
sits on PATH, so shutil.which, the subprocess argv, the exit status and the
inspect output scoville parses all cross a real process boundary. The stand-in
logs every argv it gets, which is how the read-only guardrail is checked.
"""

import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from scoville import Result, analyze, main

DOCKER = """#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
case "$1 $2" in
  "image inspect") [ -n "{image}" ] && printf '%s\\n' '{image}' && exit 0 ;;
  "inspect --format") [ -n "{container}" ] && printf '%s\\n' '{container}' && exit 0 ;;
esac
echo "Error: No such object" >&2
exit 1
"""
IMAGE_FMT = "{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{.Config.User}}|{{.Id}}"

Docker = Callable[..., Path]


@pytest.fixture
def docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Docker:
    """Install a `docker` on PATH answering with the given inspect lines; return its argv log."""
    log = tmp_path / "docker.log"

    def install(image: str = "", container: str = "") -> Path:
        exe = tmp_path / "bin" / "docker"
        exe.parent.mkdir(exist_ok=True)
        exe.write_text(DOCKER.format(log=log, image=image, container=container), encoding="utf-8")
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("PATH", f"{exe.parent}{os.pathsep}{os.environ.get('PATH', '')}")
        return log

    return install


def calls(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def worst(cmd: str) -> Result:
    return max(analyze(cmd, introspect=True), key=lambda r: r["score"])


def test_image_entrypoint_is_resolved_through_docker(docker: Docker) -> None:
    log = docker(image='["/bin/sh","-c","rm -rf /data"]|null||sha256:abc')
    r = worst("docker run acme/cleaner:1.0")
    assert r["level"] == "critical"
    assert any("resolved entrypoint" in f["why"] for f in r["factors"])
    assert any("runs as root" in f["why"] for f in r["factors"])
    assert set(calls(log)) == {f"image inspect --format {IMAGE_FMT} acme/cleaner:1.0"}


def test_container_payload_is_resolved_through_docker(docker: Docker) -> None:
    log = docker(container='null|["sleep","infinity"]|app|acme/web:2')
    r = worst("docker start web")
    assert not any("cannot inspect" in f["why"] for f in r["factors"])
    assert calls(log)
    assert all(c.startswith("inspect --format ") and c.endswith(" web") for c in calls(log))


def test_unknown_image_is_reported_and_never_pulled(docker: Docker) -> None:
    log = docker()
    r = worst("docker run acme/missing:9")
    assert any("cannot inspect image" in f["why"] for f in r["factors"])
    assert r["level"] == "medium"
    assert calls(log)
    assert all(c.startswith("image inspect ") for c in calls(log))


def test_cli_introspect_gates_on_the_resolved_entrypoint(docker: Docker, capsys: pytest.CaptureFixture[str]) -> None:
    docker(image='["/bin/sh","-c","rm -rf /"]|null|root|sha256:abc')
    assert main(["docker run acme/cleaner:1.0", "--introspect", "--fail-on", "high", "--no-config", "--quiet"]) == 1
    assert "docker run acme/cleaner:1.0" in capsys.readouterr().out
