"""Asking the local docker daemon what an image would actually do."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from typing import Any

from .scales import Entry

# ---------------------------------------------------------- introspection ---


def _docker(args: list[str], timeout: float = 5) -> str | None:
    """Run one read-only `docker` subcommand and return its stdout, or None.

    Nothing is ever executed to score it: this only ever inspects. A missing
    docker, a timeout, a non-zero exit and an OS error all mean the same
    thing to the caller — no answer — so they collapse into None.
    """
    if not shutil.which("docker"):
        return None
    try:
        exe = shutil.which("docker")
        if exe is None:
            return None
        # Read-only inspects, fixed argv, no shell.
        r = subprocess.run(  # noqa: S603
            [exe, *args], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def introspect_target(kind: str, target: str | None) -> Entry | None:
    """Read-only lookup of what a container/image actually runs.

    Never pulls, never starts anything: if the image is not local, say so.
    """
    if not target or target.startswith("-"):
        return None
    if not shutil.which("docker"):
        return {"resolved": False, "note": "no docker CLI here to resolve it with"}
    if kind == "container":
        fmt = "{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{.Config.User}}|{{.Config.Image}}"
        out = _docker(["inspect", "--format", fmt, target])
        if not out:
            return {
                "resolved": False,
                "note": f"cannot inspect container {target!r} — not running here, or no docker daemon",
            }
    else:
        out = _docker(
            [
                "image",
                "inspect",
                "--format",
                "{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{.Config.User}}|{{.Id}}",
                target,
            ]
        )
        if not out:
            return {
                "resolved": False,
                "note": f"cannot inspect image {target!r} — not pulled here, or no docker "
                f"daemon; scoville never pulls to find out",
            }
    ep, cmd, user, ref = ([*out.split("|", 3), "", "", "", ""])[:4]

    def parse(v: str) -> Any:
        try:
            return json.loads(v) or []
        except (ValueError, TypeError):
            return []

    entry = parse(ep) + parse(cmd)
    return {
        "resolved": True,
        "entrypoint": entry,
        "user": user or "root",
        "ref": ref,
        "note": "entrypoint " + (shlex.join(entry) if entry else "<none>"),
    }
