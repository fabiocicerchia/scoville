"""Commands that carry another command: docker, ssh, sudo, and friends."""

from __future__ import annotations

import re

from .parsing import tokenize
from .rules import SHELLS

# ----------------------------------------------------- carriers / payload ---

DOCKER_VALUE_FLAGS = {
    "-e",
    "--env",
    "-v",
    "--volume",
    "--mount",
    "-u",
    "--user",
    "-w",
    "--workdir",
    "--name",
    "--entrypoint",
    "-p",
    "--publish",
    "--network",
    "--net",
    "-l",
    "--label",
    "--memory",
    "-m",
    "--cpus",
    "--restart",
    "--add-host",
    "--device",
    "--tmpfs",
    "--health-cmd",
    "--env-file",
    "--log-driver",
    "--platform",
    "--pull",
    "--cap-add",
    "--cap-drop",
    "--security-opt",
}
SSH_VALUE_FLAGS = {
    "-i",
    "-p",
    "-o",
    "-l",
    "-L",
    "-R",
    "-D",
    "-F",
    "-J",
    "-b",
    "-c",
    "-E",
    "-m",
    "-w",
    "-S",
    "-W",
}


def _skip_flags(tokens: list[str], value_flags: set[str]) -> int:
    """Index of the first non-flag token.

    `value_flags` are the flags that swallow the next token as their value,
    so `docker exec -u root ctr sh` does not mistake `root` for the payload.
    """
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "--":
            return i + 1
        if t.startswith("-"):
            if "=" in t:
                i += 1
            elif t in value_flags:
                i += 2
            else:
                i += 1
            continue
        return i
    return i


def carried_command(  # noqa: PLR0911,PLR0912 — one arm per wrapper this understands
    binary: str, args: list[str]
) -> tuple[list[str] | None, str | None, str | None]:
    """Return (payload_tokens, context, target) for commands that carry another.

    context drives how the payload's score is folded in; target is the
    container/image/host the payload lands on.
    """
    if not args:
        return None, None, None
    sub = args[0]

    if binary in ("docker", "podman", "nerdctl"):
        rest = args[1:]
        if sub in ("compose",) and rest:
            sub, rest = rest[0], rest[1:]
        if sub in ("exec", "run", "create"):
            j = _skip_flags(rest, DOCKER_VALUE_FLAGS)
            if j < len(rest):
                target = rest[j]
                payload = rest[j + 1 :]
                ctx = "container" if sub == "exec" else "image"
                return (payload or None), ctx, target
        if sub == "start" and len(rest) > 0:
            return None, "container", rest[-1]
        return None, None, None

    if binary in ("kubectl", "oc") and sub in ("exec", "run", "debug"):
        if "--" in args:
            k = args.index("--")
            target = next((a for a in args[1:k] if not a.startswith("-")), None)
            return (args[k + 1 :] or None), "pod", target
        return None, "pod", None

    if binary in ("ssh", "mosh"):
        j = _skip_flags(args, SSH_VALUE_FLAGS)
        if j < len(args):
            return (args[j + 1 :] or None), "remote", args[j]
        return None, "remote", None

    if binary in SHELLS and "-c" in args:
        k = args.index("-c")
        if k + 1 < len(args):
            return tokenize(args[k + 1]), "shell", None

    if binary in ("ansible", "ansible-playbook") and "-a" in args:
        k = args.index("-a")
        if k + 1 < len(args):
            inner = re.sub(r"^\s*(cmd|_raw_params)=", "", args[k + 1])
            host = args[0] if not args[0].startswith("-") else "inventory"
            return tokenize(inner), "fleet", host

    if binary == "find":
        for flag in ("-exec", "-execdir", "-ok"):
            if flag in args:
                k = args.index(flag)
                payload = [a for a in args[k + 1 :] if a not in ("{}", ";", "\\;", "+")]
                return (payload or None), "per-file", None
        if "-delete" in args:
            return ["rm"], "per-file", None

    return None, None, None


# context -> (score weight, scope floor, note)
CONTEXTS = {
    "container": (
        0.85,
        "container",
        "runs inside the container: its filesystem, its mounts, its credentials",
    ),
    "image": (0.85, "container", "runs in a fresh container from this image"),
    "pod": (0.85, "cluster", "runs inside the pod, with the pod's service account"),
    "remote": (1.0, "host", "runs on the remote host, where you cannot see the blast"),
    "shell": (1.0, "host", "runs in a subshell"),
    "fleet": (1.2, "cluster", "runs on every host matched by the inventory pattern, in parallel"),
    "per-file": (
        1.15,
        "directory",
        "runs once per matched file: the match set is the blast radius",
    ),
}
