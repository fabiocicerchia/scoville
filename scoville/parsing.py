"""Splitting a command line into the commands it actually runs."""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from pathlib import Path

# --------------------------------------------------------------- parsing ---

OPS = ("&&", "||", ";;", "|&")


def split_commands(  # noqa: PLR0912,PLR0915 — one pass over shell syntax; the branches are the grammar
    text: str,
) -> list[tuple[str, int, str | None]]:
    """Split a shell snippet into (raw_command, offset, preceding_operator).

    Quote-, escape-, comment- and $()-aware. Not a shell grammar: it is a
    splitter good enough to find where one command ends and the next begins.
    """
    # (command, offset, the operator that preceded it -- None for the first).
    out: list[tuple[str, int, str | None]] = []
    buf: list[str] = []
    start, i, n, depth = 0, 0, len(text), 0
    prev_op: str | None = None
    quote: str | None = None

    def flush(op: str | None, end: int) -> None:
        nonlocal buf, start, prev_op
        raw = "".join(buf).strip()
        # drop grouping characters left dangling by the split, never a balanced pair
        for opener, closer in (("(", ")"), ("{", "}")):
            if raw.startswith(opener) and raw.count(opener) > raw.count(closer):
                raw = raw[1:].strip()
            if raw.endswith(closer) and raw.count(closer) > raw.count(opener):
                raw = raw[:-1].strip()
        if raw:
            out.append((raw, start, prev_op))
        buf = []
        prev_op = op
        start = end

    while i < n:
        c = text[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.extend((c, text[i + 1]))
            i += 2
            continue
        if c in "\"'":
            quote = c
            buf.append(c)
            i += 1
            continue
        if c == "#" and (not buf or buf[-1].isspace()):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("$(", i):
            depth += 1
            buf.append("$(")
            i += 2
            continue
        if c == ")" and depth:
            depth -= 1
            buf.append(c)
            i += 1
            continue
        if depth == 0:
            two = text[i : i + 2]
            if two in OPS:
                flush(two, i + 2)
                i += 2
                continue
            if c in ";\n|&":
                flush("\n" if c == "\n" else c, i + 1)
                i += 1
                continue
        buf.append(c)
        i += 1
    flush(None, n)
    return out


SUBSHELL = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def subshell_commands(raw: str, offset: int) -> Iterator[tuple[str, int]]:
    """Command substitutions run *first* and are easy to miss when skimming.

    Yields (command, offset) so a finding can point at where in the line it
    came from.
    """
    for m in SUBSHELL.finditer(raw):
        inner = m.group(1) or m.group(2) or ""
        if inner.strip():
            yield inner.strip(), offset + m.start()


def tokenize(raw: str) -> list[str]:
    """Split a command into tokens, whitespace-splitting when shlex refuses.

    An unbalanced quote is a broken command, not a reason to score nothing:
    the fallback keeps `rm -rf "/opt` visible instead of dropping it.
    """
    try:
        return shlex.split(raw, comments=True)
    except ValueError:
        return raw.split()


ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
WRAPPERS = {
    "sudo",
    "doas",
    "su",
    "env",
    "nohup",
    "time",
    "nice",
    "ionice",
    "xargs",
    "command",
    "builtin",
    "exec",
    "timeout",
    "stdbuf",
    "setsid",
    "unbuffer",
    "strace",
    "ltrace",
    "watch",
    "flock",
    "chrt",
    "taskset",
}
WRAPPER_VALUE_FLAGS = {"-u", "-g", "-n", "-I", "-P", "-L", "-a", "-s", "-p", "--user", "-i"}


def strip_prefix(tokens: list[str]) -> tuple[list[str], bool, list[str]]:
    """Peel env assignments and wrappers to reach the command that matters."""
    i, privileged = 0, False
    wrappers: list[str] = []
    while i < len(tokens):
        t = tokens[i]
        if ENV_ASSIGN.match(t):
            i += 1
            continue
        base = Path(t).name
        if base in WRAPPERS:
            if base in ("sudo", "doas", "su"):
                privileged = True
            wrappers.append(base)
            i += 1
            while i < len(tokens):
                t2 = tokens[i]
                if t2 == "--":
                    i += 1
                    break
                if t2.startswith("-"):
                    takes_value = t2 in WRAPPER_VALUE_FLAGS
                    i += 2 if takes_value and i + 1 < len(tokens) else 1
                    continue
                if base in ("timeout", "nice", "ionice", "chrt") and re.fullmatch(r"[\d.]+[smhd]?", t2):
                    i += 1
                    continue
                if base == "flock" and (t2.startswith("/") or t2.isdigit()):
                    i += 1
                    continue
                if base == "su" and not t2.startswith("-"):
                    i += 1  # target user
                    continue
                break
            continue
        break
    return tokens[i:], privileged, wrappers
