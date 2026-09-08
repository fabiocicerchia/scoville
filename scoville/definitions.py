"""Shell functions and aliases defined in the text being scored, and the
prefixes naming where a payload came from."""

from __future__ import annotations

import re

from .scales import Definition

# --------------------------------------------------------------- scoring ---

# A destructive verb in command position, for binaries no rule covers.
UNKNOWN_DESTROY = re.compile(
    r"^(?:\S+[\s:]){0,3}(delete|destroy|terminate|purge|wipe|erase|nuke|drop|"
    r"deprovision|teardown)\b"
)

FUNC_DEF = re.compile(r"^[\w.-]+\(\)$")

VAR_PATH = re.compile(r"^\$\{?(\w+)\}?(/.*)?$")

# Factor prefixes that stay visible even at zero points: "the payload is safe"
# is exactly what someone running `docker exec` wants confirmed.
# ---------------------------------------------- definitions in this text ---
#
# A wrapper script, a make target, an npm script and an image ENTRYPOINT are all
# already treated as carriers: the call site is opaque and `--introspect`
# resolves it. Shell functions and aliases are the same problem one level
# closer, and in a deploy script that defines its own helpers they are most of
# the interesting lines.

ALIAS_DEF = re.compile(
    r"(?:^|[;&|]\s*)\s*alias\s+(?P<name>[\w.-]+)="
    r"(?P<val>'[^']*'|\"[^\"]*\"|\S+)",
    re.MULTILINE,
)
# `name() {` and `function name {`, the two spellings bash accepts.
FUNC_HEAD = re.compile(r"(?:^|[;&|]\s*)\s*(?:function\s+)?(?P<name>[\w.-]+)\s*\(\s*\)\s*\{", re.MULTILINE)
FUNC_HEAD_KW = re.compile(r"(?:^|[;&|]\s*)\s*function\s+(?P<name>[\w.-]+)\s*\{", re.MULTILINE)

CARRIER_ALIAS = "resolved alias "
CARRIER_FUNCTION = "resolved function "


def _balanced_body(text: str, brace_at: int) -> str | None:
    """Text between the `{` at `brace_at` and its matching `}`, or None.

    Brace counting, not a regex: a function body containing `${VAR}` or a
    nested `if ... { }` is ordinary, and a non-greedy match to the first `}`
    would truncate the body and quietly under-report what it runs.
    """
    depth = 0
    for i in range(brace_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_at + 1 : i]
    return None


def collect_definitions(text: str) -> list[Definition]:
    """Functions and aliases defined in `text`, each with the offset it goes live.

    Nothing outside `text` is read. Resolving the user's `~/.bashrc` would make
    the same script score differently on two machines, which is a worse answer
    than an unknown command — the score has to be a property of the input.
    """
    defs: list[Definition] = []
    for m in ALIAS_DEF.finditer(text):
        val = m.group("val")
        if val[:1] in "'\"":
            val = val[1:-1]
        defs.append(
            {
                "kind": "alias",
                "name": m.group("name"),
                "value": val,
                "at": m.end(),
                "line": text.count("\n", 0, m.start()) + 1,
            }
        )
    for pattern in (FUNC_HEAD, FUNC_HEAD_KW):
        for m in pattern.finditer(text):
            brace = m.end() - 1
            body = _balanced_body(text, brace)
            if body is None:
                continue  # unterminated; scoring half a body is worse than skipping it
            defs.append(
                {
                    "kind": "function",
                    "name": m.group("name"),
                    "value": body,
                    # Live only after the closing brace: bash reads the
                    # whole definition before the name means anything.
                    "at": brace + len(body) + 2,
                    "line": text.count("\n", 0, m.start()) + 1,
                }
            )
    defs.sort(key=lambda d: d["at"])
    return defs


def definition_at(defs: list[Definition] | None, name: str, offset: int) -> Definition | None:
    """The definition of `name` in scope at `offset`, or None.

    The last definition before the call site wins — that is what redefinition
    means, and an alias shadowing a real binary is exactly the case worth
    catching. A definition *after* the call site is not applied: bash reads top
    to bottom, and scoring it anyway would be a false positive on the common
    layout of helpers at the bottom of a script.
    """
    found: Definition | None = None
    for d in defs or []:
        if d["name"] == name and d["at"] <= offset:
            found = d
    return found


PAYLOAD = "payload "
ENTRYPOINT = "resolved entrypoint "
WRAPPER = "resolved wrapper "
RBAC = "rbac "
