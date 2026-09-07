"""scoville — risk posture for shell commands, before you run them.

Risk is not a property of a binary, it is a property of
`binary + flags + target + context`. `rm` is bad, `rm -rf` is worse,
`rm -rf /` is unrecoverable; `aws s3 ls` is free, `aws s3 rb --force` is not.
scoville scores that escalation and shows every factor that contributed.

Commands that carry another command (`docker exec`, `kubectl exec -- `,
`ssh host ...`, `sh -c`, `ansible -a`, `find -exec`) are scored on their
payload, not on the wrapper. Where the payload is hidden behind an image
ENTRYPOINT, `--introspect` resolves it with read-only docker inspects.

  scoville 'rm -rf /'
  scoville -f deploy.sh --format json
  scoville 'kubectl delete ns prod' --fail-on high
"""

import argparse
import difflib
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

from .amplifiers import (
    AMPS,
    CORE_DIRS,
    DAMPENERS,
    DEVICE_TARGET_EXPECTED,
    DRY_RUN_N_BINS,
    PATH_SENSITIVE,
    REGENERABLE,
    SOFTENERS,
    SYSTEM_DIRS,
)
from .catalog import A as A
from .catalog import R as R
from .incidents import INCIDENTS
from .rules import (
    DESTROY_VERBS as DESTROY_VERBS,
)
from .rules import FETCHERS, INTERPRETERS, RESOURCE_CLIS, RULES, SHELLS
from .rules import (
    READ_ONLY as READ_ONLY,
)
from .rules import (
    READ_VERBS as READ_VERBS,
)
from .rules import (
    WRITE_VERBS as WRITE_VERBS,
)
from .scales import BANDS as BANDS
from .scales import LEVELS, Definition, Entry, Factor, FactorTuple, Override, Result, band, harder, widest
from .scales import REVERT as REVERT
from .scales import SCOPES as SCOPES

__version__ = "0.3.0"  # x-release-please-version


def entry_by_id(rid: str) -> tuple[str | None, Entry | None]:
    """Find a rule or amplifier by id. Returns (kind, entry) or (None, None).

    Amplifier ids are printed with a leading `+` by --list-rules, so both
    spellings resolve — a reader copying an id out of that output should not
    have to know which half of the table it came from.
    """
    rid = rid.strip().lstrip("+").upper()
    for r in RULES:
        if r["id"] == rid:
            return "rule", r
    for a in AMPS + SOFTENERS:
        if a["id"] == rid:
            return "amp", a
    return None, None


def rule_ids() -> list[str]:
    """Every id `--why` will answer to."""
    return sorted({r["id"] for r in RULES} | {a["id"] for a in AMPS + SOFTENERS})


def _wrap(text: str, indent: str = "  ", width: int = 78, hang: str = "") -> str:
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent + hang)


def _reachable(entry: Entry, kind: str) -> tuple[list[Entry], list[Entry]]:
    """The amplifiers and softeners that can apply to this rule's binaries.

    Answers "why this band" with the range the rule can actually reach rather
    than with its base alone: a rule at 55 whose binaries carry a +35 amplifier
    is a `critical` waiting for one flag, and that is the part a reader
    disagreeing with a score needs to see.
    """
    if kind != "rule":
        return [], []
    bins, subsumed = entry["bins"], entry["subsumes"]
    # Only the ones named for these binaries. The generic signals apply to
    # every command and listing them under each rule would bury the two or
    # three that are actually about this one.
    amps = [a for a in AMPS if a["bins"] and a["bins"] & bins and a["id"] not in subsumed]
    softs = [a for a in SOFTENERS if a["bins"] and a["bins"] & bins and a["id"] not in subsumed]
    return amps, softs


def _related(entry: Entry) -> tuple[list[Entry], list[Entry]]:
    """Other rules on the same binaries, and the generic ones this beats."""
    same: list[Entry] = []
    beats: list[Entry] = []
    for r in RULES:
        if r["id"] == entry["id"] or not (r["bins"] & entry["bins"]):
            continue
        (beats if r["generic"] and not entry["generic"] else same).append(r)
    return same, beats


def _why_head(kind: str, entry: Entry, width: int) -> list[str]:
    """The identity line: what this is, and the three facts a score reports."""
    if kind == "rule":
        head = (
            f"{entry['id']}  ·  base {entry['base']} ({band(entry['base'])})  ·  "
            f"scope: {entry['scope']}  ·  {entry['revert']}"
        )
    else:
        sign = "softener" if entry["points"] < 0 else "amplifier"
        head = f"+{entry['id']}  ·  {entry['points']:+d} ({sign})"
        if entry["scope"] or entry["revert"]:
            head += f"  ·  scope: {entry['scope'] or '—'}  ·  {entry['revert'] or '—'}"
    return [head, "=" * min(len(head), width), ""]


def _why_matches(kind: str, entry: Entry) -> list[str]:
    """What it matches, and — as importantly — what it does not."""
    out = ["MATCHES"]
    out.append(_wrap(", ".join(sorted(entry["bins"])) if entry["bins"] else "any command"))
    pattern = entry["sub"] if kind == "rule" else entry["pattern"]
    if pattern is not None:
        # Printed unwrapped: a regex broken across lines is not something you
        # can paste back into anything.
        out += ["  …when the arguments match:", f"    {pattern.pattern}"]
    elif kind == "rule":
        out.append(_wrap("…whatever the arguments are — the binary is the whole of it."))
    if kind == "rule" and entry["generic"]:
        out.append(
            _wrap(
                "This is a verb classifier: a floor for CLIs nobody has "
                "enumerated, and any specific rule beats it — including one "
                "that scores lower."
            )
        )
    elif kind == "rule":
        out.append(
            _wrap("Not matched: anything a rule with a higher base claims first. Specificity wins before score does.")
        )
    return [*out, ""]


def _why_incident(entry: Entry) -> list[str]:
    """The prose half, or an honest admission that it has not been written."""
    out = ["INCIDENT CLASS"]
    note = INCIDENTS.get(entry["id"])
    if note:
        return [*out, _wrap(note), ""]
    out.append(_wrap(f"Not written yet. The one-line reason is: {entry['why']}"))
    out.append(
        _wrap(
            "Everything above and below is derived from the rule table, so it is "
            "accurate — but the class of incident this rule exists to prevent has "
            "not been written down. That is a gap, not a judgement that the rule "
            "is uninteresting."
        )
    )
    return [*out, ""]


def _why_band(entry: Entry, kind: str) -> list[str]:
    """Why this band, and what the flags on these binaries can do to it."""
    out = [
        "WHY THIS BAND",
        _wrap(
            f"{entry['base']}/100 on its own, which is `{band(entry['base'])}`. "
            f"Blast radius `{entry['scope']}`; getting back is `{entry['revert']}`."
        ),
    ]
    amps, softs = _reachable(entry, kind)
    if amps:
        worst = max(amps, key=lambda x: x["points"])
        reached = min(100, entry["base"] + worst["points"])
        out.append("")
        out.append(
            _wrap(
                f"Amplifiers registered for these binaries — each applies only "
                f"where its own pattern matches. The largest is "
                f"{worst['points']:+d} ({worst['id']}); where it applies, "
                f"{entry['base']} becomes {reached}/`{band(reached)}`."
            )
        )
        out += _why_modifiers(sorted(amps, key=lambda x: -x["points"])[:8])
    if softs:
        out.append("")
        out.append(_wrap("Asking for it carefully scores below asking for it carelessly:"))
        out += _why_modifiers(sorted(softs, key=lambda x: x["points"])[:6])
    out.append("")
    out.append(
        _wrap(
            "The generic signals — `--force`, `-y`, `--purge`, a credential in "
            "argv, disabled TLS or signature verification, `0.0.0.0/0`, a target "
            "that names production — apply on top of any command. "
            "`--list-rules` prints them."
        )
    )
    return [*out, ""]


def _why_modifiers(entries: list[Entry]) -> list[str]:
    return [_wrap(f"{a['points']:+d}  {a['id']}: {a['why']}", indent="    ", hang="     ") for a in entries]


def _why_safer(entry: Entry) -> list[str]:
    """The alternative, or a note that the rule owes one."""
    if entry["advice"]:
        body = entry["advice"]
    elif entry["base"] >= TOP_BAND_BASE:
        body = (
            "No alternative recorded. For a rule at this level that is a gap in the "
            "rule, not a statement that none exists."
        )
    else:
        body = "Nothing to avoid — this is not a destructive rule."
    return ["SAFER", _wrap(body), ""]


def _why_related(entry: Entry) -> list[str]:
    """Neighbours on the same binaries, and the classifiers this one beats."""
    same, beats = _related(entry)
    if not (same or beats):
        return []
    out = ["RELATED"]
    out += [
        _wrap(f"{r['id']} ({r['base']}) — {r['why']}", indent="    ", hang="  ")
        for r in sorted(same, key=lambda x: -x["base"])[:8]
    ]
    out += [_wrap(f"beats {r['id']} ({r['base']}), the verb classifier", indent="    ") for r in beats]
    return [*out, ""]


def why_text(rid: str, width: int = 78) -> str | None:
    """The long form for one rule or amplifier, or None if the id is unknown.

    Assembled from the rule table rather than written out twice: the band, the
    scope, the reversibility and the reachable range are all facts the scorer
    already uses, so this view cannot disagree with the score it explains. Only
    the incident-class paragraph is prose, and it is optional — a rule without
    one says so rather than padding.

    One section per helper, in printed order, so a section can be read or
    changed without the whole view in your head.
    """
    kind, entry = entry_by_id(rid)
    if kind is None or entry is None:
        return None
    out = _why_head(kind, entry, width) + _why_matches(kind, entry) + _why_incident(entry)
    if kind == "rule":
        out += _why_band(entry, kind) + _why_safer(entry) + _why_related(entry)
    out.append(f"  scoville --list-rules   ·   {len(INCIDENTS)} of {len(rule_ids())} ids have an incident note")
    return "\n".join(out).rstrip() + "\n"


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

# ------------------------------------------------------ kubernetes RBAC ---
#
# `kubectl delete ns prod` scores the same whether the current context is
# cluster-admin on production or a read-only token that will be refused. The
# second case is noise, and noise is what makes people stop reading the output.
# scoville knows the command; it does not know the authorisation.
#
# `kubectl auth can-i` is a SelfSubjectAccessReview — a read that asks the API
# server "would you allow this?" and changes nothing. That keeps the "nothing
# is ever executed to score it" contract intact, but it is still a call to a
# live cluster, so it lives behind --introspect with everything else that
# leaves the machine.
#
# THE DIRECTION OF FAILURE IS THE WHOLE DESIGN. A dampener that fires on a bad
# `can-i` result under-reports risk, which is the one kind of wrong answer this
# tool must not give. So: nothing is dampened unless a refusal is POSITIVELY
# established. A timeout, a missing kubeconfig, an unreachable cluster and an
# answer this code cannot parse all mean "no opinion", and no opinion scores
# exactly as it does today.

KUBE_BINS = ("kubectl", "oc", "k")

# Timeout for one `can-i`. Bounded because this runs once per kubectl line, and
# a script full of them must not turn a score into a network wait.
KUBE_TIMEOUT_DEFAULT = 3.0

# Verbs whose kubectl spelling differs from the RBAC verb. Everything else is
# passed through, because the RBAC verb list is open — a CRD can define its own.
KUBE_VERB_ALIASES = {
    "apply": "patch",
    "edit": "patch",
    "set": "patch",
    "annotate": "patch",
    "label": "patch",
    "scale": "patch",
    "rollout": "patch",
    "autoscale": "patch",
    "run": "create",
    "expose": "create",
    "cordon": "patch",
    "drain": "patch",
    "uncordon": "patch",
    "taint": "patch",
    "exec": "create",
    "port-forward": "create",
    "cp": "create",
    "attach": "create",
    "describe": "get",
    "logs": "get",
    "top": "get",
    "wait": "get",
}

# kubectl's own short forms for the resources most worth knowing about. Not a
# complete table and not meant to be: an unrecognised resource is passed to
# `can-i` verbatim, which is the component that actually knows the API surface.
KUBE_RESOURCE_ALIASES = {
    "ns": "namespaces",
    "po": "pods",
    "deploy": "deployments",
    "svc": "services",
    "cm": "configmaps",
    "sts": "statefulsets",
    "ds": "daemonsets",
    "rs": "replicasets",
    "pv": "persistentvolumes",
    "pvc": "persistentvolumeclaims",
    "sa": "serviceaccounts",
    "no": "nodes",
    "ing": "ingresses",
    "crd": "customresourcedefinitions",
    "secret": "secrets",
    "job": "jobs",
    "cj": "cronjobs",
}

# Flags that take a separate value, so the token after them is not a verb or a
# resource. `-n prod` is the one that matters; the rest are here so a long
# command line does not shift the parse by one.
KUBE_VALUE_FLAGS = {
    "-n",
    "--namespace",
    "--context",
    "--cluster",
    "--user",
    "--kubeconfig",
    "-f",
    "--filename",
    "-l",
    "--selector",
    "-o",
    "--output",
    "--server",
    "--token",
    "--as",
    "--as-group",
    "-c",
    "--container",
    "--field-selector",
}


def _kubectl(binary: str, args: list[str], timeout: float) -> str | None:
    """Run one read-only kubectl subcommand and return stdout, or None.

    Same collapse as _docker: a missing binary, a timeout, a non-zero exit and
    an OS error are all "no answer" to the caller, and no answer must never
    become a dampener.
    """
    exe = shutil.which(binary)
    if not exe:
        return None
    try:
        # Read-only `kubectl auth can-i` / `config current-context`, fixed argv.
        r = subprocess.run(  # noqa: S603
            [exe, *args], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    # `can-i` exits 1 for "no" and prints "no", so stdout is read on both exit
    # codes and the caller reads the word, not the status.
    return (r.stdout or "").strip()


def kube_target(args: list[str]) -> tuple[str | None, str | None, str | None]:
    """(verb, resource, namespace) for a kubectl command line, or (None, ...).

    Positional-only: the first two non-flag tokens. Enough for the commands
    worth scoring, and it declines rather than guesses on anything else.
    """
    verb: str | None = None
    resource: str | None = None
    namespace: str | None = None
    positional: list[str] = []
    skip = False
    for i, a in enumerate(args):
        if skip:
            if namespace is None and args[i - 1] in ("-n", "--namespace"):
                namespace = a
            skip = False
            continue
        if a == "--":
            break
        if a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            if k in ("-n", "--namespace"):
                namespace = v
            continue
        if a in KUBE_VALUE_FLAGS:
            skip = True
            continue
        if a.startswith("-"):
            continue
        positional.append(a)
    if positional:
        verb = positional[0]
    if len(positional) > 1:
        # `delete pod/foo` and `delete pods foo` both mean pods.
        resource = positional[1].split("/", 1)[0]
    return verb, resource, namespace


def kube_context(binary: str, timeout: float) -> str | None:
    """The context name `can-i` will be answered by, or None.

    A local kubeconfig read, not a cluster call — but if there is no context
    there is nothing to ask, which is the cheapest way to skip the network.
    """
    out = _kubectl(binary, ["config", "current-context"], timeout)
    return out or None


def kube_can_i(binary: str, verb: str, resource: str, namespace: str | None, timeout: float) -> bool | None:
    """True / False / None for "may this context do that".

    None is not a third state to act on — it is the absence of an answer, and
    every caller treats it as "score exactly as before".
    """
    cmd = ["auth", "can-i", verb, resource]
    if namespace:
        cmd += ["-n", namespace]
    out = _kubectl(binary, cmd, timeout)
    if out is None:
        return None
    first = out.splitlines()[0].strip().lower() if out else ""
    if first.startswith("yes"):
        return True
    if first.startswith("no"):
        return False
    return None


def kube_rbac_factors(binary: str, args: list[str], timeout: float = KUBE_TIMEOUT_DEFAULT) -> list[FactorTuple]:
    """Fold the cluster's own answer in as scoring factors.

    Returns a list of factor tuples. Empty means "nothing to say", which is
    also what every failure returns.
    """
    verb, resource, ns = kube_target(args)
    if not verb or not resource:
        return []
    ctx = kube_context(binary, timeout)
    if not ctx:
        return []
    rbac_verb = KUBE_VERB_ALIASES.get(verb, verb)
    rbac_res = KUBE_RESOURCE_ALIASES.get(resource, resource)
    where = f" in {ns}" if ns else ""

    allowed = kube_can_i(binary, rbac_verb, rbac_res, ns, timeout)
    if allowed is False:
        # The one dampener. Deliberately points rather than a cap: the context
        # is read NOW and the command may run later against a different one,
        # which is why the factor names the context it asked.
        return [
            (
                -30,
                (
                    f"{RBAC}context `{ctx}` cannot {rbac_verb} {rbac_res}{where} — "
                    f"`kubectl auth can-i` says no, so this would be refused as it "
                    f"stands. Scored down, not to zero: the context is read now and "
                    f"the command may run later against another one"
                ),
                None,
                None,
                "RBAC-REFUSED",
            )
        ]
    if allowed is None:
        return [
            (
                0,
                (
                    f"{RBAC}no answer from `kubectl auth can-i {rbac_verb} {rbac_res}"
                    f"{where}` (context `{ctx}`) — scored as if it had not been asked"
                ),
                None,
                None,
                "RBAC-UNKNOWN",
            )
        ]

    # Permitted. Worth a factor only where it changes the reading: being able to
    # do everything, everywhere, is the difference between "this deletes a
    # namespace" and "this deletes a namespace and nothing will stop it".
    admin = kube_can_i(binary, "*", "*", None, timeout)
    if admin is True:
        return [
            (
                10,
                (
                    f"{RBAC}context `{ctx}` is cluster-admin (`can-i '*' '*'` says yes): "
                    f"nothing in the cluster refuses this, and there is no RBAC boundary "
                    f"left to catch a mistake"
                ),
                "cluster",
                None,
                "RBAC-CLUSTER-ADMIN",
            )
        ]
    return [
        (
            0,
            (f"{RBAC}context `{ctx}` may {rbac_verb} {rbac_res}{where} — `kubectl auth can-i` says yes"),
            None,
            None,
            "RBAC-PERMITTED",
        )
    ]


def path_factors(binary: str, args: list[str]) -> list[FactorTuple]:
    """Score the *targets*. This is where rm and `rm /` part ways."""
    out: list[FactorTuple] = []
    for a in args:
        if a.startswith("-") or ENV_ASSIGN.match(a) or "=" in a.split("/", 1)[0]:
            continue
        m = VAR_PATH.match(a)
        if m:
            var, tail = m.group(1), m.group(2) or ""
            expanded = tail or "/"
            if expanded in ("/", "//"):
                out.append(
                    (
                        40,
                        (f"if ${var} is unset or empty this expands to `/` — the classic `rm -rf $DIR/` incident"),
                        "host",
                        "irreversible",
                    )
                )
            else:
                out.append(
                    (
                        22,
                        (f"if ${var} is unset this expands to `{expanded}`, not to the path you meant"),
                        "host",
                        None,
                    )
                )
            continue
        p = a.rstrip("/") or "/"
        if p in ("/", "/*") or a in ("/", "/*"):
            out.append(
                (
                    50,
                    "target is the filesystem root: everything the caller can write to",
                    "host",
                    "irreversible",
                )
            )
            continue
        stripped = p.removesuffix("/*")
        if stripped in SYSTEM_DIRS:
            out.append((35, f"target is `{stripped}` — {SYSTEM_DIRS[stripped]}", "host", "irreversible"))
            continue
        if p in ("~", "$HOME", "${HOME}", "~/*", "$HOME/*"):
            out.append((28, "target is the user's home directory", "host", "irreversible"))
            continue
        parent = "/" + stripped.lstrip("/").split("/")[0] if stripped.startswith("/") else ""
        if parent in SYSTEM_DIRS and stripped != parent:
            pts = 18 if parent in CORE_DIRS else 8
            out.append(
                (
                    pts,
                    f"target lives under `{parent}` — {SYSTEM_DIRS[parent]}",
                    "host",
                    "irreversible",
                )
            )
            continue
        if REGENERABLE.search(p):
            out.append(
                (
                    -25,
                    (f"`{Path(p).name}` is a regenerable build/dependency directory, not source of truth"),
                    None,
                    None,
                )
            )
            continue
        if p.startswith("/dev/") and binary not in DEVICE_TARGET_EXPECTED:
            out.append((45, f"target is a device node (`{p}`), not a regular file", "host", "irreversible"))
    return out


def specific_clis() -> list[str]:
    """The resource CLIs enumerated per resource rather than by verb.

    Derived from the rule set rather than listed, because docs/rules.md names
    which CLIs are enumerated and which are carried by verb classification, and
    a hand-maintained list drifts the first time a rule is added.
    """
    enumerated = {b for r in RULES if not r["generic"] for b in r["bins"]}
    return sorted(set(RESOURCE_CLIS.split()) & enumerated)


def generic_clis() -> list[str]:
    """The resource CLIs verb classification still carries on its own."""
    return sorted(set(RESOURCE_CLIS.split()) - set(specific_clis()))


def pick_rule(binary: str, args_str: str) -> Entry | None:
    """Pick the rule that best describes a command, or None.

    Specificity wins before score does: a rule matching this exact
    subcommand always beats a generic `<cli> ... delete` classifier, even
    when the generic one would score higher. The classifier is the fallback,
    not a competitor.
    """
    candidates = [r for r in RULES if binary in r["bins"] and (r["sub"] is None or r["sub"].search(args_str))]
    if not candidates:
        return None
    return max(candidates, key=lambda r: (not r["generic"], r["sub"] is not None, r["base"]))


def _score_local_definition(  # noqa: PLR0913,PLR0917 — the scorer's whole context, passed down one level
    local: Definition,
    raw: str,
    binary: str,
    args: list[str],
    privileged: bool,
    strict: bool,
    introspect: bool,
    depth: int,
    basedir: str,
    seen: set[str] | None,
    defs: list[Definition] | None,
    offset: int,
) -> Result | None:
    """Score a call to a function or alias defined earlier in the same input.

    An alias is *expanded* — `k delete ns prod` is `kubectl delete ns prod`, and
    scoring it as anything softer would miss the shadowing that makes aliases
    worth resolving at all. A function gets carrier treatment, like a wrapper
    script: the call site contributes the frame, the body contributes the score.
    """
    seen = seen if seen is not None else set()
    key = f"{local['kind']}:{local['name']}@{local['at']}"
    site = f"defined on line {local['line']} of this input"

    if key in seen:
        # Mutual recursion arrives here too: b is on the stack when a calls it
        # back. Stopping is the whole answer; the body has already been scored
        # once further up, and its score is already carried.
        return {
            "command": raw.strip(),
            "rule": "CARRIER-RECURSION",
            "known": True,
            "score": 0,
            "level": "safe",
            "scope": "none",
            "reversibility": "reversible",
            "privileged": privileged,
            "advice": None,
            "carries": [],
            "factors": [
                {
                    "points": 0,
                    "why": f"`{binary}` is already being scored higher up this call chain — recursion stops here",
                    "keep": True,
                }
            ],
        }

    if local["kind"] == "alias":
        expanded = " ".join([local["value"], *args]).strip()
        seen.add(key)
        try:
            # Resolved at the *call* site, not the definition: bash looks a name
            # up when the line runs, so a helper defined below another one is
            # still in scope by the time either is called.
            child = score_command(
                expanded,
                tokenize(expanded),
                strict=strict,
                introspect=introspect,
                depth=depth + 1,
                basedir=basedir,
                seen=seen,
                defs=defs,
                offset=offset,
            )
        finally:
            seen.discard(key)
        if not child:
            return None
        result = dict(child)
        result["command"] = raw.strip()
        result["privileged"] = privileged or child["privileged"]
        result["factors"] = [
            {
                "points": 0,
                "why": f"{CARRIER_ALIAS}`{binary}` is `{local['value']}`, {site} — scored as `{child['command']}`",
                "rule": None,
                "keep": True,
            },
            *list(child["factors"]),
        ]
        return result

    factors: list[Factor] = [{"points": 0, "why": f"`{binary}` is a function {site}", "rule": None, "keep": True}]
    scope: str | None = "none"
    revert: str | None = "reversible"
    advice: str | None = None
    children: list[Result] = []
    seen.add(key)
    try:
        inner = analyze(
            local["value"],
            strict=strict,
            introspect=introspect,
            basedir=basedir,
            _depth=depth + 1,
            _seen=seen,
            _defs=defs,
            _at=offset,
        )
    finally:
        # Discarded, not left behind: calling the same helper twice in one
        # script is ordinary, and a visited-set would report the second call as
        # recursion and score it zero.
        seen.discard(key)
    worst: Result | None = max(inner, key=lambda r: int(r["score"]), default=None)
    if worst and worst["score"]:
        children.append(worst)
        factors.append(
            {
                "points": worst["score"],
                "why": (f"{CARRIER_FUNCTION}`{binary}()` runs `{worst['command']}`, which is {worst['level']}"),
                "rule": None,
                "keep": True,
            }
        )
        scope, revert, advice = worst["scope"], worst["reversibility"], worst["advice"]
    score = max(0, min(100, sum(int(f["points"]) for f in factors)))
    return {
        "command": raw.strip(),
        "rule": "CARRIER-FUNCTION",
        "known": True,
        "score": score,
        "level": band(score),
        "scope": scope,
        "reversibility": revert,
        "privileged": privileged,
        "advice": advice,
        "factors": factors,
        "carries": children,
    }


def _factor(f: FactorTuple) -> Factor:
    """One contributing factor, as it appears in output.

    `rule` names the rule or amplifier that produced it, so `scoville --why
    <id>` reaches the reasoning from any line of a report rather than from a
    search through the source. Factors that are not a rule — a path, a carried
    payload, a dampener — carry None rather than a made-up id.
    """
    points, why = f[0], f[1]
    return {
        "points": points,
        "why": why,
        # The five-field form carries the id of the rule it came from; the
        # four-field form is a path, a payload or a dampener, which has none.
        "rule": tuple(f)[FACTOR_RULE_INDEX] if len(f) > FACTOR_RULE_INDEX else None,
        "keep": why.startswith((PAYLOAD, ENTRYPOINT, WRAPPER)),
    }


def score_command(  # noqa: PLR0912,PLR0913,PLR0915,PLR0917 — the decision table this tool exists to be
    raw: str,
    tokens: list[str],
    strict: bool = False,
    introspect: bool = False,
    depth: int = 0,
    basedir: str = ".",
    seen: set[str] | None = None,
    defs: list[Definition] | None = None,
    offset: int = 0,
    kube_timeout: float = KUBE_TIMEOUT_DEFAULT,
) -> Result | None:
    """Score one command, or None when there is no command left to score.

    A line that is only wrappers and environment assignments -- `sudo` on its
    own, `FOO=bar` -- reaches here with nothing to name, and there is no score
    to give it.
    """
    rest, privileged, wrappers = strip_prefix(tokens)
    if not rest:
        return None
    binary = Path(rest[0]).name
    args = rest[1:]
    args_str = " ".join(args)
    if FUNC_DEF.match(binary):
        return {
            "command": raw.strip(),
            "rule": "READ-FUNCDEF",
            "known": True,
            "score": 0,
            "level": "safe",
            "scope": "none",
            "reversibility": "reversible",
            "privileged": False,
            "advice": None,
            "carries": [],
            "factors": [
                {
                    "points": 0,
                    "why": "function definition: the body is scored on its own lines",
                    "keep": False,
                }
            ],
        }

    # A name defined earlier in this same text shadows whatever is on PATH.
    # Only under --introspect: resolving a carrier is what that flag means, and
    # the default path must keep scoring exactly what it is shown.
    local = definition_at(defs, binary, offset) if (introspect and defs) else None
    if local and depth < MAX_CARRIER_DEPTH:
        resolved = _score_local_definition(
            local,
            raw,
            binary,
            args,
            privileged,
            strict,
            introspect,
            depth,
            basedir,
            seen,
            defs,
            offset,
        )
        if resolved:
            return resolved

    rule = pick_rule(binary, args_str)
    factors: list[FactorTuple] = []
    if rule:
        scope, revert, advice = rule["scope"], rule["revert"], rule["advice"]
        if rule["base"]:
            factors.append((rule["base"], rule["why"], None, None, rule["id"]))
        elif rule["base"] == 0:
            factors.append((0, rule["why"], None, None, rule["id"]))
        base_id = rule["id"]
    else:
        scope, revert, advice = "none", "reversible", None
        base_id = "UNKNOWN"
        pts = 40 if strict else 5
        unknown_why = f"no rule for `{binary}` — scored on flags and targets only"
        if strict:
            unknown_why += " (--strict: unknown means unreviewed)"
        factors.append((pts, unknown_why, None, None, "UNKNOWN"))
        verb = UNKNOWN_DESTROY.search(args_str)
        if verb:
            factors.append(
                (
                    40,
                    (
                        f"`{verb.group(1)}` is destructive in nearly every CLI, and "
                        f"nothing here knows what this one reaches — treat the "
                        f"score as a floor"
                    ),
                    "account",
                    "irreversible",
                )
            )

    subsumed: set[str] = rule["subsumes"] if rule else set()
    for amp in AMPS + SOFTENERS:
        if amp["bins"] and binary not in amp["bins"]:
            continue
        if amp["id"] in subsumed:
            continue  # the rule exists because of this flag; do not count it twice
        hay = args_str if not amp.get("raw") else raw
        if amp["pattern"].search(hay) or (amp["bins"] is None and amp["pattern"].search(raw)):
            factors.append((amp["points"], amp["why"], amp["scope"], amp["revert"], amp["id"]))

    if binary in PATH_SENSITIVE or (rule and rule["paths"]):
        factors.extend(path_factors(binary, args))

    if privileged:
        factors.append((15, f"`{wrappers[0]}`: runs as root — file permissions do not apply", "host", None))

    # payload: docker exec / kubectl exec -- / ssh host / sh -c / ansible -a / find -exec
    payload, ctx, target = carried_command(binary, args)
    children: list[Result] = []
    if ctx and depth < MAX_CARRIER_DEPTH:
        weight, scope_floor, note = CONTEXTS[ctx]
        if payload:
            child = score_command(
                shlex.join(payload),
                payload,
                strict=strict,
                introspect=introspect,
                depth=depth + 1,
                basedir=basedir,
                seen=seen,
            )
            if child:
                children.append(child)
                carried = round(child["score"] * weight)
                if ctx == "per-file" and child["score"]:
                    factors.append(
                        (
                            10,
                            ("applied to every path the walk matches, not to one argument you can read"),
                            None,
                            None,
                        )
                    )
                factors.append(
                    (
                        carried,
                        f"{PAYLOAD}`{child['command']}` is {child['level']} — {note}",
                        scope_floor,
                        child["reversibility"],
                    )
                )
        else:
            info = introspect_target(ctx if ctx != "image" else "image", target) if introspect else None
            if info and info.get("resolved"):
                entry = info["entrypoint"]
                if entry:
                    child = score_command(
                        shlex.join(entry),
                        entry,
                        strict=strict,
                        introspect=False,
                        depth=depth + 1,
                        basedir=basedir,
                        seen=seen,
                    )
                    if child:
                        children.append(child)
                        carried = round(child["score"] * weight)
                        factors.append(
                            (
                                carried,
                                (f"{ENTRYPOINT}`{child['command']}` is {child['level']} — {note}"),
                                scope_floor,
                                child["reversibility"],
                            )
                        )
                if info.get("user") in ("", "root", "0"):
                    factors.append((8, "the image runs as root", None, None))
            else:
                extra = f"; {info['note']}" if info else "; re-run with --introspect to resolve it"
                factors.append(
                    (
                        20,
                        (f"no explicit command: what runs is the image ENTRYPOINT/CMD, not this line{extra}"),
                        scope_floor,
                        None,
                    )
                )

    kind, target = hidden_payload(binary, rest, rule)
    if kind and depth < MAX_CARRIER_DEPTH:
        seen = seen if seen is not None else set()
        key = f"{kind}:{target}"
        body = None
        if introspect and key not in seen:
            seen.add(key)
            body = resolve_payload(kind, target, basedir)
        if body:
            inner = analyze(
                body,
                strict=strict,
                introspect=introspect,
                basedir=basedir,
                _depth=depth + 1,
                _seen=seen,
            )
            worst: Result | None = max(inner, key=lambda r: int(r["score"]), default=None)
            if worst and worst["score"]:
                children.append(worst)
                factors.append(
                    (
                        worst["score"],
                        (
                            f"{WRAPPER}`{target}` line {worst.get('line', 1)} runs "
                            f"`{worst['command']}`, which is {worst['level']}"
                        ),
                        worst["scope"],
                        worst["reversibility"],
                    )
                )
        else:
            why = f"runs `{target}`: {WRAPPER_NOTE[kind]}"
            why += (
                " — re-run with --introspect to read it" if not introspect else ", and it could not be read from here"
            )
            factors.append((20, why, None, None))

    # What the cluster itself says. Only under --introspect, and only for a
    # kubectl line: everything here is a call to a live API server.
    if introspect and binary in KUBE_BINS:
        factors.extend(kube_rbac_factors(binary, args, kube_timeout))

    # dampeners
    dry = None
    for pattern, why in DAMPENERS:
        if why is None:
            if binary in DRY_RUN_N_BINS and pattern.search(args_str):
                dry = "-n: dry run, nothing is written"
            continue
        if pattern.search(args_str):
            dry = why

    score = max(0, min(100, sum(p for p, *_ in factors)))
    for f in factors:
        s, r = f[2], f[3]
        if s:
            scope = widest(scope, s)
        if r:
            revert = harder(revert, r)
    if dry:
        score = min(score, 12)
        revert = "reversible"
        factors.append((0, dry, None, None))

    return {
        "command": raw.strip(),
        "rule": base_id,
        "known": rule is not None,
        "score": score,
        "level": band(score),
        "scope": scope,
        "reversibility": revert,
        "privileged": privileged,
        "advice": advice,
        "factors": [_factor(f) for f in factors],
        "carries": children,
    }


SCRIPT_EXT = (".sh", ".bash", ".zsh", ".ksh", ".py", ".rb", ".pl")
RUNNERS = {"make", "gmake", "npm", "yarn", "pnpm", "just", "task", "mise", "rake", "invoke"}
# A rule scoring at or above this is in the top band, whatever its modifiers.
TOP_BAND_BASE = 35
# A factor tuple carries (points, why, ..., rule) -- the rule id is the fifth.
FACTOR_RULE_INDEX = 4
# How far a carrier chain is followed before it is called a loop: docker exec
# into a script that runs make that runs a script is already three.
MAX_CARRIER_DEPTH = 3

MAX_SCRIPT_BYTES = 256 * 1024


def hidden_payload(  # noqa: PLR0911 — one arm per carrier shape
    binary: str, rest: list[str], rule: Entry | None
) -> tuple[str | None, str | None]:
    """A wrapper whose contents this command line does not show.

    Same shape as an image ENTRYPOINT: the risk is real, it is just not
    written here. Returns (kind, target).
    """
    if binary in ("source", "."):
        return ("script", rest[1]) if len(rest) > 1 else (None, None)
    if binary in SHELLS or (rule is None and binary in ("python", "python3", "perl", "ruby")):
        if "-c" in rest:
            return None, None  # inline code, handled as a carried payload
        for a in rest[1:]:
            if not a.startswith("-"):
                return "script", a
        return None, None
    if binary in ("make", "gmake"):
        target = next((a for a in rest[1:] if not a.startswith("-") and "=" not in a), None)
        return "make", target or "all"
    if binary in ("npm", "yarn", "pnpm"):
        args = [a for a in rest[1:] if not a.startswith("-")]
        if args and args[0] in ("run", "run-script"):
            args = args[1:]
        elif binary == "npm":
            return None, None  # `npm install` etc are packaging, not a script
        return ("npm", args[0]) if args else (None, None)
    if binary in RUNNERS:
        target = next((a for a in rest[1:] if not a.startswith("-")), None)
        return ("task", target) if target else (None, None)
    if rule is None and (rest[0].startswith(("./", "../", "/")) or rest[0].endswith(SCRIPT_EXT)):
        return "script", rest[0]
    return None, None


def _read(path: str, basedir: str) -> str | None:
    """Read a referenced payload file, or None if it cannot be read safely.

    Size-capped at MAX_SCRIPT_BYTES: a command that points at a multi-megabyte
    file is not worth stalling a pre-commit hook over.
    """
    try:
        p = str(Path(basedir) / path) if not Path(path).is_absolute() else path
        if Path(p).stat().st_size > MAX_SCRIPT_BYTES:
            return None
        with Path(p).open(encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _make_recipe(target: str | None, basedir: str) -> str | None:
    """Return the recipe lines of one Make target, or None.

    A deliberately shallow read — tab-indented lines until the next
    non-indented one, with the @/-/+ prefixes stripped. No variable
    expansion and no includes: what it cannot resolve it leaves alone rather
    than guessing at a command that was never going to run.
    """
    if target is None:
        return None
    for name in ("Makefile", "makefile", "GNUmakefile"):
        text = _read(name, basedir)
        if text is None:
            continue
        lines: list[str] = []
        collecting = False
        for line in text.splitlines():
            if re.match(rf"^{re.escape(target)}\s*:(?!=)", line):
                collecting = True
                continue
            if collecting:
                if line.startswith("\t"):
                    lines.append(line.lstrip("\t").lstrip("@-+"))
                elif line.strip() and not line.startswith((" ", "\t")):
                    break
        if lines:
            return "\n".join(lines)
    return None


def _npm_script(name: str, basedir: str) -> str | None:
    """Return the body of one npm script from package.json, or None."""
    text = _read("package.json", basedir)
    if not text:
        return None
    try:
        return json.loads(text).get("scripts", {}).get(name)
    except ValueError:
        return None


def resolve_payload(kind: str, target: str | None, basedir: str) -> str | None:
    """Read what the wrapper actually runs. Read-only, and never executes it."""
    if not target:
        return None
    if kind == "script":
        return _read(target, basedir)
    if kind == "make":
        return _make_recipe(target, basedir)
    if kind == "npm":
        return _npm_script(target, basedir)
    return None


WRAPPER_NOTE = {
    "script": "the commands are inside the script, not on this line",
    "make": "the recipe is in the Makefile, not on this line",
    "npm": "the script body is in package.json, not on this line",
    "task": "the task definition is in the runner's config, not on this line",
}


FORKBOMB = re.compile(r":\s*\(\s*\)\s*\{.*\|.*&.*\}\s*;\s*:")


def _track_downloads(raw: str, downloaded: set[str]) -> None:
    """Remember paths a fetcher wrote, so executing them later can be spotted."""
    tokens = tokenize(raw)
    rest, _, _ = strip_prefix(tokens)
    if not rest or Path(rest[0]).name not in FETCHERS:
        return
    for i, tok in enumerate(rest[1:], 1):
        if tok in ("-o", "-O", "--output", ">") and i + 1 < len(rest):
            downloaded.add(rest[i + 1])
        elif tok.startswith(("--output=", "-o=")):
            downloaded.add(tok.split("=", 1)[1])


def _flag_deferred_exec(result: Result, raw: str, downloaded: set[str]) -> None:
    """`curl -o f URL && bash f` is the pipe with a file in the middle."""
    if not downloaded:
        return
    tokens = tokenize(raw)
    rest, _, _ = strip_prefix(tokens)
    if not rest:
        return
    binary = Path(rest[0]).name
    hit = None
    if binary in INTERPRETERS:
        hit = next((a for a in rest[1:] if a in downloaded), None)
    elif rest[0] in downloaded or f"./{Path(rest[0]).name}" in downloaded:
        hit = rest[0]
    if not hit:
        return
    opaque = [f for f in result["factors"] if f["why"].startswith("runs `")]
    for f in opaque:  # subsumed by the more specific finding below
        result["factors"].remove(f)
        result["score"] -= f["points"]
    result["factors"].append(
        {
            "points": 70,
            "why": f"executes `{hit}`, which was downloaded earlier in this same snippet: nothing read it in between",
            "keep": True,
        }
    )
    result["score"] = min(100, result["score"] + 70)
    result["level"] = band(result["score"])
    result["scope"] = widest(result["scope"], "host")
    result["reversibility"] = "irreversible"
    result["advice"] = (
        "check the script between fetching and running it, or pin it by "
        "checksum: `echo '<sha256>  s.sh' | sha256sum -c`"
    )


def analyze(
    text: str,
    strict: bool = False,
    introspect: bool = False,
    basedir: str = ".",
    _depth: int = 0,
    _seen: set[str] | None = None,
    _defs: list[Definition] | None = None,
    _at: int | None = None,
    kube_timeout: float = KUBE_TIMEOUT_DEFAULT,
) -> list[Result]:
    """Analyze a snippet; returns one result per command, in execution order.

    `_defs` carries the enclosing text's function and alias definitions into a
    resolved body, and `_at` pins every command in that body to the offset of
    the call site — body offsets are body-relative and would otherwise be
    compared against offsets in a different string. The call site is the right
    point because bash resolves a name when the line runs, so a helper defined
    below the one that calls it is still in scope.
    """
    results: list[Result] = []
    defs = _defs if _defs is not None else (collect_definitions(text) if introspect else [])
    if FORKBOMB.search(text):
        results.append(
            {
                "command": text.strip().splitlines()[0][:60],
                "rule": "EXEC-FORKBOMB",
                "known": True,
                "score": 100,
                "level": "critical",
                "scope": "host",
                "reversibility": "recoverable",
                "privileged": False,
                "line": 1,
                "carries": [],
                "advice": "there is no legitimate reason for this on a machine you care about",
                "factors": [
                    {
                        "points": 100,
                        "why": "fork bomb: recursively spawns processes until the kernel's process table is exhausted",
                    }
                ],
            }
        )
        return results

    prev: Result | None = None
    downloaded: set[str] = set()
    for raw, offset, op in split_commands(text):
        line = text.count("\n", 0, offset) + 1
        for inner, ioff in subshell_commands(raw, offset):
            r = score_command(
                inner,
                tokenize(inner),
                strict=strict,
                introspect=introspect,
                depth=max(1, _depth),
                basedir=basedir,
                seen=_seen,
                defs=defs,
                offset=_at if _at is not None else ioff,
                kube_timeout=kube_timeout,
            )
            if r:
                r["line"] = text.count("\n", 0, ioff) + 1
                r["substitution"] = True
                results.append(r)
        r = score_command(
            raw,
            tokenize(raw),
            strict=strict,
            introspect=introspect,
            depth=_depth,
            basedir=basedir,
            seen=_seen,
            defs=defs,
            offset=_at if _at is not None else offset,
            kube_timeout=kube_timeout,
        )
        if not r:
            continue
        r["line"] = line
        # curl … | sh — the pipe is the whole risk, and neither half shows it
        if op == "|" and prev:
            binary = Path(strip_prefix(tokenize(raw))[0][0]).name if tokenize(raw) else ""
            src = Path(strip_prefix(tokenize(prev["command"]))[0][0]).name
            if binary in INTERPRETERS and src in FETCHERS:
                r["factors"].append(
                    {
                        "points": 78,
                        "why": "piping a downloaded script straight into an interpreter: the code runs "
                        "unreviewed, with your privileges, and the server can serve different "
                        "bytes to curl than to a browser",
                    }
                )
                r["score"] = min(100, r["score"] + 78)
                r["level"] = band(r["score"])
                r["scope"] = widest(r["scope"], "host")
                r["reversibility"] = "irreversible"
                r["advice"] = "download, read, then run: `curl -fsSL URL -o s.sh && less s.sh && sh s.sh`"
        _track_downloads(raw, downloaded)
        _flag_deferred_exec(r, raw, downloaded)
        results.append(r)
        prev = r
    return results


# ---------------------------------------------------------------- output ---

# Scoville's own scale, since the bands map onto it one for one. The slug is
# what `--quiet` prints, so it stays greppable and ASCII.
PEPPERS = {
    "safe": ("bell pepper", "bell-pepper", 0, "0 SHU"),
    "low": ("jalapeño", "jalapeno", 1, "2.5-8k SHU"),
    "medium": ("cayenne", "cayenne", 2, "30-50k SHU"),
    "high": ("habanero", "habanero", 3, "100-350k SHU"),
    "critical": ("carolina reaper", "carolina-reaper", 4, "1.6-2.2M SHU"),
}
SCALES = ("bands", "peppers")


def label(level: str, scale: str, slug: bool = False) -> str:
    """The display name for a level on the chosen scale."""
    if scale != "peppers":
        return level if slug else level.upper()
    name, short, heat, _ = PEPPERS[level]
    if slug:
        return short
    return ("🌶" * heat + " " if heat else "") + name.upper()


MARKS = {"safe": "ok", "low": "· ", "medium": "! ", "high": "!!", "critical": "XX"}
COLORS = {"safe": "32", "low": "36", "medium": "33", "high": "31", "critical": "1;31"}


def paint(text: str, level: str, on: bool) -> str:
    """Colour text for a level, or hand it back untouched when `on` is false."""
    return f"\033[{COLORS[level]}m{text}\033[0m" if on else text


def render_text(
    results: list[Result], source: str | None = None, color: bool = False, verbose: bool = False, scale: str = "bands"
) -> str:
    """Render the human-readable report: one block per command.

    Zero-weight factors are hidden unless `verbose`, or unless the command
    scored 0 — a safe command with nothing listed under it reads as a tool
    that failed to run, rather than as a verdict.
    """
    lines: list[str] = []
    width = 10 if scale == "bands" else 25
    for r in results:
        where = f"{source}:{r['line']}: " if source else ""
        tag = "(command substitution) " if r.get("substitution") else ""
        lines.append(f"{where}{tag}{r['command']}")
        lvl = label(r["level"], scale)
        # each 🌶 is one character but two terminal columns
        emoji = PEPPERS[r["level"]][2] if scale == "peppers" else 0
        pad = " " * max(0, width - len(lvl) - emoji)
        head = (
            f"  {paint(lvl, r['level'], color)}{pad} {r['score']:>3}/100  ·  "
            f"scope: {r['scope']}  ·  {r['reversibility']}"
        )
        lines.append(head)
        for f in r["factors"]:
            if f["points"] == 0 and not verbose and r["score"] > 0 and not f.get("keep"):
                continue
            sign = f"{f['points']:+d}" if f["points"] else "  ·"
            lines.append(f"    {sign:>4}  {f['why']}")
        if r["advice"] and r["level"] not in ("safe",):
            lines.append(f"    ↳ safer: {r['advice']}")
        # The path from a score to its reasoning should be one command, not a
        # search through the source. Shown on anything that scored, and under
        # --verbose on the rest.
        if r.get("known") and r["rule"] and (r["level"] != "safe" or verbose):
            lines.append(f"    ↳ why:   scoville --why {r['rule']}")
        lines.append("")
    return "\n".join(lines)


def public(results: list[Result]) -> list[Result]:
    """Drop internal render hints before serialising."""
    out: list[Result] = []
    for r in results:
        clean = {k: v for k, v in r.items() if k != "carries"}
        clean["factors"] = [{k: v for k, v in f.items() if k != "keep"} for f in r["factors"]]
        clean["carries"] = public(r.get("carries", []))
        out.append(clean)
    return out


def overall(results: list[Result]) -> Result:
    """Collapse a run into one verdict.

    Not an average: the worst score, the widest scope and the least
    reversible outcome across every command. A script is as dangerous as its
    most dangerous line, and averaging would let ten harmless commands bury
    one `rm -rf /`.
    """
    if not results:
        return {
            "score": 0,
            "level": "safe",
            "scope": "none",
            "reversibility": "reversible",
            "commands": 0,
        }
    worst = max(results, key=lambda r: r["score"])
    scope, revert = "none", "reversible"
    for r in results:
        scope = widest(scope, r["scope"])
        revert = harder(revert, r["reversibility"])
    return {
        "score": worst["score"],
        "level": worst["level"],
        "scope": scope,
        "reversibility": revert,
        "commands": len(results),
        "worst": worst["command"],
    }


# ------------------------------------------------------------ overrides ---
#
# The rule set is calibrated for the general case, but risk is contextual. A
# repo where `kubectl delete ns ci-*` is routine teardown gets the same `high`
# as one where it is an outage. Before this the only levers were --fail-on and
# --strict, both global — so the first time a legitimate command tripped the
# gate, the cheapest fix was to turn the gate off. That is the failure mode
# this is designed against.

CONFIG_NAMES = (".scovillerc", ".scovillerc.json")
OVERRIDE_ACTIONS = ("deny", "rescore", "allow")


class ConfigError(Exception):
    """A config that cannot be read as written. Never guessed at: a misspelled
    key that is silently ignored is an override the reader believes is in
    force."""


def find_config(basedir: str) -> str | None:
    """The nearest `.scovillerc` at or above `basedir`, or None.

    Walking up means a repo-root config covers every subdirectory, which is
    where the file belongs — risk is a property of the repository, not of the
    directory you happened to run from.
    """
    here = str(Path(basedir).resolve())
    while True:
        for name in CONFIG_NAMES:
            candidate = str(Path(here) / name)
            if Path(candidate).is_file():
                return candidate
        parent = str(Path(here).parent)
        if parent == here:
            return None
        here = parent


def load_config(path: str) -> list[Override]:
    """Parse and validate a config file into a list of override entries.

    JSON, not TOML. `tomllib` is 3.11+ and scoville supports 3.10, and the two
    ways round that — vendoring a parser, or dropping a supported version — both
    cost more than the comment syntax is worth for a file whose every entry
    already carries a mandatory `why`. Switching is a one-line change if the
    floor ever moves.
    """
    try:
        with Path(path).open(encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as e:
        raise ConfigError(f"{path}: {e}") from e
    except ValueError as e:
        raise ConfigError(f"{path}: not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected an object with allow/deny/rescore keys")
    # json.load only ever produces str keys; the cast says what it cannot.
    config = cast("dict[str, Any]", data)

    unknown = set(config) - set(OVERRIDE_ACTIONS)
    if unknown:
        raise ConfigError(
            f"{path}: unknown key(s) {', '.join(sorted(unknown))}; expected {', '.join(OVERRIDE_ACTIONS)}"
        )

    entries: list[Override] = []
    # Deny first, then rescore, then allow: a deny is a statement that the
    # command is never acceptable here, and it has to survive an allow written
    # by someone who did not know about it.
    for action in OVERRIDE_ACTIONS:
        rules: list[Any] = config.get(action) or []
        for i, raw in enumerate(rules):
            where = f"{path}: {action}[{i}]"
            if not isinstance(raw, dict):
                raise ConfigError(f"{where}: expected an object with `match` and `why`")
            rule = cast("dict[str, Any]", raw)
            match = rule.get("match")
            why = rule.get("why")
            if not match or not isinstance(match, str):
                raise ConfigError(f"{where}: needs a `match` glob")
            # An override with no stated reason is how a config file becomes a
            # list nobody can safely delete from.
            if not why or not isinstance(why, str):
                raise ConfigError(
                    f"{where}: needs a `why` — an unexplained override is one nobody can safely remove later"
                )
            entry: Override = {"action": action, "match": match, "why": why, "source": path}
            if action == "rescore":
                level = rule.get("level")
                if level not in LEVELS:
                    raise ConfigError(f"{where}: `level` must be one of {', '.join(LEVELS)}, got {level!r}")
                entry["level"] = level
            entries.append(entry)
    return entries


def match_override(entries: list[Entry], command: str) -> Entry | None:
    """The first entry whose glob matches `command`, or None.

    Globs, not regexes. A glob is reviewable at a glance in a file that governs
    what a safety gate lets through; a regex in the same position is a thing
    people paste and nobody audits.
    """
    for entry in entries:
        if fnmatch.fnmatch(command, entry["match"]):
            return entry
    return None


def apply_overrides(results: list[Result], entries: list[Entry]) -> list[Result]:
    """Apply config overrides in place, recording each one in the factor trace.

    A suppressed finding still appears, with its original score. Silent
    suppression is indistinguishable from a missing rule, and the whole reason
    for `why` is that someone reading the output six months later can tell the
    difference.
    """
    if not entries:
        return results
    for r in results:
        entry = match_override(entries, r["command"])
        if not entry:
            continue
        r["override"] = {k: v for k, v in entry.items() if k != "source"}
        was = r["level"]
        if entry["action"] == "deny":
            r["score"], r["level"] = 100, "critical"
            note = f"denied by {Path(entry['source']).name}: {entry['why']}"
        elif entry["action"] == "rescore":
            r["level"] = entry["level"]
            r["score"] = SCORE_FOR_LEVEL[entry["level"]]
            moved = f"re-scored {was} → {entry['level']}" if was != entry["level"] else f"pinned at {entry['level']}"
            note = f"{moved} by {Path(entry['source']).name}: {entry['why']}"
        else:
            note = f"allowed by {Path(entry['source']).name}: {entry['why']} (scored {was}, does not trip --fail-on)"
        r["factors"].append({"points": 0, "why": note, "keep": True})
        apply_overrides(r.get("carries", []), entries)
    return results


# The bottom of each band: a re-score pins the level, and the score has to agree
# with it or the two halves of the output contradict each other.
SCORE_FOR_LEVEL = {"safe": 0, "low": 15, "medium": 35, "high": 60, "critical": 85}


def gated(results: list[Result]) -> list[Result]:
    """Results that --fail-on considers: everything not explicitly allowed."""

    def allowed(r: Result) -> bool:
        override: Override = r.get("override") or {}
        return override.get("action") == "allow"

    return [r for r in results if not allowed(r)]


def main(  # noqa: PLR0911,PLR0912,PLR0915 — argument handling: one arm per flag, one exit code per failure
    argv: list[str] | None = None,
) -> int:
    """CLI entry point. Returns the process exit status.

    0 when the run completed, 1 when --fail-on is reached, 64 (EX_USAGE) when
    there was nothing to analyse or the file could not be read.
    """
    p = argparse.ArgumentParser(
        prog="scoville", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("command", nargs="*", help="command(s) to analyze; '-' reads stdin")
    p.add_argument("-f", "--file", help="analyze a script file")
    p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="text for humans, json for anything downstream",
    )
    p.add_argument(
        "--scale",
        choices=SCALES,
        default="bands",
        help="how to name the levels: bands (safe..critical) or peppers "
        "(bell pepper..carolina reaper). Text output only",
    )
    p.add_argument("--fail-on", choices=LEVELS, help="exit 1 when any command reaches this level")
    p.add_argument("--strict", action="store_true", help="treat unrecognised commands as medium risk")
    p.add_argument(
        "--introspect",
        action="store_true",
        help="resolve hidden image/container entrypoints via read-only docker inspect, "
        "and ask the current kube context what it is allowed to do",
    )
    p.add_argument(
        "--kube-timeout",
        type=float,
        default=KUBE_TIMEOUT_DEFAULT,
        metavar="SEC",
        help="bound on one `kubectl auth can-i` call under --introspect "
        f"(default {KUBE_TIMEOUT_DEFAULT}); a timeout scores as if it had not "
        "been asked",
    )
    p.add_argument("--quiet", "-q", action="store_true", help="one line per command")
    p.add_argument("--verbose", "-v", action="store_true", help="show zero-weight factors too")
    p.add_argument(
        "--no-color",
        action="store_true",
        help="never colourise (a non-tty and NO_COLOR already disable it)",
    )
    p.add_argument(
        "--config",
        metavar="PATH",
        help="override file (default: nearest .scovillerc at or above the analysed file's directory)",
    )
    p.add_argument(
        "--no-config",
        action="store_true",
        help="ignore any .scovillerc that would otherwise be discovered",
    )
    p.add_argument("--list-rules", action="store_true", help="print every rule and amplifier, then exit")
    p.add_argument(
        "--why",
        metavar="RULE",
        help="print the long form for one rule or amplifier id "
        "(as printed by --list-rules and on every finding), then exit",
    )
    p.add_argument("--version", action="version", version=f"scoville {__version__}")
    args = p.parse_args(argv)

    if args.why:
        text = why_text(args.why)
        if text is None:
            # The tool's output
            print(f"scoville: no rule or amplifier called {args.why!r}", file=sys.stderr)  # noqa: T201
            # A near miss is the common case — an id read off a finding with a
            # typo, or half remembered. Guessing is cheaper than --list-rules.
            wanted: str = str(args.why).strip().lstrip("+").upper()
            near = difflib.get_close_matches(wanted, rule_ids(), n=3, cutoff=0.5)
            if near:
                print(f"scoville: did you mean {', '.join(near)}?", file=sys.stderr)  # noqa: T201 — the tool's output
            else:
                print("scoville: --list-rules prints every id", file=sys.stderr)  # noqa: T201 — the tool's output
            return 64
        print(text, end="")  # noqa: T201 — the tool's output
        return 0

    if args.list_rules:
        for r in sorted(RULES, key=lambda x: x["id"]):
            if not r["bins"]:
                continue
            bins = ", ".join(sorted(r["bins"])[:6])
            print(f"{r['id']:<18} {r['base']:>3}  {bins}: {r['why']}")  # noqa: T201 — the tool's output
        for a in AMPS:
            bins = ", ".join(sorted(a["bins"])[:4]) if a["bins"] else "any"
            print(f"{'+' + a['id']:<18} {a['points']:>+3}  {bins}: {a['why']}")  # noqa: T201 — the tool's output
        return 0

    source = None
    if args.file:
        try:
            with Path(args.file).open(encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print(f"scoville: {e}", file=sys.stderr)  # noqa: T201 — the tool's output
            return 64
        source = args.file
    elif args.command and args.command != ["-"]:
        text = "\n".join(args.command)
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        p.print_usage(sys.stderr)
        return 64

    if not text.strip():
        print("scoville: nothing to analyze", file=sys.stderr)  # noqa: T201 — the tool's output
        return 64

    basedir = str(Path(args.file).resolve().parent) if args.file else str(Path.cwd())

    # An explicit --config that does not exist is an error, not a shrug: the
    # caller asked for a policy and running without it would silently apply a
    # different one than they think.
    entries: list[Override] = []
    if not args.no_config:
        config_path = args.config or find_config(basedir)
        if args.config and not Path(args.config).is_file():
            print(f"scoville: {args.config}: no such file", file=sys.stderr)  # noqa: T201 — the tool's output
            return 64
        if config_path:
            try:
                entries = load_config(config_path)
            except ConfigError as e:
                print(f"scoville: {e}", file=sys.stderr)  # noqa: T201 — the tool's output
                return 64

    results = apply_overrides(
        analyze(
            text,
            strict=args.strict,
            introspect=args.introspect,
            basedir=basedir,
            kube_timeout=args.kube_timeout,
        ),
        entries,
    )
    summary = overall(results)

    if args.format == "json":
        json.dump({"overall": summary, "commands": public(results)}, sys.stdout, indent=2)
        print()  # noqa: T201 — the tool's output
    elif args.quiet:
        for r in results:
            # The tool's output
            print(f"{label(r['level'], args.scale, slug=True):<15} {r['score']:>3}  {r['command']}")  # noqa: T201
    else:
        color = not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        out = render_text(results, source, color, args.verbose, args.scale)
        if out:
            print(out, end="")  # noqa: T201 — the tool's output
        plural = "" if summary["commands"] == 1 else "s"
        heat = f" ({PEPPERS[summary['level']][3]})" if args.scale == "peppers" else ""
        print(  # noqa: T201 — the tool's output
            f"scoville: {summary['commands']} command{plural}, worst "
            f"{paint(label(summary['level'], args.scale), summary['level'], color)}{heat} "
            f"{summary['score']}/100 · scope {summary['scope']} · {summary['reversibility']}"
        )

    # The summary reports what the commands really score; the gate ignores the
    # ones this repo has explicitly allowed. Reporting an allowed command as
    # safe would be a lie, and failing on it would be the reason someone turns
    # --fail-on off altogether.
    gate = overall(gated(results))
    if args.fail_on and LEVELS.index(gate["level"]) >= LEVELS.index(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:  # `scoville … | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
