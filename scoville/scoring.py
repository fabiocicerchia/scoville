"""Turning a command into factors and a score."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

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
from .carriers import CONTEXTS, carried_command
from .definitions import (
    CARRIER_ALIAS,
    CARRIER_FUNCTION,
    ENTRYPOINT,
    FUNC_DEF,
    PAYLOAD,
    RBAC,
    UNKNOWN_DESTROY,
    VAR_PATH,
    WRAPPER,
    collect_definitions,
    definition_at,
)
from .introspection import introspect_target
from .kube import (
    KUBE_BINS,
    KUBE_RESOURCE_ALIASES,
    KUBE_TIMEOUT_DEFAULT,
    KUBE_VERB_ALIASES,
    kube_can_i,
    kube_context,
    kube_target,
)
from .parsing import ENV_ASSIGN, split_commands, strip_prefix, subshell_commands, tokenize
from .rules import FETCHERS, INTERPRETERS, RESOURCE_CLIS, RULES, SHELLS
from .scales import Definition, Entry, Factor, FactorTuple, Result, band, harder, widest


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
