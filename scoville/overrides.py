"""The per-repo config that re-rates a rule for its context."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any, cast

from .scales import LEVELS, Entry, Override, Result

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
