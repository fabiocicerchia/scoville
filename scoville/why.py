"""Answering `--why`: find the entry, then explain the class of incident it
exists to prevent."""

from __future__ import annotations

import re
import textwrap
from collections.abc import Callable

from .amplifiers import AMPS, SOFTENERS
from .incidents import INCIDENTS
from .rules import RULES
from .scales import TOP_BAND_BASE, Entry, band


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


def _reachable(entry: Entry) -> tuple[list[Entry], list[Entry]]:
    """The amplifiers and softeners that can apply to this rule's binaries.

    Answers "why this band" with the range the rule can actually reach rather
    than with its base alone: a rule at 55 whose binaries carry a +35 amplifier
    is a `critical` waiting for one flag, and that is the part a reader
    disagreeing with a score needs to see.
    """
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


def _rule_head(entry: Entry, width: int) -> list[str]:
    """The identity line: what this is, and the three facts a score reports."""
    head = (
        f"{entry['id']}  ·  base {entry['base']} ({band(entry['base'])})  ·  "
        f"scope: {entry['scope']}  ·  {entry['revert']}"
    )
    return [head, "=" * min(len(head), width), ""]


def _amp_head(entry: Entry, width: int) -> list[str]:
    """The identity line for an amplifier or softener: its sign and weight."""
    sign = "softener" if entry["points"] < 0 else "amplifier"
    head = f"+{entry['id']}  ·  {entry['points']:+d} ({sign})"
    if entry["scope"] or entry["revert"]:
        head += f"  ·  scope: {entry['scope'] or '—'}  ·  {entry['revert'] or '—'}"
    return [head, "=" * min(len(head), width), ""]


def _matches_on(entry: Entry, pattern: re.Pattern[str] | None) -> list[str]:
    """The binaries, and the argument pattern if there is one."""
    out = ["MATCHES", _wrap(", ".join(sorted(entry["bins"])) if entry["bins"] else "any command")]
    if pattern is not None:
        # Printed unwrapped: a regex broken across lines is not something you
        # can paste back into anything.
        out += ["  …when the arguments match:", f"    {pattern.pattern}"]
    return out


def _rule_matches(entry: Entry) -> list[str]:
    """What it matches, and — as importantly — what it does not."""
    out = _matches_on(entry, entry["sub"])
    if entry["sub"] is None:
        out.append(_wrap("…whatever the arguments are — the binary is the whole of it."))
    if entry["generic"]:
        out.append(
            _wrap(
                "This is a verb classifier: a floor for CLIs nobody has "
                "enumerated, and any specific rule beats it — including one "
                "that scores lower."
            )
        )
    else:
        out.append(
            _wrap("Not matched: anything a rule with a higher base claims first. Specificity wins before score does.")
        )
    return [*out, ""]


def _amp_matches(entry: Entry) -> list[str]:
    """What an amplifier or softener applies to."""
    return [*_matches_on(entry, entry["pattern"]), ""]


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


def _why_band(entry: Entry) -> list[str]:
    """Why this band, and what the flags on these binaries can do to it."""
    out = [
        "WHY THIS BAND",
        _wrap(
            f"{entry['base']}/100 on its own, which is `{band(entry['base'])}`. "
            f"Blast radius `{entry['scope']}`; getting back is `{entry['revert']}`."
        ),
    ]
    amps, softs = _reachable(entry)
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


# One view per kind of entry: its identity line, then its sections in printed
# order. A new kind of entry adds a row here, not a branch in every section.
_VIEWS: dict[str, tuple[Callable[[Entry, int], list[str]], tuple[Callable[[Entry], list[str]], ...]]] = {
    "rule": (_rule_head, (_rule_matches, _why_incident, _why_band, _why_safer, _why_related)),
    "amp": (_amp_head, (_amp_matches, _why_incident)),
}


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
    head, sections = _VIEWS[kind]
    out = head(entry, width)
    for section in sections:
        out.extend(section(entry))
    out.append(f"  scoville --list-rules   ·   {len(INCIDENTS)} of {len(rule_ids())} ids have an incident note")
    return "\n".join(out).rstrip() + "\n"
