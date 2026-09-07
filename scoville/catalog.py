"""The two constructors the catalogues are written with.

R and A are table columns with names on them -- keeping them here lets
rules.py and amplifiers.py be nothing but data."""

from __future__ import annotations

import re

from .scales import REVERT, SCOPES, Entry



def _check(rid: str, scope: str | None, revert: str | None) -> None:
    """Refuse a rule that names a scope or reversibility nobody defined.

    The rule set is data, so a typo in a literal would otherwise sail through
    and score commands with a vocabulary the rest of the module cannot read.
    """
    if scope not in SCOPES:
        msg = f"{rid}: unknown scope {scope!r}"
        raise ValueError(msg)
    if revert not in REVERT:
        msg = f"{rid}: unknown reversibility {revert!r}"
        raise ValueError(msg)


def R(  # noqa: N802,PLR0913,PLR0917 — the rule table's columns; see the comment above
    rid: str,
    # Space-separated, because that is how the table below reads: one string
    # per rule rather than a list literal per row. `.split()` happens once,
    # here.
    bins: str,
    sub: str | None,
    base: int,
    scope: str | None,
    revert: str | None,
    why: str,
    advice: str | None = None,
    generic: bool = False,
    paths: bool = False,
    subsumes: str = "",
) -> Entry:
    """A rule: what this command *is*, before flags and targets are read.

    `generic` marks verb-classification rules (any `<cli> … delete`). A
    specific rule always beats a generic one, including when it scores lower.
    """
    _check(rid, scope, revert)
    return {
        "id": rid,
        "bins": set(bins.split()),
        "sub": re.compile(sub) if sub else None,
        "base": base,
        "scope": scope,
        "revert": revert,
        "why": why,
        "advice": advice,
        "generic": generic,
        "paths": paths,
        "subsumes": set(subsumes.split()),
    }



def A(  # noqa: N802,PLR0913,PLR0917 — the amplifier table's columns; see above
    aid: str,
    # Space-separated like R's, and None for an amplifier that applies to any
    # command rather than to a named set.
    bins: str | None,
    pattern: str,
    points: int,
    why: str,
    scope: str | None = None,
    revert: str | None = None,
    raw: bool = False,
) -> Entry:
    """A modifier: how flags make the same command better or worse.

    Amplifiers carry no advice — the rule owns that — so a stray fourth string
    here would land in `scope`. Validated rather than trusted.
    """
    _check(aid, scope or "none", revert or "reversible")
    return {
        "id": aid,
        "bins": set(bins.split()) if bins else None,
        "pattern": re.compile(pattern),
        "points": points,
        "why": why,
        "scope": scope,
        "revert": revert,
        "raw": raw,
    }
