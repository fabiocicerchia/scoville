"""The vocabulary every other module scores in: levels, bands, scopes,
reversibility, and the three helpers that compare them."""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------- scales ---

# score -> band. Deliberately coarse: the band drives decisions, the score
# only orders commands within a band.
# A rule or amplifier as the tables below declare it, and a scored result as
# the renderers consume it. Both stay dicts: the tables are written as literals,
# and every reader does a `.get` on optional keys rather than reaching for an
# attribute that may not be there.
Entry = dict[str, Any]
Result = dict[str, Any]
# One function or alias definition found in the text being scored:
# {kind, name, value, at, line}.
Definition = dict[str, Any]
# One factor line under a result: what matched, and what it did to the score.
Factor = dict[str, Any]
# A factor as the scanners emit it, before it becomes a Factor dict: the
# points, why, the scope and reversibility it implies, and -- when it came
# from a named rule or amplifier -- that id.
FactorTuple = tuple[int, str, str | None, str | None] | tuple[int, str, str | None, str | None, str]
# A parsed config file (--config), or the defaults.
# One entry from a .scovillerc: {action, match, why, source} and, for a
# rescore, the level it forces.
Override = dict[str, Any]

BANDS = ((85, "critical"), (60, "high"), (35, "medium"), (15, "low"), (0, "safe"))
LEVELS = ("safe", "low", "medium", "high", "critical")

# blast radius, ordered. A command's scope is the widest one it touches.
SCOPES = ("none", "file", "directory", "container", "host", "network", "cluster", "account")
# how hard it is to get back to where you were.
REVERT = ("reversible", "recoverable", "irreversible")


def band(score: int) -> str:
    """Name the band a score falls in.

    Deliberately coarse: the band is what a caller acts on, the score only
    orders commands inside one.
    """
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "safe"


def widest(a: str, b: str) -> str:
    """Return the wider of two blast radii — scope only ever grows."""
    return a if SCOPES.index(a) >= SCOPES.index(b) else b


def harder(a: str, b: str) -> str:
    """Return the less recoverable of two verdicts — reversibility only ever
    gets worse as factors accumulate."""
    return a if REVERT.index(a) >= REVERT.index(b) else b
