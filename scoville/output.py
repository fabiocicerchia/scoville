"""Rendering the result: the peppers, the table, the JSON."""

from __future__ import annotations

from .scales import Result, harder, widest

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
