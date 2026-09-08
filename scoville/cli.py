"""The command line: one arm per flag, one exit code per failure."""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from pathlib import Path

from .amplifiers import AMPS
from .kube import KUBE_TIMEOUT_DEFAULT
from .output import PEPPERS, SCALES, label, overall, paint, public, render_text
from .overrides import ConfigError, apply_overrides, find_config, gated, load_config
from .rules import RULES
from .scales import LEVELS, Override
from .scoring import analyze
from .version import __version__
from .why import rule_ids, why_text


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
