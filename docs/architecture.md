# Architecture

One module, no dependencies. `scoville.py` holds the splitter, the rule table
and the scorer; `tests/corpus.tsv` holds the calibration.

## Overview

Risk is not a property of a binary — it is a property of
`binary + flags + target + context`. Everything below exists to keep those four
things separable, so `rm`, `rm -rf` and `rm -rf /` can score differently
without three hand-written rules.

## Components

| Component | Responsibility |
|---|---|
| Splitter | Turns a line, a pipeline or a script into individual commands. Handles quoting, `$(…)`, comments, keywords and operators. It is a splitter, not a shell — nothing is executed. |
| Rule table | Base scores per command, plus generic amplifiers (`--force`, `-y`, credentials in argv, disabled TLS, `0.0.0.0/0`) and softeners (`rm -i`, `--force-with-lease`, `--limit`). |
| Verb classifier | The long tail. ~50 resource CLIs are scored by the verb in command position, so a new CLI still cannot score `safe` on `delete`. |
| Carrier unwrapping | `docker exec`, `kubectl exec --`, `ssh`, `sh -c`, `ansible -a`, `find -exec`, `sudo`, `xargs` and command substitutions are scored on their payload, folded back with a context weight. |
| Introspection | Opt-in (`--introspect`): reads wrapper scripts, Makefile targets, `package.json` scripts and image entrypoints. Read-only, recursive, with a cycle guard. Never pulls, runs or evaluates. |
| Reporter | Band, score, scope, reversibility and the factor trace; `--format json` for machines. |

## Data flow

```text
input (argv | -f file | stdin)
  → split into commands
  → per command: match rules → base + amplifiers − softeners → clamp 0..100
  → unwrap carriers, score the payload, fold back with context weight
  → derive band, widest scope, worst reversibility
  → report (text | json), exit per --fail-on
```

## Decisions

**Two facets, not one number.** Scope and reversibility answer different
questions — `terraform destroy` and `rm -rf ~/notes` can score alike and still
deserve different answers.

**Bands are coarse on purpose.** The band drives decisions; the score only
orders commands within a band.

**Specific beats generic even when it scores lower.** `virsh destroy` powers a
domain off rather than deleting it, so it sits below `virsh undefine`.

**Calibration lives in a corpus, not in the code.** `tests/corpus.tsv` is
executed by the suite and generates `INVENTORY.md`, so a rule change that moves
a command between bands fails a test instead of quietly recalibrating the tool.

**Not adversary-resistant, by design.** It is a safety tool for commands
written in good faith, not a sandbox. Quoting, encoding or run-time
construction defeats it. Don't put it between untrusted input and a shell.
