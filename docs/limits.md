# Known limits

[BEHAVIOUR.md](https://github.com/fabiocicerchia/scoville/blob/main/BEHAVIOUR.md)
documents how the tool works and where it stops — the scoring order, precedence,
carrier weights, introspection, and a full limitations section. The short
version:

- It is a **splitter, not a shell**: quoting, `$(…)`, comments, keywords and
  operators are handled; heredocs, arrays and arithmetic expansion are not.
  Nothing is ever executed to find out.
- It **cannot see values**. `rm -rf $DIR` is scored on the shape of the
  argument; if `DIR` holds `/etc`, there is no way to know.
- It has **no control flow**: a command inside a branch that never runs is still
  scored.
- It knows **nothing about your environment** — which cluster, which account,
  whether a backup exists. Production detection is a string heuristic.
- Scores are **calibrated judgement, not measurement**. Ordinal, and meant to be
  argued with; `tests/corpus.tsv` is where that argument gets settled.
- It is **not adversary-resistant**. It is a safety tool for commands written in
  good faith, not a sandbox: quoting, encoding or run-time construction defeats
  it by design. Do not put it between untrusted input and a shell.

That last one is the important one. A gate that people believe is a sandbox is
worse than no gate, because it changes what they are willing to pipe into it.

## Shell functions and aliases

Under `--introspect`, functions and aliases **defined in the analysed input**
(and in the files it sources) are resolved: the call site is scored as the body
it runs, and an alias is expanded to the command it really is. A helper defined
in a deploy script is a carrier like a make target or an image ENTRYPOINT — the
call site shows nothing, and in a script that defines its own helpers that is
most of the interesting lines.

Three boundaries are deliberate:

- **Nothing outside the input is read.** Your `~/.bashrc` is not consulted, so
  the same script scores the same on two machines. An interactive alias you
  have loaded will still be scored as an unknown command.
- **Definitions are ordered, but resolved at the call site.** A function called
  above its definition is *not* resolved — bash reads top to bottom, and a
  script with its helpers at the bottom is common enough that assuming
  otherwise is a false positive. But a function that calls one defined below it
  *is* resolved, because by the time either runs both are in scope.
- **Recursion stops, it does not unroll.** A name already on the call chain
  scores zero and says so; the non-recursive arm of the body is still counted.

The value-blindness limit above still applies, one level further away:
`deploy prod` binds `$1`, and the body's `rm -rf "$1"` is scored on its shape,
not on what `prod` expands to.
