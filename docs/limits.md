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
