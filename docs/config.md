# Per-repo overrides: `.scovillerc`

The rule set is calibrated for the general case, but risk is contextual. A repo
where `kubectl delete ns ci-*` is routine teardown gets the same `high` as one
where it is an outage.

Without a way to say so, the only levers are `--fail-on` and `--strict`, and
both are global — so the first time a legitimate command trips the gate, the
team's cheapest fix is to turn the gate off. That is the failure mode this is
designed against.

## The file

`.scovillerc` (or `.scovillerc.json`), discovered from the analysed file's
directory upwards, or named with `--config PATH`. A repo-root file therefore
covers every subdirectory: risk is a property of the repository, not of the
directory you happened to run from.

```json
{
  "allow": [
    {
      "match": "kubectl delete ns ci-*",
      "why": "ephemeral CI namespaces; recreated by the pipeline on every run"
    }
  ],
  "deny": [
    {
      "match": "*--context prod*",
      "why": "production changes go through the pipeline, never a laptop"
    }
  ],
  "rescore": [
    {
      "match": "terraform apply*",
      "level": "critical",
      "why": "our state is shared across three teams; apply is never routine"
    }
  ]
}
```

## The three operations

| Operation | Effect |
| --- | --- |
| `allow` | Score and report as normal, but **do not trip `--fail-on`** |
| `deny` | Force `critical`, whatever the command would otherwise score |
| `rescore` | Pin to a named band |

**`allow` does not hide the finding.** The command keeps its real score and the
override is appended to the factor trace with its reason. Silent suppression is
indistinguishable from a missing rule, and the point of `why` is that whoever
reads the output in six months can tell which one they are looking at.

**`deny` is about policy, not danger.** `kubectl get pods --context prod-eu` is
read-only and scores nothing on its own; denying it says *this is not done from
here*, which is a different statement and one the tool could not otherwise make.

## Every override needs a `why`

It is required, and a missing one is a hard error rather than a default. An
override with no stated reason is how a config file becomes a list nobody can
safely delete from — two years later, nobody remembers whether that `allow` was
a considered decision or a Friday afternoon.

## Precedence

1. **`deny`** — has to survive an `allow` written by someone who did not know
   about it.
1. **`rescore`**
1. **`allow`**

Within an operation, the first matching entry wins.

Against the other flags:

- **`--strict`** raises unknown commands to medium. An explicit `allow` still
  holds the gate open — the repo has said it knows what that command is, which
  is exactly the information `--strict` is complaining it lacks.
- **`--fail-on`** reads the overridden levels, minus anything allowed. The
  printed summary reports what the commands really score, so an allowed `high`
  still reads `high`; only the exit status ignores it.
- **`--no-config`** ignores a discovered file entirely. A `--config` naming a
  file that does not exist is an error, not a shrug: running without the policy
  you asked for silently applies a different one.

## Matching is globs, not regexes

`fnmatch` against the whole command string, so `kubectl delete ns ci-*` and
`terraform apply*` work as they read, and an exact command matches itself.

Regex was considered and rejected. A glob in a file that governs what a safety
gate lets through is reviewable at a glance; a regex in the same position is a
thing people paste and nobody audits.

## Why JSON and not TOML

`tomllib` is 3.11+, and scoville supports 3.10. The two ways round that —
vendoring a parser, or dropping a supported Python — both cost more than comment
syntax is worth for a file where every entry already carries a mandatory `why`.
If the floor ever moves to 3.11, switching is a one-line change in
`load_config()`.

## In `--format json`

Every overridden command carries an `override` object, so a pipeline can tell an
allowed `high` from an unreviewed one:

```json
{
  "command": "terraform apply",
  "level": "critical",
  "override": {
    "action": "rescore",
    "match": "terraform apply*",
    "level": "critical",
    "why": "our state is shared across three teams; apply is never routine"
  }
}
```
