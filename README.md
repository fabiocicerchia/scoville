# 🌶 scoville

> **Risk posture for shell commands, before you run them.**

[![CI](https://github.com/fabiocicerchia/scoville/actions/workflows/ci.yml/badge.svg)](https://github.com/fabiocicerchia/scoville/actions/workflows/ci.yml)
[![Code Quality](https://github.com/fabiocicerchia/scoville/actions/workflows/code-quality.yml/badge.svg)](https://github.com/fabiocicerchia/scoville/actions/workflows/code-quality.yml)
[![Security](https://github.com/fabiocicerchia/scoville/actions/workflows/security.yml/badge.svg)](https://github.com/fabiocicerchia/scoville/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fabiocicerchia/scoville/badge)](https://securityscorecards.dev/viewer/?uri=github.com/fabiocicerchia/scoville)
[![CI carbon](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/fabiocicerchia/scoville/gh-pages/badge.json)](.github/workflows/carbon-badge.yml)
[![Release](https://img.shields.io/github/v/release/fabiocicerchia/scoville)](https://github.com/fabiocicerchia/scoville/releases)

A Scoville scale for your terminal: how spicy is this command, and what does it
burn? Give it a command, a pipeline or a whole script; get a score, a blast
radius, a reversibility verdict — and every factor that contributed, so you can
disagree with it.

Risk is not a property of a binary. It is a property of
`binary + flags + target + context`. `rm` is bad, `rm -rf` is worse,
`rm -rf /` is unrecoverable. scoville scores that escalation instead of
pattern-matching a deny-list. Stdlib-only, no dependencies.

> **0.x — scores are judgement, not measurement.** The corpus in
> `tests/corpus.tsv` pins every command to a band, so a rule change that
> moves one has to fail the suite; the *numbers* inside a band will still
> shift as rules land. Treat the band as the contract and pin a version if
> you gate on it. It is a safety tool for commands written in good faith,
> **not** a sandbox — see [Known limits](#known-limits).

```console
$ scoville 'rm -rf $BUILD_DIR/'
rm -rf $BUILD_DIR/
  CRITICAL    98/100  ·  scope: host  ·  irreversible
     +35  rm unlinks immediately: no trash, no undo
     +15  -r/-R recurses into every subdirectory below the target
      +8  -f suppresses every prompt and error: nothing will stop it midway
     +40  if $BUILD_DIR is unset or empty this expands to `/` — the classic `rm -rf $DIR/` incident
    ↳ safer: `rm -i`, or move to a staging dir and delete it later
```

## How it works

One pass, no shell. Input is split by a quote-, escape- and comment-aware
splitter, then each command runs the same pipeline:

```
  "sudo docker run --privileged acme/importer:1.2 && rm -rf $BUILD/"
      │
      ├─ split ──────────────► one command per &&/||/;/newline/pipe
      │
      ▼  for each command
  strip wrappers ──────────► sudo env nohup timeout xargs ...  (privilege noted, not lost)
      │
  pick rule ───────────────► binary + regex over argv → base points, scope, revert, why
      │                       specific beats generic, even when it scores lower
      │
      ├─ amplifiers ────────► -r --force --privileged 0.0.0.0/0 ...      (+)
      ├─ softeners ─────────► -i --force-with-lease --preserve-root ...  (−)
      ├─ targets ───────────► /  /etc  ~  /dev/sda  $VAR/  build/        (±)
      ├─ privilege ─────────► sudo/doas/su → scope host                  (+)
      ├─ carried payload ───► docker exec | kubectl exec -- | ssh | sh -c
      │                       scored recursively, folded back with a context weight
      └─ dampeners ─────────► --dry-run --check -n → capped at 12, reversible
      │
      ▼
  clamp 0–100 ─────────────► band  ·  widest scope  ·  hardest reversibility
```

Scope and reversibility are the **widest** and **hardest** value any factor
contributed, never an average: one file touched irreversibly and one host
touched reversibly reports `host` and `irreversible`.

The full order, with the precedence rules that keep the tables from
double-counting, is in [BEHAVIOUR.md](BEHAVIOUR.md).

## Install

```sh
pipx install git+https://github.com/fabiocicerchia/scoville
```

Or with pip:

```sh
pip install git+https://github.com/fabiocicerchia/scoville
```

From a clone:

```sh
pipx install .        # or: pip install .
```

Or as a container — published to GHCR on every release:

```sh
docker run --rm ghcr.io/fabiocicerchia/scoville 'rm -rf $BUILD_DIR/'
```

## Usage

```sh
scoville 'kubectl delete ns prod'   # one or more commands, quoted
scoville -f deploy.sh               # a whole script, with line numbers
cat job.sh | scoville               # or stdin

scoville 'docker run acme/importer:1.2' --introspect   # resolve what actually runs
scoville -f deploy.sh --fail-on high                   # CI / agent gate
scoville 'rm -rf /' --format json                      # machine-readable
scoville --list-rules                                  # the whole rule set
scoville --why K8S-DELETE-NS                            # why that rule exists
```

Exit codes: `0` below threshold, `1` at or above `--fail-on`, `64` usage error.

The whole interface:

```console
$ scoville --help
usage: scoville [-h] [-f FILE] [--format {text,json}]
                [--scale {bands,peppers}]
                [--fail-on {safe,low,medium,high,critical}] [--strict]
                [--introspect] [--quiet] [--verbose] [--no-color]
                [--config PATH] [--no-config] [--list-rules] [--why RULE]
                [--version]
                [command ...]

positional arguments:
  command               command(s) to analyze; '-' reads stdin

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  analyze a script file
  --format {text,json}  text for humans, json for anything downstream
  --scale {bands,peppers}
                        how to name the levels: bands (safe..critical) or
                        peppers (bell pepper..carolina reaper). Text output
                        only
  --fail-on {safe,low,medium,high,critical}
                        exit 1 when any command reaches this level
  --strict              treat unrecognised commands as medium risk
  --introspect          resolve hidden image/container entrypoints via read-
                        only docker inspect
  --quiet, -q           one line per command
  --verbose, -v         show zero-weight factors too
  --no-color            never colourise (a non-tty and NO_COLOR already
                        disable it)
  --config PATH         override file (default: nearest .scovillerc at or
                        above the analysed file's directory)
  --no-config           ignore any .scovillerc that would otherwise be
                        discovered
  --list-rules          print every rule and amplifier, then exit
  --why RULE            print the long form for one rule or amplifier id (as
                        printed by --list-rules and on every finding), then
                        exit
  --version             show program's version number and exit
```

And a real run of two commands:

```console
$ scoville 'kubectl delete ns prod' 'git push --force origin main'
kubectl delete ns prod
  CRITICAL    95/100  ·  scope: cluster  ·  irreversible
     +80  deleting a namespace cascades to everything inside it, PVCs included
     +15  the target names a production environment
    ↳ safer: there is no undo and no controller that will rebuild it — export the namespace first
    ↳ why:   scoville --why K8S-DELETE-NS

git push --force origin main
  HIGH        80/100  ·  scope: network  ·  irreversible
     +55  force-push overwrites remote history; other clones diverge silently
     +25  force-pushing the default branch: everyone else's clone breaks on the next pull
    ↳ safer: `--force-with-lease` refuses when the remote moved under you
    ↳ why:   scoville --why GIT-PUSH-F
scoville: 2 commands, worst CRITICAL 95/100 · scope cluster · irreversible

```

More in [`docs/getting-started.md`](docs/getting-started.md).

## The payload, not the wrapper

`docker exec` is a middling risk on its own; what matters is what it carries.
scoville unwraps `docker exec/run`, `kubectl exec --`, `ssh host …`, `sh -c`,
`ansible -a`, `find -exec`, `sudo`, `xargs` and command substitutions, scores
the payload, and folds it back with a context weight — a container is
*narrower* than the host, a fleet is *wider*.

The same problem wears other costumes: a wrapper script, a make target, an npm
script, an image `ENTRYPOINT`. `--introspect` reads them — resolving `foo.sh`,
`Makefile` targets, `package.json` scripts and image entrypoints from disk and
read-only `docker inspect` calls, recursively, with a cycle guard. Nothing is
ever executed. Reading resolves uncertainty in *both* directions: a wrapper that
turns out to run `ls` scores lower once it has been read, not higher.

More in [`docs/architecture.md`](docs/architecture.md).

## Scoring

A 0–100 score in five bands, plus two orthogonal facets — **scope**
(`none → … → account`) and **reversibility** (`reversible → recoverable →
irreversible`) — because `terraform destroy` and `rm -rf ~/notes` can score
similarly and still deserve different answers.

`--scale peppers` names the bands the way people already talk about risky
commands: bell pepper, jalapeño, cayenne, habanero, carolina reaper.

More in [`docs/scoring.md`](docs/scoring.md).

## Rules

259 rules, 64 amplifiers and 8 softeners across filesystem and devices,
permissions, system and service state, networking, package managers, git,
containers, Kubernetes, Terraform/Pulumi, AWS/GCP/Azure, databases, backup
tooling, storage, virtualisation, audit trail and config management. Resource
CLIs where the blast radius and the traffic are both high — `vault`, `velero`,
`argocd`, `openstack`, `flyctl`, `gh` among them — are enumerated per resource;
the remaining ~40 are covered by verb classification rather than enumeration,
and an unknown CLI still cannot score `safe` on `delete`.

The rule set *is* the product; it is meant to grow. Every rule carries a
plain-language *why*, and destructive ones carry a safer alternative.

More in [`docs/rules.md`](docs/rules.md).

## Uses

**Guardrail for AI coding agents.** Gate commands before an agent runs them —
a Claude Code `PreToolUse` hook, one line:

```sh
scoville "$COMMAND" --fail-on high --strict --quiet || exit 2
```

**CI / pre-commit.** Score the shell in your pipelines and Makefiles:

```sh
scoville -f scripts/deploy.sh --fail-on critical
```

**Review aid.** `--format json` per changed script, posted on the PR.

## Known limits

scoville is a splitter, not a shell; it cannot see values, has no control flow,
and knows nothing about your environment. It is **not adversary-resistant** —
a safety tool for commands written in good faith, not a sandbox. Do not put it
between untrusted input and a shell.

More in [`docs/limits.md`](docs/limits.md).

## Documentation

Full docs live in [`docs/`](docs/) (also published via mkdocs). Runnable
examples live in [`examples/`](examples/).

Two references sit at the repository root because they are generated and
executed by the test suite:

- [BEHAVIOUR.md](BEHAVIOUR.md) — how it behaves, in order, and where it stops.
- [INVENTORY.md](INVENTORY.md) — every command it is calibrated against, with
  the band, scope and reversibility each one gets.

## Common errors

**`scoville: nothing to analyze`** (exit 64)
Nothing reached it. With no arguments scoville reads stdin, so an empty pipe
or a `-f` pointing at an empty file lands here rather than scoring zero
commands — the difference matters when it is wired into a hook.

**`scoville: [Errno 2] No such file or directory: 'deploy.sh'`** (exit 64)
`-f` is resolved relative to the working directory, and `--introspect`
resolves the wrappers it finds relative to the *script's* directory, not
yours.

**`--scale peppers` printed bands anyway.**
The pepper names are a text-output affectation; `--format json` always
reports the band names, because that is what a consumer can compare.

**An unknown CLI scored `safe`.**
Only without `--strict`. A gate should pass `--strict`, which floors
unrecognised commands at `medium` — the rule set is meant to grow, and
"never heard of it" is not evidence of harmlessness.

## References

The scores are judgement, but the failure modes they encode are documented
ones:

- [`rm(1)`](https://man7.org/linux/man-pages/man1/rm.1.html) — `--preserve-root`
  is the default and `--no-preserve-root` is the reason that amplifier exists.
- [`git push --force-with-lease`](https://git-scm.com/docs/git-push#Documentation/git-push.txt---no-force-with-lease)
  — why the careful spelling has to score below the careless one.
- [Kubernetes: namespace deletion](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)
  — what cascades, and why `kubectl delete ns` outranks `kubectl delete pod`.
- [Docker: runtime privilege](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
  — what `--privileged` actually hands over.
- [`sysexits.h`](https://man.freebsd.org/cgi/man.cgi?query=sysexits) — where
  the 64 usage exit code comes from.
- Claude Code
  [hooks](https://docs.claude.com/en/docs/claude-code/hooks) — the `PreToolUse`
  contract the agent-guardrail example plugs into.

## Release cycle

[Semantic Versioning](https://semver.org/), cut by release-please from
[Conventional Commits](https://www.conventionalcommits.org/). Releases are
drafts until their assets are attached, so a tag always has its artifacts.

- **Major** — a change to the output contract: the JSON shape, the exit
  codes, or the band boundaries.
- **Minor** — new rules, new amplifiers, new flags. A command can change
  band here, and when it does, `tests/corpus.tsv` changes in the same commit
  with the reason in the message.
- **Patch** — fixes that leave every corpus band where it was.

Pre-1.0 the minor number carries the band changes; pin an exact version if a
gate depends on them.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md). scoville uses
[Conventional Commits](https://www.conventionalcommits.org/) and release-please.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please don't open a
public issue.

## Support

Need help implementing this? [Get in touch](https://fabiocicerchia.it/contact).

## License

[Apache-2.0](LICENSE) © Fabio Cicerchia
