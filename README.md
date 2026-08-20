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
```

Exit codes: `0` below threshold, `1` at or above `--fail-on`, `64` usage error.

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

200 rules, 55 amplifiers and 5 softeners across filesystem and devices,
permissions, system and service state, networking, package managers, git,
containers, Kubernetes, Terraform/Pulumi, AWS/GCP/Azure, databases, backup
tooling, storage, virtualisation, audit trail and config management. The long
tail — ~50 resource CLIs — is covered by verb classification rather than
enumeration, and an unknown CLI still cannot score `safe` on `delete`.

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
