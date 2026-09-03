# Getting Started

## Prerequisites

Python 3.10 or newer. Nothing else — scoville has no runtime dependencies.

## Install

```sh
pipx install git+https://github.com/fabiocicerchia/scoville
```

From a clone:

```sh
pipx install .        # or: pip install .
```

### As a container

Every release publishes a multi-arch image (`linux/amd64`, `linux/arm64`) to
GHCR, tagged `vX.Y.Z`, `vX.Y` and `latest`:

```sh
docker run --rm ghcr.io/fabiocicerchia/scoville 'rm -rf $BUILD_DIR/'
```

Pass a script on stdin the same way:

```sh
docker run --rm -i ghcr.io/fabiocicerchia/scoville < deploy.sh
```

`--introspect` is the one thing the container cannot do on its own: it reads
wrapper scripts and asks the docker socket about images, and neither is mounted
in. Mount what it needs to resolve, read-only, or run scoville on the host for
that.

## First run

```sh
scoville 'rm -rf $BUILD_DIR/'
```

You get a band, a score out of 100, the blast radius, the reversibility
verdict, and one line per factor that contributed — including the safer
alternative where there is one.

## Day to day

```sh
scoville 'kubectl delete ns prod' 'aws s3 ls'   # several commands at once
scoville -f scripts/deploy.sh                   # a whole script, with line numbers
cat job.sh | scoville                           # or stdin
```

Useful flags:

| Flag | What it does |
|---|---|
| `--fail-on LEVEL` | exit 1 at `safe`\|`low`\|`medium`\|`high`\|`critical` |
| `--strict` | unknown commands count as medium, not safe |
| `--introspect` | read wrapper scripts, make targets, npm scripts and image entrypoints (read-only; never executes) |
| `--format json` | machine-readable, every factor included |
| `--scale peppers` | name the bands after the peppers instead |
| `--list-rules` | print the whole rule set |
| `--why RULE` | the long form for one rule: what it matches, why that band |

Exit codes: `0` below threshold, `1` at or above `--fail-on`, `64` usage error.

## As a gate

An agent guardrail — a Claude Code `PreToolUse` hook, one line:

```sh
scoville "$COMMAND" --fail-on high --strict --quiet || exit 2
```

In CI, over the shell you actually ship:

```sh
scoville -f scripts/deploy.sh --fail-on critical
```

## Development

```sh
make dev     # editable install with dev dependencies
make test    # pytest
make lint    # ruff
make setup   # install the pre-commit hook CI also runs
```
