# scoville

**Risk posture for shell commands, before you run them.** A Scoville scale for
your terminal: how spicy is this command, and what does it burn? Give it a command,
a pipeline or a whole script; get a score, a blast radius, a reversibility
verdict — and every factor that contributed, so you can disagree with it.

[![CI](https://github.com/fabiocicerchia/scoville/actions/workflows/ci.yml/badge.svg)](https://github.com/fabiocicerchia/scoville/actions/workflows/ci.yml)
[![Code Quality](https://github.com/fabiocicerchia/scoville/actions/workflows/code-quality.yml/badge.svg)](https://github.com/fabiocicerchia/scoville/actions/workflows/code-quality.yml)
[![Security](https://github.com/fabiocicerchia/scoville/actions/workflows/security.yml/badge.svg)](https://github.com/fabiocicerchia/scoville/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fabiocicerchia/scoville/badge)](https://securityscorecards.dev/viewer/?uri=github.com/fabiocicerchia/scoville)
[![CI carbon](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/fabiocicerchia/scoville/gh-pages/badge.json)](.github/workflows/carbon-badge.yml)

Risk is not a property of a binary. It is a property of
`binary + flags + target + context`. `rm` is bad, `rm -rf` is worse,
`rm -rf /` is unrecoverable. `aws s3 ls` is free, `aws s3 rb --force` is not.
`ifup` is fine, `ifdown` is how you lose a remote host; `mount` is additive and
`umount /` is not; `shutdown -c` *cancels* a shutdown. scoville scores that
escalation instead of pattern-matching a deny-list.

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

## The payload, not the wrapper

`docker exec` is a middling risk on its own; what matters is what it carries.
scoville unwraps `docker exec/run`, `kubectl exec -- `, `ssh host …`,
`sh -c`, `ansible -a`, `find -exec`, `sudo`, `xargs` and command
substitutions, scores the payload, and folds it back with a context weight —
a container is *narrower* than the host, a fleet is *wider*.

```console
$ scoville 'docker exec web ls /app' 'docker exec -u root api rm -rf /var/lib/data'
docker exec web ls /app
  LOW         20/100  ·  scope: container  ·  reversible
     +20  runs a command inside a running container: scored on the payload below
       ·  payload `ls /app` is safe — runs inside the container: its filesystem, its mounts, its credentials

docker exec -u root api rm -rf /var/lib/data
  HIGH        77/100  ·  scope: container  ·  irreversible
     +20  runs a command inside a running container: scored on the payload below
      +8  runs as root inside the container
     +49  payload `rm -rf /var/lib/data` is medium — runs inside the container: its filesystem, its mounts, its credentials
```

The same problem wears other costumes: a wrapper script, a make target, an
npm script. `./deploy.sh` shows you nothing, so it is scored as opaque and
`--introspect` reads it — resolving `foo.sh`, `Makefile` targets and
`package.json` scripts from disk, recursively, with a cycle guard:

```console
$ scoville './foo.sh prod'
  MEDIUM      40/100  ·  scope: none  ·  reversible
     +20  runs `./foo.sh`: the commands are inside the script, not on this line — re-run with --introspect to read it

$ scoville './foo.sh prod' --introspect
  CRITICAL   100/100  ·  scope: host  ·  irreversible
     +98  resolved wrapper `./foo.sh` line 6 runs `rm -rf "$BUILD_DIR"/`, which is critical
```

Reading resolves uncertainty in *both* directions — a wrapper that turns out
to run `ls` scores lower once it has been read, not higher.

When the payload is **hidden behind an image ENTRYPOINT**, the command line
alone cannot tell you anything — so scoville says so, and `--introspect`
resolves it with read-only `docker inspect` calls (never a pull, never a run):

```console
$ scoville 'docker run acme/importer:1.2'
docker run acme/importer:1.2
  MEDIUM      40/100  ·  scope: container  ·  reversible
     +20  starts a container: what actually runs is the image ENTRYPOINT/CMD unless overridden
     +20  no explicit command: what runs is the image ENTRYPOINT/CMD, not this line; re-run with --introspect to resolve it

$ scoville 'docker run acme/importer:1.2' --introspect
docker run acme/importer:1.2
  CRITICAL   100/100  ·  scope: container  ·  irreversible
     +20  starts a container: what actually runs is the image ENTRYPOINT/CMD unless overridden
     +85  resolved entrypoint `/bin/sh -c 'rm -rf /data'` is critical — runs in a fresh container from this image
      +8  the image runs as root
```

## Install

```sh
pipx install git+https://github.com/fabiocicerchia/scoville
```

From a clone:

```sh
pipx install .        # or: pip install .
```

## Usage

```text
scoville COMMAND...            # one or more commands, quoted
scoville -f deploy.sh          # a whole script, with line numbers
cat job.sh | scoville          # or stdin

  --format json                machine-readable, every factor included
  --fail-on LEVEL              exit 1 at safe|low|medium|high|critical
  --strict                     unknown commands count as medium, not safe
  --introspect                 read wrapper scripts, make targets, npm scripts
                               and image entrypoints (read-only; never executes)
  --scale bands|peppers        name the levels safe..critical, or by pepper
  --quiet                      one line per command
  --verbose                    show zero-weight factors too
  --list-rules                 the whole rule set
```

Exit codes: `0` below threshold, `1` at or above `--fail-on`, `64` usage error.

## How the score works

Every command starts from a **base** (what the binary does), then collects
**amplifiers** (flags, targets, privilege, production hints) and
**dampeners** (`--dry-run`, regenerable targets like `node_modules`). The
factors are summed and clamped to 0–100:

| Band | Score | Meaning |
|---|---|---|
| `safe` | 0–14 | reads state, changes nothing |
| `low` | 15–34 | local, trivially undone |
| `medium` | 35–59 | mutates real state, recoverable with effort |
| `high` | 60–84 | destructive and scoped |
| `critical` | 85–100 | unbounded, irreversible, or both |

Two orthogonal facets are reported alongside the score, because they answer
different questions:

- **scope** — `none → file → directory → container → host → network → cluster → account`
- **reversibility** — `reversible → recoverable → irreversible`

`terraform destroy` and `rm -rf ~/notes` can score similarly and still deserve
different answers; the facets are what make that visible.

### The scale it is named after

`--scale peppers` names the bands the way people already talk about risky
commands. Same analysis, same score, same factors — only the label changes, and
`--format json` always stays on the band names.

| Band | Pepper | Scoville units |
|---|---|---|
| `safe` | bell pepper | 0 |
| `low` | jalapeño | 2,500–8,000 |
| `medium` | cayenne | 30,000–50,000 |
| `high` | habanero | 100,000–350,000 |
| `critical` | carolina reaper | 1,600,000–2,200,000 |

```console
$ scoville 'aws s3 ls' 'apt install nginx' 'aws s3 rb s3://assets' 'rm -rf /' --scale peppers
aws s3 ls
  BELL PEPPER                 0/100  ·  scope: none  ·  reversible
apt install nginx
  🌶🌶 CAYENNE               35/100  ·  scope: host  ·  recoverable
aws s3 rb s3://assets
  🌶🌶🌶 HABANERO            75/100  ·  scope: account  ·  irreversible
rm -rf /
  🌶🌶🌶🌶 CAROLINA REAPER  100/100  ·  scope: host  ·  irreversible
```

Wilbur Scoville's 1912 test diluted an extract until a panel of tasters could
no longer detect the burn, and the dilution factor was the score. Hand-calibrated
judgement, made reproducible — which is what [`tests/corpus.tsv`](tests/corpus.tsv)
is for.

## Rules

200 rules, 55 amplifiers and 5 softeners across filesystem and devices, permissions,
system and service state, networking (including lockout risk), package
managers, git, containers, Kubernetes, Terraform/Pulumi, AWS/GCP/Azure,
databases, backup tooling, storage, virtualisation, audit trail and config
management. `--list-rules` prints all of it.

**[INVENTORY.md](INVENTORY.md) is the catalogue** — 315 commands with the band,
scope and reversibility each one gets. It is generated from
[`tests/corpus.tsv`](tests/corpus.tsv) and executed by the suite, so a rule
change that moves a command between bands fails the tests rather than
silently recalibrating the tool. That corpus is also where new coverage
starts: add the command and the band you expect, then make it pass.

Some signals mean the same thing on **any** binary, so they are scored
generically rather than per-command: `--force`, `-y`/`--yes` in all its
spellings (`--noconfirm`, `--batch`, `--no-interaction`, and combined flags
like `-qy`), `--purge`, a credential in argv (visible in `ps` to every user on
the host), disabled TLS or package-signature verification, and `0.0.0.0/0`. Softeners work the same
way in reverse — `rm -i`, `sed -i.bak`, `--force-with-lease` and ansible's
`--limit` score *below* their careless form, which is what makes a
`--fail-on` gate usable rather than something people switch off.

Remote code is tracked in every spelling it travels under, not just the
famous one: `curl … | bash`, `bash <(curl …)`, `eval "$(curl …)"`,
`base64 -d | sh`, and the two-step `curl -o f URL && bash f` — in a script
nothing read the file between those steps, so it is the same unreviewed code.

Exposure is scored as its own failure mode, separate from destruction:
`aws iam create-access-key`, `--acl public-read`, a `0.0.0.0/0` security-group
rule, `--member=allUsers`, a `cluster-admin` binding and `setenforce 0` are
all about widening access rather than deleting anything.

**The long tail is covered by verb classification, not enumeration.** Roughly
50 resource CLIs — `hcloud`, `scw`, `doctl`, `linode-cli`, `flyctl`, `heroku`,
`wrangler`, `gh`, `openstack`, `incus`, `pscale`, `vault`, `velero`, `argocd`
and friends — are scored by the verb in command position, so
`hcloud server delete` is `high` and `hcloud server list` is `safe` without
a per-CLI rule. Position matters: `hcloud server describe delete-me` stays
`safe`.

Where a verb lies, a specific rule overrides the generic one **even when it
scores lower**: `virsh destroy` powers a domain off rather than deleting it,
so it sits below `virsh undefine`.

And for a CLI nobody has enumerated yet, a destructive verb still cannot score
`safe` — `frobctl delete cluster prod` is `high`, flagged as a floor rather
than a measurement. That is the failure mode that would otherwise make a gate
worthless the day a new CLI ships.

The rule set *is* the product; it is meant to grow. Every rule carries a
plain-language *why*, and destructive ones carry a safer alternative.

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

**[BEHAVIOUR.md](BEHAVIOUR.md) documents how the tool works and where it stops**
— the scoring order, precedence, carrier weights, introspection, and a full
limitations section. The short version:

- It is a **splitter, not a shell**: quoting, `$(…)`, comments, keywords and
  operators are handled; heredocs, arrays and arithmetic expansion are not.
  Nothing is ever executed to find out.
- It **cannot see values**. `rm -rf $DIR` is scored on the shape of the
  argument; if `DIR` holds `/etc`, there is no way to know.
- It has **no control flow**: a command inside a branch that never runs is
  still scored.
- It knows **nothing about your environment** — which cluster, which account,
  whether a backup exists. Production detection is a string heuristic.
- Scores are **calibrated judgement, not measurement**. Ordinal, and meant to
  be argued with; `tests/corpus.tsv` is where that argument gets settled.
- It is **not adversary-resistant**. It is a safety tool for commands written
  in good faith, not a sandbox: quoting, encoding or run-time construction
  defeats it by design. Do not put it between untrusted input and a shell.

## Status & roadmap

- [x] Escalating scoring engine, scope + reversibility facets, factor traces
- [x] Payload unwrapping for carrier commands + read-only entrypoint introspection
- [x] Pipeline, command-substitution and script analysis with line numbers
- [x] Verb classification + unknown-CLI floor for the long tail
- [x] A 315-command inventory, executed as tests (425 assertions)
- [x] JSON output, `--fail-on` gate
- [ ] `.scovillerc` for per-repo overrides (allow, deny, re-score)
- [ ] Per-CLI rules for the resource CLIs currently handled only generically
- [ ] Kubernetes RBAC awareness: score `kubectl` against what the context can do
- [ ] `--why RULE` to print the incident class a rule comes from
- [ ] Shell function/alias resolution before scoring

## Documentation

- [BEHAVIOUR.md](BEHAVIOUR.md) — how it behaves, in order, and where it stops
- [INVENTORY.md](INVENTORY.md) — every command it is calibrated against
- [`docs/`](docs/) — architecture and getting started; [`examples/`](examples/) — runnable examples

## Development

`make dev` then `make test` / `make lint`. `make setup` installs the pre-commit
hook that CI runs too.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) — please don't open a
public issue.

## License

MIT — see [LICENSE](LICENSE).
