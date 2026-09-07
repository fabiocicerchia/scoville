# How scoville behaves

What the tool does, in the order it does it, and — just as importantly — what
it does not do. [README.md](README.md) is the introduction;
[INVENTORY.md](INVENTORY.md) is the catalogue of scored commands. This file is
the reference: read it before trusting a score, and before arguing with one.

- [The model](#the-model)
- [Reading the input](#reading-the-input)
- [Scoring one command](#scoring-one-command)
- [Precedence and double counting](#precedence-and-double-counting)
- [Commands that carry other commands](#commands-that-carry-other-commands)
- [Wrappers and introspection](#wrappers-and-introspection)
- [Remote code](#remote-code)
- [Commands it has never heard of](#commands-it-has-never-heard-of)
- [Output and exit codes](#output-and-exit-codes)
- [Limitations](#limitations)

---

## The model

Risk is treated as a property of `binary + flags + target + context`, never of
the binary alone. Every finding is a **factor** with points and a plain-language
reason; the factors are summed, clamped to 0–100, and mapped to a band.

| Band       | Score  | Meaning                                     |
| ---------- | ------ | ------------------------------------------- |
| `safe`     | 0–14   | reads state, changes nothing                |
| `low`      | 15–34  | local, trivially undone                     |
| `medium`   | 35–59  | mutates real state, recoverable with effort |
| `high`     | 60–84  | destructive and scoped                      |
| `critical` | 85–100 | unbounded, irreversible, or both            |

Two facets are reported alongside the score, because a single number cannot
answer both questions:

- **scope** — how far it reaches:
  `none → file → directory → container → host → network → cluster → account`
- **reversibility** — how hard it is to undo:
  `reversible → recoverable → irreversible`

Each is the **widest/hardest** value contributed by any factor, not an average.
A command that touches one file irreversibly and one host reversibly reports
`host` and `irreversible`.

The score orders commands *within* a band. The band is what you should make
decisions on; the individual points exist so you can see the reasoning and
disagree with it.

---

## Reading the input

scoville accepts a command string, several of them, a script via `-f`, or
stdin. Input is split into individual commands by a quote-, escape- and
comment-aware splitter — **not** a shell.

What the splitter handles:

- separators `;`, newline, `&&`, `||`, `|`, `&`
- single and double quotes, and backslash escapes
- `#` comments and shebangs
- shell keywords (`if`, `then`, `fi`, `do`, `done`, …) and function-definition
  lines, which are recognised as structure and scored zero — a function's body
  is scored on its own lines
- `$(…)` and backtick substitutions, which are extracted and scored **as their
  own commands** (they run first, and are easy to miss when skimming)
- grouping characters left dangling by a split — `(cd x && rm y)` splits into
  two commands without stray parentheses

Each command is then tokenised, and wrappers are peeled off to find the binary
that matters: environment assignments (`FOO=bar cmd`), and `sudo`, `doas`,
`su`, `env`, `nohup`, `time`, `nice`, `xargs`, `timeout`, `watch`, `flock` and
friends. `sudo` and `doas` also record that the command runs as root.

Line numbers are reported for `-f` input. A command that spans several lines is
reported at the line it starts on.

---

## Scoring one command

In order:

1. **Base rule.** The binary (plus a regex over its arguments) selects one rule,
   which supplies the base points, an initial scope and reversibility, the
   *why*, and often a safer alternative.
1. **Amplifiers.** Flags and arguments that make the same command worse — `-r`,
   `--no-preserve-root`, `--privileged`, `--all`, `--force`, a credential in
   argv, `0.0.0.0/0`. Some also widen the scope or harden reversibility.
1. **Softeners.** The same mechanism with negative points, for the careful form
   of a command: `rm -i`, `sed -i.bak`, `--force-with-lease`, `--preserve-root`,
   ansible's `--limit`. Without these a gate is unusable, because the careful
   spelling would score the same as the careless one.
1. **Targets.** For commands that act on paths, each argument is examined: the
   filesystem root, an exact system directory, a path *under* one (weighted by
   whether losing it breaks the host or loses payload), a home directory, a
   device node, a regenerable build directory (which *subtracts*), and the
   classic `$VAR/` that becomes `/` when the variable is unset.
1. **Privilege.** Running under `sudo`/`doas`/`su` adds points and widens scope
   to `host`.
1. **Carried payloads and wrappers.** See the two sections below.
1. **Dampeners.** `--dry-run`, `--dryrun`, `--what-if`, `--check`, and `-n` for
   the binaries where it means dry run. A dampened command is **capped at 12
   points** (`safe`) and reported as reversible, regardless of what it would
   otherwise have scored.

The result is clamped to 0–100.

---

## Precedence and double counting

Two mechanisms keep the tables honest as they grow:

**Specific beats generic.** Rules may be marked generic — the verb-classifying
ones such as "any `<cli> … delete`" or `kubectl delete`. A specific rule always
wins over a generic one, *including when it scores lower*. This is what makes
`virsh destroy` (a power-off, 45) rank below `virsh undefine` (a deletion, 70),
and `kubectl delete pod` (a restart the controller undoes, 25) below
`kubectl delete deploy` (55).

**Rules subsume their own amplifiers.** A rule that exists *because* of a flag
declares that it subsumes the generic amplifier for it, so the flag is not
counted twice. `git push --force` scores force once, via the rule; `fsck -y`
scores its auto-confirm once, via the rule.

---

## Commands that carry other commands

A wrapper's risk is its payload. These are unwrapped, scored recursively, and
folded back with a weight reflecting where the payload lands:

| Carrier                            | Context         | Weight |
| ---------------------------------- | --------------- | ------ |
| `docker exec`, `docker run/create` | container       | 0.85   |
| `kubectl exec … --`, `kubectl run` | pod             | 0.85   |
| `ssh host …`                       | remote host     | 1.0    |
| `sh -c`, `bash -c`                 | same host       | 1.0    |
| `find -exec`, `find -delete`       | once per match  | 1.15   |
| `ansible -a`, `ansible -m shell`   | whole inventory | 1.2    |

A container is *narrower* than the host — its filesystem is usually
reconstructible — so `docker exec web rm -rf /` scores below `rm -rf /` on the
host. A fleet is *wider*, so the same command through ansible scores above it.
Weights compose with the carrier's own amplifiers: `--privileged`, a `/` bind
mount or `--pid=host` widen the scope back to `host`.

Recursion is limited to 3 levels.

---

## Wrappers and introspection

Where the payload exists but is not written on the command line — an image
`ENTRYPOINT`, `./deploy.sh`, `make deploy`, `npm run reset-db` — the command is
scored as **opaque**, with a factor saying where the real commands live. This is
a deliberate design choice: the honest answer to "what does this do?" is
"that is not visible from here", not silence.

`--introspect` resolves them, **by reading only**:

- image and container entrypoints via `docker inspect` — never a pull, never a
  run; an image that is not local is reported as unresolved
- `./foo.sh` and `source foo.sh` from disk
- `Makefile` recipes for the named target
- `package.json` scripts for `npm`/`yarn`/`pnpm run`
- shell **functions and aliases defined in the analysed input** (and in what it
  sources): a call to a local function is scored as its body, and an alias is
  expanded to the command it really is

Resolved content is analysed recursively and reported with the file, the line
and the command that drove the score. Limits: 3 levels deep, 256 KB per file,
and a cycle guard so a script that runs itself terminates.

Introspection resolves uncertainty in **both** directions. A wrapper that turns
out to run `ls` scores *lower* once read, not higher.

Local definitions have three rules of their own:

- **Nothing outside the analysed input is read.** `~/.bashrc` is not consulted,
  so a script scores the same on any machine.
- **A name is resolved at the call site.** A function called *above* its own
  definition is not resolved — bash reads top to bottom — but a function that
  calls one defined below it is, because both are in scope by the time either
  runs. A later definition of the same name wins, which is what redefinition
  means, and an alias shadowing a real binary is the case most worth catching.
- **Recursion stops rather than unrolling.** A name already on the call chain
  contributes zero and says so; the non-recursive arm of the body is still
  scored. The guard is a call stack, not a visited set, so calling the same
  helper twice scores both calls.

Paths resolve against the directory of the file passed to `-f`, or the current
working directory otherwise.

### Kubernetes RBAC

Under `--introspect`, a `kubectl` line is also checked against the context that
would run it, with `kubectl auth can-i` — a `SelfSubjectAccessReview`, which
asks the API server *would you allow this* and creates, changes and runs
nothing.

| what `can-i` said                                              | effect                                             |
| -------------------------------------------------------------- | -------------------------------------------------- |
| `no`                                                           | **−30**, and the factor names the context it asked |
| `yes`, and `can-i '*' '*'` also `yes`                          | **+10**, scope widened to `cluster`                |
| `yes`                                                          | no change, recorded in the trace                   |
| nothing usable — no context, timeout, unreachable, unparseable | **no change**, recorded as "no answer"             |

The last row is the rule: **nothing is dampened unless a refusal is positively
established**, because a dampener that fires on a failed check under-reports
risk. `--kube-timeout` bounds one call, and a timeout is "no answer".

The refusal is points, not a cap: the context is read now and the command may
run later against a different one, which is also why the factor names it.
Verbs are mapped to the RBAC verbs they need (`apply` → `patch`) and short
resource names expanded (`ns` → `namespaces`) before the question is asked; an
unrecognised resource is passed through verbatim, because the RBAC resource
list is open.

---

## Remote code

Fetching code and executing it without reading it is tracked in every spelling
it travels under, not just the famous one:

- `curl … | sh`, and any fetcher into any interpreter
- decoders as fetchers: `base64 -d | sh`, `openssl`, `gunzip`, `xxd`
- `bash <(curl …)` and `eval "$(curl …)"` — substitution instead of a pipe
- the two-step `curl -o f URL && bash f`: paths written by a fetcher are
  remembered, and a later command that executes one of them is flagged, whether
  through an interpreter or directly after a `chmod +x`

The two-step case is scored slightly below the pipe, because a human at a
terminal *might* have read the file in between. In a script, nothing did.

`eval` is scored `high` on its own, before any of this. It is the one construct
that defeats every static reader, including this one: what runs is assembled at
run time and cannot be read from the line, so any reviewer — human or tool — is
being asked to approve something they cannot see. Text built from a variable or
a substitution scores higher still.

---

## Commands it has never heard of

An unrecognised binary is scored on flags and targets alone, at 5 points, and
reported with `"known": false` in JSON. But a **destructive verb in command
position** — `delete`, `destroy`, `terminate`, `purge`, `wipe`, `drop` — adds
40 and is explicitly labelled a floor rather than a measurement. `frobctl delete
cluster prod` scores `high` even though no rule for `frobctl` exists.

This is why around 40 resource CLIs are classified by verb rather than
enumerated: `hcloud server delete` is `high` and `hcloud server list` is `safe`
without a per-CLI rule, and position decides, so `hcloud server describe
delete-me` stays `safe`.

Classification is a floor, not a measurement, and it is replaced where the
measurement is worth having. The CLIs enumerated per resource — `vault`,
`velero`, `argocd`, `openstack`, `flyctl`, `gh`, and the storage and
virtualisation tools alongside them — score on *what* is being acted on
(`openstack volume delete` costs data, `openstack server stop` costs a reboot)
and on the CLI's own flags. `specific_clis()` and `generic_clis()` report the
split. Enumeration is per resource, not per binary: a subcommand with no rule of
its own still falls back to verb classification, so `gh label delete` is `high`
on the floor rather than unscored.

A specific rule always beats a generic one, **including when it scores lower**.
That is what lets a lying verb be corrected downwards: `vault kv delete` is a
soft delete Vault can undo, and scoring it as a destroy would train people to
ignore the one that cannot be undone (`vault kv destroy`).

`--strict` raises unknown commands from 5 to 40 (`medium`), for gates where
"nobody has reviewed this" should itself block.

---

## Per-repo overrides

A `.scovillerc` discovered from the analysed file's directory upwards (or named
with `--config`) can `allow`, `deny` or `rescore` commands matched by glob. Each
entry requires a `why`, and each override is appended to the factor trace rather
than applied silently — a suppressed finding keeps its real score and says who
suppressed it.

Precedence is `deny` > `rescore` > `allow`. An `allow` holds `--fail-on` open
but does not change the reported level, and survives `--strict`. See
[docs/config.md](docs/config.md).

---

## Output and exit codes

Text output prints every factor with its points and reason, then the safer
alternative where one exists. `--scale peppers` renames the bands
(bell pepper → carolina reaper) without changing any part of the analysis;
`--quiet` prints ASCII slugs (`carolina-reaper`) so it stays greppable, and
`--format json` always reports band names regardless of the scale. `--quiet` prints one line per command;
`--verbose` also shows zero-weight factors; `--format json` emits `overall` plus
one object per command with `score`, `level`, `scope`, `reversibility`,
`known`, `privileged`, `rule`, `factors[]`, `advice`, `carries[]` and `line`.
Each entry in `factors[]` carries `points`, `why` and `rule` — the id of the
rule or amplifier that produced it, or `null` for a factor that is not one (a
path, a carried payload, a dry-run dampener).

`overall` reports the **worst single command** in the input, with scope and
reversibility aggregated across all of them.

Every finding that scored also prints `↳ why: scoville --why <ID>`, and that
command prints the long form for the rule: what it matches and what it
deliberately does not, the class of incident it exists to prevent, why the band,
scope and reversibility are what they are, the safer alternative, and the
related rules including the generic ones it beats. Everything except the
incident paragraph is derived from the rule table, so the explanation and the
score cannot disagree. A rule with no incident paragraph written yet says so
rather than printing a formulaic one. An unknown id exits `64` and suggests the
closest matches; amplifier ids resolve in both the `FORCE` and `+FORCE`
spellings.

| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| 0    | below the `--fail-on` threshold, or no threshold given    |
| 1    | at or above `--fail-on`                                   |
| 64   | usage error — bad arguments, unreadable file, empty input |

---

## Limitations

Read this section before wiring scoville into anything that blocks.

### It is not a shell

The splitter is good enough to find command boundaries, and no more. It does
not implement heredocs, arrays, arithmetic expansion, brace expansion, or
parameter expansion with defaults (`${VAR:-x}`). It never executes anything to
find out what a command would do.

### It cannot see values

`rm -rf $DIR` is scored on the *shape* of the argument. scoville flags the case
where an unset variable would expand to `/`, because that is visible in the
text — but if `DIR` holds `/etc`, it cannot know. Variables, aliases and
functions defined elsewhere are not resolved.

A function's body is scored where it is **defined**, not where it is called: in
a script, `cleanup() { rm -rf "$BUILD_DIR"/; }` is reported at the `rm` line,
and the later call to `cleanup` scores as an unknown command. The worst score
for the file is still correct; the attribution is not.

### It has no control flow

Every command in a script is scored, including ones inside a branch that never
runs. There is no path sensitivity and no dead-code elimination. A `rm -rf /`
inside `if false; then … fi` is still reported as critical.

### It knows nothing about your environment

It does not know which cluster `kubectl` points at, which AWS profile or account
is active, whether a path exists, whether a bucket has versioning, whether a
database has a backup, or whether you have permission to run the command at all.
Production detection is a **string heuristic** on the command text: a host named
`prod-1` is flagged, a production host named `blue-4` is not.

### Scores are judgement, not measurement

They are ordinal, hand-calibrated against the 315-command corpus, and reflect
opinions you may not share — that `kill -9 1` is critical, that
`kubectl delete deploy` is medium because GitOps usually restores it, that a
container is narrower than a host. Every factor is printed so you can disagree.
`tests/corpus.tsv` is where a disagreement gets settled: change the expected
band, run the suite, and the tool either agrees or fails.

### Dampeners are trusted as written

`--dry-run` caps a score without checking that the binary actually has such a
flag, or that it means what it usually means. A typo'd dry-run flag will
under-score a real command. `--dry-run=server` is deliberately *not* treated as
a dampener, since it mutates on the server side.

### It is not adversary-resistant

This matters most, and is the easiest thing to forget when a tool returns a
number. scoville is a **safety** tool, for commands someone wrote in good faith
and for scripts nobody has read carefully. It is not a sandbox and not a
security boundary. Anyone who wants to get a command past it can: quote the
binary name (`r''m`), build it from variables, encode it, obfuscate it, or write
it to a file at run time and execute that. `eval` and run-time construction
defeat static reading by definition — which is why `eval` scores high rather
than being quietly ignored.

Do not use it as the only thing standing between untrusted input and a shell.

### Coverage is uneven and always will be

The rule set is the product and it grows. POSIX and the major cloud/container/
database tooling are covered densely; the long tail is covered by verb
classification and the unknown-command floor, which are heuristics. Windows and
PowerShell are not covered at all. Expect both false positives and false
negatives, and expect them to cluster in tools nobody has added a rule for yet.

### It scores commands, not plans

There is no cross-command reasoning beyond pipelines, substitutions, and
tracking a downloaded file to its execution. It does not know that a
`terraform plan` reviewed before an `apply` is safer than an `apply` alone, or
that a backup two lines earlier changes what a `DROP TABLE` costs.

### Introspection reads the file as it is now

`--introspect` reads a wrapper at analysis time. What actually runs later may
differ — the file can change, and `$PATH` decides which `foo.sh` is found. It
resolves what it can see from where it is run.

The same applies to the cluster: the kube context is read at scoring time and
the command may run later under a different one, or with a token that has been
re-bound since. An RBAC factor is evidence about *this* context, named in the
factor for exactly that reason — it is never a guarantee about the run.
