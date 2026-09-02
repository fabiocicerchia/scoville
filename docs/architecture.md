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

## Carriers and introspection, worked

`docker exec` is a middling risk on its own; what matters is what it carries.
The wrapper contributes a base and a context weight, the payload contributes the
rest:

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

A wrapper script hides the payload the same way, so it is scored as opaque until
`--introspect` reads it:

```console
$ scoville './foo.sh prod'
  MEDIUM      40/100  ·  scope: none  ·  reversible
     +20  runs `./foo.sh`: the commands are inside the script, not on this line — re-run with --introspect to read it

$ scoville './foo.sh prod' --introspect
  CRITICAL   100/100  ·  scope: host  ·  irreversible
     +98  resolved wrapper `./foo.sh` line 6 runs `rm -rf "$BUILD_DIR"/`, which is critical
```

Reading resolves uncertainty in *both* directions — a wrapper that turns out to
run `ls` scores lower once it has been read, not higher.

When the payload is hidden behind an image `ENTRYPOINT`, the command line alone
cannot tell you anything, so scoville says so and `--introspect` resolves it
with read-only `docker inspect` calls — never a pull, never a run:

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

## Asking the cluster what it will allow

`kubectl delete ns prod` scores the same whether the current context is
cluster-admin on production or a read-only token that will be refused. The
second case is noise, and noise is what makes people stop reading the output.

Under `--introspect`, a `kubectl` line is checked against the context that
would actually run it:

```console
$ scoville 'kubectl delete ns prod'
kubectl delete ns prod
  CRITICAL   90/100  ·  scope: cluster  ·  irreversible

$ scoville 'kubectl delete ns prod' --introspect      # read-only token
kubectl delete ns prod
  HIGH       60/100  ·  scope: cluster  ·  irreversible
     -30  rbac context `prod-readonly` cannot delete namespaces — `kubectl auth
          can-i` says no, so this would be refused as it stands
```

`kubectl auth can-i` is a `SelfSubjectAccessReview`: the API server is asked
*would you allow this*, and nothing is created, changed or run. That keeps the
"nothing is ever executed to score it" contract intact. It is still a call to a
live cluster, so it sits behind `--introspect` with everything else that leaves
the machine, and `--kube-timeout` bounds one call.

### The direction of failure is the whole design

A dampener that fires on a bad `can-i` result **under-reports risk**, which is
the one kind of wrong answer this tool must not give. So nothing is dampened
unless a refusal is positively established:

| what happened | what it scores |
| --- | --- |
| `can-i` says `no` | −30, with the context named |
| `can-i` says `yes` **and** `can-i '*' '*'` says `yes` | +10, scope widened to `cluster` — nothing left to catch a mistake |
| `can-i` says `yes` | unchanged, recorded in the trace |
| no kubeconfig, no context, timeout, unreachable cluster, unparseable answer | **unchanged**, recorded as "no answer" |

The refusal is points rather than a cap (which is what `--dry-run` gets),
because the context is read **now** and the command may run later against a
different one. That is also why the factor text names the context it asked:
a −30 that does not say whose permissions it checked is not reviewable.

`kubectl`'s verbs are mapped to the RBAC verbs they actually need before the
question is asked — `apply`, `edit`, `scale` and `annotate` all need `patch`,
and asking about `apply` gets a useless answer. Short resource names are
expanded the same way. An *unrecognised* resource is passed through verbatim:
the RBAC resource list is open, a CRD defines its own, and this table must not
be the thing that decides what exists.

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
