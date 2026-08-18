# Rules

200 rules, 55 amplifiers and 5 softeners across filesystem and devices,
permissions, system and service state, networking (including lockout risk),
package managers, git, containers, Kubernetes, Terraform/Pulumi, AWS/GCP/Azure,
databases, backup tooling, storage, virtualisation, audit trail and config
management. `--list-rules` prints all of it.

**[INVENTORY.md](https://github.com/fabiocicerchia/scoville/blob/main/INVENTORY.md)
is the catalogue** — 315 commands with the band, scope and reversibility each
one gets. It is generated from
[`tests/corpus.tsv`](https://github.com/fabiocicerchia/scoville/blob/main/tests/corpus.tsv)
and executed by the suite, so a rule change that moves a command between bands
fails the tests rather than silently recalibrating the tool. That corpus is also
where new coverage starts: add the command and the band you expect, then make it
pass.

## Generic signals

Some signals mean the same thing on **any** binary, so they are scored
generically rather than per-command:

- `--force`
- `-y`/`--yes` in all its spellings (`--noconfirm`, `--batch`,
  `--no-interaction`, and combined flags like `-qy`)
- `--purge`
- a credential in argv — visible in `ps` to every user on the host
- disabled TLS or package-signature verification
- `0.0.0.0/0`

Softeners work the same way in reverse — `rm -i`, `sed -i.bak`,
`--force-with-lease` and ansible's `--limit` score *below* their careless form,
which is what makes a `--fail-on` gate usable rather than something people
switch off.

## Remote code

Tracked in every spelling it travels under, not just the famous one:

- `curl … | bash`
- `bash <(curl …)`
- `eval "$(curl …)"`
- `base64 -d | sh`
- the two-step `curl -o f URL && bash f` — in a script nothing read the file
  between those steps, so it is the same unreviewed code.

## Exposure

Scored as its own failure mode, separate from destruction:
`aws iam create-access-key`, `--acl public-read`, a `0.0.0.0/0` security-group
rule, `--member=allUsers`, a `cluster-admin` binding and `setenforce 0` are all
about widening access rather than deleting anything.

## The long tail

**Covered by verb classification, not enumeration.** Roughly 50 resource CLIs —
`hcloud`, `scw`, `doctl`, `linode-cli`, `flyctl`, `heroku`, `wrangler`, `gh`,
`openstack`, `incus`, `pscale`, `vault`, `velero`, `argocd` and friends — are
scored by the verb in command position, so `hcloud server delete` is `high` and
`hcloud server list` is `safe` without a per-CLI rule. Position matters:
`hcloud server describe delete-me` stays `safe`.

Where a verb lies, a specific rule overrides the generic one **even when it
scores lower**: `virsh destroy` powers a domain off rather than deleting it, so
it sits below `virsh undefine`.

And for a CLI nobody has enumerated yet, a destructive verb still cannot score
`safe` — `frobctl delete cluster prod` is `high`, flagged as a floor rather than
a measurement. That is the failure mode that would otherwise make a gate
worthless the day a new CLI ships.

## Growing the set

The rule set *is* the product; it is meant to grow. Every rule carries a
plain-language *why*, and destructive ones carry a safer alternative — a finding
with neither is a finding people learn to ignore.
