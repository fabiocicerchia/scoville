# Rules

259 rules, 64 amplifiers and 8 softeners across filesystem and devices,
permissions, system and service state, networking (including lockout risk),
package managers, git, containers, Kubernetes, Terraform/Pulumi, AWS/GCP/Azure,
databases, backup tooling, storage, virtualisation, audit trail and config
management. `--list-rules` prints all of it.

**[INVENTORY.md](https://github.com/fabiocicerchia/scoville/blob/main/INVENTORY.md)
is the catalogue** — 382 commands with the band, scope and reversibility each
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

**Covered by verb classification, not enumeration.** Around 40 resource CLIs —
`hcloud`, `scw`, `doctl`, `linode-cli`, `wrangler`, `pscale`, `incus`, `glab`,
`vercel`, `stripe` and friends — are scored by the verb in command position, so
`hcloud server delete` is `high` and `hcloud server list` is `safe` without a
per-CLI rule. Position matters: `hcloud server describe delete-me` stays `safe`.

For a CLI nobody has enumerated yet, a destructive verb still cannot score
`safe` — `frobctl delete cluster prod` is `high`, flagged as a floor rather than
a measurement. That is the failure mode that would otherwise make a gate
worthless the day a new CLI ships.

## Which CLIs are enumerated

Verb classification is a floor. It cannot see what a resource is worth
(`openstack volume delete` costs data, `openstack server stop` costs a reboot),
and it cannot see a verb that lies. So the CLIs where both the traffic and the
blast radius are high are enumerated per resource instead:

**Enumerated per resource** — `argocd`, `ceph`, `eksctl`, `etcdctl`,
`flyctl`/`fly`, `gh`, `heroku`, `nomad`, `openstack`, `pulumi`, `rbd`,
`rclone`, `restic`/`borg`, `s3cmd`, `snap`, `vault`, `velero`, `virsh`, `zfs`.

**Carried by verb classification** — everything else in `RESOURCE_CLIS`:
`hcloud`, `scw`, `doctl`, `linode-cli`, `vultr-cli`, `civo`, `exo`, `upcloud`,
`ibmcloud`, `oci`, `aliyun`, `railway`, `vercel`, `netlify`, `render`,
`pscale`, `supabase`, `wrangler`, `glab`, `tea`, `flux`, `linkerd`,
`istioctl`, `incus`, `lxc`, `machinectl`, `consul`, `cdk`, `cdktf`,
`serverless`, `stripe`, `twilio`, `fastly`, `akamai`, `cf`, and the rest.

`specific_clis()` and `generic_clis()` compute those two lists from the rule set
rather than from a hand-maintained table, and the suite asserts the split — so a
CLI cannot quietly move between columns.

Enumeration is **per resource, not per binary**: a subcommand nobody has written
a rule for still falls back to verb classification. `gh label delete wontfix`
scores on `CLI-DESTROY`, exactly as it did before `gh` was enumerated.

### Verbs that lie

Where a verb lies, a specific rule overrides the generic one **even when it
scores lower**:

- `virsh destroy` force-powers-off a domain rather than deleting it, so it sits
  below `virsh undefine`.
- `vault kv delete` is a *soft* delete — `vault kv undelete` brings the versions
  back. `vault kv destroy` is the permanent one.
- `openstack project delete` does not delete the servers and volumes in the
  project. They keep running, and keep billing, with no project left to manage
  them through.
- `argocd cluster rm` de-registers a cluster from Argo CD; it does not touch the
  cluster.
- `velero restore delete` deletes the restore *record*, not the objects the
  restore created.
- `gh api -X DELETE /repos/{owner}/{repo}` deletes a repository, and nothing in
  the command line is a destructive verb.

## The reasoning behind a rule

Every finding names the rule that produced it, and `scoville --why <ID>` prints
the long form for that rule:

```console
$ scoville 'openstack project delete acme'
openstack project delete acme
  HIGH        60/100  ·  scope: account  ·  irreversible
     +60  deleting a project does not delete what is in it: the servers, …
    ↳ safer: `openstack project purge --project <id>` removes them first
    ↳ why:   scoville --why OS-PROJECT-DELETE
```

The detail view carries what it matches and what it deliberately does not, the
class of incident it exists to prevent, why the band, scope and reversibility
are what they are, the safer alternative, and the related rules — including the
generic ones it beats. It also accepts amplifier ids in the `+FORCE` spelling
`--list-rules` prints, so an id copied out of any output resolves.

Everything except the incident paragraph is **read out of the rule table**, so
the explanation and the score are the same facts and cannot drift apart. The
incident paragraph is prose and is written per rule; a rule that does not have
one yet says so plainly rather than printing a formulaic body, because a body
people learn to skip is worse than an honest gap.

An unknown id exits `64` and guesses:

```console
$ scoville --why K8S-DELETE-NAMESPACE
scoville: no rule or amplifier called 'K8S-DELETE-NAMESPACE'
scoville: did you mean K8S-DELETE-NS, K8S-DELETE-PVC, K8S-DELETE-POD?
```

`--format json` carries the rule id on every factor that has one, so a gate can
link straight to the reasoning for the factor that failed it. Factors that are
not a rule — a path, a carried payload, a dry-run dampener — carry `null`
rather than an invented id.

## Growing the set

The rule set *is* the product; it is meant to grow. Every rule carries a
plain-language *why*, and destructive ones carry a safer alternative — a finding
with neither is a finding people learn to ignore.

A new rule ideally carries an incident-class note for `--why` as well. The notes
live next to the rule table in `scoville.py`, keyed by rule id, and the suite
fails if one names an id that no longer exists — so they cannot drift the way a
separate document would.
