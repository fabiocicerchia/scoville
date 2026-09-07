"""The long form for a rule: the class of incident it exists to prevent.

Data only, keyed by rule or amplifier id, validated by the suite."""

from __future__ import annotations




# The long form for a rule: the class of incident it exists to prevent.
#
# Keyed by rule or amplifier id and validated by the suite — an entry naming
# something that does not exist fails the tests, which is the drift the notes
# would otherwise be prone to. Kept beside the rule table rather than inside it
# because that table is read top to bottom as a catalogue, and sixty paragraphs
# threaded through it would stop that working.
#
# Not every rule has one. `--why` says so plainly rather than printing a
# formulaic paragraph: a body people learn to skip is worse than an admission
# that the note has not been written yet.
INCIDENTS = {
    # --- filesystem and devices --------------------------------------------
    "FS-RM": (
        "The command everyone has already run wrong once. `rm` has no undo and "
        "no trash: the kernel unlinks the inode and the space is reusable "
        "immediately, so recovery means an unmounted filesystem and a "
        "forensics tool, not a command. The dangerous shape is not `rm file`, "
        "it is `rm` with a variable that was empty, a glob that matched more "
        "than it did when you tested, or a relative path run from a directory "
        "you were not in. `-r` turns one mistake into a subtree and `-f` "
        "removes the prompt that would have shown you the mistake, which is "
        "why they are scored on top rather than folded in."
    ),
    "FS-SED-I": (
        "In-place edit with no backup suffix. `sed -i` writes a new file and "
        "renames it over the original, so the previous contents are gone the "
        "instant the command returns — there is no staging area and nothing to "
        "diff against. The incident is a regex that matched more lines than "
        "intended across a `find -exec` or a glob, discovered after the "
        "commit. `sed -i.bak` costs one character and leaves the original next "
        "to the edited file."
    ),
    "FS-MKFS": (
        "Making a filesystem writes a new superblock over whatever was there. "
        "The classic incident is a device name that moved: `/dev/sdb` is not a "
        "stable identifier, and a disk added, removed or enumerated in a "
        "different order between the check and the command points the same "
        "name at different hardware. Partitioning tools belong here for the "
        "same reason. Use `/dev/disk/by-id/…` or a UUID, and run `lsblk` "
        "immediately before, not five minutes before."
    ),
    "FS-CRYPT": (
        "Formatting or erasing a LUKS device destroys the key slots. The data "
        "is still on the platters and is now permanently unreadable: without "
        "the master key there is no recovery path at any budget. `luksFormat` "
        "on a device that already held a volume is the incident, and it looks "
        "identical to the first-time setup it is usually copied from. Take a "
        "header backup (`cryptsetup luksHeaderBackup`) before touching key "
        "slots on anything that holds data."
    ),
    "FS-DISCARD": (
        "A discard or secure-erase tells the drive itself to forget. Unlike a "
        "delete, this is honoured by the flash translation layer, so undelete "
        "tools have nothing to find — the blocks are genuinely gone, not "
        "merely unreferenced. This is the intended behaviour when "
        "decommissioning hardware and a total loss when the device is still in "
        "service. There is no partial version of it to try first."
    ),
    "FS-ZPOOL": (
        "Destroying or splitting a pool takes every dataset, snapshot and "
        "clone it holds in one operation — a pool is the unit, not the "
        "dataset. `zpool destroy` can sometimes be reversed with `zpool import "
        "-D` if nothing has reused the disks, but that is a rescue, not a "
        "plan. The frequent incident is destroying the pool when the intent "
        "was one filesystem on it."
    ),
    "LVM-REMOVE": (
        "Removing a logical volume, volume group or RAID superblock discards "
        "the metadata that says where the data lives. The extents are still on "
        "disk but nothing can find them, and `mdadm --zero-superblock` on the "
        "wrong member turns a degraded array into an unassembled one. Recovery "
        "means reconstructing the exact original layout by hand. Keep "
        "`vgcfgbackup` output somewhere off the machine."
    ),
    "FS-RESIZE": (
        "Shrinking is the direction that loses data. Growing a filesystem is "
        "routine; reducing one below the extent of its used blocks, or "
        "reducing the logical volume before the filesystem on it, truncates "
        "live data with no warning from either layer. `xfs_growfs` is here "
        "because XFS cannot shrink at all, so the operation people reach for "
        "next is a dump, mkfs and restore."
    ),
    "MAC-DISKUTIL": (
        "Erase and reformat verbs on macOS take a volume identifier that is "
        "easy to get wrong — `disk2` and `disk2s1` are one character apart and "
        "mean the whole device or one volume on it. APFS container deletion "
        "takes every volume inside the container, which on a Mac is usually "
        "the system and the data volume together."
    ),
    # --- permissions and privilege -----------------------------------------
    "PRIV-CHMOD": (
        "Permissions are load-bearing in places that give no error until much "
        "later. World-writable is the obvious one — any local user or "
        "compromised process can rewrite the file — but the quieter incident "
        "is a recursive chmod that strips the execute bit from directories, "
        "which makes them untraversable, or adds it to every file in a tree. "
        "SSH refuses to use a private key whose mode is too open, and sudo "
        "refuses a sudoers file whose mode is wrong, which is how a broad "
        "chmod locks you out of the machine you are fixing."
    ),
    "SEC-IAM-ADMIN": (
        "Attaching an administrator policy is not a deployment step, it is a "
        "grant of everything. The incident is the debugging shortcut that "
        "survives: a wildcard policy attached to unblock a failing pipeline, "
        "never narrowed, and later inherited by every workload assuming that "
        "role. It does not break anything, which is precisely why nobody "
        "revisits it. Scope to the actions the caller actually failed on."
    ),
    "SEC-K8S-ADMIN": (
        "`cluster-admin` bound to a service account gives every pod using it "
        "the API rights to read every secret in the cluster and to schedule "
        "anything anywhere. The usual route in is a Helm chart or an operator "
        "that asks for it to avoid enumerating what it needs. A compromise of "
        "one workload then reaches the whole cluster, and the binding is "
        "invisible in the workload's own manifests."
    ),
    "SEC-S3-PUBLIC": (
        "A public-read ACL or bucket policy is the single most common cause of "
        "an accidental data disclosure. The bucket usually holds exactly what "
        "you would expect it to — backups, exports, uploaded user files — and "
        "the change is made to fix a 403 on one object. Public buckets are "
        "indexed by scanners within minutes, so 'briefly public' is not a "
        "thing that exists."
    ),
    "SEC-GCP-ALLUSERS": (
        "`allUsers` and `allAuthenticatedUsers` are not 'everyone in my "
        "organisation' — the first is the internet and the second is every "
        "Google account in existence. Both are routinely added to make a "
        "static asset load, and both grant whatever role is named to the whole "
        "world, which is rarely the reader role people assume."
    ),
    "SEC-IAM-KEY": (
        "A long-lived access key is a credential with no expiry that will end "
        "up in a repository, a CI variable, or a laptop backup. The incident "
        "is not the creation, it is that the key outlives the reason for it by "
        "years and nobody can say what still uses it. Prefer a role, an OIDC "
        "trust or a short-lived session; if a key is genuinely needed, record "
        "where it went at the moment it was made."
    ),
    # --- system and boot ----------------------------------------------------
    "SYS-POWER": (
        "Rebooting a machine you reached over SSH is a bet that it comes back. "
        "The failure mode is not the reboot, it is what was only true in "
        "memory: a network config applied but never written, a filesystem "
        "mounted by hand, a kernel that was updated but whose bootloader entry "
        "was not. On a remote host with no console, a machine that does not "
        "come back is a support ticket with a datacentre."
    ),
    "SYS-POWER-CTL": (
        "Same failure as a direct `reboot`, reached through systemd. Worth "
        "distinguishing because `systemctl` is also the tool for routine "
        "service work, so the power verbs sit one word away from commands "
        "people run all day."
    ),
    "SYS-MASK": (
        "Masking symlinks a unit to `/dev/null` so it cannot be started — not "
        "by a dependency, not by an admin who does not know it was masked, not "
        "after a reboot. That is stronger than `disable` and much harder to "
        "diagnose: the service simply never comes up, and `systemctl start` "
        "reports success in some versions. Mask deliberately, and leave a note "
        "where the next person will look."
    ),
    "SYS-INIT": (
        "Changing the runlevel out from under a running system stops every "
        "service not in the target, which on a remote host includes the one "
        "you are connected through. `telinit 1` in particular drops to single "
        "user and takes networking with it."
    ),
    "BOOT-KEXEC": (
        "`kexec` jumps straight into a new kernel without firmware "
        "re-initialisation. When the target kernel or initrd is wrong there is "
        "no BIOS POST to fall back through and no bootloader menu — the "
        "machine is simply gone until someone power-cycles it, and on cloud "
        "hardware that means a console session you may not have."
    ),
    # --- networking ---------------------------------------------------------
    "NET-IPTABLES": (
        "Firewall edits are applied to the live packet path immediately. The "
        "incident is always the same shape: a rule that removes the one "
        "allowing your own session, discovered because the shell stops "
        "responding mid-command with no way back in. Anything that flushes a "
        "chain removes the accept rules along with the deny ones."
    ),
    "NET-IPTABLES-P": (
        "Setting a chain's default policy to DROP takes effect before you add "
        "the rules that would have let you back in. This is the canonical "
        "remote lockout — the connection dies during the command that caused "
        "it, so there is no prompt and no chance to revert. Schedule a "
        "`iptables-restore` from a saved ruleset on a timer before you start, "
        "and cancel it once you are still connected."
    ),
    "NET-CONNTRACK": (
        "Flushing connection tracking drops every NAT mapping the host holds. "
        "Established connections through it break mid-stream — not refused, "
        "just silently stalled until each end times out — and on a NAT gateway "
        "that is every flow for every client behind it at once."
    ),
    "NET-NETNS": (
        "Deleting a network namespace takes its interfaces with it, and "
        "anything running inside it loses connectivity with no log line "
        "explaining why. On a container or virtualisation host, a namespace is "
        "usually a workload's entire network."
    ),
    # --- packages -----------------------------------------------------------
    "PKG-REMOVE": (
        "Package removal is scored on what the solver decides to take with it. "
        "Removing one library can cascade into a desktop environment or, on a "
        "server, into the very tooling you were about to use to fix things — "
        "`apt remove` printing a list nobody reads is the setup for most of "
        "these. Read the list. `--purge` additionally deletes configuration "
        "that a reinstall will not bring back."
    ),
    "PKG-PUBLISH": (
        "Publishing is public and, on most registries, permanent: npm, PyPI "
        "and crates.io all restrict or forbid deleting a version once anything "
        "may depend on it. The incident is a package published from a dirty "
        "working tree, or with credentials or an internal path baked into the "
        "artifact, which cannot then be unpublished. Build from a clean "
        "checkout and inspect the tarball before the upload."
    ),
    # --- git ----------------------------------------------------------------
    "GIT-PUSH-F": (
        "A force push replaces the remote branch. Commits that were only on "
        "the remote — someone else's work pushed between your fetch and your "
        "push — become unreferenced, and on a hosted forge they are garbage "
        "collected without warning. The other half of the incident is "
        "everyone's local checkout: their next pull is a conflict they did not "
        "cause. `--force-with-lease` refuses when the remote moved under you, "
        "which is exactly the case that loses work."
    ),
    "GIT-RESET": (
        "`reset --hard` discards the working tree and the index against the "
        "target commit. Committed work is recoverable through the reflog for "
        "as long as it lasts; uncommitted work is not recoverable at all, "
        "because git never saw it. The incident is running it to 'clean up' "
        "with an edit in progress somewhere in the tree."
    ),
    "GIT-CLEAN": (
        "`git clean -fdx` deletes untracked files, and untracked is not the "
        "same as unimportant: `.env`, local configuration, uncommitted "
        "scratch work and anything a `.gitignore` deliberately keeps out of "
        "the repository all go. Git has never seen these files, so nothing in "
        "git can bring them back. `-n` prints the list first."
    ),
    "GIT-REFLOG-EXPIRE": (
        "The reflog is the safety net under every other git mistake — it is "
        "what makes a bad `reset --hard` or rebase recoverable. Expiring it "
        "and running `gc --prune=now` removes that net and makes every "
        "previously recoverable operation permanent. It is usually run to "
        "reclaim disk space, which it does badly compared to the cost."
    ),
    "GIT-PUSH-MIRROR": (
        "`push --mirror` makes the remote match the local repository exactly: "
        "every branch and tag the remote has and you do not is deleted, not "
        "merged. Run against the wrong remote — a fork, or an upstream you "
        "have push rights to — it removes other people's branches wholesale."
    ),
    "GIT-PUSH-DEL": (
        "Deleting a remote branch or tag removes the only name pointing at "
        "that history. For a tag this is worse than it looks: release tooling, "
        "deployment pipelines and other people's lockfiles may reference it, "
        "and re-creating a tag at a different commit is how you get two builds "
        "that disagree about what a version contains."
    ),
    "GIT-REWRITE": (
        "History rewriting changes every commit hash from the rewrite point "
        "forward. Signatures break, existing references from issues and "
        "reviews point at commits that no longer exist, and every collaborator "
        "has to reset rather than pull. Doing it to remove a leaked secret "
        "also does not remove it: the old objects survive in forks, caches and "
        "the forge's own reflogs, so the credential still has to be rotated."
    ),
    "GIT-CHECKOUT-F": (
        "A forced checkout overwrites local modifications without asking. It "
        "is the fastest way to lose an hour of uncommitted work, and it is "
        "usually reached for because git refused the safe version — that "
        "refusal was the warning."
    ),
    "GIT-STASH-CLEAR": (
        "`stash clear` drops every stash entry at once. Entries are "
        "recoverable through dangling commits for a while, but the recovery is "
        "obscure enough that in practice this is a delete. People run it to "
        "tidy up and lose the one stash from three months ago that mattered."
    ),
    # --- containers ---------------------------------------------------------
    "CTR-VOLUME-RM": (
        "A named volume is where a container keeps the state that is supposed "
        "to outlive it — the database directory, the uploads, the certificate "
        "cache. Removing one deletes that data, and the volume's name usually "
        "gives no clue what it held. Nothing in Docker versions or snapshots "
        "volumes, so the only copy is whatever backup you took yourself."
    ),
    "CTR-PRUNE": (
        "Prune deletes everything the daemon considers unused, and 'unused' is "
        "the daemon's definition, not yours: a stopped container you meant to "
        "restart, an image you built and never tagged, and with `--volumes` "
        "the data of any container that is not currently running. On a shared "
        "or CI host this reaches other people's work."
    ),
    "CTR-RM": (
        "Removing a container discards its writable layer — anything written "
        "inside it that was not on a mounted volume. The incident is a "
        "container someone shelled into to fix something live, removed during "
        "cleanup before that fix was written down anywhere."
    ),
    # --- kubernetes ---------------------------------------------------------
    "K8S-DELETE": (
        "A `kubectl delete` is applied to whatever the selector matches at the "
        "moment it runs, which is not necessarily what it matched when you "
        "tested it. Deleting a controller cascades to what it owns by default. "
        "The scariest form is a label selector with a typo that matches "
        "nothing — harmless — sitting one character away from one that matches "
        "everything."
    ),
    "K8S-DELETE-NS": (
        "Deleting a namespace deletes every object inside it, PersistentVolume "
        "Claims included, and with a Delete reclaim policy the underlying "
        "volumes go too. It is also asynchronous and hard to stop: the "
        "namespace enters Terminating and the cascade continues while you read "
        "the output. There is no partial undo."
    ),
    "K8S-DELETE-CRD": (
        "Deleting a CustomResourceDefinition deletes every custom resource of "
        "that kind across the whole cluster, in every namespace, immediately. "
        "The objects are removed by the API server itself, so an operator "
        "watching them sees deletions and acts on them — which for a database "
        "or storage operator means real infrastructure. This is the single "
        "largest blast radius available from one kubectl command."
    ),
    "K8S-DELETE-PVC": (
        "A PVC delete releases the PersistentVolume behind it, and with the "
        "default Delete reclaim policy the storage class then destroys the "
        "actual disk. The pod may still be running and writing when this "
        "happens. Check the reclaim policy before, not after."
    ),
    "K8S-DRAIN": (
        "Draining evicts every pod on a node. That is routine when the rest of "
        "the cluster has room and PodDisruptionBudgets are honest, and an "
        "outage when it does not — the pods have nowhere to reschedule and "
        "sit Pending. Draining several nodes in sequence without waiting for "
        "the previous one to settle is how a rolling maintenance becomes a "
        "cold cluster."
    ),
    "K8S-SCALE-0": (
        "Scaling to zero is an outage with a tidy audit trail: nothing is "
        "deleted, the deployment still exists, and the service simply stops "
        "serving. It is recoverable in one command, which is why it is scored "
        "below a delete — but the recovery only starts once someone notices."
    ),
    # --- infrastructure as code ---------------------------------------------
    "IAC-APPLY": (
        "Apply is where the plan stops being hypothetical. The incident is "
        "applying a plan generated against a different workspace, variable "
        "file or state than the one now in effect — Terraform will happily "
        "reconcile you to a configuration that was written for staging. "
        "Anything the diff shows as replace rather than update is a destroy "
        "followed by a create, and for a database that is the whole of it."
    ),
    "IAC-DESTROY": (
        "`destroy` tears down every resource in the state, in dependency "
        "order, including the ones nobody remembers are in there. The usual "
        "incident is the wrong workspace or the wrong `-var-file`, in a shell "
        "where the last apply was against something else. Data resources with "
        "no deletion protection — RDS instances, S3 buckets, EBS volumes — go "
        "with everything else."
    ),
    "IAC-STATE-RM": (
        "Removing something from state does not remove it from the cloud: it "
        "removes Terraform's knowledge of it. The resource keeps running and "
        "keeps billing, unmanaged, and the next apply tries to create a second "
        "one — which either conflicts on a unique name or quietly doubles the "
        "infrastructure. This is the verb most often reached for in a hurry "
        "during an incident."
    ),
    "IAC-WORKSPACE": (
        "Workspaces are the mechanism people use to keep production and "
        "staging apart, so selecting or deleting the wrong one aims every "
        "subsequent command at the wrong environment. `workspace delete` "
        "discards a state file, which orphans everything that state described."
    ),
    # --- aws / gcp / azure --------------------------------------------------
    "AWS-S3-RB": (
        "Removing a bucket with `--force` empties it first: every object and "
        "every version, in one call, with no progress you can act on. Bucket "
        "names are globally unique and immediately claimable by anyone once "
        "released, so even a rebuild does not necessarily get the name back."
    ),
    "AWS-S3-RM-R": (
        "A recursive `s3 rm` is a prefix delete, and S3 prefixes are not "
        "directories — `s3://bucket/logs` and `s3://bucket/logs-archive` share "
        "a prefix. A missing trailing slash is the whole incident. Versioning "
        "helps only if it was on before the delete, and a lifecycle rule may "
        "then expire the delete markers anyway."
    ),
    "AWS-EC2-TERM": (
        "Terminate is not stop. Instance store volumes are lost, and EBS "
        "volumes created with DeleteOnTermination — which is the default for "
        "the root volume — are deleted with the instance. The Elastic IP is "
        "released or, worse, silently kept and billed. `stop` is the verb for "
        "'I want this to cost less'."
    ),
    "AWS-RDS-DEL": (
        "Deleting a database instance with `--skip-final-snapshot` removes the "
        "one artefact that would have made it recoverable. Automated backups "
        "are deleted with the instance unless they were explicitly retained, "
        "so the flag added to make the command succeed is the flag that makes "
        "it terminal."
    ),
    "AWS-KMS-DEL": (
        "Scheduling a KMS key for deletion is the rare AWS operation with a "
        "genuine point of no return: after the waiting period the key material "
        "is destroyed and every object encrypted with it is permanently "
        "unreadable, including backups and snapshots. Disable the key first "
        "and watch for the access denied errors that tell you what still uses "
        "it — that list is never what you expect."
    ),
    "AWS-IAM-DEL": (
        "Deleting a role, policy or user breaks whatever was authenticating or "
        "authorising through it, and IAM gives no dependency list. The failure "
        "surfaces somewhere else entirely, minutes or hours later, as an "
        "AccessDenied in a service nobody connected to this change. Detach and "
        "watch before deleting."
    ),
    "AWS-ORG": (
        "Organisation-level operations act on whole accounts. Removing or "
        "closing a member account, or deleting a service control policy, "
        "changes the security boundary for everything inside it — and account "
        "closure has a waiting period after which it is not reversible at all."
    ),
    "GCP-PROJECT": (
        "Deleting a project schedules everything in it for deletion: every "
        "resource, every dataset, every bucket, all at once. There is a "
        "recovery window of about 30 days, which is the only reason this is "
        "survivable, and restoring does not always bring back resources whose "
        "names were released."
    ),
    "AZ-GROUP-DEL": (
        "A resource group delete is a bulk delete of everything in it — VMs, "
        "disks, databases, the lot — and it runs asynchronously once accepted. "
        "Azure resource groups are frequently used as an environment "
        "boundary, so the wrong name here is the wrong environment entirely."
    ),
    # --- databases ----------------------------------------------------------
    "DB-DROP": (
        "`DROP TABLE` removes the data and the schema together, and in most "
        "engines it is not transactional in the way people assume — MySQL "
        "commits implicitly around DDL, so a `BEGIN` before it protects "
        "nothing. Recovery means the last backup plus whatever replay you "
        "have, which turns a one-word mistake into a restore window."
    ),
    "DB-DROP-DB": (
        "Dropping a database is every table at once, and the name in the "
        "command is usually one character from the name of another "
        "environment. Managed engines make this worse by putting production "
        "and staging behind endpoints that differ only by a suffix."
    ),
    "DB-TRUNCATE": (
        "`TRUNCATE` empties the table without producing per-row entries in the "
        "binary log the way a DELETE does, and it cannot be rolled back on "
        "MySQL. It is fast precisely because it skips the mechanisms that "
        "would have let you undo it."
    ),
    "DB-DELETE-ALL": (
        "A `DELETE` with no `WHERE` — or with a `WHERE` on a column that is "
        "NULL for every row — removes the whole table's contents. Inside a "
        "transaction it is recoverable; run through a client that autocommits, "
        "it is not. The tell is a row count far larger than you expected, "
        "reported after the fact."
    ),
    "DB-UPDATE-ALL": (
        "An `UPDATE` without a `WHERE` rewrites every row, and unlike a delete "
        "it leaves no obvious hole — the table still has the right number of "
        "rows, all now wrong. It is often noticed days later, by which time "
        "the backup that predates it has aged out."
    ),
    "DB-DROP-COLUMN": (
        "Dropping a column discards its data immediately and, on a large "
        "table, may rewrite the whole table under a lock. The deployment "
        "incident is dropping a column that the currently running application "
        "version still selects, which turns a schema change into an outage "
        "until the rollback."
    ),
    "DB-FLUSH": (
        "`FLUSHALL` and `FLUSHDB` empty Redis instantly. When Redis is a cache "
        "this is a thundering herd against whatever it was caching; when it is "
        "a session or queue store — which it often quietly is — it is data "
        "loss. Persistence does not save you: the flush is written to the "
        "AOF and RDB as well."
    ),
    "DB-MONGO-DROP": (
        "`dropDatabase()` runs against whichever database the shell is "
        "currently on, which is the one the last `use` selected and not "
        "necessarily the one in your scrollback. There is no confirmation and "
        "no undo."
    ),
    "MIGRATE-DOWN": (
        "Migrating down to zero unwinds every migration, and 'down' migrations "
        "are the least-tested code in most repositories — they are written "
        "once, run never, and drop the tables the up migration created. "
        "Rolling back a deployment rarely requires rolling back the schema."
    ),
    "MIGRATE-RESET": (
        "A reset drops the database and rebuilds it from migrations. In "
        "development that is the intended workflow, which is exactly why it "
        "gets run against a `DATABASE_URL` inherited from a shell that was "
        "pointed somewhere else."
    ),
    "MIGRATE-PRISMA": (
        "`prisma migrate reset` drops and recreates the database from the "
        "migration history, then re-seeds. It prompts interactively, so the "
        "incident is the non-interactive form in a script or a CI job that "
        "was pointed at a real database."
    ),
    "PG-RESET": (
        "`pg_resetwal` is a last-resort recovery tool that discards the "
        "write-ahead log. Running it on a cluster that could have been "
        "recovered normally leaves the data files internally inconsistent in "
        "ways that surface later as unreadable pages and wrong query results. "
        "Take a filesystem-level copy of the data directory before, always."
    ),
    # --- cluster state and backups ------------------------------------------
    "ETCDCTL-DEL": (
        "A prefix delete against etcd removes keys the API server believes "
        "exist. For a Kubernetes cluster, etcd *is* the state: objects vanish "
        "without going through admission or finalizers, controllers act on the "
        "resulting deletions, and the cluster is not so much broken as "
        "confidently wrong."
    ),
    "ETCD-RESTORE": (
        "Restoring a snapshot replaces cluster state wholesale. Every object "
        "created since the snapshot disappears, and any member not restored "
        "from the same snapshot will disagree — a partial restore across a "
        "cluster is worse than no restore at all."
    ),
    "RESTIC-FORGET": (
        "This deletes from the backup repository, which is the copy you keep "
        "for when the primary is already gone. The incident is a retention "
        "policy applied with the wrong tag or host filter, which silently "
        "matches more snapshots than intended and prunes them in the same "
        "command. `--dry-run` first; the output is the whole point."
    ),
    "RCLONE-SYNC": (
        "`sync` makes the destination match the source, which means deleting "
        "everything at the destination that is not at the source. Swap the two "
        "arguments and you have replicated an empty or partial directory over "
        "a full one. `copy` never deletes; use it unless removal is the goal."
    ),
    "RCLONE-PURGE": (
        "`purge` removes the directory and its contents at the remote without "
        "the per-object listing `delete` produces, so there is no output to "
        "notice a wrong path in before it completes. On a bucket that is "
        "someone's backup target, the first sign is the next restore."
    ),
    "S3CMD-RB": (
        "Bucket and object removal against object storage, with the same "
        "prefix-is-not-a-directory trap as the AWS CLI and no versioning "
        "guarantee at all on non-AWS S3-compatible endpoints. Where AWS gives "
        "you version history to recover from, a MinIO or Ceph gateway may give "
        "you nothing, and the command line looks identical either way."
    ),
    # --- keys, certificates, cluster membership -----------------------------
    "KEY-DELETE": (
        "Deleting a private key or a keystore entry destroys the only thing "
        "that can decrypt or sign. Everything encrypted to it becomes "
        "permanently unreadable, and unlike a password there is no reset. GPG "
        "secret keys and Java keystores are both routinely deleted while "
        "'cleaning up' a machine that turned out to be the only place a key "
        "existed."
    ),
    "CERT-REVOKE": (
        "Revocation is published and cannot be taken back. Clients that check "
        "OCSP or CRLs will refuse the certificate from then on, and issuing a "
        "replacement takes as long as validation takes — which for a "
        "DNS-01 challenge on a domain you do not directly control can be "
        "hours. Revoke only for actual key compromise."
    ),
    "CLUSTER-RESET": (
        "`kubeadm reset` and the k3s/k0s uninstall scripts tear the node's "
        "cluster membership down and remove the local state, including etcd's "
        "data directory on a control-plane node. On the last remaining "
        "control-plane node this is the cluster, not the node."
    ),
    "CLUSTER-LEAVE": (
        "Leaving a cluster removes this node from the quorum. Doing it to "
        "enough members — sometimes just one, on a three-node cluster already "
        "missing a member — costs quorum, and a cluster without quorum stops "
        "accepting writes rather than degrading gracefully."
    ),
    "KAFKA-DELETE": (
        "Deleting a topic deletes its log segments on every broker. Consumers "
        "that had not caught up lose those messages permanently, and a "
        "recreated topic with the same name starts at offset zero, which "
        "confuses every consumer group that remembers a higher one."
    ),
    "MQ-RESET": (
        "`rabbitmqctl reset` returns the node to its virgin state: every "
        "queue, exchange, binding and message it held is discarded, and the "
        "node forgets the cluster it was part of. It is the documented way out "
        "of a split brain, which is why it gets copied out of a runbook and "
        "run on the node that had the good data."
    ),
    # --- the enumerated CLIs ------------------------------------------------
    "VAULT-KV-DELETE": (
        "The verb lies, in the safe direction, which is why it has its own "
        "rule. `kv delete` marks versions deleted and leaves them in storage; "
        "`vault kv undelete -versions=N` brings them back. Scoring it as a "
        "destroy would be the more dangerous error: people who learn that "
        "Vault deletes are recoverable will treat `kv destroy` the same way."
    ),
    "VAULT-KV-DESTROY": (
        "This is the permanent one. `destroy` removes the version's data and "
        "`metadata delete` removes every version and the metadata with them. "
        "Nothing in Vault brings either back, and the secret is typically the "
        "only copy — that is the point of putting it there."
    ),
    "VAULT-SECRETS-DISABLE": (
        "Disabling a mount deletes everything stored under it, not just the "
        "route to it. The command reads like unmounting a filesystem and "
        "behaves like formatting one. To move a mount, use `vault secrets "
        "move`; to retire one, read what is under it first."
    ),
    "VAULT-AUDIT-DISABLE": (
        "Vault stops recording who read which secret, and keeps serving "
        "requests while it does — the gap is silent. Vault only refuses "
        "requests when *every* audit device fails, so disabling the last one "
        "does not fail closed, it just stops writing. Enable the replacement "
        "before removing the incumbent."
    ),
    "VAULT-LEASE-REVOKE": (
        "Revoking leases revokes the credentials behind them: the database "
        "users and cloud keys Vault issued are dropped as it goes. With "
        "`-prefix` that is every lease under a path, which on a busy mount is "
        "every application currently holding a connection. `-force` is worse "
        "in a different direction — it drops Vault's record without revoking "
        "the credential, leaving it live and untracked."
    ),
    "VAULT-RAFT-RESTORE": (
        "A snapshot restore replaces the whole of Vault's storage. Every "
        "secret, policy, mount and token written since the snapshot was taken "
        "is gone, and unlike most restores there is no partial or per-path "
        "form. Take a fresh snapshot before restoring an old one."
    ),
    "VAULT-REKEY": (
        "Rekeying invalidates the existing unseal shares the moment it "
        "completes. Everyone holding an old share can no longer unseal, and if "
        "the new shares are not distributed and stored before the next restart "
        "the cluster cannot be brought back at all."
    ),
    "VELERO-BACKUP-DELETE": (
        "Deleting a backup deletes the objects behind it in storage, so that "
        "point in time stops being restorable. Nothing breaks today — the cost "
        "is paid at the restore you have not needed yet, which is the hardest "
        "kind of loss to notice in review."
    ),
    "VELERO-SCHEDULE": (
        "Deleting or pausing a schedule stops backups being taken. There is no "
        "immediate symptom at all: the cluster is fine, the last backup is "
        "still there, and the gap only becomes visible when someone reads the "
        "backup list during an incident."
    ),
    "VELERO-RESTORE-DELETE": (
        "The verb lies. This deletes the restore *record*, not the objects the "
        "restore created — those stay in the cluster, now with nothing "
        "describing where they came from. People run it expecting to undo a "
        "restore and get the opposite of clarity."
    ),
    "VELERO-UNINSTALL": (
        "Removing Velero removes its CRDs, and with them the Backup and "
        "Restore objects describing every backup you hold. The data may still "
        "be in the bucket, but nothing in the cluster can enumerate or read it "
        "until Velero is reinstalled and re-synced against the same location."
    ),
    "ARGOCD-APP-SYNC": (
        "Sync applies whatever is in git to the cluster right now. It does not "
        "care why HEAD moved, so an unreviewed commit, a merged branch or a "
        "bumped chart version is deployed by the same command. With `--prune` "
        "it also deletes cluster resources that are not in git — including "
        "anything created outside Argo CD, which is usually the thing someone "
        "added by hand during an incident."
    ),
    "ARGOCD-APP-DELETE": (
        "Deleting an application cascades by default to the Kubernetes "
        "resources it manages, so this is a workload delete wearing an Argo CD "
        "command. `--cascade=false` removes only the Argo CD record and leaves "
        "everything running, which is what people usually mean."
    ),
    "ARGOCD-CLUSTER-RM": (
        "The verb lies. `cluster rm` de-registers a cluster from Argo CD and "
        "does not touch the cluster itself. Nothing goes down — the "
        "applications targeting it simply stop being reconciled, and drift "
        "from git silently from that moment."
    ),
    "OS-PROJECT-DELETE": (
        "The verb lies, expensively. Deleting a project does not delete the "
        "servers, volumes and floating IPs inside it: they keep running and "
        "keep billing, with no project left to manage them through. Purge the "
        "resources first, then delete the project."
    ),
    "OS-PROJECT-PURGE": (
        "The other half of the pair, and the one that actually deletes: every "
        "resource the project owns — servers, volumes, images, networks — in "
        "one call. `--dry-run` prints the list, and that list is routinely "
        "longer than the person running it expects."
    ),
    "OS-VOLUME-DELETE": (
        "The data on the volume goes with it, and `--force` deletes it while "
        "an instance still has it attached — the guest sees I/O errors rather "
        "than a clean unmount. A snapshot is the only way back and has to "
        "exist beforehand."
    ),
    "OS-CATALOG-DELETE": (
        "The service catalog is how every client finds the region's APIs. "
        "Removing an endpoint or a service makes that service unreachable "
        "region-wide without touching anything it manages, and the failure "
        "looks like an outage in the service rather than a change to the "
        "catalog."
    ),
    "FLY-VOLUME-DESTROY": (
        "A Fly volume is a single local disk, not a replicated one. "
        "Destroying it destroys the only copy of what was on it. Snapshots are "
        "kept for about five days and are the only route back, so a volume "
        "destroyed a week after the data mattered is simply gone."
    ),
    "FLY-SECRETS": (
        "Setting a secret restarts every machine in the app — this is a "
        "deploy, not a config write, and it happens the moment the command "
        "returns. `--stage` stores the value without restarting and lets the "
        "next deploy pick it up."
    ),
    "FLY-APPS-DESTROY": (
        "Destroys the app with its machines and its volumes, and releases the "
        "name for anyone else to claim. `fly scale count 0` stops it running "
        "and billing without destroying anything, which is what 'turn this off "
        "for now' usually means."
    ),
    "GH-REPO-DEL": (
        "Deletes the repository with its issues, pull requests, releases and "
        "wiki. GitHub's restore window is short and does not cover everything, "
        "and the name becomes claimable — which for a public repository means "
        "someone else can publish under a path other people's tooling still "
        "fetches. `gh repo archive` is read-only and reversible."
    ),
    "GH-API-DELETE": (
        "`gh api` is the raw REST API, so the verb that matters is in `-X` and "
        "not in the subcommand — nothing else on the command line says what "
        "this changes. `gh api -X DELETE /repos/{owner}/{repo}` deletes a "
        "repository, and verb classification reads it as a harmless `api` "
        "call. This is the shape to watch for in scripts."
    ),
    "GH-PR-MERGE": (
        "On a repository that deploys on merge, this is the deploy. `--admin` "
        "makes it worse by merging past branch protection — required reviews "
        "and status checks are bypassed, which is the control the repository "
        "configured on purpose. `--auto` queues behind the checks instead."
    ),
    "GH-RELEASE-DELETE": (
        "Deletes the release and every asset attached to it. Anything pinned "
        "to those download URLs breaks — including other people's CI, which is "
        "the part you do not find out about. `--cleanup-tag` additionally "
        "removes the tag, so the commit is no longer named."
    ),
    "VIRSH-DESTROY": (
        "The verb lies, in the safe direction. `virsh destroy` force-powers-off "
        "a domain — the equivalent of pulling the plug — and does not delete "
        "it. The disk survives and the domain can be started again; the cost "
        "is an unclean shutdown, not a loss."
    ),
    "VIRSH-UNDEFINE": (
        "This is the one that deletes. It removes the domain definition, and "
        "with `--remove-all-storage` the disk images too. A domain that is "
        "undefined while running keeps running until it stops, and then cannot "
        "be started again."
    ),
    "HEROKU-DESTROY": (
        "`apps:destroy` and `pg:reset` remove the application or empty the "
        "database, add-on data included. Both prompt for the app name, which "
        "is the only guard, and both are frequently run against the app whose "
        "name differs from the intended one by a `-staging` suffix."
    ),
    "EKSCTL-DEL": (
        "Deleting a cluster deletes the CloudFormation stacks behind it, which "
        "is more than the control plane: node groups, their instances, and any "
        "resources the stack owns. Persistent volumes provisioned through the "
        "cluster may be deleted with it depending on their reclaim policy."
    ),
    "PULUMI-DESTROY": (
        "Tears down every resource in the stack, with the same wrong-stack "
        "risk Terraform has and the same absence of a per-resource "
        "confirmation. `pulumi stack rm` additionally discards the state, "
        "which orphans anything the state described."
    ),
    "CEPH-DEL": (
        "Pool deletion in Ceph removes every object in the pool, and Ceph "
        "requires two confirmation flags precisely because there is no way "
        "back. `osd destroy` removes an OSD's identity and, with enough of "
        "them, the redundancy that was keeping the data available."
    ),
    "CM-ANSIBLE": (
        "The blast radius is the inventory pattern, not the playbook. A play "
        "that is fine on one host is the same play on four hundred, executed "
        "in parallel, and the mistake is usually a pattern that matched more "
        "than intended — `all` inherited from a group_vars default, or a "
        "wildcard that also matched production. `--check --diff` first, then "
        "`--limit` one host, then the fleet."
    ),
    # --- amplifiers ---------------------------------------------------------
    "FORCE": (
        "`--force` exists to get past a check. Every check it disables was put "
        "there by someone who had seen what happens without it, so the flag "
        "converts a refusal you could have read into an action you cannot "
        "undo. In an incident it is the flag people reach for after the third "
        "failure, which is exactly when they are least able to reason about "
        "what the check was for."
    ),
    "ASSUME-YES": (
        "Auto-confirmation removes the last human checkpoint. The prompt it "
        "suppresses is usually the one that would have printed the list — the "
        "packages about to be removed, the objects about to be deleted — so "
        "the flag does not just skip the question, it hides the answer. In CI "
        "it is unavoidable; in a shell it is a habit worth noticing."
    ),
    "SECRET-IN-ARGV": (
        "A credential on the command line is visible to every user on the host "
        "through `ps`, lands in shell history, and is captured verbatim by any "
        "process supervisor or CI log collector. It leaks without anything "
        "going wrong. Pass it by environment file, on stdin, or through a "
        "credential helper — and treat one that has been in argv as already "
        "disclosed."
    ),
    "OPEN-TO-WORLD": (
        "`0.0.0.0/0` is the entire internet, not 'anywhere in our network'. "
        "Ports opened this way are found by scanners within minutes, and the "
        "rule is usually added to unblock a connectivity problem whose real "
        "cause was something else. Name a CIDR you control."
    ),
    "NO-TLS-VERIFY": (
        "Disabling certificate verification makes a machine-in-the-middle "
        "indistinguishable from the real endpoint. It is almost always added "
        "to work around an expired or internal CA, and it then stays in the "
        "script long after the certificate is fixed — silently accepting any "
        "certificate for every later run."
    ),
    "REMOTE-EXEC-SUBST": (
        "Fetching a script inside a substitution runs unreviewed remote code "
        "with your privileges, and hides the fetch as its own step: there is "
        "no file on disk to read afterwards and nothing in the command line "
        "that looks like a download. The server can serve different content to "
        "a browser than to the shell, so 'I read it in my browser first' is "
        "not the check it feels like."
    ),
    "HISTFILE": (
        "Disabling shell history stops the audit trail at exactly the point "
        "someone would later want to read it. There are legitimate reasons — a "
        "secret typed by hand — but it is also the first line of a session "
        "nobody can reconstruct."
    ),
    "PROD-HINT": (
        "The target names a production environment. This is a weak signal by "
        "design: it is a string match, not knowledge. It exists because the "
        "single most common ingredient in a serious incident is a command that "
        "was correct for one environment run against another."
    ),
    "K8S-ALL": (
        "`--all` and `--all-namespaces` widen the selector to everything the "
        "credential can see, which on an admin kubeconfig is the cluster. The "
        "flag is often added to make a command that returned nothing return "
        "something — and the reason it returned nothing was usually a wrong "
        "namespace, not too narrow a selector."
    ),
    "RECURSIVE": (
        "Recursion turns one target into a subtree. The mistake is rarely the "
        "flag; it is the flag combined with a path that resolved differently "
        "than expected — a trailing slash, an unset variable, a symlink into "
        "somewhere much larger."
    ),
    "NO-PRESERVE-ROOT": (
        "`--no-preserve-root` disables the one guard `rm` has against deleting "
        "`/`. There is no legitimate interactive use: the guard exists because "
        "this has happened, repeatedly, to people who knew better."
    ),
    "PRIVILEGED": (
        "`--privileged` drops container isolation. The container can access "
        "host devices, load kernel modules and, through `/proc` and the "
        "cgroup filesystem, reach the host itself — this is host-level access "
        "wearing a container's name. It is usually added to make a mount or a "
        "device work, where a specific capability would have done."
    ),
    "HOST-MOUNT": (
        "Bind-mounting a host path into a container makes container writes "
        "host writes, with the container's user mapping rather than yours. "
        "Mounting `/` or `/var/run/docker.sock` is a full escape: the "
        "container can rewrite the host filesystem or start further "
        "containers with any options it likes."
    ),
}
