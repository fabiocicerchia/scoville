#!/usr/bin/env python3
"""scoville — risk posture for shell commands, before you run them.

Risk is not a property of a binary, it is a property of
`binary + flags + target + context`. `rm` is bad, `rm -rf` is worse,
`rm -rf /` is unrecoverable; `aws s3 ls` is free, `aws s3 rb --force` is not.
scoville scores that escalation and shows every factor that contributed.

Commands that carry another command (`docker exec`, `kubectl exec -- `,
`ssh host ...`, `sh -c`, `ansible -a`, `find -exec`) are scored on their
payload, not on the wrapper. Where the payload is hidden behind an image
ENTRYPOINT, `--introspect` resolves it with read-only docker inspects.

  scoville 'rm -rf /'
  scoville -f deploy.sh --format json
  scoville 'kubectl delete ns prod' --fail-on high
"""
import argparse
import difflib
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import textwrap

__version__ = "0.2.1"  # x-release-please-version

# ---------------------------------------------------------------- scales ---

# score -> band. Deliberately coarse: the band drives decisions, the score
# only orders commands within a band.
BANDS = ((85, "critical"), (60, "high"), (35, "medium"), (15, "low"), (0, "safe"))
LEVELS = ("safe", "low", "medium", "high", "critical")

# blast radius, ordered. A command's scope is the widest one it touches.
SCOPES = ("none", "file", "directory", "container", "host", "network", "cluster", "account")
# how hard it is to get back to where you were.
REVERT = ("reversible", "recoverable", "irreversible")


def band(score):
    """Name the band a score falls in.

    Deliberately coarse: the band is what a caller acts on, the score only
    orders commands inside one.
    """
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "safe"


def widest(a, b):
    """Return the wider of two blast radii — scope only ever grows."""
    return a if SCOPES.index(a) >= SCOPES.index(b) else b


def harder(a, b):
    """Return the less recoverable of two verdicts — reversibility only ever
    gets worse as factors accumulate."""
    return a if REVERT.index(a) >= REVERT.index(b) else b


# ----------------------------------------------------------------- rules ---


def _check(rid, scope, revert):
    """Refuse a rule that names a scope or reversibility nobody defined.

    The rule set is data, so a typo in a literal would otherwise sail through
    and score commands with a vocabulary the rest of the module cannot read.
    """
    assert scope in SCOPES, f"{rid}: unknown scope {scope!r}"
    assert revert in REVERT, f"{rid}: unknown reversibility {revert!r}"


def R(rid, bins, sub, base, scope, revert, why, advice=None, generic=False, paths=False,
      subsumes=""):
    """A rule: what this command *is*, before flags and targets are read.

    `generic` marks verb-classification rules (any `<cli> … delete`). A
    specific rule always beats a generic one, including when it scores lower.
    """
    _check(rid, scope, revert)
    return {
        "id": rid, "bins": set(bins.split()), "sub": re.compile(sub) if sub else None,
        "base": base, "scope": scope, "revert": revert, "why": why, "advice": advice,
        "generic": generic, "paths": paths, "subsumes": set(subsumes.split()),
    }


READ_ONLY = (
    "ls cat echo pwd whoami id date uname df du free ps top htop grep egrep fgrep awk head tail "
    "wc sort uniq which type file stat printenv hostname dig nslookup host whois ping traceroute "
    "mtr netstat ss lsof uptime env true false sleep tree jq yq column tee less more diff cmp "
    "md5sum sha256sum base64 seq basename dirname realpath readlink getent locale tty arch nproc"
)

# CLIs that manage resources somewhere else — cloud, SaaS, storage, virt.
# Their verbs are consistent enough to classify generically, which is what
# keeps a CLI nobody has written a rule for from scoring "safe".
RESOURCE_CLIS = (
    "hcloud scw doctl linode-cli lin vultr-cli exo civo upcloud ibmcloud oci aliyun ovhai "
    "flyctl fly heroku railway vercel netlify wrangler render pscale supabase planetscale "
    "gh glab tea eksctl velero argocd flux linkerd istioctl virsh incus lxc machinectl "
    "s3cmd rclone restic borg etcdctl vault consul nomad pulumi cdk cdktf serverless sls "
    "openstack ionosctl hetzner-k3s stripe twilio fastly akamai cf snap zfs ceph rbd"
)
# Verb position matters: the first verb in the command wins, so a resource
# *named* delete-me does not turn a describe into a destroy.
_LEAD = r"(?:\S+[\s:]){0,3}"
_READ = r"(?:list|ls|describe|get|show|info|status|version|inspect|read|view|search|find|diff)"
READ_VERBS = rf"^{_LEAD}{_READ}\b"
WRITE_VERBS = (rf"^(?!{_LEAD}{_READ}\b){_LEAD}"
               r"(?:create|add|new|update|set|attach|enable|apply|deploy|scale|resize|restart|"
               r"import|upload|put|publish|promote|rename|label|tag)\b")
DESTROY_VERBS = (rf"^(?!{_LEAD}{_READ}\b){_LEAD}"
                 r"(?:delete|destroy|remove|rm|terminate|purge|prune|wipe|revoke|disable|detach|"
                 r"drop|kill|reset|teardown|down|deprovision|decommission|expire)\b")

RULES = [
    # --- read-only baseline -------------------------------------------------
    R("READ", READ_ONLY, None, 0, "none", "reversible", "read-only: inspects, changes nothing"),
    R("READ-BUILTIN", "set cd export alias local declare readonly shift trap pushd popd dirs "
                      "umask ulimit test [ time getopts read printf let", None, 0, "none",
      "reversible", "shell builtin: affects this shell only"),
    R("READ-KEYWORD", "if then else elif fi for while until do done case esac in function "
                      "select break continue return exit", None, 0, "none", "reversible",
      "shell keyword: control flow, not a command"),
    R("READ-SED", "sed", None, 0, "none", "reversible", "stream edit to stdout, no file touched"),
    R("FS-SED-I", "sed perl", r"(^|\s)-i", 35, "file", "irreversible",
      "in-place edit: the original is overwritten unless a backup suffix is given",
      "`sed -i.bak` keeps the original next to the edited file", paths=True),
    R("READ-FIND", "find", None, 0, "none", "reversible", "directory walk, no mutation"),
    R("READ-CURL", "curl wget", None, 5, "none", "reversible",
      "network fetch; harmless until the response is executed or written"),
    R("READ-SSH", "ssh", None, 10, "host", "reversible",
      "opens a session on another host; risk is whatever runs there"),

    # --- filesystem ---------------------------------------------------------
    R("FS-RM", "rm", None, 35, "file", "irreversible",
      "rm unlinks immediately: no trash, no undo",
      "`rm -i`, or move to a staging dir and delete it later"),
    R("FS-RMDIR", "rmdir unlink", None, 20, "file", "irreversible", "removes a directory entry"),
    R("FS-SHRED", "shred wipe", None, 55, "file", "irreversible",
      "overwrites the data before unlinking: undelete tools cannot help"),
    R("FS-MV", "mv", None, 25, "file", "recoverable",
      "moves/overwrites; a destination that exists is silently replaced",
      "`mv -n` refuses to clobber an existing destination"),
    R("FS-CP", "cp rsync install", None, 20, "file", "recoverable",
      "writes over the destination tree"),
    R("FS-TRUNCATE", "truncate", None, 45, "file", "irreversible", "resizes a file in place"),
    R("FS-DD", "dd", None, 45, "file", "irreversible",
      "raw block writes, no filesystem safety net",
      "double-check `of=`; `status=progress` will not save you from the wrong device"),
    R("FS-MKFS", "mkfs mkfs.ext4 mkfs.xfs mkfs.btrfs mkswap wipefs sgdisk fdisk parted "
                 "cfdisk gdisk", None, 85, "host", "irreversible",
      "formats or repartitions a device: every filesystem on it is gone",
      "verify with `lsblk -f` first; unmount and take an image if the data matters"),
    R("FS-MOUNT", "mount", None, 15, "host", "reversible",
      "makes a filesystem visible: additive, and undone by unmounting it again"),
    R("FS-REMOUNT-RO", "mount", r"remount.*(^|[,\s])ro([,\s]|$)|(^|[,\s])ro([,\s]|$).*remount",
      45, "host", "recoverable",
      "remounting read-only: every writer on that filesystem starts failing immediately, "
      "usually as corruption-looking errors rather than a clean stop"),
    R("FS-UMOUNT", "umount", None, 35, "host", "recoverable",
      "detaches a filesystem; every process holding a file under it breaks",
      "`fuser -m <path>` or `lsof +D <path>` shows who is using it first"),
    R("FS-CHATTR", "chattr", None, 30, "file", "reversible", "changes immutable/append-only bits"),

    # --- permissions & privilege -------------------------------------------
    R("PRIV-CHMOD", "chmod", None, 25, "file", "reversible",
      "changes access bits; over-permissive modes are a security finding"),
    R("PRIV-CHOWN", "chown chgrp", None, 30, "file", "recoverable",
      "changes ownership; services fail when they can no longer read their own files"),
    R("PRIV-USERDEL", "userdel groupdel deluser delgroup", None, 55, "host", "irreversible",
      "removes an account; `-r` takes the home directory with it"),
    R("PRIV-PASSWD", "passwd chpasswd usermod", None, 40, "host", "recoverable",
      "changes credentials; locking the wrong account ends your access"),
    R("PRIV-VISUDO", "visudo", None, 35, "host", "recoverable", "edits sudo policy"),

    # --- shell / execution --------------------------------------------------
    R("EXEC-EVAL", "eval", None, 60, "host", "irreversible",
      "eval runs text assembled at run time: what executes cannot be read from this line, by "
      "you or by any reviewer, and if any part of that text came from outside the script it is "
      "arbitrary code execution",
      "there is almost always a direct form — arrays, `${!name}` indirection or a case "
      "statement — that says what it runs; if eval is truly needed, echo the string first"),
    R("EXEC-SOURCE", "source .", None, 35, "host", "recoverable",
      "runs another file's commands in this shell, so it can also change this shell's "
      "environment and functions"),
    R("EXEC-SHELL", "sh bash zsh dash ksh", None, 10, "host", "reversible",
      "spawns a shell; risk is whatever it is told to run"),
    R("EXEC-FORKBOMB", "", None, 0, "none", "reversible", "placeholder"),
    R("EXEC-HISTORY", "history", r"-c|-d", 40, "host", "irreversible",
      "erases shell history: destroys the record of what was run",
      "if this is not deliberate audit-trail removal, do not run it"),

    # --- system state -------------------------------------------------------
    R("SYS-POWER-CTL", "systemctl",
      r"^(poweroff|reboot|halt|emergency|rescue|kexec|isolate)\b", 70, "host", "recoverable",
      "takes the host down or into a target with almost nothing running"),
    R("SYS-POWER-CANCEL", "shutdown", r"(^|\s)-c(\s|$)", 0, "none", "reversible",
      "cancels a pending shutdown: this is the undo, not the action"),
    R("SYS-POWER", "reboot shutdown halt poweroff", None, 70, "host", "recoverable",
      "takes the host down; remote hosts may not come back without console access",
      "check for other sessions (`who`) and confirm out-of-band access first"),
    R("SYS-INIT", "init telinit", r"^[06]", 70, "host", "recoverable", "changes runlevel: halt/reboot"),
    R("SYS-KILL", "kill pkill killall", None, 35, "host", "recoverable",
      "terminates processes; `-9` gives them no chance to flush state"),
    R("SYS-SYSTEMCTL-R", "systemctl service", r"^(status|show|list-|is-|cat|get-default)", 0,
      "none", "reversible", "read-only service query"),
    R("SYS-SYSTEMCTL-W", "systemctl service",
      r"^(restart|reload|start|enable|daemon-reload|daemon-reexec|set-property|edit)\b", 25,
      "host", "recoverable",
      "changes service state; a restart is a brief outage, and a config that no longer parses "
      "will not come back up"),
    R("SYS-SYSTEMCTL", "systemctl service", r"^(stop|disable|kill)", 45, "host", "recoverable",
      "stops a service; anything depending on it fails now"),
    R("SYS-MASK", "systemctl", r"^mask", 55, "host", "recoverable",
      "masking hides the unit entirely: later `start` silently does nothing"),
    R("SYS-CRONTAB", "crontab", r"(^|\s)-r(\s|$)", 60, "host", "irreversible",
      "`crontab -r` deletes the whole crontab with no confirmation (and sits next to `-e`)",
      "`crontab -l > backup.cron` first — always"),
    R("SYS-SWAP", "swapoff", None, 30, "host", "reversible", "disables swap; can trigger the OOM killer"),
    R("SYS-SYSCTL", "sysctl", r"-w|=", 35, "host", "reversible", "changes kernel parameters at runtime"),

    # --- network ------------------------------------------------------------
    R("NET-IFUP", "ifup", None, 10, "network", "reversible",
      "brings an interface up: additive, and reversible from the same session"),
    R("NET-IFDOWN", "ifdown", None, 50, "network", "recoverable",
      "brings an interface down: if it carries your session, you lose the host "
      "and the command that would bring it back",
      "wrap it: `(ifdown eth0; sleep 60; ifup eth0) &` — or use a console"),
    R("NET-IPLINK", "ip", r"^link\s+set\b.*\bdown\b", 50, "network", "recoverable",
      "downs a link; same lockout risk as ifdown"),
    R("NET-IPREAD", "ip", r"^\w+\s+(show|list|get)|^(a|addr|link|route|neigh)$", 0, "none",
      "reversible", "read-only network query"),
    R("NET-IPROUTE", "ip route",
      r"^(a|addr|address|route|r|rule|neigh|link|l)\s+(del|delete|flush|change|replace)|"
      r"^(del|delete|flush)\b", 45, "network", "recoverable",
      "rewrites addressing or routing: the path your session is on may be one of them"),
    R("NET-NMCLI", "nmcli", r"^(c|con|connection)\s+(delete|down)|^(d|dev|device)\s+disconnect",
      50, "network", "recoverable",
      "takes down or deletes a NetworkManager connection: same lockout risk as ifdown"),
    R("NET-IPTABLES", "iptables ip6tables nft", r"-F|--flush|flush", 65, "network", "recoverable",
      "flushing rules drops every allow rule too; with a DROP policy the host goes silent",
      "`iptables-save > rules.bak` first, and use a rollback timer"),
    R("NET-IPTABLES-P", "iptables ip6tables", r"-P\s+INPUT\s+DROP", 75, "network", "recoverable",
      "sets the default input policy to DROP: immediate lockout unless SSH is already allowed"),
    R("NET-UFW", "ufw firewall-cmd",
      r"^(disable|reset|--force reset)|--remove-(service|port|source)|--set-target=DROP", 45,
      "network", "recoverable", "removes or narrows host firewalling — including, possibly, "
      "the rule that lets you back in"),
    R("NET-NC", "nc ncat netcat", r"-e|-c", 60, "network", "irreversible",
      "`nc -e` hands a shell to whatever is on the other end"),
    R("NET-TC", "tc", r"\bdel\b|\badd\b", 40, "network", "recoverable",
      "traffic control changes affect every flow on the interface"),

    # --- packages -----------------------------------------------------------
    # Installing is not a read: maintainer scripts run as root, and removals
    # take dependants and config with them.
    R("PKG-READ", "apt apt-get aptitude yum dnf apk zypper brew pacman pip pip3 pipx npm yarn "
                  "pnpm gem cargo composer nix-env snap flatpak port conda mamba poetry uv",
      r"^(list|search|show|info|policy|update|why|deps|outdated|audit|view|ls)\b", 5, "none",
      "reversible", "queries or refreshes package metadata"),
    R("PKG-READ-FLAG", "dpkg rpm", r"(^|\s)-[a-zA-Z]*[lLqsSV](\s|$)|--(list|query|verify)\b", 0,
      "none", "reversible", "queries the package database"),
    R("PKG-INSTALL", "apt apt-get aptitude yum dnf apk zypper pacman brew pip pip3 pipx npm yarn "
                     "pnpm gem cargo go composer nix-env emerge port snap flatpak conda mamba "
                     "micromamba poetry uv",
      r"^(install|add|i|upgrade|update|reinstall|get|build|sync)\b|(^|\s)-S(\s|$)", 35, "host",
      "recoverable",
      "installs code and runs its maintainer/post-install scripts as root: arbitrary "
      "code execution by design, from whoever owns that package today",
      "pin the version, and read what a new repo/tap actually ships before adding it"),
    R("PKG-REMOVE", "apt apt-get aptitude yum dnf apk zypper pacman brew pip pip3 pipx npm yarn "
                    "pnpm gem cargo composer nix-env port conda mamba micromamba poetry uv "
                    "flatpak snap",
      r"^(remove|purge|autoremove|uninstall|erase|del|delete|rm|unmerge|prune)\b", 45, "host",
      "recoverable",
      "removes packages; purge/autoremove also take configuration and dependencies",
      "read the 'to be REMOVED' list — autoremove has uninstalled running kernels before"),
    # Flag-style removal, per binary: one shared regex either misses `-Rns` or
    # reads `pacman -Qe` as a removal.
    R("PKG-RM-PACMAN", "pacman yay paru", r"(^|\s)-[A-Za-z]*R", 50, "host", "recoverable",
      "`-R` removes packages; `-Rns` also takes their configs and unused dependencies"),
    R("PKG-RM-DPKG", "dpkg", r"(^|\s)-[rP](\s|$)|--(remove|purge)\b", 50, "host", "recoverable",
      "removes a package without consulting the dependency solver"),
    R("PKG-RM-RPM", "rpm", r"(^|\s)-e\b|--erase\b", 50, "host", "recoverable",
      "`rpm -e` removes a package with no transaction to roll back"),
    R("PKG-RM-NIX", "nix-env", r"(^|\s)-e\b|--uninstall\b", 45, "host", "recoverable",
      "removes a package from the profile (the generation is still there until GC)"),
    R("PKG-RM-EMERGE", "emerge", r"(^|\s)-C\b|--unmerge\b|--depclean\b", 50, "host",
      "recoverable", "unmerges packages; `--depclean` decides for itself what is unused"),
    R("PKG-RELEASE-UPGRADE", "do-release-upgrade", None, 55, "host", "recoverable",
      "distribution release upgrade: replaces the kernel, libc and init in one transaction",
      "snapshot or image the host first; this is the operation servers do not come back from"),
    R("PKG-DIST-UPGRADE", "apt apt-get do-release-upgrade dnf zypper pacman",
      r"^(full-upgrade|dist-upgrade|system-upgrade|dup)\b|(^|\s)-Syu", 55, "host", "recoverable",
      "distribution upgrade: replaces the kernel, libc and init in one transaction",
      "snapshot or image the host first; this is the operation servers do not come back from"),
    R("PKG-GC", "nix-collect-garbage brew yum dnf pacman",
      r"^(cleanup|clean)\b|(^|\s)-(d|Scc)(\s|$)", 40, "host", "irreversible",
      "garbage-collects package state; `nix-collect-garbage -d` deletes the older generations, "
      "which are the rollback targets"),
    R("PKG-FORCE", "dpkg rpm apt-get", r"--force|--nodeps|--allow-downgrades", 55, "host",
      "recoverable", "overrides the package manager's own consistency checks",
      subsumes="FORCE"),
    R("PKG-RUN", "npm yarn pnpm", r"^(run|run-script|exec|dlx)\b", 10, "host", "reversible",
      "runs a script defined in package.json"),
    R("RUN-MAKE", "make gmake just task mise", None, 10, "host", "reversible",
      "runs a target defined in the project's build/task file"),
    R("PKG-PUBLISH", "npm cargo gem twine", r"^publish\b|^upload\b", 60, "account",
      "irreversible",
      "publishes to a public registry: unpublish windows are short and versions are permanent",
      "`npm publish --dry-run` and check `files`/`.npmignore` for secrets first"),

    # --- remote code --------------------------------------------------------
    R("SEC-PIPE-SHELL", "", None, 0, "none", "reversible", "placeholder"),

    # --- git ----------------------------------------------------------------
    R("GIT-READ", "git", r"^(status|log|diff|show|branch$|remote|fetch|describe|blame|stash list)",
      0, "none", "reversible", "read-only git query"),
    R("GIT-PUSH", "git", r"^push\b", 20, "network", "recoverable", "publishes commits"),
    R("GIT-PUSH-F", "git", r"^push\b.*(--force(?!-with-lease)|(\s|^)-f\b)", 55, "network",
      "irreversible", "force-push overwrites remote history; other clones diverge silently",
      "`--force-with-lease` refuses when the remote moved under you", subsumes="FORCE"),
    R("GIT-PUSH-DEL", "git", r"^push\b.*(--delete|\s:\w)", 50, "network", "recoverable",
      "deletes a remote ref"),
    R("GIT-RESET", "git", r"^reset\b.*--hard", 40, "directory", "irreversible",
      "discards uncommitted work in the tree and index",
      "`git stash -u` costs nothing and is undoable"),
    R("GIT-CLEAN", "git", r"^clean\b.*-[a-z]*[fd]", 45, "directory", "irreversible",
      "deletes untracked files; `-x` also takes ignored ones (.env, local configs)",
      "`git clean -nd` prints what it would delete"),
    R("GIT-BRANCH-D", "git", r"^branch\b.*-D", 25, "directory", "recoverable",
      "force-deletes a branch without a merge check (reflog keeps it for a while)"),
    R("GIT-REFLOG-EXPIRE", "git",
      r"^reflog\s+expire.*--expire[= ](now|all)|^gc\b.*--prune[= ]now", 60, "directory",
      "irreversible",
      "the reflog is what makes `reset --hard` and a deleted branch recoverable; expiring it "
      "turns every earlier 'recoverable' into 'gone'"),
    R("GIT-PUSH-MIRROR", "git", r"^push\b.*--mirror", 70, "network", "irreversible",
      "`--mirror` makes the remote match your local refs exactly: branches and tags you do "
      "not have locally are deleted on the remote"),
    R("GIT-STASH-CLEAR", "git", r"^stash\s+(clear|drop)", 35, "directory", "irreversible",
      "stash entries are unreachable once dropped; only a reflog hunt finds them"),
    R("GIT-REWRITE", "git", r"^(filter-branch|filter-repo|rebase\b.*-i)", 45, "directory",
      "recoverable", "rewrites history: every existing clone and PR is invalidated"),
    R("GIT-CHECKOUT-F", "git",
      r"^(checkout|restore|switch)\b.*(-f|--force|--hard)|^(checkout|restore)\s+\.(\s|$)", 35,
      "directory", "irreversible", "overwrites local modifications"),

    # --- containers ---------------------------------------------------------
    R("CTR-READ", "docker podman nerdctl",
      r"^(ps|images|image ls|logs|inspect|stats|top|version|info|port|diff|history)\b", 0, "none",
      "reversible", "read-only container query"),
    R("CTR-EXEC", "docker podman nerdctl kubectl", r"^exec\b", 20, "container", "reversible",
      "runs a command inside a running container: scored on the payload below"),
    R("CTR-RUN", "docker podman nerdctl", r"^(run|create|start)\b", 20, "container", "reversible",
      "starts a container: what actually runs is the image ENTRYPOINT/CMD unless overridden"),
    R("CTR-RM", "docker podman nerdctl", r"^(rm|rmi|image rm|container rm)\b", 30, "container",
      "recoverable", "removes containers/images; anything not in a volume goes with them"),
    R("CTR-VOLUME-RM", "docker podman", r"^volume\s+(rm|prune)", 60, "host", "irreversible",
      "volumes are where the data actually lives",
      "`docker run --rm -v vol:/v alpine tar cf - /v > vol.tar` before removing"),
    R("CTR-PRUNE", "docker podman",
      r"^(system|image|container|builder|network)\s+prune", 45, "host", "irreversible",
      "prunes unused objects; `-a --volumes` interprets 'unused' very broadly"),
    R("CTR-COMPOSE-DOWN", "docker-compose", r"^down\b.*(-v|--volumes)", 60, "host", "irreversible",
      "`down -v` deletes the stack's volumes: databases included", subsumes="PURGE-FLAG"),
    R("CTR-KILL", "docker podman", r"^(kill|stop|restart)\b", 30, "container", "recoverable",
      "stops running containers"),

    # --- kubernetes ---------------------------------------------------------
    R("K8S-READ", "kubectl oc",
      r"^(get|describe|logs|top|explain|api-resources|api-versions|version|cluster-info|diff|"
      r"auth can-i|config (view|get|current))\b", 0, "none", "reversible", "read-only cluster query"),
    R("K8S-APPLY", "kubectl oc", r"^(apply|create|replace|patch|edit|set|label|annotate)\b", 30,
      "cluster", "recoverable", "mutates cluster state"),
    R("K8S-DELETE", "kubectl oc", r"^delete\b", 55, "cluster", "irreversible",
      "deletes resources; controllers will not bring back what they did not create",
      "`--dry-run=server` first, and keep the manifest in git", generic=True),
    R("K8S-DELETE-POD", "kubectl oc",
      r"^delete\s+(pod|pods|po)\b(?!.*(--all|--all-namespaces|(\s)-A(\s|$)))", 25, "cluster",
      "recoverable",
      "a named pod is replaced by its controller — this is a restart, not a deletion"),
    R("K8S-DELETE-NS", "kubectl oc", r"^delete\b.*\b(ns|namespace)\b", 80, "cluster",
      "irreversible",
      "deleting a namespace cascades to everything inside it, PVCs included",
      "there is no undo and no controller that will rebuild it — export the namespace first"),
    R("K8S-DELETE-CRD", "kubectl oc", r"^delete\b.*\b(crd|customresourcedefinition)", 85,
      "cluster", "irreversible",
      "deleting a CRD deletes every custom resource of that kind, cluster-wide, in one go",
      "check `kubectl get <kind> -A` first — the cascade is invisible from this line"),
    R("K8S-DELETE-PVC", "kubectl oc", r"^delete\b.*\b(pvc|persistentvolumeclaim|pv)\b", 75,
      "cluster", "irreversible",
      "PVCs are the data; with a Delete reclaim policy the underlying volume goes too"),
    R("K8S-DRAIN", "kubectl oc", r"^drain\b", 50, "cluster", "recoverable",
      "evicts every pod from a node; PDBs are the only thing keeping this safe"),
    R("K8S-CORDON", "kubectl oc", r"^(cordon|uncordon|taint)\b", 20, "cluster", "reversible",
      "changes node schedulability"),
    R("K8S-SCALE-0", "kubectl oc", r"^scale\b.*--replicas[= ]0\b", 45, "cluster", "reversible",
      "scales to zero: an outage that looks like a config change"),
    R("K8S-ROLLOUT", "kubectl oc", r"^rollout\s+(restart|undo)", 30, "cluster", "recoverable",
      "restarts or reverts a workload"),
    R("K8S-PF", "kubectl oc", r"^(port-forward|proxy)\b", 15, "network", "reversible",
      "bridges cluster network into this host for as long as it runs"),
    R("HELM-READ", "helm", r"^(list|ls|status|get|show|history|template|diff|search)\b", 0, "none",
      "reversible", "read-only release query"),
    R("HELM-INSTALL", "helm", r"^(install|upgrade)\b", 35, "cluster", "recoverable",
      "applies a chart; `--force` recreates resources rather than patching them"),
    R("HELM-DELETE", "helm", r"^(uninstall|delete)\b", 60, "cluster", "irreversible",
      "removes a release; PVCs created by the chart usually go too"),

    # --- IaC ----------------------------------------------------------------
    R("IAC-READ", "terraform tofu", r"^(plan|validate|fmt|show|output|providers|version|graph)\b",
      0, "none", "reversible", "read-only or planning operation"),
    R("IAC-APPLY", "terraform tofu", r"^apply\b", 45, "account", "recoverable",
      "applies a plan to real infrastructure"),
    R("IAC-DESTROY", "terraform tofu", r"^destroy\b", 80, "account", "irreversible",
      "destroys every resource in the state file",
      "`terraform plan -destroy` and check the workspace — this is how prod dies"),
    R("IAC-STATE-RM", "terraform tofu", r"^state\s+(rm|mv|push|replace-provider)", 60, "account",
      "recoverable", "edits state directly: state and reality drift apart from here",
      "`terraform state pull > state.bak` first"),
    R("IAC-TAINT", "terraform tofu", r"^(taint|apply -replace|untaint)", 40, "account",
      "recoverable", "marks resources for recreation on the next apply"),
    R("IAC-WORKSPACE", "terraform tofu", r"^workspace\s+delete", 45, "account", "irreversible",
      "deletes a workspace and its state pointer"),

    # --- cloud CLIs ---------------------------------------------------------
    R("AWS-READ", "aws", r"^\S+\s+(ls|describe|list|get|head|lookup|search|estimate|preview|"
                        r"validate|simulate|test|generate|wait|check)[\w-]*", 0, "none",
      "reversible", "read-only AWS API call", generic=True),
    R("AWS-WRITE", "aws", r"^\S+\s+(create|put|update|modify|attach|associate|register|enable|"
                          r"tag|set|import|copy|start|run|invoke|publish|authorize|grant|"
                          r"allow|share|add)[\w-]*", 30, "account",
      "recoverable", "mutates cloud state and may cost money immediately", generic=True),
    R("AWS-DESTROY", "aws", r"^\S+\s+(delete|terminate|remove|destroy|deregister|detach|disable|"
                            r"revoke|purge|release|cancel|abort|reboot|stop)[\w-]*", 65, "account",
      "irreversible", "destructive AWS API call",
      "confirm the account and region on the profile you are about to use", generic=True),
    R("AWS-S3-RB", "aws", r"^s3\s+rb\b|^s3api\s+delete-bucket", 75, "account", "irreversible",
      "deletes a bucket; the name is then claimable by anyone and links 404 forever"),
    R("AWS-S3-RM-R", "aws", r"^s3\s+rm\b.*--recursive", 80, "account", "irreversible",
      "recursive object delete: without versioning there is nothing to restore from",
      "`--dryrun` prints the exact key list it would delete"),
    R("AWS-EC2-TERM", "aws", r"^ec2\s+terminate-instances", 80, "account", "irreversible",
      "terminates instances; instance-store data and the instance itself are gone"),
    R("AWS-RDS-DEL", "aws", r"^rds\s+delete-db-(instance|cluster)", 85, "account", "irreversible",
      "deletes a database",
      "never with `--skip-final-snapshot`; take the final snapshot"),
    R("AWS-CFN-DEL", "aws", r"^cloudformation\s+delete-stack", 80, "account", "irreversible",
      "deletes every resource the stack owns"),
    R("AWS-KMS-DEL", "aws", r"^kms\s+(schedule-key-deletion|disable-key)", 85, "account",
      "irreversible", "without the key, every ciphertext under it is permanently unreadable"),
    R("AWS-IAM-DEL", "aws", r"^iam\s+(delete|detach|remove|update-assume-role-policy)", 70,
      "account", "recoverable",
      "IAM changes can lock you (or every workload) out of the account",
      "check `iam simulate-principal-policy` and keep a break-glass admin session open"),
    R("AWS-ORG", "aws", r"^organizations\s+(leave|remove-account|delete|close-account)", 90,
      "account", "irreversible", "organization-level change affecting whole accounts"),
    R("GCP-READ", "gcloud gsutil bq", r"^(\S+\s+)*(list|describe|get|ls|cat|show|info|version)\b",
      0, "none", "reversible", "read-only GCP call", generic=True),
    R("GCP-DESTROY", "gcloud gsutil bq",
      r"^(\S+\s+)*(delete|destroy|remove|rm|rb|disable|revoke)\b", 65, "account", "irreversible",
      "destructive GCP call", generic=True),
    R("GCP-WRITE", "gcloud gsutil bq",
      r"^(\S+\s+){0,3}(create|add|update|set|enable|deploy|import|cp|mv|apply|attach)\b", 30,
      "account", "recoverable", "creates or mutates GCP resources, and may start billing",
      generic=True),
    R("GCP-PROJECT", "gcloud", r"^projects\s+delete", 90, "account", "irreversible",
      "deletes a project and everything in it"),
    R("AZ-READ", "az", r"^(\S+\s+)*(list|show|get|check|version)\b", 0, "none", "reversible",
      "read-only Azure call", generic=True),
    R("AZ-DESTROY", "az", r"^(\S+\s+)*(delete|remove|purge|disable|revoke)\b", 65, "account",
      "irreversible", "destructive Azure call", generic=True),
    R("AZ-WRITE", "az",
      r"^(\S+\s+){0,3}(create|add|update|set|enable|deploy|import|start|restart)\b", 30,
      "account", "recoverable", "creates or mutates Azure resources, and may start billing",
      generic=True),
    R("AZ-GROUP-DEL", "az", r"^group\s+delete", 85, "account", "irreversible",
      "deletes a resource group: everything inside it goes, asynchronously and silently"),

    # --- databases ----------------------------------------------------------
    R("DB-CLIENT", "psql mysql mariadb mongo mongosh redis-cli sqlite3 clickhouse-client", None,
      15, "host", "recoverable", "database client session"),
    R("DB-DROP", "psql mysql mariadb sqlite3 clickhouse-client",
      r"\bDROP\s+(TABLE|INDEX|VIEW|SEQUENCE)\b", 78, "account", "irreversible",
      "DROP is instant and unlogged in most setups: restore-from-backup is the only undo",
      "take a dump first; wrap it in BEGIN/ROLLBACK to see what it touches"),
    R("DB-DROP-DB", "psql mysql mariadb sqlite3 clickhouse-client",
      r"\bDROP\s+(DATABASE|SCHEMA)\b", 88, "account", "irreversible",
      "drops an entire database: every table, index and grant in it",
      "restore-testing your backup is cheaper than discovering it does not restore"),
    R("DB-TRUNCATE", "psql mysql mariadb sqlite3", r"\bTRUNCATE\b", 70, "account", "irreversible",
      "TRUNCATE empties the table and usually skips triggers and the redo path"),
    R("DB-DELETE-ALL", "psql mysql mariadb sqlite3",
      r"\bDELETE\s+FROM\s+[\w.\"`]+\s*(;|$|\")", 75, "account", "irreversible",
      "DELETE with no WHERE clause: every row",
      "run it as `SELECT count(*)` first, then add the WHERE"),
    R("DB-UPDATE-ALL", "psql mysql mariadb sqlite3",
      r"\bUPDATE\s+[\w.\"`]+\s+SET\b(?!.*\bWHERE\b)", 65, "account", "irreversible",
      "UPDATE with no WHERE clause: every row"),
    R("DB-DROP-COLUMN", "psql mysql mariadb sqlite3",
      r"\bALTER\s+TABLE\b.*\bDROP\s+(COLUMN|CONSTRAINT)\b", 70, "account", "irreversible",
      "dropping a column deletes its data; no migration framework can bring it back"),
    R("DB-GRANT", "psql mysql mariadb", r"\b(GRANT|REVOKE|ALTER\s+USER|DROP\s+USER)\b", 45,
      "account", "recoverable", "changes database access control"),
    R("DB-FLUSH", "redis-cli", r"\bFLUSH(ALL|DB)\b", 85, "account", "irreversible",
      "empties the keyspace; if this is a cache in front of a cold DB, it is also an outage"),
    R("DB-MONGO-DROP", "mongo mongosh", r"\bdrop(Database|Collection)?\s*\(", 88, "account",
      "irreversible", "drops a Mongo database or collection"),
    R("DB-RESTORE", "pg_restore mysqlimport mongorestore", r"--drop|--clean", 60, "account",
      "irreversible", "restore with --clean/--drop removes existing objects before loading"),

    # --- exposure: widening access is a different failure from destroying ----
    R("SEC-IAM-KEY", "aws", r"^iam\s+create-access-key", 50, "account", "recoverable",
      "mints a long-lived access key: it does not expire, it will end up in a file, and it "
      "carries everything that user can do",
      "prefer a role with short-lived credentials; if you must, record the key id to rotate"),
    R("SEC-S3-PUBLIC", "aws", r"(put-bucket-acl|put-object-acl).*(public-read|public-read-write)|"
                              r"delete-public-access-block|"
                              r"put-public-access-block.*BlockPublicAcls=false", 70, "account",
      "recoverable", "makes bucket contents world-readable — this is the classic data leak",
      "check what is in the bucket before, not after"),
    R("SEC-IAM-ADMIN", "aws", r"(attach|put)-(role|user|group)-policy.*"
                              r"(AdministratorAccess|PowerUserAccess)", 70, "account",
      "recoverable", "grants administrator rights: whoever holds that principal now owns the "
      "account"),
    R("SEC-GCP-ALLUSERS", "gcloud gsutil", r"(allUsers|allAuthenticatedUsers)", 70, "account",
      "recoverable", "`allUsers` means the public internet, unauthenticated"),
    R("SEC-K8S-ADMIN", "kubectl oc",
      r"create\s+clusterrolebinding.*(cluster-admin|--user=system:anonymous)|"
      r"create\s+clusterrolebinding.*--group=system:unauthenticated", 70, "cluster",
      "recoverable", "binds cluster-admin: this is full control of every workload and secret"),
    R("SEC-SELINUX", "setenforce aa-disable", None, 45, "host", "reversible",
      "disables mandatory access control for the whole host"),
    R("SEC-AUDIT", "auditctl", r"(^|\s)-D(\s|$)|-e\s+0", 60, "host", "irreversible",
      "deletes every audit rule: the host stops recording what happens next"),
    R("SEC-JOURNAL", "journalctl", r"--vacuum-(time|size|files)|--rotate", 45, "host",
      "irreversible", "truncates the journal: the evidence of what happened goes with it"),

    # --- storage, devices, virtualisation ------------------------------------
    R("FS-DISCARD", "blkdiscard nvme hdparm sg_format", r"^(format|--security-erase|"
      r"--security-erase-enhanced|--trim-sector-ranges)|^/dev/", 90, "host", "irreversible",
      "issues a device-level erase: the controller drops the mapping, so no undelete exists",
      "there is no recovery path for this one — verify the device node twice"),
    R("FS-CRYPT", "cryptsetup", r"^(luksFormat|erase|luksErase|luksRemoveKey|luksKillSlot)", 90,
      "host", "irreversible",
      "destroys or rewrites the LUKS header; without it the data is unrecoverable even with "
      "the right passphrase",
      "`cryptsetup luksHeaderBackup` first, always"),
    R("FS-BADBLOCKS", "badblocks", r"(^|\s)-w", 85, "host", "irreversible",
      "`-w` is the destructive write test: it overwrites every block it checks"),
    R("FS-ZPOOL", "zpool", r"^(destroy|labelclear|remove|split)", 85, "host", "irreversible",
      "destroys a pool or clears its labels; every dataset on it goes"),
    R("FS-FSCK", "fsck e2fsck xfs_repair", r"(^|\s)-[ypfL]|(^|\s)-a\b", 55, "host",
      "recoverable",
      "auto-repair discards what it cannot reconcile; `xfs_repair -L` zeroes the log and its "
      "unflushed writes",
      "image the filesystem first if the data is worth more than the downtime",
      subsumes="ASSUME-YES"),
    R("FS-RESIZE", "resize2fs lvreduce xfs_growfs",
      r"(^|\s)-[LrR]\b|\b\d+[KMGTPkmgtp]?(\s|$)|--size", 70, "host",
      "irreversible", "shrinking a filesystem or volume below its used size truncates data"),
    R("FS-MDADM", "mdadm", r"--(zero-superblock|fail|remove|stop|create)", 80, "host",
      "irreversible", "changes RAID membership; zeroing a superblock forgets the array layout"),
    R("SYS-SYSRQ", "", None, 0, "none", "reversible", "placeholder"),

    # --- boot path: the host comes back, or it does not ----------------------
    R("BOOT-LOADER", "grub-install update-grub grub2-mkconfig grub2-install dracut mkinitcpio "
                     "update-initramfs efibootmgr bootctl", None, 60, "host", "recoverable",
      "rewrites the boot path; a mistake here is not visible until the next reboot, and the "
      "fix needs console or rescue media",
      "keep the previous kernel entry, and reboot while you still have console access"),
    R("BOOT-TUNE2FS", "tune2fs", r"-U|-L|-O", 65, "host", "recoverable",
      "changing a filesystem UUID or label breaks every fstab entry and bootloader stanza "
      "that referenced the old one"),
    R("BOOT-KEXEC", "kexec", r"-e|--exec", 70, "host", "recoverable",
      "switches to another kernel immediately, without firmware or a clean shutdown"),
    R("BOOT-MODULE", "rmmod modprobe insmod", r"^(-r|--remove)|^\w", 45, "host", "recoverable",
      "unloading a kernel module can remove the storage or network driver the host is using"),
    R("SYS-TIME", "timedatectl ntpdate chronyc hwclock",
      r"set-time|set-timezone|makestep|-w|--systohc|^\S+\.", 40, "host", "recoverable",
      "a clock jump invalidates TLS sessions, tokens and TOTP, and confuses anything that "
      "reasons about ordering (replication, leases, certificates)"),

    # --- keys and certificates ----------------------------------------------
    R("CERT-REVOKE", "certbot acme.sh lego", r"^(revoke|delete)\b|--revoke", 70, "network",
      "irreversible",
      "revoking a certificate breaks TLS for every client that checks revocation, "
      "immediately and irreversibly — reissue is a new certificate, not an undo"),
    R("KEY-DELETE", "gpg keytool ssh-keygen",
      r"--delete-secret|--delete-key|-delete\b|--remove-key", 75, "account", "irreversible",
      "deleting a private key destroys access to everything encrypted or signed with it"),

    # --- cluster membership --------------------------------------------------
    R("CLUSTER-RESET", "kubeadm k3s-uninstall.sh k0s", r"^reset\b|^uninstall\b|^stop\b", 85,
      "cluster", "irreversible",
      "resets the node out of the cluster: certificates, etcd member and CNI state are all "
      "removed",
      "on a control-plane node this can lose quorum for the whole cluster"),
    R("CLUSTER-LEAVE", "docker consul nomad",
      r"^swarm\s+leave|^leave\b|^(server|node)\s+force-leave", 60, "cluster", "recoverable",
      "removes this node from its cluster"),
    R("ETCD-RESTORE", "etcdctl etcdutl", r"snapshot\s+restore", 80, "cluster", "irreversible",
      "restoring a snapshot replaces current cluster state with the snapshot's: everything "
      "written since it was taken is gone"),

    # --- data services -------------------------------------------------------
    R("MQ-RESET", "rabbitmqctl", r"^(reset|force_reset|purge_queue|delete_queue|delete_vhost)",
      75, "account", "irreversible",
      "resets the broker or empties a queue: in-flight messages have no other copy"),
    R("KAFKA-DELETE", "kafka-topics.sh kafka-topics kafka-configs.sh",
      r"--delete\b", 75, "account", "irreversible",
      "deleting a topic drops its partitions and every retained message"),
    R("PG-RESET", "pg_resetwal pg_resetxlog", None, 90, "account", "irreversible",
      "resetting the write-ahead log discards unreplayed transactions and can leave the "
      "cluster silently inconsistent",
      "this is a last resort after hardware failure, not a startup fix — take a file-level "
      "copy of the data directory first"),
    R("PG-STOP-IMMEDIATE", "pg_ctl", r"stop\b.*-m\s*(immediate|i)\b", 55, "host", "recoverable",
      "immediate mode aborts every session without a checkpoint: recovery runs on next start"),
    R("MYSQLADMIN", "mysqladmin", r"^(drop|shutdown|flush-logs|reset)", 70, "account",
      "irreversible", "drops a database or stops the server without a graceful shutdown"),

    # --- schema migrations ---------------------------------------------------
    R("MIGRATE-CLEAN", "flyway liquibase", r"^(clean|dropAll|drop-all)\b", 90, "account",
      "irreversible",
      "drops every object in the target schema — this is the command Flyway ships a "
      "`cleanDisabled` setting for, because it has erased production before"),
    R("MIGRATE-RESET", "rails rake bin/rails", r"db:(drop|reset|purge)\b", 85, "account",
      "irreversible", "drops the application database"),
    R("MIGRATE-DJANGO", "django-admin manage.py python", r"(manage\.py\s+)?(flush|sqlflush)\b",
      70, "account", "irreversible", "`flush` deletes every row in every table"),
    R("MIGRATE-PRISMA", "prisma npx", r"migrate\s+reset\b", 80, "account", "irreversible",
      "drops and recreates the database from migrations: all data goes"),
    R("MIGRATE-DOWN", "alembic knex sequelize goose dbmate",
      r"downgrade\s+base|migrate:rollback.*--all|down-to\s+0|^down\b", 70, "account",
      "irreversible", "rolls every migration back to an empty schema"),

    # --- network plumbing ----------------------------------------------------
    R("NET-CONNTRACK", "conntrack", r"(^|\s)-F(\s|$)|--flush", 45, "network", "recoverable",
      "flushing connection tracking drops every NAT mapping: established connections through "
      "this host break mid-stream"),
    R("NET-NETNS", "ip", r"^netns\s+(del|delete)", 50, "network", "recoverable",
      "deleting a network namespace takes its interfaces and the workloads using them"),
    R("NET-BRIDGE", "ovs-vsctl brctl", r"^(del-br|delbr|del-port|delif|emer-reset)", 55,
      "network", "recoverable",
      "removing a bridge disconnects every interface attached to it — on a hypervisor that "
      "is every guest"),

    # --- macOS ---------------------------------------------------------------
    R("MAC-DISKUTIL", "diskutil", r"^(eraseDisk|eraseVolume|reformat|apfs\s+delete|"
      r"apfs\s+deleteContainer|zeroDisk|secureErase)", 90, "host", "irreversible",
      "erases or reformats a volume"),

    # --- config management --------------------------------------------------
    # --- the long tail: any CLI that manages remote resources -----------------
    # Verb classification, so a CLI nobody wrote a rule for is still scored.
    R("CLI-READ", RESOURCE_CLIS, READ_VERBS, 0, "none", "reversible",
      "read-only query against a managed resource", generic=True),
    R("CLI-WRITE", RESOURCE_CLIS, WRITE_VERBS, 25, "account", "recoverable",
      "creates or mutates a managed resource, and may start billing", generic=True),
    R("CLI-DESTROY", RESOURCE_CLIS, DESTROY_VERBS, 65, "account", "irreversible",
      "destructive verb against a managed resource",
      "confirm the profile/project/zone this CLI is pointed at before it runs", generic=True),

    # --- CLIs whose verbs do not mean what the generic rules assume ----------
    R("VIRSH-DESTROY", "virsh", r"^destroy\b", 45, "host", "recoverable",
      "`virsh destroy` force-powers-off a domain — it does not delete it; the disk survives"),
    R("VIRSH-UNDEFINE", "virsh", r"^(undefine|vol-delete|pool-delete|snapshot-delete)\b", 70,
      "host", "irreversible", "removes the domain/volume definition and, with --remove-all-storage, "
      "its disks"),
    R("RCLONE-SYNC", "rclone", r"^(sync|move)\b", 55, "account", "irreversible",
      "`rclone sync` makes the destination match the source: files only at the destination are "
      "deleted", "`--dry-run` first, and prefer `copy` when nothing should be removed"),
    R("RCLONE-PURGE", "rclone", r"^(purge|delete|deletefile|rmdir|rmdirs)\b", 70, "account",
      "irreversible", "removes objects at the remote"),
    R("RESTIC-FORGET", "restic borg borgmatic", r"(forget|prune|delete)", 65, "account",
      "irreversible", "drops snapshots from the backup repository — this is the copy you keep "
      "for when the primary is already gone",
      "`restic forget --dry-run`, and keep a retention policy rather than ad-hoc forgets"),
    R("ETCDCTL-DEL", "etcdctl", r"\bdel\b.*--prefix|--prefix.*\bdel\b", 90, "cluster",
      "irreversible", "prefix delete against etcd: for a Kubernetes cluster this is the entire "
      "API state"),
    R("PULUMI-DESTROY", "pulumi", r"^(destroy|stack\s+rm)\b", 80, "account", "irreversible",
      "tears down every resource in the stack"),
    R("PULUMI-UP", "pulumi", r"^(up|refresh|import)\b", 45, "account", "recoverable",
      "applies stack changes to real infrastructure"),
    R("EKSCTL-DEL", "eksctl", r"^delete\s+cluster", 85, "account", "irreversible",
      "deletes the cluster and the CloudFormation stacks behind it"),
    R("HEROKU-DESTROY", "heroku", r"(apps:destroy|pg:reset|addons:destroy)", 85, "account",
      "irreversible", "destroys the app or resets the database, add-on data included"),
    R("ZFS-DESTROY", "zfs btrfs", r"^(destroy|delete|subvolume delete)\b", 80, "host",
      "irreversible", "destroys a dataset, subvolume or snapshot",
      "`zfs destroy -n -v` prints what would go, snapshots included"),
    R("LVM-REMOVE", "lvremove vgremove pvremove mdadm", r"", 80, "host", "irreversible",
      "removes a logical volume, volume group or RAID superblock: the data on it is gone"),
    R("CEPH-DEL", "ceph rbd", r"(purge|pool\s+(delete|rm)|rm\b|osd\s+destroy)", 80, "cluster",
      "irreversible", "destructive Ceph operation against pooled storage"),
    R("SNAP-REMOVE", "snap flatpak", r"^(remove|uninstall)\b", 45, "host", "recoverable",
      "removing a snap deletes the application's data unless a snapshot is kept"),
    R("NOMAD-PURGE", "nomad", r"^job\s+stop\b.*-purge", 55, "cluster", "irreversible",
      "purges the job from state, not just its allocations"),
    R("S3CMD-RB", "s3cmd", r"^(rb|del|rm)\b", 65, "account", "irreversible",
      "removes objects or a bucket"),


    # --- promoted CLIs: enumerated per resource, not classified by verb -----
    #
    # Verb classification is a floor, not a measurement: it cannot see that
    # `openstack volume delete` costs data and `openstack server stop` costs a
    # reboot, and it cannot see the verbs that lie. These six carry the traffic
    # and the blast radius, so they are enumerated. Everything else in
    # RESOURCE_CLIS is still classified — see the CLI-* rules above.

    # vault ------------------------------------------------------------------
    R("VAULT-READ", "vault", r"^(read|kv\s+get)\b", 15, "account", "reversible",
      "prints a secret to stdout: from here it is in the scrollback, in the CI log if this "
      "runs in one, and in whatever consumed it — Vault records the read, it cannot unsend it",
      "`-field=<key>` prints one value instead of the whole secret, and a short-lived dynamic "
      "credential beats reading a static one"),
    R("VAULT-KV-DELETE", "vault", r"^kv\s+delete\b", 35, "account", "recoverable",
      "`kv delete` is a soft delete: the versions are marked deleted and stay in storage — it "
      "is `kv destroy` and `kv metadata delete` that are permanent",
      "`vault kv undelete -versions=N <path>` brings it back"),
    R("VAULT-KV-DESTROY", "vault", r"^kv\s+(destroy|metadata\s+delete)\b", 70, "account",
      "irreversible",
      "removes the version data itself; `kv undelete` cannot bring it back, and "
      "`kv metadata delete` takes every version and the metadata with them",
      "`vault kv delete` is the soft form and is recoverable"),
    R("VAULT-SECRETS-DISABLE", "vault", r"^secrets\s+disable\b", 80, "account", "irreversible",
      "disabling a secrets mount deletes every secret stored under it, not just the route to "
      "them",
      "`vault secrets move` relocates a mount without emptying it"),
    R("VAULT-AUTH-DISABLE", "vault", r"^auth\s+disable\b", 75, "account", "irreversible",
      "disabling an auth method revokes every token it issued: every client that authenticates "
      "this way is locked out at once, including the one running this",
      "`vault list auth/<path>/role` shows what still comes in through it"),
    R("VAULT-AUDIT-DISABLE", "vault", r"^audit\s+disable\b", 60, "account", "irreversible",
      "Vault stops recording who read which secret, and keeps serving requests while it does "
      "— the gap in the audit trail is silent",
      "enable the replacement device first; Vault only refuses requests when *every* audit "
      "device fails"),
    R("VAULT-LEASE-REVOKE", "vault", r"^lease\s+revoke\b", 65, "account", "irreversible",
      "revokes leases and the credentials behind them: the database users and cloud keys "
      "Vault issued are dropped as it goes",
      "`vault list sys/leases/lookup/<prefix>` first — it prints exactly what would be revoked"),
    R("VAULT-TOKEN-REVOKE", "vault", r"^token\s+revoke\b", 45, "account", "irreversible",
      "a token revoke takes its child tokens too, so revoking a parent ends every session "
      "issued from it"),
    R("VAULT-POLICY-DELETE", "vault", r"^policy\s+delete\b", 55, "account", "recoverable",
      "every token and role bound to this policy loses the access it granted, immediately and "
      "with no error here — it shows up as permission denied somewhere else",
      "`vault policy read <name>` and keep the HCL before deleting it"),
    R("VAULT-SEAL", "vault", r"^operator\s+(seal|step-down)\b", 60, "cluster", "recoverable",
      "sealing Vault stops every client that needs a secret until enough key holders unseal it "
      "again — which needs the people, not just the command"),
    R("VAULT-REKEY", "vault", r"^operator\s+(rekey|generate-root|rotate)\b", 70, "cluster",
      "irreversible",
      "rekeying invalidates the existing unseal shares: the old ones stop working the moment "
      "it completes, and losing the new ones loses the cluster"),
    R("VAULT-RAFT-RESTORE", "vault", r"^operator\s+raft\s+snapshot\s+restore\b", 90, "cluster",
      "irreversible",
      "replaces the whole of Vault's storage with the snapshot: every secret, policy, mount and "
      "token written since it was taken is gone",
      "take a fresh snapshot first — this is the one operation with no other way back"),
    R("VAULT-RAFT-PEER", "vault", r"^operator\s+raft\s+remove-peer\b", 65, "cluster",
      "recoverable",
      "shrinks the raft quorum; one peer too many and the cluster loses quorum and stops "
      "serving entirely"),

    # velero -----------------------------------------------------------------
    R("VELERO-BACKUP-CREATE", "velero", r"^backup\s+create\b", 10, "cluster", "reversible",
      "takes a backup: the cost is load on the cluster and object storage, not data"),
    R("VELERO-BACKUP-DELETE", "velero", r"^backup\s+delete\b", 70, "cluster", "irreversible",
      "deletes the backup and the objects behind it in storage: that point in time stops being "
      "restorable, and you find out at the restore",
      "`velero backup describe <name>` — check something newer covers the same namespaces"),
    R("VELERO-RESTORE-DELETE", "velero", r"^restore\s+delete\b", 35, "cluster", "recoverable",
      "deletes the restore *record*, not what it restored — the objects it created stay in the "
      "cluster, now with nothing describing where they came from"),
    R("VELERO-RESTORE-CREATE", "velero", r"^restore\s+create\b", 50, "cluster", "irreversible",
      "a restore writes into a live cluster: existing objects are skipped by default, but the "
      "ones it does create are hard to tell apart from what was already there afterwards",
      "`--namespace-mappings old:scratch` restores into a scratch namespace you can inspect"),
    R("VELERO-SCHEDULE", "velero", r"^schedule\s+(delete|pause)\b", 55, "cluster", "recoverable",
      "nothing breaks today: backups simply stop being taken, and the cost lands at the next "
      "restore instead",
      "`velero schedule get` to confirm what else still covers these namespaces"),
    R("VELERO-LOCATION-DELETE", "velero",
      r"^(backup-location|snapshot-location)\s+delete\b", 65, "cluster", "irreversible",
      "removes the storage location: every backup that lives there stops being visible to "
      "Velero, whether or not the bucket still holds it"),
    R("VELERO-UNINSTALL", "velero", r"^uninstall\b", 75, "cluster", "irreversible",
      "removes Velero and its CRDs — the Backup and Restore objects describing every existing "
      "backup go with them, leaving data in the bucket with nothing that can read it",
      "keep the backup storage location and its bucket; a reinstall can re-sync from it"),

    # argocd -----------------------------------------------------------------
    R("ARGOCD-APP-DELETE", "argocd", r"^app\s+delete\b", 60, "cluster", "irreversible",
      "deleting an application cascades by default: the Kubernetes resources it manages are "
      "deleted with it",
      "`--cascade=false` removes the Argo CD record and leaves the workloads running"),
    R("ARGOCD-APP-SYNC", "argocd", r"^app\s+sync\b", 40, "cluster", "recoverable",
      "applies whatever is in git to the cluster right now — including a commit nobody has "
      "reviewed yet, because sync does not care why HEAD moved",
      "`argocd app diff` prints what would change, and `--dry-run` runs it without applying",
      subsumes="PURGE-FLAG FORCE"),
    R("ARGOCD-PROJ-DELETE", "argocd", r"^(proj|project)\s+delete\b", 70, "cluster",
      "irreversible",
      "deleting a project takes every application in it, and each of those cascades to its own "
      "cluster resources"),
    R("ARGOCD-CLUSTER-RM", "argocd", r"^cluster\s+rm\b", 45, "cluster", "recoverable",
      "`cluster rm` de-registers the cluster from Argo CD — it does not touch the cluster. The "
      "applications targeting it stop being reconciled and drift silently from here",
      "`argocd app list --dest-server <url>` shows what stops being managed"),
    R("ARGOCD-REPO-RM", "argocd", r"^repo\s+rm\b", 40, "cluster", "recoverable",
      "removes the repository credentials: every application sourced from it fails to refresh, "
      "with no change to what is already running"),
    R("ARGOCD-ADMIN-IMPORT", "argocd", r"^admin\s+import\b", 70, "cluster", "irreversible",
      "replaces Argo CD's stored state with the contents of the export: applications and "
      "projects that are not in the file are deleted",
      "`argocd admin export > backup.yaml` first"),

    # openstack --------------------------------------------------------------
    R("OS-SERVER-POWER", "openstack",
      r"^server\s+(stop|reboot|shelve|suspend|pause|rescue|unset)\b", 30, "account",
      "recoverable", "stops or reboots the instance; the disk and the ports survive it"),
    R("OS-SERVER-DELETE", "openstack", r"^server\s+delete\b", 70, "account", "irreversible",
      "deletes the instance and its ephemeral disk; a boot-from-volume instance keeps its root "
      "volume only if it was not created with delete-on-termination",
      "`openstack server shelve` frees the compute and keeps the instance"),
    R("OS-VOLUME-DELETE", "openstack", r"^volume\s+delete\b", 80, "account", "irreversible",
      "the data on the volume goes with it, and `--force` deletes it even while an instance "
      "still has it attached",
      "`openstack volume snapshot create` first — the snapshot is the only way back"),
    R("OS-SNAPSHOT-DELETE", "openstack",
      r"^(backup|volume\s+snapshot|image\s+snapshot)\s+delete\b", 65, "account",
      "irreversible", "removes a restore point for a volume that is still running"),
    R("OS-IMAGE-DELETE", "openstack", r"^image\s+delete\b", 60, "account", "irreversible",
      "instances already running are unaffected; everything that rebuilds, autoscales or "
      "launches from this image fails from now on"),
    R("OS-PROJECT-DELETE", "openstack", r"^project\s+delete\b", 60, "account", "irreversible",
      "deleting a project does not delete what is in it: the servers, volumes and floating IPs "
      "keep running and keep billing, with no project left to manage them through",
      "`openstack project purge --project <id>` removes the resources first — then delete it"),
    R("OS-PROJECT-PURGE", "openstack", r"^project\s+purge\b", 88, "account", "irreversible",
      "deletes every resource the project owns — servers, volumes, images, networks — in one "
      "call",
      "`--dry-run` prints the list without touching any of it"),
    R("OS-STACK-DELETE", "openstack", r"^stack\s+delete\b", 85, "account", "irreversible",
      "a Heat stack delete removes every resource the template created, database volumes "
      "included"),
    R("OS-NETWORK-DELETE", "openstack",
      r"^(network|subnet|router|port)\s+delete\b", 70, "network", "irreversible",
      "removing the network takes the ports on it: every instance attached loses connectivity, "
      "and on a cloud you administer remotely this is how you lock yourself out"),
    R("OS-CATALOG-DELETE", "openstack", r"^(endpoint|service)\s+delete\b", 75, "account",
      "irreversible",
      "the service catalog is how every client finds this region's APIs — removing an entry "
      "makes that service unreachable region-wide without touching anything it manages"),
    R("OS-USER-DELETE", "openstack", r"^(user|role|group)\s+delete\b", 55, "account",
      "irreversible",
      "the tokens stop working immediately; resources the user owned keep running, now with "
      "nobody who can reach them"),
    R("OS-SG-RULE", "openstack", r"^security\s+group\s+rule\s+create\b", 30, "network",
      "reversible",
      "opens a port to whatever `--remote-ip` names — the range is the whole of the decision",
      "name a CIDR you control; `0.0.0.0/0` is the entire internet"),

    # flyctl -----------------------------------------------------------------
    R("FLY-DEPLOY", "flyctl fly", r"^deploy\b", 35, "account", "recoverable",
      "rolls the app forward to a new release",
      "`fly releases` lists what to roll back to, and `fly deploy --image <ref>` does it"),
    R("FLY-SECRETS", "flyctl fly", r"^secrets\s+(set|unset|import)\b", 40, "account",
      "recoverable",
      "setting a secret restarts every machine in the app — this is a deploy, not a config "
      "write, and it happens the moment the command returns",
      "`--stage` stores the secret without restarting; the next deploy picks it up"),
    R("FLY-SCALE-ZERO", "flyctl fly", r"^scale\s+count\s+0\b", 55, "account", "recoverable",
      "zero machines is an outage: nothing is deleted and scaling back up restores it, but the "
      "app is off until you do"),
    R("FLY-MACHINE-DESTROY", "flyctl fly", r"^machines?\s+(destroy|remove)\b", 55, "account",
      "recoverable",
      "destroys one machine — the app, its volumes and its config survive, and `fly deploy` "
      "recreates it"),
    R("FLY-VOLUME-DESTROY", "flyctl fly", r"^volumes?\s+(destroy|delete)\b", 85, "account",
      "irreversible",
      "a Fly volume is a single local disk, not a replicated one: this destroys the only copy "
      "of the data on it",
      "`fly volumes snapshots list <id>` — snapshots are kept about five days and are the only "
      "way back"),
    R("FLY-APPS-DESTROY", "flyctl fly", r"^apps\s+destroy\b", 80, "account", "irreversible",
      "destroys the app with its machines and its volumes, and releases the name for anyone "
      "else to claim",
      "`fly scale count 0` stops it running and billing without destroying anything"),
    R("FLY-PG-DETACH", "flyctl fly", r"^(postgres|pg|mysql)\s+(detach|db\s+delete)\b", 65,
      "account", "irreversible",
      "detaching drops the database user and removes DATABASE_URL from the app: the app loses "
      "its database at the next restart, not at this command"),
    R("FLY-CERTS-REMOVE", "flyctl fly", r"^certs\s+remove\b", 45, "network", "recoverable",
      "removes the certificate for that hostname; requests to it stop being served over HTTPS "
      "until a new one is issued and validated"),

    # gh ---------------------------------------------------------------------
    R("GH-REPO-ARCHIVE", "gh", r"^repo\s+archive\b", 20, "account", "recoverable",
      "makes the repository read-only and can be undone — the reversible alternative to "
      "`repo delete`"),
    R("GH-REPO-DEL", "gh", r"^repo\s+delete\b", 75, "account", "irreversible",
      "deletes the repository with its issues, PRs and releases; the name is then claimable by "
      "anyone",
      "`gh repo archive` keeps it readable and reversible"),
    R("GH-PR-MERGE", "gh", r"^pr\s+merge\b", 40, "account", "recoverable",
      "merges into the base branch — on a repository that deploys on merge, this is the deploy",
      "`--auto` waits for the required checks instead of merging now"),
    R("GH-RELEASE-DELETE", "gh", r"^release\s+delete\b", 55, "account", "irreversible",
      "deletes the release and every asset attached to it: anything pinned to those download "
      "URLs breaks, including other people's CI",
      "`gh release edit <tag> --draft` hides it and keeps the assets"),
    R("GH-ISSUE-DELETE", "gh", r"^issue\s+delete\b", 50, "account", "irreversible",
      "GitHub has no undo for a deleted issue: the thread, its comments and every "
      "cross-reference to it go",
      "closing it keeps the history and is reversible"),
    R("GH-RUN-DELETE", "gh", r"^(run\s+delete|cache\s+delete)\b", 35, "account", "irreversible",
      "deletes the run and its logs — the record of what CI actually did is the thing being "
      "removed"),
    R("GH-SECRET", "gh", r"^(secret|variable)\s+(set|delete)\b", 40, "account", "recoverable",
      "changes what every workflow in this repository runs with; `secret delete` cannot be "
      "undone without the original value, which by design nothing here can read back"),
    R("GH-WORKFLOW-RUN", "gh", r"^workflow\s+run\b", 35, "account", "recoverable",
      "triggers a workflow: what it does is whatever the workflow does, which on a deploy "
      "pipeline is a deploy"),
    R("GH-AUTH-TOKEN", "gh", r"^auth\s+token\b", 35, "account", "reversible",
      "prints the OAuth token to stdout, where it lands in scrollback and in the CI log if "
      "this runs in one",
      "let `gh` make the authenticated call instead of extracting the token"),
    R("GH-API-WRITE", "gh", r"^api\b(?=.*(?:-X|--method)[= ]?(?:POST|PUT|PATCH))", 45,
      "account", "recoverable",
      "`gh api` is the raw REST API: the verb that matters is in `-X`, and nothing else on the "
      "command line says what this changes",
      "run it with `--method GET` first and read what the endpoint returns"),
    R("GH-API-DELETE", "gh", r"^api\b(?=.*(?:-X|--method)[= ]?DELETE)", 70, "account",
      "irreversible",
      "a DELETE through `gh api` is whatever that endpoint deletes — `/repos/{owner}/{repo}` "
      "is the repository itself — and no verb in the command line says so",
      "check the endpoint in the REST docs; `gh` has a named command for most of the "
      "destructive ones, and those prompt"),

    R("CM-ANSIBLE", "ansible ansible-playbook", None, 40, "cluster", "recoverable",
      "runs against every host in the inventory pattern at once",
      "`--check --diff` first, and `--limit` to one host before the fleet"),
    R("CM-SALT", "salt", None, 45, "cluster", "recoverable", "runs across matched minions"),
]

SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
# Anything that turns bytes on stdin into a script: fetching and decoding are
# the same move when the next stage is an interpreter.
FETCHERS = {"curl", "wget", "fetch", "aria2c", "http", "httpie",
            "base64", "xxd", "openssl", "gunzip", "zcat", "gzip", "bunzip2", "xz"}
INTERPRETERS = SHELLS | {"python", "python3", "perl", "ruby", "node", "php"}

# ------------------------------------------------------------ amplifiers ---


def A(aid, bins, pattern, points, why, scope=None, revert=None, raw=False):
    """A modifier: how flags make the same command better or worse.

    Amplifiers carry no advice — the rule owns that — so a stray fourth string
    here would land in `scope`. Validated rather than trusted.
    """
    _check(aid, scope or "none", revert or "reversible")
    return {
        "id": aid, "bins": set(bins.split()) if bins else None,
        "pattern": re.compile(pattern), "points": points, "why": why,
        "scope": scope, "revert": revert, "raw": raw,
    }


AMPS = [
    A("RECURSIVE", "rm chmod chown chgrp shred",
      r"(^|\s)-[a-zA-Z]*[rR](\s|$|[a-zA-Z])", 15,
      "-r/-R recurses into every subdirectory below the target", "directory"),
    A("FORCE-RM", "rm", r"(^|\s)-[a-zA-Z]*f(\s|$|[a-zA-Z])", 8,
      "-f suppresses every prompt and error: nothing will stop it midway"),
    A("NO-PRESERVE-ROOT", "rm", r"--no-preserve-root", 45,
      "--no-preserve-root disables the one guard rm has against deleting /",
      "host", "irreversible"),
    A("GLOB", "rm shred mv chmod chown", r"(^|\s|/)\*", 12,
      "a glob expands to whatever is there right now, not to what you tested against"),
    A("DD-DEVICE", "dd", r"of=/dev/(sd|nvme|hd|vd|xvd|disk|mmcblk)", 40,
      "of= points at a raw block device: this overwrites a disk, not a file",
      "host", "irreversible"),
    A("REDIR-DEVICE", None, r">\s*/dev/(sd|nvme|hd|vd|xvd|mmcblk)", 55,
      "redirects into a block device", "host", "irreversible"),
    A("KILL-9", "kill pkill killall", r"(^|\s)-(9|KILL|SIGKILL)\b", 15,
      "SIGKILL gives the process no chance to flush buffers or release locks"),
    A("KILL-INIT", "kill", r"(^|\s)1(\s|$)", 40, "PID 1 is init: killing it panics the host",
      "host", "recoverable"),
    A("CHMOD-777", "chmod", r"(^|\s)(-[a-zA-Z]+\s+)*(0?777|a\+rwx|o\+w)", 20,
      "world-writable: any local user or compromised process can rewrite these files"),
    A("CHMOD-SUID", "chmod", r"(^|\s)(-[a-zA-Z]+\s+)*([2467][0-7]{3}|[ugo]?\+s)", 25,
      "setuid/setgid bit: the file now runs with the owner's privileges", "host"),
    A("SSH-NOVERIFY", "ssh scp sftp rsync", r"StrictHostKeyChecking=no|-o\s+UserKnownHostsFile=/dev/null",
      20, "host key verification disabled: a MITM is indistinguishable from the real host"),
    A("SSH-AGENT-FWD", "ssh", r"(^|\s)-A(\s|$)", 15,
      "agent forwarding lets root on the remote host use your keys"),
    # long forms are covered by the generic NO-TLS-VERIFY amp; this is only the
    # short flag, so the same argument is never counted twice
    A("CURL-INSECURE", "curl wget", r"(^|\s)-k(\s|$)", 20, "TLS verification disabled"),
    A("PRIVILEGED", "docker podman nerdctl", r"--privileged|--cap-add[= ]?(ALL|SYS_ADMIN)", 35,
      "--privileged drops container isolation: this is host-level access", "host"),
    A("HOST-MOUNT", "docker podman nerdctl", r"(-v|--volume|--mount[^ ]*)[= ]\s*/(:|\S*:/)", 30,
      "bind-mounts a host path into the container: container writes are host writes", "host"),
    A("HOST-NS", "docker podman nerdctl", r"--(pid|net|network|ipc|userns)[= ](host)", 25,
      "shares a host namespace with the container", "host"),
    A("CTR-ROOT", "docker podman nerdctl kubectl", r"(^|\s)(-u|--user)[= ]\s*(0|root)\b", 8,
      "runs as root inside the container"),
    A("K8S-ALL", "kubectl oc",
      r"^(delete|drain|scale|patch|label|annotate|cordon|taint|rollout|replace)\b"
      r".*(--all\b|--all-namespaces\b|(\s)-A(\s|$))", 25,
      "applies to every matching object, across every namespace it can see", "cluster"),
    A("K8S-FORCE", "kubectl oc", r"--grace-period[= ]0\b", 12,
      "grace period zero: the API forgets the object while the kubelet may still be running it"),
    A("K8S-REMOTE-MANIFEST", "kubectl oc", r"-f\s+https?://", 25,
      "applies a manifest fetched at run time: content can change between plan and apply"),
    A("GIT-DEFAULT-BRANCH", "git",
      r"^push\b.*(--force(?!-with-lease)|(\s|^)-f\b).*\b(main|master|trunk|release)\b", 25,
      "force-pushing the default branch: everyone else's clone breaks on the next pull",
      "network", "irreversible"),
    A("AUTO-APPROVE", "terraform tofu", r"-auto-approve", 15,
      "-auto-approve skips the plan review: nobody sees the diff before it happens"),
    A("TF-TARGET-ALL", "terraform tofu", r"-refresh=false", 10,
      "-refresh=false plans against possibly stale state"),
    A("AWS-SKIP-SNAPSHOT", "aws", r"--skip-final-snapshot", 15,
      "no final snapshot: the data is unrecoverable the moment this returns", None, "irreversible"),
    A("AWS-RECURSIVE", "aws", r"--recursive\b", 15, "applies to every key under the prefix"),
    A("UMOUNT-SYSTEM", "umount",
      r"(^|\s)/(\s|$)|(^|\s)/(usr|var|etc|boot|home|srv|opt|lib|root)(/\S*)?(\s|$)", 30,
      "a filesystem the running system reads from: everything on it fails until it is back",
      "host"),
    A("REMOUNT-ROOT", "mount", r"remount.*(^|\s)/(\s|$)", 25,
      "remounting the root filesystem: this is host-wide, not scoped to one service", "host"),
    A("UMOUNT-ALL", "umount", r"(^|\s)-[a-zA-Z]*a(\s|$)|--all\b", 45,
      "-a unmounts everything in the mount table, including the filesystems the running "
      "system is reading from", "host"),
    A("UMOUNT-LAZY", "umount", r"(^|\s)-[a-zA-Z]*l(\s|$)|--lazy\b", 15,
      "lazy detach: the command returns success now and the filesystem goes away later, "
      "when you are no longer watching"),
    A("UMOUNT-FORCE", "umount", r"(^|\s)-[a-zA-Z]*f(\s|$)|--force\b", 10,
      "forces the detach with I/O still in flight"),
    A("POWER-FORCE", "reboot shutdown halt poweroff systemctl",
      r"(^|\s)-f(\s|$)|--force\b", 15,
      "skips the clean shutdown: filesystems are not unmounted and services get no chance "
      "to flush", "host"),
    A("POWER-SCHEDULED", "shutdown", r"(^|\s)\+[0-9]+(\s|$)|(^|\s)[0-9]{1,2}:[0-9]{2}(\s|$)",
      -15, "scheduled rather than immediate: it is announced, and `shutdown -c` still cancels it"),
    A("SWAP-ALL", "swapoff", r"(^|\s)-a(\s|$)|--all\b", 10,
      "-a disables every swap device at once: everything currently swapped out has to fit "
      "in RAM, or the OOM killer picks what dies", "host"),
    A("USERDEL-R", "userdel deluser", r"(^|\s)(-r|--remove(-home)?)(\s|$)", 15,
      "`-r` deletes the account's home directory and mail spool along with the account",
      None, "irreversible"),
    A("PKG-CRITICAL", "apt apt-get aptitude yum dnf apk zypper pacman dpkg rpm nix-env emerge",
      r"\b(linux-image[\w.-]*|linux-firmware|kernel[\w.-]*|glibc|libc6|systemd|init|coreutils|"
      r"bash|dash|openssh-server|sudo|grub[\w.-]*|util-linux)\b", 30,
      "one of these packages is what makes the host boot, log in, or run shell scripts at all",
      "host", "recoverable"),
    A("PKG-UNTRUSTED", "pip pip3 pipx npm yarn pnpm gem cargo go composer",
      r"(git\+|https?://|git@|file:|\.\./|\.tar\.gz)", 20,
      "installs from outside the registry: no version resolution you can audit, and the "
      "source can change under the same reference"),
    A("PKG-SYSTEM-PY", "pip pip3", r"--break-system-packages|--target[= ]/usr|--prefix[= ]/usr", 15,
      "writes into the system interpreter, which the OS's own tooling depends on", "host"),
    A("RSYNC-DELETE", "rsync", r"--delete(-before|-during|-after|-excluded)?\b", 35,
      "`--delete` removes files at the destination that are not at the source: a wrong source "
      "path empties the destination", "directory", "irreversible"),
    A("TAR-OVERWRITE", "tar unzip", r"--overwrite|(^|\s)-o(\s|$)|-C\s+/(\s|$)", 25,
      "extracts over whatever is already there, from paths the archive chooses"),
    A("REDIR-SYSTEM", None, r"(?<!>)>\s*/(etc|boot|usr|lib|var/log|var/lib)/", 30,
      "truncates and replaces a system file — `>` does not append", "host", "irreversible"),
    A("SYSRQ", None, r">\s*/proc/sysrq-trigger", 45,
      "sysrq acts at kernel level: no unmount, no flush, no service shutdown", "host"),
    A("DD-MEM", "dd", r"of=/dev/(mem|kmem|port|random|urandom)", 40,
      "writing to kernel memory devices corrupts a running system", "host", "irreversible"),
    # --- generic arguments: these mean the same thing on any binary ----------
    A("FORCE", None,
      r"--force(?!-with-lease)(\b|-\w+)|--no-confirm\b|--no-prompt\b|--overwrite-existing\b",
      12, "`--force` exists to get past the check that would otherwise have stopped this"),
    A("ASSUME-YES", None,
      r"--(yes|assume-?yes|noconfirm|no-confirm|non-interactive|no-interaction|force-yes|"
      r"no-input|approve|batch|accept-all|skip-confirmation)\b|(^|\s)-[a-zA-Z]*y(\s|$)", 8,
      "auto-confirms every prompt, including the ones you would have stopped at — the last "
      "human checkpoint before this runs"),
    # `--cascade=false` is the opposite of a purge, so the negated forms are
    # excluded rather than counted as the thorough variant they name.
    A("PURGE-FLAG", None, r"--(purge|prune|wipe|hard|cascade|destroy-data|delete-data|"
                          r"remove-data|permanent)\b(?![= ]?(false|no|off|none)\b)", 12,
      "asks for the thorough variant: state that would otherwise survive goes too"),
    A("SECRET-IN-ARGV", None,
      r"--(password|passwd|token|api-key|apikey|secret|access-key|private-key)[= ]\S|"
      r"(^|\s)(PGPASSWORD|MYSQL_PWD|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN)=", 25,
      "a credential on the command line is visible to every user on the host via `ps` and "
      "lands in shell history — pass it by env file, stdin or a credential helper"),
    A("NO-TLS-VERIFY", None,
      r"--(insecure|no-verify|no-check-certificate|skip-tls-verify|tls-skip-verify|"
      r"insecure-skip-tls-verify|trust-all|no-verify-ssl|disable-ssl-validation)\b|"
      r"--validate=false", 20,
      "certificate verification disabled: a machine-in-the-middle is indistinguishable from "
      "the real endpoint"),
    A("NO-SIGNATURE-CHECK", None,
      r"--(allow-unauthenticated|nogpgcheck|no-gpg-check|allow-untrusted|trusted-host|"
      r"insecure-registry|skip-verify|force-yes)\b", 25,
      "package or image signature verification disabled: the signature is the only thing "
      "separating the real artifact from a substituted one"),
    A("OPEN-TO-WORLD", None, r"0\.0\.0\.0/0|::/0", 35,
      "reachable from the entire internet, not from a network you control", "network"),
    A("REMOTE-EXEC-SUBST", "sh bash zsh dash ksh python python3 perl ruby node eval source .",
      r"[<$]\(\s*[\w./-]*\b(curl|wget|fetch|aria2c|httpie)\b", 78,
      "runs a script fetched inside a substitution: same as piping a download into a shell, "
      "and the fetch is not visible as its own step", "host", "irreversible", raw=True),
    A("EVAL-DYNAMIC", "eval", r"\$[\w{(]|`", 15,
      "the evaluated text is built from a variable or a substitution, so its contents are "
      "decided at run time and nothing here can show them", "host", "irreversible"),
    A("PROD-HINT", None, r"(^|[\s\"'=/:_.,-])(prod|production|live)([\s\"'/:_.,-]|$)", 15,
      "the target names a production environment"),
    A("SUDO-EDIT", "tee dd cp mv sed perl awk", r"/etc/(sudoers|passwd|shadow|ssh/)", 30,
      "writes into system authentication/authorisation config", "host", "recoverable"),
    A("SSHD-STOP", "systemctl service", r"^(stop|disable|mask|kill|restart)\b.*\b(ssh|sshd)\b",
      20, "this is the daemon your session depends on", "host"),
    A("SSHD-KILL", "pkill killall", r"\b(ssh|sshd)\b", 20,
      "this is the daemon your session depends on", "host"),
    A("HISTFILE", None, r"unset\s+HISTFILE|HISTFILE=/dev/null|set \+o history", 30,
      "disables shell history: the audit trail stops here", "host", "irreversible"),

    # --- flags that only mean something on one CLI ---------------------------
    A("VAULT-LEASE-PREFIX", "vault", r"^lease\s+revoke\b(?=.*(^|\s)-prefix\b)", 15,
      "`-prefix` revokes every lease under the path rather than the one named", "account"),
    A("VAULT-LEASE-FORCE", "vault", r"^lease\s+revoke\b(?=.*(^|\s)-force\b)", 20,
      "vault's `-force` drops the lease without revoking the credential behind it: the database "
      "user or cloud key stays live with nothing left tracking its expiry",
      "account", "irreversible"),
    A("VELERO-OVERWRITE", "velero", r"--existing-resource-policy[= ]update", 20,
      "restores over objects that already exist: live resources are overwritten with the state "
      "in the backup", "cluster", "irreversible"),
    A("ARGOCD-PRUNE", "argocd", r"--prune\b", 25,
      "`--prune` deletes cluster resources that are no longer in git — anything created outside "
      "Argo CD goes with them", "cluster", "irreversible"),
    A("ARGOCD-REPLACE", "argocd", r"--(replace|force)\b", 15,
      "argocd's `--replace`/`--force` delete and recreate each resource instead of patching it: "
      "pods restart, and anything holding local state comes back empty", "cluster"),
    A("FLY-IMMEDIATE", "flyctl fly", r"--strategy[= ]immediate", 25,
      "the immediate strategy stops every machine before starting the new ones — a full outage, "
      "not a rolling deploy", "account"),
    A("GH-ADMIN", "gh", r"--admin\b", 22,
      "`--admin` merges past branch protection: required reviews and status checks are bypassed",
      "account"),
    A("GH-CLEANUP-TAG", "gh", r"--cleanup-tag\b", 12,
      "deletes the git tag as well as the release, so the commit it pointed at is no longer named"),
]

# Softeners: the same command, asked for in a way that leaves you an out. A
# gate is only usable if the careful form of a command scores below the
# careless one.
SOFTENERS = [
    A("INTERACTIVE", "rm cp mv ln", r"(^|\s)-[a-zA-Z]*i(\s|$)|--interactive\b", -12,
      "prompts before each delete or overwrite: you still get to say no"),
    A("BACKUP", "sed perl cp mv install",
      r"(^|\s)-i\.[A-Za-z0-9]|(^|\s)-b(\s|$)|--backup\b|--suffix[= ]", -12,
      "keeps a backup of what it replaces"),
    A("PRESERVE-ROOT", "rm", r"--preserve-root", -10,
      "explicitly asks for the guard that stops this at `/`"),
    A("LIMIT", "ansible ansible-playbook", r"--limit(\s|=)", -15,
      "`--limit` narrows the run to part of the inventory rather than the whole fleet"),
    A("FORCE-WITH-LEASE", "git", r"--force-with-lease", -5,
      "refuses to overwrite the remote if it moved since you last fetched"),
    A("ARGOCD-NO-CASCADE", "argocd", r"--cascade[= ]?false", -20,
      "`--cascade=false` removes the Argo CD record only: the Kubernetes resources it manages "
      "stay running"),
    A("FLY-STAGE", "flyctl fly", r"--stage\b", -15,
      "`--stage` stores the secret without restarting the app; the next deploy applies it"),
    A("GH-AUTO-MERGE", "gh", r"--auto\b", -12,
      "`--auto` queues the merge behind the required checks instead of merging now"),
]

DAMPENERS = [
    (re.compile(r"--dry-run(?![= ]?(none|server))|--dryrun|--what-if|--no-act|(^|\s)--check(\s|$)"),
     "--dry-run: reports what it would do and changes nothing"),
    (re.compile(r"(^|\s)-n(\s|$)"), None),  # only honoured for the bins below
    # vault prints the equivalent curl invocation and makes no request at all.
    (re.compile(r"-output-curl-string\b"),
     "-output-curl-string: prints the request as curl and sends nothing"),
]
DRY_RUN_N_BINS = {"rsync", "mv", "cp", "ln", "make", "ansible-playbook", "fsck", "e2fsck",
                  "patch", "git"}

# Directories whose loss costs a rebuild, not a restore.
REGENERABLE = re.compile(
    r"(^|/)(node_modules|\.venv|venv|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|"
    r"target|dist|build|out|\.next|\.nuxt|coverage|\.terraform|vendor|\.cache|tmp)/?$")

SYSTEM_DIRS = {
    "/etc": "system configuration", "/var": "logs, spools, databases and container state",
    "/usr": "the entire userland", "/bin": "core binaries", "/sbin": "system binaries",
    "/lib": "shared libraries — nothing dynamically linked will start after this",
    "/lib64": "shared libraries", "/boot": "kernel and bootloader: the host will not boot",
    "/opt": "third-party software", "/srv": "served data", "/root": "the root user's home",
    "/home": "every user's home directory", "/dev": "device nodes",
    "/proc": "kernel interface", "/sys": "kernel interface", "/data": "application data",
    "/mnt": "mount points — may be a live filesystem", "/media": "mounted removable media",
}
# Losing something *under* /etc breaks the host; losing something under /srv
# loses payload. Both are bad, they are not equally bad.
CORE_DIRS = {"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys"}

# Commands whose whole job is to act on a device node: pointing them at
# /dev/sdb is not the surprise, it is the usage.
DEVICE_TARGET_EXPECTED = {
    "mount", "umount", "fsck", "e2fsck", "xfs_repair", "resize2fs", "mkfs", "wipefs",
    "blkdiscard", "badblocks", "cryptsetup", "mdadm", "zpool", "hdparm", "nvme",
}

PATH_SENSITIVE = {
    "rm", "rmdir", "unlink", "shred", "wipe", "mv", "cp", "rsync", "chmod", "chown", "chgrp",
    "truncate", "dd", "tar", "install", "ln", "tee", "find", "chattr", "mkfs", "wipefs",
}

# ------------------------------------------------------------------ why ---

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


def entry_by_id(rid):
    """Find a rule or amplifier by id. Returns (kind, entry) or (None, None).

    Amplifier ids are printed with a leading `+` by --list-rules, so both
    spellings resolve — a reader copying an id out of that output should not
    have to know which half of the table it came from.
    """
    rid = rid.strip().lstrip("+").upper()
    for r in RULES:
        if r["id"] == rid:
            return "rule", r
    for a in AMPS + SOFTENERS:
        if a["id"] == rid:
            return "amp", a
    return None, None


def rule_ids():
    """Every id `--why` will answer to."""
    return sorted({r["id"] for r in RULES} | {a["id"] for a in AMPS + SOFTENERS})


def _wrap(text, indent="  ", width=78, hang=""):
    return textwrap.fill(text, width=width, initial_indent=indent,
                         subsequent_indent=indent + hang)


def _reachable(entry, kind):
    """The amplifiers and softeners that can apply to this rule's binaries.

    Answers "why this band" with the range the rule can actually reach rather
    than with its base alone: a rule at 55 whose binaries carry a +35 amplifier
    is a `critical` waiting for one flag, and that is the part a reader
    disagreeing with a score needs to see.
    """
    if kind != "rule":
        return [], []
    bins, subsumed = entry["bins"], entry["subsumes"]
    # Only the ones named for these binaries. The generic signals apply to
    # every command and listing them under each rule would bury the two or
    # three that are actually about this one.
    amps = [a for a in AMPS
            if a["bins"] and a["bins"] & bins and a["id"] not in subsumed]
    softs = [a for a in SOFTENERS
             if a["bins"] and a["bins"] & bins and a["id"] not in subsumed]
    return amps, softs


def _related(entry):
    """Other rules on the same binaries, and the generic ones this beats."""
    same, beats = [], []
    for r in RULES:
        if r["id"] == entry["id"] or not (r["bins"] & entry["bins"]):
            continue
        (beats if r["generic"] and not entry["generic"] else same).append(r)
    return same, beats


def _why_head(kind, entry, width):
    """The identity line: what this is, and the three facts a score reports."""
    if kind == "rule":
        head = (f"{entry['id']}  ·  base {entry['base']} ({band(entry['base'])})  ·  "
                f"scope: {entry['scope']}  ·  {entry['revert']}")
    else:
        sign = "softener" if entry["points"] < 0 else "amplifier"
        head = f"+{entry['id']}  ·  {entry['points']:+d} ({sign})"
        if entry["scope"] or entry["revert"]:
            head += (f"  ·  scope: {entry['scope'] or '—'}  ·  "
                     f"{entry['revert'] or '—'}")
    return [head, "=" * min(len(head), width), ""]


def _why_matches(kind, entry):
    """What it matches, and — as importantly — what it does not."""
    out = ["MATCHES"]
    out.append(_wrap(", ".join(sorted(entry["bins"])) if entry["bins"] else "any command"))
    pattern = entry["sub"] if kind == "rule" else entry["pattern"]
    if pattern is not None:
        # Printed unwrapped: a regex broken across lines is not something you
        # can paste back into anything.
        out += ["  …when the arguments match:", f"    {pattern.pattern}"]
    elif kind == "rule":
        out.append(_wrap("…whatever the arguments are — the binary is the whole of it."))
    if kind == "rule" and entry["generic"]:
        out.append(_wrap("This is a verb classifier: a floor for CLIs nobody has "
                         "enumerated, and any specific rule beats it — including one "
                         "that scores lower."))
    elif kind == "rule":
        out.append(_wrap("Not matched: anything a rule with a higher base claims first. "
                         "Specificity wins before score does."))
    return out + [""]


def _why_incident(entry):
    """The prose half, or an honest admission that it has not been written."""
    out = ["INCIDENT CLASS"]
    note = INCIDENTS.get(entry["id"])
    if note:
        return out + [_wrap(note), ""]
    out.append(_wrap(f"Not written yet. The one-line reason is: {entry['why']}"))
    out.append(_wrap("Everything above and below is derived from the rule table, so it is "
                     "accurate — but the class of incident this rule exists to prevent has "
                     "not been written down. That is a gap, not a judgement that the rule "
                     "is uninteresting."))
    return out + [""]


def _why_band(entry, kind):
    """Why this band, and what the flags on these binaries can do to it."""
    out = ["WHY THIS BAND",
           _wrap(f"{entry['base']}/100 on its own, which is `{band(entry['base'])}`. "
                 f"Blast radius `{entry['scope']}`; getting back is `{entry['revert']}`.")]
    amps, softs = _reachable(entry, kind)
    if amps:
        worst = max(amps, key=lambda x: x["points"])
        reached = min(100, entry["base"] + worst["points"])
        out.append("")
        out.append(_wrap(f"Amplifiers registered for these binaries — each applies only "
                         f"where its own pattern matches. The largest is "
                         f"{worst['points']:+d} ({worst['id']}); where it applies, "
                         f"{entry['base']} becomes {reached}/`{band(reached)}`."))
        out += _why_modifiers(sorted(amps, key=lambda x: -x["points"])[:8])
    if softs:
        out.append("")
        out.append(_wrap("Asking for it carefully scores below asking for it carelessly:"))
        out += _why_modifiers(sorted(softs, key=lambda x: x["points"])[:6])
    out.append("")
    out.append(_wrap("The generic signals — `--force`, `-y`, `--purge`, a credential in "
                     "argv, disabled TLS or signature verification, `0.0.0.0/0`, a target "
                     "that names production — apply on top of any command. "
                     "`--list-rules` prints them."))
    return out + [""]


def _why_modifiers(entries):
    return [_wrap(f"{a['points']:+d}  {a['id']}: {a['why']}", indent="    ", hang="     ")
            for a in entries]


def _why_safer(entry):
    """The alternative, or a note that the rule owes one."""
    if entry["advice"]:
        body = entry["advice"]
    elif entry["base"] >= 35:
        body = ("No alternative recorded. For a rule at this level that is a gap in the "
                "rule, not a statement that none exists.")
    else:
        body = "Nothing to avoid — this is not a destructive rule."
    return ["SAFER", _wrap(body), ""]


def _why_related(entry):
    """Neighbours on the same binaries, and the classifiers this one beats."""
    same, beats = _related(entry)
    if not (same or beats):
        return []
    out = ["RELATED"]
    out += [_wrap(f"{r['id']} ({r['base']}) — {r['why']}", indent="    ", hang="  ")
            for r in sorted(same, key=lambda x: -x["base"])[:8]]
    out += [_wrap(f"beats {r['id']} ({r['base']}), the verb classifier", indent="    ")
            for r in beats]
    return out + [""]


def why_text(rid, width=78):
    """The long form for one rule or amplifier, or None if the id is unknown.

    Assembled from the rule table rather than written out twice: the band, the
    scope, the reversibility and the reachable range are all facts the scorer
    already uses, so this view cannot disagree with the score it explains. Only
    the incident-class paragraph is prose, and it is optional — a rule without
    one says so rather than padding.

    One section per helper, in printed order, so a section can be read or
    changed without the whole view in your head.
    """
    kind, entry = entry_by_id(rid)
    if not entry:
        return None
    out = _why_head(kind, entry, width) + _why_matches(kind, entry) + _why_incident(entry)
    if kind == "rule":
        out += _why_band(entry, kind) + _why_safer(entry) + _why_related(entry)
    out.append(f"  scoville --list-rules   ·   {len(INCIDENTS)} of {len(rule_ids())} ids "
               "have an incident note")
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------- parsing ---

OPS = ("&&", "||", ";;", "|&")


def split_commands(text):
    """Split a shell snippet into (raw_command, offset, preceding_operator).

    Quote-, escape-, comment- and $()-aware. Not a shell grammar: it is a
    splitter good enough to find where one command ends and the next begins.
    """
    out, buf = [], []
    start, i, n, depth = 0, 0, len(text), 0
    prev_op = None
    quote = None

    def flush(op, end):
        nonlocal buf, start, prev_op
        raw = "".join(buf).strip()
        # drop grouping characters left dangling by the split, never a balanced pair
        for opener, closer in (("(", ")"), ("{", "}")):
            if raw.startswith(opener) and raw.count(opener) > raw.count(closer):
                raw = raw[1:].strip()
            if raw.endswith(closer) and raw.count(closer) > raw.count(opener):
                raw = raw[:-1].strip()
        if raw:
            out.append((raw, start, prev_op))
        buf = []
        prev_op = op
        start = end

    while i < n:
        c = text[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.extend((c, text[i + 1]))
            i += 2
            continue
        if c in "\"'":
            quote = c
            buf.append(c)
            i += 1
            continue
        if c == "#" and (not buf or buf[-1].isspace()):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("$(", i):
            depth += 1
            buf.append("$(")
            i += 2
            continue
        if c == ")" and depth:
            depth -= 1
            buf.append(c)
            i += 1
            continue
        if depth == 0:
            two = text[i:i + 2]
            if two in OPS:
                flush(two, i + 2)
                i += 2
                continue
            if c in ";\n|&":
                flush("\n" if c == "\n" else c, i + 1)
                i += 1
                continue
        buf.append(c)
        i += 1
    flush(None, n)
    return out


SUBSHELL = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def subshell_commands(raw, offset):
    """Command substitutions run *first* and are easy to miss when skimming."""
    for m in SUBSHELL.finditer(raw):
        inner = m.group(1) or m.group(2) or ""
        if inner.strip():
            yield inner.strip(), offset + m.start()


def tokenize(raw):
    """Split a command into tokens, whitespace-splitting when shlex refuses.

    An unbalanced quote is a broken command, not a reason to score nothing:
    the fallback keeps `rm -rf "/opt` visible instead of dropping it.
    """
    try:
        return shlex.split(raw, comments=True)
    except ValueError:
        return raw.split()


ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
WRAPPERS = {
    "sudo", "doas", "su", "env", "nohup", "time", "nice", "ionice", "xargs", "command",
    "builtin", "exec", "timeout", "stdbuf", "setsid", "unbuffer", "strace", "ltrace",
    "watch", "flock", "chrt", "taskset",
}
WRAPPER_VALUE_FLAGS = {"-u", "-g", "-n", "-I", "-P", "-L", "-a", "-s", "-p", "--user", "-i"}


def strip_prefix(tokens):
    """Peel env assignments and wrappers to reach the command that matters."""
    i, privileged, wrappers = 0, False, []
    while i < len(tokens):
        t = tokens[i]
        if ENV_ASSIGN.match(t):
            i += 1
            continue
        base = os.path.basename(t)
        if base in WRAPPERS:
            if base in ("sudo", "doas", "su"):
                privileged = True
            wrappers.append(base)
            i += 1
            while i < len(tokens):
                t2 = tokens[i]
                if t2 == "--":
                    i += 1
                    break
                if t2.startswith("-"):
                    takes_value = t2 in WRAPPER_VALUE_FLAGS
                    i += 2 if takes_value and i + 1 < len(tokens) else 1
                    continue
                if base in ("timeout", "nice", "ionice", "chrt") and re.fullmatch(r"[\d.]+[smhd]?", t2):
                    i += 1
                    continue
                if base == "flock" and (t2.startswith("/") or t2.isdigit()):
                    i += 1
                    continue
                if base == "su" and not t2.startswith("-"):
                    i += 1  # target user
                    continue
                break
            continue
        break
    return tokens[i:], privileged, wrappers


# ----------------------------------------------------- carriers / payload ---

DOCKER_VALUE_FLAGS = {
    "-e", "--env", "-v", "--volume", "--mount", "-u", "--user", "-w", "--workdir", "--name",
    "--entrypoint", "-p", "--publish", "--network", "--net", "-l", "--label", "--memory", "-m",
    "--cpus", "--restart", "--add-host", "--device", "--tmpfs", "--health-cmd", "--env-file",
    "--log-driver", "--platform", "--pull", "--cap-add", "--cap-drop", "--security-opt",
}
SSH_VALUE_FLAGS = {"-i", "-p", "-o", "-l", "-L", "-R", "-D", "-F", "-J", "-b", "-c", "-E", "-m",
                   "-w", "-S", "-W"}


def _skip_flags(tokens, value_flags):
    """Index of the first non-flag token.

    `value_flags` are the flags that swallow the next token as their value,
    so `docker exec -u root ctr sh` does not mistake `root` for the payload.
    """
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "--":
            return i + 1
        if t.startswith("-"):
            if "=" in t:
                i += 1
            elif t in value_flags:
                i += 2
            else:
                i += 1
            continue
        return i
    return i


def carried_command(binary, args):
    """Return (payload_tokens, context, target) for commands that carry another.

    context drives how the payload's score is folded in; target is the
    container/image/host the payload lands on.
    """
    if not args:
        return None, None, None
    sub = args[0]

    if binary in ("docker", "podman", "nerdctl"):
        rest = args[1:]
        if sub in ("compose",) and rest:
            sub, rest = rest[0], rest[1:]
        if sub in ("exec", "run", "create"):
            j = _skip_flags(rest, DOCKER_VALUE_FLAGS)
            if j < len(rest):
                target = rest[j]
                payload = rest[j + 1:]
                ctx = "container" if sub == "exec" else "image"
                return (payload or None), ctx, target
        if sub == "start" and len(rest) > 0:
            return None, "container", rest[-1]
        return None, None, None

    if binary in ("kubectl", "oc") and sub in ("exec", "run", "debug"):
        if "--" in args:
            k = args.index("--")
            target = next((a for a in args[1:k] if not a.startswith("-")), None)
            return (args[k + 1:] or None), "pod", target
        return None, "pod", None

    if binary in ("ssh", "mosh"):
        j = _skip_flags(args, SSH_VALUE_FLAGS)
        if j < len(args):
            return (args[j + 1:] or None), "remote", args[j]
        return None, "remote", None

    if binary in SHELLS and "-c" in args:
        k = args.index("-c")
        if k + 1 < len(args):
            return tokenize(args[k + 1]), "shell", None

    if binary in ("ansible", "ansible-playbook") and "-a" in args:
        k = args.index("-a")
        if k + 1 < len(args):
            inner = re.sub(r"^\s*(cmd|_raw_params)=", "", args[k + 1])
            host = args[0] if not args[0].startswith("-") else "inventory"
            return tokenize(inner), "fleet", host

    if binary == "find":
        for flag in ("-exec", "-execdir", "-ok"):
            if flag in args:
                k = args.index(flag)
                payload = [a for a in args[k + 1:] if a not in ("{}", ";", "\\;", "+")]
                return (payload or None), "per-file", None
        if "-delete" in args:
            return ["rm"], "per-file", None

    return None, None, None


# context -> (score weight, scope floor, note)
CONTEXTS = {
    "container": (0.85, "container",
                  "runs inside the container: its filesystem, its mounts, its credentials"),
    "image": (0.85, "container", "runs in a fresh container from this image"),
    "pod": (0.85, "cluster", "runs inside the pod, with the pod's service account"),
    "remote": (1.0, "host", "runs on the remote host, where you cannot see the blast"),
    "shell": (1.0, "host", "runs in a subshell"),
    "fleet": (1.2, "cluster", "runs on every host matched by the inventory pattern, in parallel"),
    "per-file": (1.15, "directory",
                 "runs once per matched file: the match set is the blast radius"),
}

# ---------------------------------------------------------- introspection ---


def _docker(args, timeout=5):
    """Run one read-only `docker` subcommand and return its stdout, or None.

    Nothing is ever executed to score it: this only ever inspects. A missing
    docker, a timeout, a non-zero exit and an OS error all mean the same
    thing to the caller — no answer — so they collapse into None.
    """
    if not shutil.which("docker"):
        return None
    try:
        r = subprocess.run(["docker", *args], capture_output=True, text=True,
                           timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def introspect_target(kind, target):
    """Read-only lookup of what a container/image actually runs.

    Never pulls, never starts anything: if the image is not local, say so.
    """
    if not target or target.startswith("-"):
        return None
    if not shutil.which("docker"):
        return {"resolved": False, "note": "no docker CLI here to resolve it with"}
    if kind == "container":
        fmt = ("{{json .Config.Entrypoint}}|{{json .Config.Cmd}}"
               "|{{.Config.User}}|{{.Config.Image}}")
        out = _docker(["inspect", "--format", fmt, target])
        if not out:
            return {"resolved": False,
                    "note": f"cannot inspect container {target!r} — not running here, "
                            f"or no docker daemon"}
    else:
        out = _docker(["image", "inspect", "--format",
                       "{{json .Config.Entrypoint}}|{{json .Config.Cmd}}|{{.Config.User}}|{{.Id}}",
                       target])
        if not out:
            return {"resolved": False,
                    "note": f"cannot inspect image {target!r} — not pulled here, or no docker "
                            f"daemon; scoville never pulls to find out"}
    ep, cmd, user, ref = (out.split("|", 3) + ["", "", "", ""])[:4]

    def parse(v):
        try:
            return json.loads(v) or []
        except (ValueError, TypeError):
            return []

    entry = parse(ep) + parse(cmd)
    return {
        "resolved": True, "entrypoint": entry, "user": user or "root", "ref": ref,
        "note": "entrypoint " + (shlex.join(entry) if entry else "<none>"),
    }


# --------------------------------------------------------------- scoring ---

# A destructive verb in command position, for binaries no rule covers.
UNKNOWN_DESTROY = re.compile(
    r"^(?:\S+[\s:]){0,3}(delete|destroy|terminate|purge|wipe|erase|nuke|drop|"
    r"deprovision|teardown)\b")

FUNC_DEF = re.compile(r"^[\w.-]+\(\)$")

VAR_PATH = re.compile(r"^\$\{?(\w+)\}?(/.*)?$")

# Factor prefixes that stay visible even at zero points: "the payload is safe"
# is exactly what someone running `docker exec` wants confirmed.
# ---------------------------------------------- definitions in this text ---
#
# A wrapper script, a make target, an npm script and an image ENTRYPOINT are all
# already treated as carriers: the call site is opaque and `--introspect`
# resolves it. Shell functions and aliases are the same problem one level
# closer, and in a deploy script that defines its own helpers they are most of
# the interesting lines.

ALIAS_DEF = re.compile(
    r"(?:^|[;&|]\s*)\s*alias\s+(?P<name>[\w.-]+)="
    r"(?P<val>'[^']*'|\"[^\"]*\"|\S+)", re.MULTILINE)
# `name() {` and `function name {`, the two spellings bash accepts.
FUNC_HEAD = re.compile(
    r"(?:^|[;&|]\s*)\s*(?:function\s+)?(?P<name>[\w.-]+)\s*\(\s*\)\s*\{", re.MULTILINE)
FUNC_HEAD_KW = re.compile(
    r"(?:^|[;&|]\s*)\s*function\s+(?P<name>[\w.-]+)\s*\{", re.MULTILINE)

CARRIER_ALIAS = "resolved alias "
CARRIER_FUNCTION = "resolved function "


def _balanced_body(text, brace_at):
    """Text between the `{` at `brace_at` and its matching `}`, or None.

    Brace counting, not a regex: a function body containing `${VAR}` or a
    nested `if ... { }` is ordinary, and a non-greedy match to the first `}`
    would truncate the body and quietly under-report what it runs.
    """
    depth = 0
    for i in range(brace_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_at + 1:i]
    return None


def collect_definitions(text):
    """Functions and aliases defined in `text`, each with the offset it goes live.

    Nothing outside `text` is read. Resolving the user's `~/.bashrc` would make
    the same script score differently on two machines, which is a worse answer
    than an unknown command — the score has to be a property of the input.
    """
    defs = []
    for m in ALIAS_DEF.finditer(text):
        val = m.group("val")
        if val[:1] in "'\"":
            val = val[1:-1]
        defs.append({"kind": "alias", "name": m.group("name"), "value": val,
                     "at": m.end(), "line": text.count("\n", 0, m.start()) + 1})
    for pattern in (FUNC_HEAD, FUNC_HEAD_KW):
        for m in pattern.finditer(text):
            brace = m.end() - 1
            body = _balanced_body(text, brace)
            if body is None:
                continue  # unterminated; scoring half a body is worse than skipping it
            defs.append({"kind": "function", "name": m.group("name"), "value": body,
                         # Live only after the closing brace: bash reads the
                         # whole definition before the name means anything.
                         "at": brace + len(body) + 2,
                         "line": text.count("\n", 0, m.start()) + 1})
    defs.sort(key=lambda d: d["at"])
    return defs


def definition_at(defs, name, offset):
    """The definition of `name` in scope at `offset`, or None.

    The last definition before the call site wins — that is what redefinition
    means, and an alias shadowing a real binary is exactly the case worth
    catching. A definition *after* the call site is not applied: bash reads top
    to bottom, and scoring it anyway would be a false positive on the common
    layout of helpers at the bottom of a script.
    """
    found = None
    for d in defs:
        if d["name"] == name and d["at"] <= offset:
            found = d
    return found


PAYLOAD = "payload "
ENTRYPOINT = "resolved entrypoint "
WRAPPER = "resolved wrapper "


def path_factors(binary, args):
    """Score the *targets*. This is where rm and `rm /` part ways."""
    out = []
    for a in args:
        if a.startswith("-") or ENV_ASSIGN.match(a) or "=" in a.split("/", 1)[0]:
            continue
        m = VAR_PATH.match(a)
        if m:
            var, tail = m.group(1), m.group(2) or ""
            expanded = tail or "/"
            if expanded in ("/", "//"):
                out.append((40, (f"if ${var} is unset or empty this expands to `/` — "
                                 f"the classic `rm -rf $DIR/` incident"),
                            "host", "irreversible"))
            else:
                out.append((22, (f"if ${var} is unset this expands to `{expanded}`, "
                                 f"not to the path you meant"), "host", None))
            continue
        p = a.rstrip("/") or "/"
        if p in ("/", "/*") or a in ("/", "/*"):
            out.append((50, "target is the filesystem root: everything the caller can write to",
                        "host", "irreversible"))
            continue
        stripped = p.removesuffix("/*")
        if stripped in SYSTEM_DIRS:
            out.append((35, f"target is `{stripped}` — {SYSTEM_DIRS[stripped]}",
                        "host", "irreversible"))
            continue
        if p in ("~", "$HOME", "${HOME}", "~/*", "$HOME/*"):
            out.append((28, "target is the user's home directory", "host", "irreversible"))
            continue
        parent = "/" + stripped.lstrip("/").split("/")[0] if stripped.startswith("/") else ""
        if parent in SYSTEM_DIRS and stripped != parent:
            pts = 18 if parent in CORE_DIRS else 8
            out.append((pts, f"target lives under `{parent}` — {SYSTEM_DIRS[parent]}",
                        "host", "irreversible"))
            continue
        if REGENERABLE.search(p):
            out.append((-25, (f"`{os.path.basename(p)}` is a regenerable build/dependency "
                              f"directory, not source of truth"), None, None))
            continue
        if p.startswith("/dev/") and binary not in DEVICE_TARGET_EXPECTED:
            out.append((45, f"target is a device node (`{p}`), not a regular file",
                        "host", "irreversible"))
    return out


def specific_clis():
    """The resource CLIs enumerated per resource rather than by verb.

    Derived from the rule set rather than listed, because docs/rules.md names
    which CLIs are enumerated and which are carried by verb classification, and
    a hand-maintained list drifts the first time a rule is added.
    """
    enumerated = {b for r in RULES if not r["generic"] for b in r["bins"]}
    return sorted(set(RESOURCE_CLIS.split()) & enumerated)


def generic_clis():
    """The resource CLIs verb classification still carries on its own."""
    return sorted(set(RESOURCE_CLIS.split()) - set(specific_clis()))


def pick_rule(binary, args_str):
    """Pick the rule that best describes a command, or None.

    Specificity wins before score does: a rule matching this exact
    subcommand always beats a generic `<cli> ... delete` classifier, even
    when the generic one would score higher. The classifier is the fallback,
    not a competitor.
    """
    candidates = [r for r in RULES if binary in r["bins"]
                  and (r["sub"] is None or r["sub"].search(args_str))]
    if not candidates:
        return None
    return max(candidates, key=lambda r: (not r["generic"], r["sub"] is not None, r["base"]))


def _score_local_definition(local, raw, binary, args, privileged, strict, introspect,
                            depth, basedir, seen, defs, offset):
    """Score a call to a function or alias defined earlier in the same input.

    An alias is *expanded* — `k delete ns prod` is `kubectl delete ns prod`, and
    scoring it as anything softer would miss the shadowing that makes aliases
    worth resolving at all. A function gets carrier treatment, like a wrapper
    script: the call site contributes the frame, the body contributes the score.
    """
    seen = seen if seen is not None else set()
    key = f"{local['kind']}:{local['name']}@{local['at']}"
    site = f"defined on line {local['line']} of this input"

    if key in seen:
        # Mutual recursion arrives here too: b is on the stack when a calls it
        # back. Stopping is the whole answer; the body has already been scored
        # once further up, and its score is already carried.
        return {
            "command": raw.strip(), "rule": "CARRIER-RECURSION", "known": True, "score": 0,
            "level": "safe", "scope": "none", "reversibility": "reversible",
            "privileged": privileged, "advice": None, "carries": [],
            "factors": [{"points": 0, "why": f"`{binary}` is already being scored higher up "
                                             f"this call chain — recursion stops here",
                         "keep": True}],
        }

    if local["kind"] == "alias":
        expanded = " ".join([local["value"], *args]).strip()
        seen.add(key)
        try:
            # Resolved at the *call* site, not the definition: bash looks a name
            # up when the line runs, so a helper defined below another one is
            # still in scope by the time either is called.
            child = score_command(expanded, tokenize(expanded), strict=strict,
                                  introspect=introspect, depth=depth + 1, basedir=basedir,
                                  seen=seen, defs=defs, offset=offset)
        finally:
            seen.discard(key)
        if not child:
            return None
        result = dict(child)
        result["command"] = raw.strip()
        result["privileged"] = privileged or child["privileged"]
        result["factors"] = [{"points": 0,
                              "why": (f"{CARRIER_ALIAS}`{binary}` is `{local['value']}`, {site} "
                                      f"— scored as `{child['command']}`"),
                              "rule": None, "keep": True}] + list(child["factors"])
        return result

    factors = [{"points": 0, "why": f"`{binary}` is a function {site}",
                "rule": None, "keep": True}]
    scope, revert, advice, children = "none", "reversible", None, []
    seen.add(key)
    try:
        inner = analyze(local["value"], strict=strict, introspect=introspect, basedir=basedir,
                        _depth=depth + 1, _seen=seen, _defs=defs, _at=offset)
    finally:
        # Discarded, not left behind: calling the same helper twice in one
        # script is ordinary, and a visited-set would report the second call as
        # recursion and score it zero.
        seen.discard(key)
    worst = max(inner, key=lambda r: r["score"], default=None)
    if worst and worst["score"]:
        children.append(worst)
        factors.append({"points": worst["score"],
                        "why": (f"{CARRIER_FUNCTION}`{binary}()` runs `{worst['command']}`, "
                                f"which is {worst['level']}"),
                        "rule": None, "keep": True})
        scope, revert, advice = worst["scope"], worst["reversibility"], worst["advice"]
    score = max(0, min(100, sum(f["points"] for f in factors)))
    return {
        "command": raw.strip(), "rule": "CARRIER-FUNCTION", "known": True, "score": score,
        "level": band(score), "scope": scope, "reversibility": revert,
        "privileged": privileged, "advice": advice, "factors": factors, "carries": children,
    }


def _factor(f):
    """One contributing factor, as it appears in output.

    `rule` names the rule or amplifier that produced it, so `scoville --why
    <id>` reaches the reasoning from any line of a report rather than from a
    search through the source. Factors that are not a rule — a path, a carried
    payload, a dampener — carry None rather than a made-up id.
    """
    points, why = f[0], f[1]
    return {
        "points": points, "why": why,
        "rule": f[4] if len(f) > 4 else None,
        "keep": why.startswith((PAYLOAD, ENTRYPOINT, WRAPPER)),
    }


def score_command(raw, tokens, strict=False, introspect=False, depth=0, basedir=".",
                  seen=None, defs=None, offset=0):
    """Score one command. Returns a result dict; recurses into payloads."""
    rest, privileged, wrappers = strip_prefix(tokens)
    if not rest:
        return None
    binary = os.path.basename(rest[0])
    args = rest[1:]
    args_str = " ".join(args)
    if FUNC_DEF.match(binary):
        return {
            "command": raw.strip(), "rule": "READ-FUNCDEF", "known": True, "score": 0,
            "level": "safe", "scope": "none", "reversibility": "reversible", "privileged": False,
            "advice": None, "carries": [],
            "factors": [{"points": 0, "why": "function definition: the body is scored on its "
                                             "own lines", "keep": False}],
        }

    # A name defined earlier in this same text shadows whatever is on PATH.
    # Only under --introspect: resolving a carrier is what that flag means, and
    # the default path must keep scoring exactly what it is shown.
    local = definition_at(defs, binary, offset) if (introspect and defs) else None
    if local and depth < 3:
        resolved = _score_local_definition(
            local, raw, binary, args, privileged, strict, introspect, depth, basedir, seen,
            defs, offset)
        if resolved:
            return resolved

    rule = pick_rule(binary, args_str)
    factors = []
    if rule:
        scope, revert, advice = rule["scope"], rule["revert"], rule["advice"]
        if rule["base"]:
            factors.append((rule["base"], rule["why"], None, None, rule["id"]))
        elif rule["base"] == 0:
            factors.append((0, rule["why"], None, None, rule["id"]))
        base_id = rule["id"]
    else:
        scope, revert, advice = "none", "reversible", None
        base_id = "UNKNOWN"
        pts = 40 if strict else 5
        unknown_why = f"no rule for `{binary}` — scored on flags and targets only"
        if strict:
            unknown_why += " (--strict: unknown means unreviewed)"
        factors.append((pts, unknown_why, None, None, "UNKNOWN"))
        verb = UNKNOWN_DESTROY.search(args_str)
        if verb:
            factors.append((40, (f"`{verb.group(1)}` is destructive in nearly every CLI, and "
                                 f"nothing here knows what this one reaches — treat the "
                                 f"score as a floor"), "account", "irreversible"))

    subsumed = rule["subsumes"] if rule else set()
    for amp in AMPS + SOFTENERS:
        if amp["bins"] and binary not in amp["bins"]:
            continue
        if amp["id"] in subsumed:
            continue  # the rule exists because of this flag; do not count it twice
        hay = args_str if not amp.get("raw") else raw
        if amp["pattern"].search(hay) or (amp["bins"] is None and amp["pattern"].search(raw)):
            factors.append((amp["points"], amp["why"], amp["scope"], amp["revert"], amp["id"]))

    if binary in PATH_SENSITIVE or (rule and rule["paths"]):
        factors.extend(path_factors(binary, args))

    if privileged:
        factors.append((15, f"`{wrappers[0]}`: runs as root — file permissions do not apply",
                        "host", None))

    # payload: docker exec / kubectl exec -- / ssh host / sh -c / ansible -a / find -exec
    payload, ctx, target = carried_command(binary, args)
    children = []
    if ctx and depth < 3:
        weight, scope_floor, note = CONTEXTS[ctx]
        if payload:
            child = score_command(shlex.join(payload), payload, strict=strict,
                                  introspect=introspect, depth=depth + 1, basedir=basedir,
                                  seen=seen)
            if child:
                children.append(child)
                carried = round(child["score"] * weight)
                if ctx == "per-file" and child["score"]:
                    factors.append((10, ("applied to every path the walk matches, not to "
                                         "one argument you can read"), None, None))
                factors.append((carried,
                                f"{PAYLOAD}`{child['command']}` is {child['level']} — {note}",
                                scope_floor, child["reversibility"]))
        else:
            info = introspect_target(ctx if ctx != "image" else "image", target) if introspect \
                else None
            if info and info.get("resolved"):
                entry = info["entrypoint"]
                if entry:
                    child = score_command(shlex.join(entry), entry, strict=strict,
                                          introspect=False, depth=depth + 1, basedir=basedir,
                                          seen=seen)
                    if child:
                        children.append(child)
                        carried = round(child["score"] * weight)
                        factors.append((carried,
                                        (f"{ENTRYPOINT}`{child['command']}` is "
                                         f"{child['level']} — {note}"),
                                        scope_floor, child["reversibility"]))
                if info.get("user") in ("", "root", "0"):
                    factors.append((8, "the image runs as root", None, None))
            else:
                extra = f"; {info['note']}" if info else \
                    "; re-run with --introspect to resolve it"
                factors.append((20, (f"no explicit command: what runs is the image "
                                     f"ENTRYPOINT/CMD, not this line{extra}"),
                                scope_floor, None))

    kind, target = hidden_payload(binary, rest, rule)
    if kind and depth < 3:
        seen = seen if seen is not None else set()
        key = f"{kind}:{target}"
        body = None
        if introspect and key not in seen:
            seen.add(key)
            body = resolve_payload(kind, target, basedir)
        if body:
            inner = analyze(body, strict=strict, introspect=introspect, basedir=basedir,
                            _depth=depth + 1, _seen=seen)
            worst = max(inner, key=lambda r: r["score"], default=None)
            if worst and worst["score"]:
                children.append(worst)
                factors.append((worst["score"],
                                (f"{WRAPPER}`{target}` line {worst.get('line', 1)} runs "
                                 f"`{worst['command']}`, which is {worst['level']}"),
                                worst["scope"], worst["reversibility"]))
        else:
            why = f"runs `{target}`: {WRAPPER_NOTE[kind]}"
            why += (" — re-run with --introspect to read it" if not introspect
                    else ", and it could not be read from here")
            factors.append((20, why, None, None))

    # dampeners
    dry = None
    for pattern, why in DAMPENERS:
        if why is None:
            if binary in DRY_RUN_N_BINS and pattern.search(args_str):
                dry = "-n: dry run, nothing is written"
            continue
        if pattern.search(args_str):
            dry = why

    score = max(0, min(100, sum(p for p, *_ in factors)))
    for f in factors:
        s, r = f[2], f[3]
        if s:
            scope = widest(scope, s)
        if r:
            revert = harder(revert, r)
    if dry:
        score = min(score, 12)
        revert = "reversible"
        factors.append((0, dry, None, None))

    return {
        "command": raw.strip(), "rule": base_id, "known": rule is not None,
        "score": score, "level": band(score), "scope": scope, "reversibility": revert,
        "privileged": privileged, "advice": advice,
        "factors": [_factor(f) for f in factors],
        "carries": children,
    }


SCRIPT_EXT = (".sh", ".bash", ".zsh", ".ksh", ".py", ".rb", ".pl")
RUNNERS = {"make", "gmake", "npm", "yarn", "pnpm", "just", "task", "mise", "rake", "invoke"}
MAX_SCRIPT_BYTES = 256 * 1024


def hidden_payload(binary, rest, rule):
    """A wrapper whose contents this command line does not show.

    Same shape as an image ENTRYPOINT: the risk is real, it is just not
    written here. Returns (kind, target).
    """
    if binary in ("source", "."):
        return ("script", rest[1]) if len(rest) > 1 else (None, None)
    if binary in SHELLS or (rule is None and binary in ("python", "python3", "perl", "ruby")):
        if "-c" in rest:
            return None, None  # inline code, handled as a carried payload
        for a in rest[1:]:
            if not a.startswith("-"):
                return "script", a
        return None, None
    if binary in ("make", "gmake"):
        target = next((a for a in rest[1:] if not a.startswith("-") and "=" not in a), None)
        return "make", target or "all"
    if binary in ("npm", "yarn", "pnpm"):
        args = [a for a in rest[1:] if not a.startswith("-")]
        if args and args[0] in ("run", "run-script"):
            args = args[1:]
        elif binary == "npm":
            return None, None  # `npm install` etc are packaging, not a script
        return ("npm", args[0]) if args else (None, None)
    if binary in RUNNERS:
        target = next((a for a in rest[1:] if not a.startswith("-")), None)
        return ("task", target) if target else (None, None)
    if rule is None and (rest[0].startswith(("./", "../", "/")) or rest[0].endswith(SCRIPT_EXT)):
        return "script", rest[0]
    return None, None


def _read(path, basedir):
    """Read a referenced payload file, or None if it cannot be read safely.

    Size-capped at MAX_SCRIPT_BYTES: a command that points at a multi-megabyte
    file is not worth stalling a pre-commit hook over.
    """
    try:
        p = os.path.join(basedir, path) if not os.path.isabs(path) else path
        if os.path.getsize(p) > MAX_SCRIPT_BYTES:
            return None
        with open(p, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _make_recipe(target, basedir):
    """Return the recipe lines of one Make target, or None.

    A deliberately shallow read — tab-indented lines until the next
    non-indented one, with the @/-/+ prefixes stripped. No variable
    expansion and no includes: what it cannot resolve it leaves alone rather
    than guessing at a command that was never going to run.
    """
    for name in ("Makefile", "makefile", "GNUmakefile"):
        text = _read(name, basedir)
        if text is None:
            continue
        lines, collecting = [], False
        for line in text.splitlines():
            if re.match(rf"^{re.escape(target)}\s*:(?!=)", line):
                collecting = True
                continue
            if collecting:
                if line.startswith("\t"):
                    lines.append(line.lstrip("\t").lstrip("@-+"))
                elif line.strip() and not line.startswith((" ", "\t")):
                    break
        if lines:
            return "\n".join(lines)
    return None


def _npm_script(name, basedir):
    """Return the body of one npm script from package.json, or None."""
    text = _read("package.json", basedir)
    if not text:
        return None
    try:
        return json.loads(text).get("scripts", {}).get(name)
    except ValueError:
        return None


def resolve_payload(kind, target, basedir):
    """Read what the wrapper actually runs. Read-only, and never executes it."""
    if not target:
        return None
    if kind == "script":
        return _read(target, basedir)
    if kind == "make":
        return _make_recipe(target, basedir)
    if kind == "npm":
        return _npm_script(target, basedir)
    return None


WRAPPER_NOTE = {
    "script": "the commands are inside the script, not on this line",
    "make": "the recipe is in the Makefile, not on this line",
    "npm": "the script body is in package.json, not on this line",
    "task": "the task definition is in the runner's config, not on this line",
}


FORKBOMB = re.compile(r":\s*\(\s*\)\s*\{.*\|.*&.*\}\s*;\s*:")


def _track_downloads(raw, downloaded):
    """Remember paths a fetcher wrote, so executing them later can be spotted."""
    tokens = tokenize(raw)
    rest, _, _ = strip_prefix(tokens)
    if not rest or os.path.basename(rest[0]) not in FETCHERS:
        return
    for i, tok in enumerate(rest[1:], 1):
        if tok in ("-o", "-O", "--output", ">") and i + 1 < len(rest):
            downloaded.add(rest[i + 1])
        elif tok.startswith(("--output=", "-o=")):
            downloaded.add(tok.split("=", 1)[1])


def _flag_deferred_exec(result, raw, downloaded):
    """`curl -o f URL && bash f` is the pipe with a file in the middle."""
    if not downloaded:
        return
    tokens = tokenize(raw)
    rest, _, _ = strip_prefix(tokens)
    if not rest:
        return
    binary = os.path.basename(rest[0])
    hit = None
    if binary in INTERPRETERS:
        hit = next((a for a in rest[1:] if a in downloaded), None)
    elif rest[0] in downloaded or f"./{os.path.basename(rest[0])}" in downloaded:
        hit = rest[0]
    if not hit:
        return
    opaque = [f for f in result["factors"] if f["why"].startswith("runs `")]
    for f in opaque:  # subsumed by the more specific finding below
        result["factors"].remove(f)
        result["score"] -= f["points"]
    result["factors"].append({
        "points": 70,
        "why": f"executes `{hit}`, which was downloaded earlier in this same snippet: "
               f"nothing read it in between",
        "keep": True,
    })
    result["score"] = min(100, result["score"] + 70)
    result["level"] = band(result["score"])
    result["scope"] = widest(result["scope"], "host")
    result["reversibility"] = "irreversible"
    result["advice"] = ("check the script between fetching and running it, or pin it by "
                        "checksum: `echo '<sha256>  s.sh' | sha256sum -c`")


def analyze(text, strict=False, introspect=False, basedir=".", _depth=0, _seen=None,
            _defs=None, _at=None):
    """Analyze a snippet; returns one result per command, in execution order.

    `_defs` carries the enclosing text's function and alias definitions into a
    resolved body, and `_at` pins every command in that body to the offset of
    the call site — body offsets are body-relative and would otherwise be
    compared against offsets in a different string. The call site is the right
    point because bash resolves a name when the line runs, so a helper defined
    below the one that calls it is still in scope.
    """
    results = []
    defs = _defs if _defs is not None else (collect_definitions(text) if introspect else [])
    if FORKBOMB.search(text):
        results.append({
            "command": text.strip().splitlines()[0][:60], "rule": "EXEC-FORKBOMB", "known": True,
            "score": 100, "level": "critical", "scope": "host", "reversibility": "recoverable",
            "privileged": False, "line": 1, "carries": [],
            "advice": "there is no legitimate reason for this on a machine you care about",
            "factors": [{"points": 100, "why": "fork bomb: recursively spawns processes until the "
                                               "kernel's process table is exhausted"}],
        })
        return results

    prev, downloaded = None, set()
    for raw, offset, op in split_commands(text):
        line = text.count("\n", 0, offset) + 1
        for inner, ioff in subshell_commands(raw, offset):
            r = score_command(inner, tokenize(inner), strict=strict, introspect=introspect,
                              depth=max(1, _depth), basedir=basedir, seen=_seen, defs=defs,
                              offset=_at if _at is not None else ioff)
            if r:
                r["line"] = text.count("\n", 0, ioff) + 1
                r["substitution"] = True
                results.append(r)
        r = score_command(raw, tokenize(raw), strict=strict, introspect=introspect,
                          depth=_depth, basedir=basedir, seen=_seen, defs=defs,
                          offset=_at if _at is not None else offset)
        if not r:
            continue
        r["line"] = line
        # curl … | sh — the pipe is the whole risk, and neither half shows it
        if op == "|" and prev:
            binary = os.path.basename(strip_prefix(tokenize(raw))[0][0]) if tokenize(raw) else ""
            src = os.path.basename(strip_prefix(tokenize(prev["command"]))[0][0])
            if binary in INTERPRETERS and src in FETCHERS:
                r["factors"].append({
                    "points": 78,
                    "why": "piping a downloaded script straight into an interpreter: the code runs "
                           "unreviewed, with your privileges, and the server can serve different "
                           "bytes to curl than to a browser",
                })
                r["score"] = min(100, r["score"] + 78)
                r["level"] = band(r["score"])
                r["scope"] = widest(r["scope"], "host")
                r["reversibility"] = "irreversible"
                r["advice"] = "download, read, then run: `curl -fsSL URL -o s.sh && less s.sh && sh s.sh`"
        _track_downloads(raw, downloaded)
        _flag_deferred_exec(r, raw, downloaded)
        results.append(r)
        prev = r
    return results


# ---------------------------------------------------------------- output ---

# Scoville's own scale, since the bands map onto it one for one. The slug is
# what `--quiet` prints, so it stays greppable and ASCII.
PEPPERS = {
    "safe": ("bell pepper", "bell-pepper", 0, "0 SHU"),
    "low": ("jalapeño", "jalapeno", 1, "2.5-8k SHU"),
    "medium": ("cayenne", "cayenne", 2, "30-50k SHU"),
    "high": ("habanero", "habanero", 3, "100-350k SHU"),
    "critical": ("carolina reaper", "carolina-reaper", 4, "1.6-2.2M SHU"),
}
SCALES = ("bands", "peppers")


def label(level, scale, slug=False):
    """The display name for a level on the chosen scale."""
    if scale != "peppers":
        return level if slug else level.upper()
    name, short, heat, _ = PEPPERS[level]
    if slug:
        return short
    return ("🌶" * heat + " " if heat else "") + name.upper()


MARKS = {"safe": "ok", "low": "· ", "medium": "! ", "high": "!!", "critical": "XX"}
COLORS = {"safe": "32", "low": "36", "medium": "33", "high": "31", "critical": "1;31"}


def paint(text, level, on):
    """Colour text for a level, or hand it back untouched when `on` is false."""
    return f"\033[{COLORS[level]}m{text}\033[0m" if on else text


def render_text(results, source=None, color=False, verbose=False, scale="bands"):
    """Render the human-readable report: one block per command.

    Zero-weight factors are hidden unless `verbose`, or unless the command
    scored 0 — a safe command with nothing listed under it reads as a tool
    that failed to run, rather than as a verdict.
    """
    lines = []
    width = 10 if scale == "bands" else 25
    for r in results:
        where = f"{source}:{r['line']}: " if source else ""
        tag = "(command substitution) " if r.get("substitution") else ""
        lines.append(f"{where}{tag}{r['command']}")
        lvl = label(r["level"], scale)
        # each 🌶 is one character but two terminal columns
        emoji = PEPPERS[r["level"]][2] if scale == "peppers" else 0
        pad = " " * max(0, width - len(lvl) - emoji)
        head = (f"  {paint(lvl, r['level'], color)}{pad} {r['score']:>3}/100  ·  "
                f"scope: {r['scope']}  ·  {r['reversibility']}")
        lines.append(head)
        for f in r["factors"]:
            if f["points"] == 0 and not verbose and r["score"] > 0 and not f.get("keep"):
                continue
            sign = f"{f['points']:+d}" if f["points"] else "  ·"
            lines.append(f"    {sign:>4}  {f['why']}")
        if r["advice"] and r["level"] not in ("safe",):
            lines.append(f"    ↳ safer: {r['advice']}")
        # The path from a score to its reasoning should be one command, not a
        # search through the source. Shown on anything that scored, and under
        # --verbose on the rest.
        if r.get("known") and r["rule"] and (r["level"] != "safe" or verbose):
            lines.append(f"    ↳ why:   scoville --why {r['rule']}")
        lines.append("")
    return "\n".join(lines)


def public(results):
    """Drop internal render hints before serialising."""
    out = []
    for r in results:
        clean = {k: v for k, v in r.items() if k != "carries"}
        clean["factors"] = [{k: v for k, v in f.items() if k != "keep"} for f in r["factors"]]
        clean["carries"] = public(r.get("carries", []))
        out.append(clean)
    return out


def overall(results):
    """Collapse a run into one verdict.

    Not an average: the worst score, the widest scope and the least
    reversible outcome across every command. A script is as dangerous as its
    most dangerous line, and averaging would let ten harmless commands bury
    one `rm -rf /`.
    """
    if not results:
        return {"score": 0, "level": "safe", "scope": "none", "reversibility": "reversible",
                "commands": 0}
    worst = max(results, key=lambda r: r["score"])
    scope, revert = "none", "reversible"
    for r in results:
        scope = widest(scope, r["scope"])
        revert = harder(revert, r["reversibility"])
    return {"score": worst["score"], "level": worst["level"], "scope": scope,
            "reversibility": revert, "commands": len(results), "worst": worst["command"]}


# ------------------------------------------------------------ overrides ---
#
# The rule set is calibrated for the general case, but risk is contextual. A
# repo where `kubectl delete ns ci-*` is routine teardown gets the same `high`
# as one where it is an outage. Before this the only levers were --fail-on and
# --strict, both global — so the first time a legitimate command tripped the
# gate, the cheapest fix was to turn the gate off. That is the failure mode
# this is designed against.

CONFIG_NAMES = (".scovillerc", ".scovillerc.json")
OVERRIDE_ACTIONS = ("deny", "rescore", "allow")


class ConfigError(Exception):
    """A config that cannot be read as written. Never guessed at: a misspelled
    key that is silently ignored is an override the reader believes is in
    force."""


def find_config(basedir):
    """The nearest `.scovillerc` at or above `basedir`, or None.

    Walking up means a repo-root config covers every subdirectory, which is
    where the file belongs — risk is a property of the repository, not of the
    directory you happened to run from.
    """
    here = os.path.abspath(basedir)
    while True:
        for name in CONFIG_NAMES:
            candidate = os.path.join(here, name)
            if os.path.isfile(candidate):
                return candidate
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


def load_config(path):
    """Parse and validate a config file into a list of override entries.

    JSON, not TOML. `tomllib` is 3.11+ and scoville supports 3.10, and the two
    ways round that — vendoring a parser, or dropping a supported version — both
    cost more than the comment syntax is worth for a file whose every entry
    already carries a mandatory `why`. Switching is a one-line change if the
    floor ever moves.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as e:
        raise ConfigError(f"{path}: {e}") from e
    except ValueError as e:
        raise ConfigError(f"{path}: not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected an object with allow/deny/rescore keys")

    unknown = set(data) - set(OVERRIDE_ACTIONS)
    if unknown:
        raise ConfigError(f"{path}: unknown key(s) {', '.join(sorted(unknown))}; "
                          f"expected {', '.join(OVERRIDE_ACTIONS)}")

    entries = []
    # Deny first, then rescore, then allow: a deny is a statement that the
    # command is never acceptable here, and it has to survive an allow written
    # by someone who did not know about it.
    for action in OVERRIDE_ACTIONS:
        for i, raw in enumerate(data.get(action) or []):
            where = f"{path}: {action}[{i}]"
            if not isinstance(raw, dict):
                raise ConfigError(f"{where}: expected an object with `match` and `why`")
            match = raw.get("match")
            why = raw.get("why")
            if not match or not isinstance(match, str):
                raise ConfigError(f"{where}: needs a `match` glob")
            # An override with no stated reason is how a config file becomes a
            # list nobody can safely delete from.
            if not why or not isinstance(why, str):
                raise ConfigError(f"{where}: needs a `why` — an unexplained override "
                                  f"is one nobody can safely remove later")
            entry = {"action": action, "match": match, "why": why, "source": path}
            if action == "rescore":
                level = raw.get("level")
                if level not in LEVELS:
                    raise ConfigError(f"{where}: `level` must be one of "
                                      f"{', '.join(LEVELS)}, got {level!r}")
                entry["level"] = level
            entries.append(entry)
    return entries


def match_override(entries, command):
    """The first entry whose glob matches `command`, or None.

    Globs, not regexes. A glob is reviewable at a glance in a file that governs
    what a safety gate lets through; a regex in the same position is a thing
    people paste and nobody audits.
    """
    for entry in entries:
        if fnmatch.fnmatch(command, entry["match"]):
            return entry
    return None


def apply_overrides(results, entries):
    """Apply config overrides in place, recording each one in the factor trace.

    A suppressed finding still appears, with its original score. Silent
    suppression is indistinguishable from a missing rule, and the whole reason
    for `why` is that someone reading the output six months later can tell the
    difference.
    """
    if not entries:
        return results
    for r in results:
        entry = match_override(entries, r["command"])
        if not entry:
            continue
        r["override"] = {k: v for k, v in entry.items() if k != "source"}
        was = r["level"]
        if entry["action"] == "deny":
            r["score"], r["level"] = 100, "critical"
            note = f"denied by {os.path.basename(entry['source'])}: {entry['why']}"
        elif entry["action"] == "rescore":
            r["level"] = entry["level"]
            r["score"] = SCORE_FOR_LEVEL[entry["level"]]
            moved = f"re-scored {was} → {entry['level']}" if was != entry["level"] \
                else f"pinned at {entry['level']}"
            note = f"{moved} by {os.path.basename(entry['source'])}: {entry['why']}"
        else:
            note = (f"allowed by {os.path.basename(entry['source'])}: {entry['why']} "
                    f"(scored {was}, does not trip --fail-on)")
        r["factors"].append({"points": 0, "why": note, "keep": True})
        apply_overrides(r.get("carries", []), entries)
    return results


# The bottom of each band: a re-score pins the level, and the score has to agree
# with it or the two halves of the output contradict each other.
SCORE_FOR_LEVEL = {"safe": 0, "low": 15, "medium": 35, "high": 60, "critical": 85}


def gated(results):
    """Results that --fail-on considers: everything not explicitly allowed."""
    return [r for r in results
            if (r.get("override") or {}).get("action") != "allow"]


def main(argv=None):
    """CLI entry point. Returns the process exit status.

    0 when the run completed, 1 when --fail-on is reached, 64 (EX_USAGE) when
    there was nothing to analyse or the file could not be read.
    """
    p = argparse.ArgumentParser(prog="scoville", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", nargs="*", help="command(s) to analyze; '-' reads stdin")
    p.add_argument("-f", "--file", help="analyze a script file")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="text for humans, json for anything downstream")
    p.add_argument("--scale", choices=SCALES, default="bands",
                   help="how to name the levels: bands (safe..critical) or peppers "
                        "(bell pepper..carolina reaper). Text output only")
    p.add_argument("--fail-on", choices=LEVELS, help="exit 1 when any command reaches this level")
    p.add_argument("--strict", action="store_true",
                   help="treat unrecognised commands as medium risk")
    p.add_argument("--introspect", action="store_true",
                   help="resolve hidden image/container entrypoints via read-only docker inspect")
    p.add_argument("--quiet", "-q", action="store_true", help="one line per command")
    p.add_argument("--verbose", "-v", action="store_true", help="show zero-weight factors too")
    p.add_argument("--no-color", action="store_true",
                   help="never colourise (a non-tty and NO_COLOR already disable it)")
    p.add_argument("--config", metavar="PATH",
                   help="override file (default: nearest .scovillerc at or above the "
                        "analysed file's directory)")
    p.add_argument("--no-config", action="store_true",
                   help="ignore any .scovillerc that would otherwise be discovered")
    p.add_argument("--list-rules", action="store_true",
                   help="print every rule and amplifier, then exit")
    p.add_argument("--why", metavar="RULE",
                   help="print the long form for one rule or amplifier id "
                        "(as printed by --list-rules and on every finding), then exit")
    p.add_argument("--version", action="version", version=f"scoville {__version__}")
    args = p.parse_args(argv)

    if args.why:
        text = why_text(args.why)
        if text is None:
            print(f"scoville: no rule or amplifier called {args.why!r}", file=sys.stderr)
            # A near miss is the common case — an id read off a finding with a
            # typo, or half remembered. Guessing is cheaper than --list-rules.
            near = difflib.get_close_matches(args.why.strip().lstrip("+").upper(),
                                             rule_ids(), n=3, cutoff=0.5)
            if near:
                print(f"scoville: did you mean {', '.join(near)}?", file=sys.stderr)
            else:
                print("scoville: --list-rules prints every id", file=sys.stderr)
            return 64
        print(text, end="")
        return 0

    if args.list_rules:
        for r in sorted(RULES, key=lambda x: x["id"]):
            if not r["bins"]:
                continue
            bins = ", ".join(sorted(r["bins"])[:6])
            print(f"{r['id']:<18} {r['base']:>3}  {bins}: {r['why']}")
        for a in AMPS:
            bins = ", ".join(sorted(a["bins"])[:4]) if a["bins"] else "any"
            print(f"{'+' + a['id']:<18} {a['points']:>+3}  {bins}: {a['why']}")
        return 0

    source = None
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print(f"scoville: {e}", file=sys.stderr)
            return 64
        source = args.file
    elif args.command and args.command != ["-"]:
        text = "\n".join(args.command)
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        p.print_usage(sys.stderr)
        return 64

    if not text.strip():
        print("scoville: nothing to analyze", file=sys.stderr)
        return 64

    basedir = os.path.dirname(os.path.abspath(args.file)) if args.file else os.getcwd()

    # An explicit --config that does not exist is an error, not a shrug: the
    # caller asked for a policy and running without it would silently apply a
    # different one than they think.
    entries = []
    if not args.no_config:
        config_path = args.config or find_config(basedir)
        if args.config and not os.path.isfile(args.config):
            print(f"scoville: {args.config}: no such file", file=sys.stderr)
            return 64
        if config_path:
            try:
                entries = load_config(config_path)
            except ConfigError as e:
                print(f"scoville: {e}", file=sys.stderr)
                return 64

    results = apply_overrides(
        analyze(text, strict=args.strict, introspect=args.introspect, basedir=basedir),
        entries)
    summary = overall(results)

    if args.format == "json":
        json.dump({"overall": summary, "commands": public(results)}, sys.stdout, indent=2)
        print()
    elif args.quiet:
        for r in results:
            print(f"{label(r['level'], args.scale, slug=True):<15} {r['score']:>3}  "
                  f"{r['command']}")
    else:
        color = not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        out = render_text(results, source, color, args.verbose, args.scale)
        if out:
            print(out, end="")
        plural = "" if summary["commands"] == 1 else "s"
        heat = f" ({PEPPERS[summary['level']][3]})" if args.scale == "peppers" else ""
        print(f"scoville: {summary['commands']} command{plural}, worst "
              f"{paint(label(summary['level'], args.scale), summary['level'], color)}{heat} "
              f"{summary['score']}/100 · scope {summary['scope']} · {summary['reversibility']}")

    # The summary reports what the commands really score; the gate ignores the
    # ones this repo has explicitly allowed. Reporting an allowed command as
    # safe would be a lie, and failing on it would be the reason someone turns
    # --fail-on off altogether.
    gate = overall(gated(results))
    if args.fail_on and LEVELS.index(gate["level"]) >= LEVELS.index(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:  # `scoville … | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
