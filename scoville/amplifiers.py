"""Amplifiers and softeners: the same command asked for in a way that
makes it worse, or leaves you an out."""

from __future__ import annotations

import re

from .catalog import A



AMPS = [
    A(
        "RECURSIVE",
        "rm chmod chown chgrp shred",
        r"(^|\s)-[a-zA-Z]*[rR](\s|$|[a-zA-Z])",
        15,
        "-r/-R recurses into every subdirectory below the target",
        "directory",
    ),
    A(
        "FORCE-RM",
        "rm",
        r"(^|\s)-[a-zA-Z]*f(\s|$|[a-zA-Z])",
        8,
        "-f suppresses every prompt and error: nothing will stop it midway",
    ),
    A(
        "NO-PRESERVE-ROOT",
        "rm",
        r"--no-preserve-root",
        45,
        "--no-preserve-root disables the one guard rm has against deleting /",
        "host",
        "irreversible",
    ),
    A(
        "GLOB",
        "rm shred mv chmod chown",
        r"(^|\s|/)\*",
        12,
        "a glob expands to whatever is there right now, not to what you tested against",
    ),
    A(
        "DD-DEVICE",
        "dd",
        r"of=/dev/(sd|nvme|hd|vd|xvd|disk|mmcblk)",
        40,
        "of= points at a raw block device: this overwrites a disk, not a file",
        "host",
        "irreversible",
    ),
    A(
        "REDIR-DEVICE",
        None,
        r">\s*/dev/(sd|nvme|hd|vd|xvd|mmcblk)",
        55,
        "redirects into a block device",
        "host",
        "irreversible",
    ),
    A(
        "KILL-9",
        "kill pkill killall",
        r"(^|\s)-(9|KILL|SIGKILL)\b",
        15,
        "SIGKILL gives the process no chance to flush buffers or release locks",
    ),
    A(
        "KILL-INIT",
        "kill",
        r"(^|\s)1(\s|$)",
        40,
        "PID 1 is init: killing it panics the host",
        "host",
        "recoverable",
    ),
    A(
        "CHMOD-777",
        "chmod",
        r"(^|\s)(-[a-zA-Z]+\s+)*(0?777|a\+rwx|o\+w)",
        20,
        "world-writable: any local user or compromised process can rewrite these files",
    ),
    A(
        "CHMOD-SUID",
        "chmod",
        r"(^|\s)(-[a-zA-Z]+\s+)*([2467][0-7]{3}|[ugo]?\+s)",
        25,
        "setuid/setgid bit: the file now runs with the owner's privileges",
        "host",
    ),
    A(
        "SSH-NOVERIFY",
        "ssh scp sftp rsync",
        r"StrictHostKeyChecking=no|-o\s+UserKnownHostsFile=/dev/null",
        20,
        "host key verification disabled: a MITM is indistinguishable from the real host",
    ),
    A(
        "SSH-AGENT-FWD",
        "ssh",
        r"(^|\s)-A(\s|$)",
        15,
        "agent forwarding lets root on the remote host use your keys",
    ),
    # long forms are covered by the generic NO-TLS-VERIFY amp; this is only the
    # short flag, so the same argument is never counted twice
    A("CURL-INSECURE", "curl wget", r"(^|\s)-k(\s|$)", 20, "TLS verification disabled"),
    A(
        "PRIVILEGED",
        "docker podman nerdctl",
        r"--privileged|--cap-add[= ]?(ALL|SYS_ADMIN)",
        35,
        "--privileged drops container isolation: this is host-level access",
        "host",
    ),
    A(
        "HOST-MOUNT",
        "docker podman nerdctl",
        r"(-v|--volume|--mount[^ ]*)[= ]\s*/(:|\S*:/)",
        30,
        "bind-mounts a host path into the container: container writes are host writes",
        "host",
    ),
    A(
        "HOST-NS",
        "docker podman nerdctl",
        r"--(pid|net|network|ipc|userns)[= ](host)",
        25,
        "shares a host namespace with the container",
        "host",
    ),
    A(
        "CTR-ROOT",
        "docker podman nerdctl kubectl",
        r"(^|\s)(-u|--user)[= ]\s*(0|root)\b",
        8,
        "runs as root inside the container",
    ),
    A(
        "K8S-ALL",
        "kubectl oc",
        r"^(delete|drain|scale|patch|label|annotate|cordon|taint|rollout|replace)\b"
        r".*(--all\b|--all-namespaces\b|(\s)-A(\s|$))",
        25,
        "applies to every matching object, across every namespace it can see",
        "cluster",
    ),
    A(
        "K8S-FORCE",
        "kubectl oc",
        r"--grace-period[= ]0\b",
        12,
        "grace period zero: the API forgets the object while the kubelet may still be running it",
    ),
    A(
        "K8S-REMOTE-MANIFEST",
        "kubectl oc",
        r"-f\s+https?://",
        25,
        "applies a manifest fetched at run time: content can change between plan and apply",
    ),
    A(
        "GIT-DEFAULT-BRANCH",
        "git",
        r"^push\b.*(--force(?!-with-lease)|(\s|^)-f\b).*\b(main|master|trunk|release)\b",
        25,
        "force-pushing the default branch: everyone else's clone breaks on the next pull",
        "network",
        "irreversible",
    ),
    A(
        "AUTO-APPROVE",
        "terraform tofu",
        r"-auto-approve",
        15,
        "-auto-approve skips the plan review: nobody sees the diff before it happens",
    ),
    A(
        "TF-TARGET-ALL",
        "terraform tofu",
        r"-refresh=false",
        10,
        "-refresh=false plans against possibly stale state",
    ),
    A(
        "AWS-SKIP-SNAPSHOT",
        "aws",
        r"--skip-final-snapshot",
        15,
        "no final snapshot: the data is unrecoverable the moment this returns",
        None,
        "irreversible",
    ),
    A("AWS-RECURSIVE", "aws", r"--recursive\b", 15, "applies to every key under the prefix"),
    A(
        "UMOUNT-SYSTEM",
        "umount",
        r"(^|\s)/(\s|$)|(^|\s)/(usr|var|etc|boot|home|srv|opt|lib|root)(/\S*)?(\s|$)",
        30,
        "a filesystem the running system reads from: everything on it fails until it is back",
        "host",
    ),
    A(
        "REMOUNT-ROOT",
        "mount",
        r"remount.*(^|\s)/(\s|$)",
        25,
        "remounting the root filesystem: this is host-wide, not scoped to one service",
        "host",
    ),
    A(
        "UMOUNT-ALL",
        "umount",
        r"(^|\s)-[a-zA-Z]*a(\s|$)|--all\b",
        45,
        "-a unmounts everything in the mount table, including the filesystems the running system is reading from",
        "host",
    ),
    A(
        "UMOUNT-LAZY",
        "umount",
        r"(^|\s)-[a-zA-Z]*l(\s|$)|--lazy\b",
        15,
        "lazy detach: the command returns success now and the filesystem goes away later, "
        "when you are no longer watching",
    ),
    A(
        "UMOUNT-FORCE",
        "umount",
        r"(^|\s)-[a-zA-Z]*f(\s|$)|--force\b",
        10,
        "forces the detach with I/O still in flight",
    ),
    A(
        "POWER-FORCE",
        "reboot shutdown halt poweroff systemctl",
        r"(^|\s)-f(\s|$)|--force\b",
        15,
        "skips the clean shutdown: filesystems are not unmounted and services get no chance to flush",
        "host",
    ),
    A(
        "POWER-SCHEDULED",
        "shutdown",
        r"(^|\s)\+[0-9]+(\s|$)|(^|\s)[0-9]{1,2}:[0-9]{2}(\s|$)",
        -15,
        "scheduled rather than immediate: it is announced, and `shutdown -c` still cancels it",
    ),
    A(
        "SWAP-ALL",
        "swapoff",
        r"(^|\s)-a(\s|$)|--all\b",
        10,
        "-a disables every swap device at once: everything currently swapped out has to fit "
        "in RAM, or the OOM killer picks what dies",
        "host",
    ),
    A(
        "USERDEL-R",
        "userdel deluser",
        r"(^|\s)(-r|--remove(-home)?)(\s|$)",
        15,
        "`-r` deletes the account's home directory and mail spool along with the account",
        None,
        "irreversible",
    ),
    A(
        "PKG-CRITICAL",
        "apt apt-get aptitude yum dnf apk zypper pacman dpkg rpm nix-env emerge",
        r"\b(linux-image[\w.-]*|linux-firmware|kernel[\w.-]*|glibc|libc6|systemd|init|coreutils|"
        r"bash|dash|openssh-server|sudo|grub[\w.-]*|util-linux)\b",
        30,
        "one of these packages is what makes the host boot, log in, or run shell scripts at all",
        "host",
        "recoverable",
    ),
    A(
        "PKG-UNTRUSTED",
        "pip pip3 pipx npm yarn pnpm gem cargo go composer",
        r"(git\+|https?://|git@|file:|\.\./|\.tar\.gz)",
        20,
        "installs from outside the registry: no version resolution you can audit, and the "
        "source can change under the same reference",
    ),
    A(
        "PKG-SYSTEM-PY",
        "pip pip3",
        r"--break-system-packages|--target[= ]/usr|--prefix[= ]/usr",
        15,
        "writes into the system interpreter, which the OS's own tooling depends on",
        "host",
    ),
    A(
        "RSYNC-DELETE",
        "rsync",
        r"--delete(-before|-during|-after|-excluded)?\b",
        35,
        "`--delete` removes files at the destination that are not at the source: a wrong source "
        "path empties the destination",
        "directory",
        "irreversible",
    ),
    A(
        "TAR-OVERWRITE",
        "tar unzip",
        r"--overwrite|(^|\s)-o(\s|$)|-C\s+/(\s|$)",
        25,
        "extracts over whatever is already there, from paths the archive chooses",
    ),
    A(
        "REDIR-SYSTEM",
        None,
        r"(?<!>)>\s*/(etc|boot|usr|lib|var/log|var/lib)/",
        30,
        "truncates and replaces a system file — `>` does not append",
        "host",
        "irreversible",
    ),
    A(
        "SYSRQ",
        None,
        r">\s*/proc/sysrq-trigger",
        45,
        "sysrq acts at kernel level: no unmount, no flush, no service shutdown",
        "host",
    ),
    A(
        "DD-MEM",
        "dd",
        r"of=/dev/(mem|kmem|port|random|urandom)",
        40,
        "writing to kernel memory devices corrupts a running system",
        "host",
        "irreversible",
    ),
    # --- generic arguments: these mean the same thing on any binary ----------
    A(
        "FORCE",
        None,
        r"--force(?!-with-lease)(\b|-\w+)|--no-confirm\b|--no-prompt\b|--overwrite-existing\b",
        12,
        "`--force` exists to get past the check that would otherwise have stopped this",
    ),
    A(
        "ASSUME-YES",
        None,
        r"--(yes|assume-?yes|noconfirm|no-confirm|non-interactive|no-interaction|force-yes|"
        r"no-input|approve|batch|accept-all|skip-confirmation)\b|(^|\s)-[a-zA-Z]*y(\s|$)",
        8,
        "auto-confirms every prompt, including the ones you would have stopped at — the last "
        "human checkpoint before this runs",
    ),
    # `--cascade=false` is the opposite of a purge, so the negated forms are
    # excluded rather than counted as the thorough variant they name.
    A(
        "PURGE-FLAG",
        None,
        r"--(purge|prune|wipe|hard|cascade|destroy-data|delete-data|"
        r"remove-data|permanent)\b(?![= ]?(false|no|off|none)\b)",
        12,
        "asks for the thorough variant: state that would otherwise survive goes too",
    ),
    A(
        "SECRET-IN-ARGV",
        None,
        r"--(password|passwd|token|api-key|apikey|secret|access-key|private-key)[= ]\S|"
        r"(^|\s)(PGPASSWORD|MYSQL_PWD|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN)=",
        25,
        "a credential on the command line is visible to every user on the host via `ps` and "
        "lands in shell history — pass it by env file, stdin or a credential helper",
    ),
    A(
        "NO-TLS-VERIFY",
        None,
        r"--(insecure|no-verify|no-check-certificate|skip-tls-verify|tls-skip-verify|"
        r"insecure-skip-tls-verify|trust-all|no-verify-ssl|disable-ssl-validation)\b|"
        r"--validate=false",
        20,
        "certificate verification disabled: a machine-in-the-middle is indistinguishable from the real endpoint",
    ),
    A(
        "NO-SIGNATURE-CHECK",
        None,
        r"--(allow-unauthenticated|nogpgcheck|no-gpg-check|allow-untrusted|trusted-host|"
        r"insecure-registry|skip-verify|force-yes)\b",
        25,
        "package or image signature verification disabled: the signature is the only thing "
        "separating the real artifact from a substituted one",
    ),
    A(
        "OPEN-TO-WORLD",
        None,
        r"0\.0\.0\.0/0|::/0",
        35,
        "reachable from the entire internet, not from a network you control",
        "network",
    ),
    A(
        "REMOTE-EXEC-SUBST",
        "sh bash zsh dash ksh python python3 perl ruby node eval source .",
        r"[<$]\(\s*[\w./-]*\b(curl|wget|fetch|aria2c|httpie)\b",
        78,
        "runs a script fetched inside a substitution: same as piping a download into a shell, "
        "and the fetch is not visible as its own step",
        "host",
        "irreversible",
        raw=True,
    ),
    A(
        "EVAL-DYNAMIC",
        "eval",
        r"\$[\w{(]|`",
        15,
        "the evaluated text is built from a variable or a substitution, so its contents are "
        "decided at run time and nothing here can show them",
        "host",
        "irreversible",
    ),
    A(
        "PROD-HINT",
        None,
        r"(^|[\s\"'=/:_.,-])(prod|production|live)([\s\"'/:_.,-]|$)",
        15,
        "the target names a production environment",
    ),
    A(
        "SUDO-EDIT",
        "tee dd cp mv sed perl awk",
        r"/etc/(sudoers|passwd|shadow|ssh/)",
        30,
        "writes into system authentication/authorisation config",
        "host",
        "recoverable",
    ),
    A(
        "SSHD-STOP",
        "systemctl service",
        r"^(stop|disable|mask|kill|restart)\b.*\b(ssh|sshd)\b",
        20,
        "this is the daemon your session depends on",
        "host",
    ),
    A(
        "SSHD-KILL",
        "pkill killall",
        r"\b(ssh|sshd)\b",
        20,
        "this is the daemon your session depends on",
        "host",
    ),
    A(
        "HISTFILE",
        None,
        r"unset\s+HISTFILE|HISTFILE=/dev/null|set \+o history",
        30,
        "disables shell history: the audit trail stops here",
        "host",
        "irreversible",
    ),
    # --- flags that only mean something on one CLI ---------------------------
    A(
        "VAULT-LEASE-PREFIX",
        "vault",
        r"^lease\s+revoke\b(?=.*(^|\s)-prefix\b)",
        15,
        "`-prefix` revokes every lease under the path rather than the one named",
        "account",
    ),
    A(
        "VAULT-LEASE-FORCE",
        "vault",
        r"^lease\s+revoke\b(?=.*(^|\s)-force\b)",
        20,
        "vault's `-force` drops the lease without revoking the credential behind it: the database "
        "user or cloud key stays live with nothing left tracking its expiry",
        "account",
        "irreversible",
    ),
    A(
        "VELERO-OVERWRITE",
        "velero",
        r"--existing-resource-policy[= ]update",
        20,
        "restores over objects that already exist: live resources are overwritten with the state in the backup",
        "cluster",
        "irreversible",
    ),
    A(
        "ARGOCD-PRUNE",
        "argocd",
        r"--prune\b",
        25,
        "`--prune` deletes cluster resources that are no longer in git — anything created outside "
        "Argo CD goes with them",
        "cluster",
        "irreversible",
    ),
    A(
        "ARGOCD-REPLACE",
        "argocd",
        r"--(replace|force)\b",
        15,
        "argocd's `--replace`/`--force` delete and recreate each resource instead of patching it: "
        "pods restart, and anything holding local state comes back empty",
        "cluster",
    ),
    A(
        "FLY-IMMEDIATE",
        "flyctl fly",
        r"--strategy[= ]immediate",
        25,
        "the immediate strategy stops every machine before starting the new ones — a full outage, not a rolling deploy",
        "account",
    ),
    A(
        "GH-ADMIN",
        "gh",
        r"--admin\b",
        22,
        "`--admin` merges past branch protection: required reviews and status checks are bypassed",
        "account",
    ),
    A(
        "GH-CLEANUP-TAG",
        "gh",
        r"--cleanup-tag\b",
        12,
        "deletes the git tag as well as the release, so the commit it pointed at is no longer named",
    ),
]

# Softeners: the same command, asked for in a way that leaves you an out. A
# gate is only usable if the careful form of a command scores below the
# careless one.
SOFTENERS = [
    A(
        "INTERACTIVE",
        "rm cp mv ln",
        r"(^|\s)-[a-zA-Z]*i(\s|$)|--interactive\b",
        -12,
        "prompts before each delete or overwrite: you still get to say no",
    ),
    A(
        "BACKUP",
        "sed perl cp mv install",
        r"(^|\s)-i\.[A-Za-z0-9]|(^|\s)-b(\s|$)|--backup\b|--suffix[= ]",
        -12,
        "keeps a backup of what it replaces",
    ),
    A(
        "PRESERVE-ROOT",
        "rm",
        r"--preserve-root",
        -10,
        "explicitly asks for the guard that stops this at `/`",
    ),
    A(
        "LIMIT",
        "ansible ansible-playbook",
        r"--limit(\s|=)",
        -15,
        "`--limit` narrows the run to part of the inventory rather than the whole fleet",
    ),
    A(
        "FORCE-WITH-LEASE",
        "git",
        r"--force-with-lease",
        -5,
        "refuses to overwrite the remote if it moved since you last fetched",
    ),
    A(
        "ARGOCD-NO-CASCADE",
        "argocd",
        r"--cascade[= ]?false",
        -20,
        "`--cascade=false` removes the Argo CD record only: the Kubernetes resources it manages stay running",
    ),
    A(
        "FLY-STAGE",
        "flyctl fly",
        r"--stage\b",
        -15,
        "`--stage` stores the secret without restarting the app; the next deploy applies it",
    ),
    A(
        "GH-AUTO-MERGE",
        "gh",
        r"--auto\b",
        -12,
        "`--auto` queues the merge behind the required checks instead of merging now",
    ),
]

DAMPENERS = [
    (
        re.compile(r"--dry-run(?![= ]?(none|server))|--dryrun|--what-if|--no-act|(^|\s)--check(\s|$)"),
        "--dry-run: reports what it would do and changes nothing",
    ),
    (re.compile(r"(^|\s)-n(\s|$)"), None),  # only honoured for the bins below
    # vault prints the equivalent curl invocation and makes no request at all.
    (
        re.compile(r"-output-curl-string\b"),
        "-output-curl-string: prints the request as curl and sends nothing",
    ),
]
DRY_RUN_N_BINS = {
    "rsync",
    "mv",
    "cp",
    "ln",
    "make",
    "ansible-playbook",
    "fsck",
    "e2fsck",
    "patch",
    "git",
}

# Directories whose loss costs a rebuild, not a restore.
REGENERABLE = re.compile(
    r"(^|/)(node_modules|\.venv|venv|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|"
    r"target|dist|build|out|\.next|\.nuxt|coverage|\.terraform|vendor|\.cache|tmp)/?$"
)

SYSTEM_DIRS = {
    "/etc": "system configuration",
    "/var": "logs, spools, databases and container state",
    "/usr": "the entire userland",
    "/bin": "core binaries",
    "/sbin": "system binaries",
    "/lib": "shared libraries — nothing dynamically linked will start after this",
    "/lib64": "shared libraries",
    "/boot": "kernel and bootloader: the host will not boot",
    "/opt": "third-party software",
    "/srv": "served data",
    "/root": "the root user's home",
    "/home": "every user's home directory",
    "/dev": "device nodes",
    "/proc": "kernel interface",
    "/sys": "kernel interface",
    "/data": "application data",
    "/mnt": "mount points — may be a live filesystem",
    "/media": "mounted removable media",
}
# Losing something *under* /etc breaks the host; losing something under /srv
# loses payload. Both are bad, they are not equally bad.
CORE_DIRS = {"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys"}

# Commands whose whole job is to act on a device node: pointing them at
# /dev/sdb is not the surprise, it is the usage.
DEVICE_TARGET_EXPECTED = {
    "mount",
    "umount",
    "fsck",
    "e2fsck",
    "xfs_repair",
    "resize2fs",
    "mkfs",
    "wipefs",
    "blkdiscard",
    "badblocks",
    "cryptsetup",
    "mdadm",
    "zpool",
    "hdparm",
    "nvme",
}

PATH_SENSITIVE = {
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "wipe",
    "mv",
    "cp",
    "rsync",
    "chmod",
    "chown",
    "chgrp",
    "truncate",
    "dd",
    "tar",
    "install",
    "ln",
    "tee",
    "find",
    "chattr",
    "mkfs",
    "wipefs",
}

