"""Reading a kubectl command: verbs, resources, context, and what RBAC says."""

from __future__ import annotations

import shutil
import subprocess

# ------------------------------------------------------ kubernetes RBAC ---
#
# `kubectl delete ns prod` scores the same whether the current context is
# cluster-admin on production or a read-only token that will be refused. The
# second case is noise, and noise is what makes people stop reading the output.
# scoville knows the command; it does not know the authorisation.
#
# `kubectl auth can-i` is a SelfSubjectAccessReview — a read that asks the API
# server "would you allow this?" and changes nothing. That keeps the "nothing
# is ever executed to score it" contract intact, but it is still a call to a
# live cluster, so it lives behind --introspect with everything else that
# leaves the machine.
#
# THE DIRECTION OF FAILURE IS THE WHOLE DESIGN. A dampener that fires on a bad
# `can-i` result under-reports risk, which is the one kind of wrong answer this
# tool must not give. So: nothing is dampened unless a refusal is POSITIVELY
# established. A timeout, a missing kubeconfig, an unreachable cluster and an
# answer this code cannot parse all mean "no opinion", and no opinion scores
# exactly as it does today.

KUBE_BINS = ("kubectl", "oc", "k")

# Timeout for one `can-i`. Bounded because this runs once per kubectl line, and
# a script full of them must not turn a score into a network wait.
KUBE_TIMEOUT_DEFAULT = 3.0

# Verbs whose kubectl spelling differs from the RBAC verb. Everything else is
# passed through, because the RBAC verb list is open — a CRD can define its own.
KUBE_VERB_ALIASES = {
    "apply": "patch",
    "edit": "patch",
    "set": "patch",
    "annotate": "patch",
    "label": "patch",
    "scale": "patch",
    "rollout": "patch",
    "autoscale": "patch",
    "run": "create",
    "expose": "create",
    "cordon": "patch",
    "drain": "patch",
    "uncordon": "patch",
    "taint": "patch",
    "exec": "create",
    "port-forward": "create",
    "cp": "create",
    "attach": "create",
    "describe": "get",
    "logs": "get",
    "top": "get",
    "wait": "get",
}

# kubectl's own short forms for the resources most worth knowing about. Not a
# complete table and not meant to be: an unrecognised resource is passed to
# `can-i` verbatim, which is the component that actually knows the API surface.
KUBE_RESOURCE_ALIASES = {
    "ns": "namespaces",
    "po": "pods",
    "deploy": "deployments",
    "svc": "services",
    "cm": "configmaps",
    "sts": "statefulsets",
    "ds": "daemonsets",
    "rs": "replicasets",
    "pv": "persistentvolumes",
    "pvc": "persistentvolumeclaims",
    "sa": "serviceaccounts",
    "no": "nodes",
    "ing": "ingresses",
    "crd": "customresourcedefinitions",
    "secret": "secrets",
    "job": "jobs",
    "cj": "cronjobs",
}

# Flags that take a separate value, so the token after them is not a verb or a
# resource. `-n prod` is the one that matters; the rest are here so a long
# command line does not shift the parse by one.
KUBE_VALUE_FLAGS = {
    "-n",
    "--namespace",
    "--context",
    "--cluster",
    "--user",
    "--kubeconfig",
    "-f",
    "--filename",
    "-l",
    "--selector",
    "-o",
    "--output",
    "--server",
    "--token",
    "--as",
    "--as-group",
    "-c",
    "--container",
    "--field-selector",
}


def _kubectl(binary: str, args: list[str], timeout: float) -> str | None:
    """Run one read-only kubectl subcommand and return stdout, or None.

    Same collapse as _docker: a missing binary, a timeout, a non-zero exit and
    an OS error are all "no answer" to the caller, and no answer must never
    become a dampener.
    """
    exe = shutil.which(binary)
    if not exe:
        return None
    try:
        # Read-only `kubectl auth can-i` / `config current-context`, fixed argv.
        r = subprocess.run(  # noqa: S603
            [exe, *args], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    # `can-i` exits 1 for "no" and prints "no", so stdout is read on both exit
    # codes and the caller reads the word, not the status.
    return (r.stdout or "").strip()


def kube_target(args: list[str]) -> tuple[str | None, str | None, str | None]:
    """(verb, resource, namespace) for a kubectl command line, or (None, ...).

    Positional-only: the first two non-flag tokens. Enough for the commands
    worth scoring, and it declines rather than guesses on anything else.
    """
    verb: str | None = None
    resource: str | None = None
    namespace: str | None = None
    positional: list[str] = []
    skip = False
    for i, a in enumerate(args):
        if skip:
            if namespace is None and args[i - 1] in ("-n", "--namespace"):
                namespace = a
            skip = False
            continue
        if a == "--":
            break
        if a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            if k in ("-n", "--namespace"):
                namespace = v
            continue
        if a in KUBE_VALUE_FLAGS:
            skip = True
            continue
        if a.startswith("-"):
            continue
        positional.append(a)
    if positional:
        verb = positional[0]
    if len(positional) > 1:
        # `delete pod/foo` and `delete pods foo` both mean pods.
        resource = positional[1].split("/", 1)[0]
    return verb, resource, namespace


def kube_context(binary: str, timeout: float) -> str | None:
    """The context name `can-i` will be answered by, or None.

    A local kubeconfig read, not a cluster call — but if there is no context
    there is nothing to ask, which is the cheapest way to skip the network.
    """
    out = _kubectl(binary, ["config", "current-context"], timeout)
    return out or None


def kube_can_i(binary: str, verb: str, resource: str, namespace: str | None, timeout: float) -> bool | None:
    """True / False / None for "may this context do that".

    None is not a third state to act on — it is the absence of an answer, and
    every caller treats it as "score exactly as before".
    """
    cmd = ["auth", "can-i", verb, resource]
    if namespace:
        cmd += ["-n", namespace]
    out = _kubectl(binary, cmd, timeout)
    if out is None:
        return None
    first = out.splitlines()[0].strip().lower() if out else ""
    if first.startswith("yes"):
        return True
    if first.startswith("no"):
        return False
    return None
