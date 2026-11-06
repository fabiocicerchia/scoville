"""The rule table: what each command is, and how much it costs to be wrong.

Read top to bottom as a catalogue. Every entry is one R(...) call, kept in
rules_host, rules_platform, rules_services and rules_clis by domain."""

from __future__ import annotations

from .rules_clis import CLI_RULES
from .rules_host import HOST_RULES
from .rules_platform import PLATFORM_RULES
from .rules_services import SERVICE_RULES
from .verbs import DESTROY_VERBS as DESTROY_VERBS
from .verbs import DO_DB as DO_DB
from .verbs import DO_DELETE as DO_DELETE
from .verbs import DO_DROPLET as DO_DROPLET
from .verbs import DO_DROPLET_ACTION as DO_DROPLET_ACTION
from .verbs import DO_K8S as DO_K8S
from .verbs import DO_NODE_POOL as DO_NODE_POOL
from .verbs import READ_ONLY as READ_ONLY
from .verbs import READ_VERBS as READ_VERBS
from .verbs import RESOURCE_CLIS as RESOURCE_CLIS
from .verbs import WRITE_VERBS as WRITE_VERBS

# Order is precedence: the first matching rule wins, so the domains are
# concatenated in the order the single table used to read.
RULES = [*HOST_RULES, *PLATFORM_RULES, *SERVICE_RULES, *CLI_RULES]

SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
# Anything that turns bytes on stdin into a script: fetching and decoding are
# the same move when the next stage is an interpreter.
FETCHERS = {
    "curl",
    "wget",
    "fetch",
    "aria2c",
    "http",
    "httpie",
    "base64",
    "xxd",
    "openssl",
    "gunzip",
    "zcat",
    "gzip",
    "bunzip2",
    "xz",
}
INTERPRETERS = SHELLS | {"python", "python3", "perl", "ruby", "node", "php"}
