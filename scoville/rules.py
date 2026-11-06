"""The rule table: what each command is, and how much it costs to be wrong.

Read top to bottom as a catalogue. Every entry is one R(...) call, kept in
rules_host, rules_platform, rules_services and rules_clis by domain."""

from __future__ import annotations

from .rules_clis import CLI_RULES
from .rules_host import HOST_RULES
from .rules_platform import PLATFORM_RULES
from .rules_services import SERVICE_RULES
from .verbs import (
    DESTROY_VERBS,
    DO_DB,
    DO_DELETE,
    DO_DROPLET,
    DO_DROPLET_ACTION,
    DO_K8S,
    DO_NODE_POOL,
    READ_ONLY,
    READ_VERBS,
    RESOURCE_CLIS,
    WRITE_VERBS,
)

# The verb sets moved to verbs.py; listed here so existing `from .rules import ...` keeps working.
__all__ = [
    "DESTROY_VERBS",
    "DO_DB",
    "DO_DELETE",
    "DO_DROPLET",
    "DO_DROPLET_ACTION",
    "DO_K8S",
    "DO_NODE_POOL",
    "FETCHERS",
    "INTERPRETERS",
    "READ_ONLY",
    "READ_VERBS",
    "RESOURCE_CLIS",
    "RULES",
    "SHELLS",
    "WRITE_VERBS",
]

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
