from pathlib import Path

p = Path("scoville/rules.py")
L = p.read_text().splitlines(keepends=True)


def sl(a, b):
    return "".join(L[a - 1 : b])


H = '"""{doc}"""\n\nfrom __future__ import annotations\n\nfrom .catalog import R\n{imp}'
CLI_IMP = (
    "from .verbs import (\n    DESTROY_VERBS,\n    DO_DB,\n    DO_DELETE,\n    DO_DROPLET,\n    DO_DROPLET_ACTION,\n"
    "    DO_K8S,\n    DO_NODE_POOL,\n    READ_VERBS,\n    RESOURCE_CLIS,\n    WRITE_VERBS,\n)\n"
)
parts = [
    ("rules_host", "HOST_RULES", "The host itself: files, privilege, shells, system state, network, packages.",
     "from .verbs import READ_ONLY\n", 55, 657),
    ("rules_platform", "PLATFORM_RULES", "Source control, containers, Kubernetes, IaC and the big cloud CLIs.", "", 658, 1226),
    ("rules_services", "SERVICE_RULES",
     "Data and the machinery under it: databases, exposure, storage, boot, keys, clusters.", "", 1227, 1716),
    ("rules_clis", "CLI_RULES", "Resource CLIs: verb-classified in the long tail, enumerated for the promoted few.",
     CLI_IMP, 1717, 2787),
]
for mod, name, doc, imp, a, b in parts:
    Path(f"scoville/{mod}.py").write_text(H.format(doc=doc, imp=imp) + f"\n{name} = [\n" + sl(a, b) + "]\n")
Path("scoville/verbs.py").write_text(
    '"""The verb vocabulary the rule table and the amplifiers are written in."""\n\n'
    "from __future__ import annotations\n\n" + sl(9, 52)
)
names = ["DESTROY_VERBS", "DO_DB", "DO_DELETE", "DO_DROPLET", "DO_DROPLET_ACTION", "DO_K8S", "DO_NODE_POOL",
         "READ_ONLY", "READ_VERBS", "RESOURCE_CLIS", "WRITE_VERBS"]
head = sl(1, 6)
head += "".join(f"from .rules_{m} import {n}\n" for m, n in
                [("clis", "CLI_RULES"), ("host", "HOST_RULES"), ("platform", "PLATFORM_RULES"), ("services", "SERVICE_RULES")])
head += "".join(f"from .verbs import {n} as {n}\n" for n in names)
body = (
    "\n# Order is precedence: the first matching rule wins, so the domains are\n"
    "# concatenated in the order the single table used to read.\n"
    "RULES = [*HOST_RULES, *PLATFORM_RULES, *SERVICE_RULES, *CLI_RULES]\n" + sl(2789, len(L))
)
p.write_text(head + body)
