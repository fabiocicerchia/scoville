"""The verb vocabulary the rule table and the amplifiers are written in."""

from __future__ import annotations

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
# doctl's own aliases, which every DO- rule and amplifier accepts. One
# fragment per command group, so an alias added here reaches all of them.
DO_DELETE = r"(delete|del|rm|d)"
DO_DROPLET = r"^compute\s+(droplet|d)\s+"
DO_DROPLET_ACTION = r"^compute\s+(droplet-action|da)\s+"
DO_DB = r"^(databases|database|db|dbs|d)\s+"
# `doctl kubernetes cluster` and its aliases (`kube clusters` is as valid as
# the long form). The delete verb is closed with `(?!-)` because
# `delete-selective` and `delete-node` are subcommands of their own, and `\b`
# alone stops at the hyphen.
DO_K8S = r"^(kubernetes|kube|k8s|k)\s+(cluster|clusters|c)\s+"
DO_NODE_POOL = r"(node-pool|node-pools|nodepool|nodepools|pool|pools|np|p)\s+"
READ_VERBS = rf"^{_LEAD}{_READ}\b"
WRITE_VERBS = (
    rf"^(?!{_LEAD}{_READ}\b){_LEAD}"
    r"(?:create|add|new|update|set|attach|enable|apply|deploy|scale|resize|restart|"
    r"import|upload|put|publish|promote|rename|label|tag)\b"
)
DESTROY_VERBS = (
    rf"^(?!{_LEAD}{_READ}\b){_LEAD}"
    r"(?:delete|destroy|remove|rm|terminate|purge|prune|wipe|revoke|disable|detach|"
    r"drop|kill|reset|teardown|down|deprovision|decommission|expire)\b"
)
