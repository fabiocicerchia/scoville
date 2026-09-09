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

from .amplifiers import AMPS as AMPS
from .amplifiers import CORE_DIRS as CORE_DIRS
from .amplifiers import DAMPENERS as DAMPENERS
from .amplifiers import DEVICE_TARGET_EXPECTED as DEVICE_TARGET_EXPECTED
from .amplifiers import DRY_RUN_N_BINS as DRY_RUN_N_BINS
from .amplifiers import PATH_SENSITIVE as PATH_SENSITIVE
from .amplifiers import REGENERABLE as REGENERABLE
from .amplifiers import SOFTENERS as SOFTENERS
from .amplifiers import SYSTEM_DIRS as SYSTEM_DIRS
from .carriers import CONTEXTS as CONTEXTS
from .carriers import DOCKER_VALUE_FLAGS as DOCKER_VALUE_FLAGS
from .carriers import SSH_VALUE_FLAGS as SSH_VALUE_FLAGS
from .carriers import carried_command as carried_command
from .catalog import A as A
from .catalog import R as R
from .cli import main as main
from .definitions import ALIAS_DEF as ALIAS_DEF
from .definitions import CARRIER_ALIAS as CARRIER_ALIAS
from .definitions import CARRIER_FUNCTION as CARRIER_FUNCTION
from .definitions import ENTRYPOINT as ENTRYPOINT
from .definitions import FUNC_DEF as FUNC_DEF
from .definitions import FUNC_HEAD as FUNC_HEAD
from .definitions import FUNC_HEAD_KW as FUNC_HEAD_KW
from .definitions import PAYLOAD as PAYLOAD
from .definitions import RBAC as RBAC
from .definitions import UNKNOWN_DESTROY as UNKNOWN_DESTROY
from .definitions import VAR_PATH as VAR_PATH
from .definitions import WRAPPER as WRAPPER
from .definitions import collect_definitions as collect_definitions
from .definitions import definition_at as definition_at
from .incidents import INCIDENTS as INCIDENTS
from .introspection import introspect_target as introspect_target
from .kube import KUBE_BINS as KUBE_BINS
from .kube import KUBE_RESOURCE_ALIASES as KUBE_RESOURCE_ALIASES
from .kube import KUBE_TIMEOUT_DEFAULT as KUBE_TIMEOUT_DEFAULT
from .kube import KUBE_VALUE_FLAGS as KUBE_VALUE_FLAGS
from .kube import KUBE_VERB_ALIASES as KUBE_VERB_ALIASES
from .kube import kube_can_i as kube_can_i
from .kube import kube_context as kube_context
from .kube import kube_target as kube_target
from .output import COLORS as COLORS
from .output import MARKS as MARKS
from .output import PEPPERS as PEPPERS
from .output import SCALES as SCALES
from .output import label as label
from .output import overall as overall
from .output import paint as paint
from .output import public as public
from .output import render_text as render_text
from .overrides import CONFIG_NAMES as CONFIG_NAMES
from .overrides import OVERRIDE_ACTIONS as OVERRIDE_ACTIONS
from .overrides import SCORE_FOR_LEVEL as SCORE_FOR_LEVEL
from .overrides import ConfigError as ConfigError
from .overrides import apply_overrides as apply_overrides
from .overrides import find_config as find_config
from .overrides import gated as gated
from .overrides import load_config as load_config
from .overrides import match_override as match_override
from .parsing import ENV_ASSIGN as ENV_ASSIGN
from .parsing import OPS as OPS
from .parsing import SUBSHELL as SUBSHELL
from .parsing import WRAPPER_VALUE_FLAGS as WRAPPER_VALUE_FLAGS
from .parsing import WRAPPERS as WRAPPERS
from .parsing import split_commands as split_commands
from .parsing import strip_prefix as strip_prefix
from .parsing import subshell_commands as subshell_commands
from .parsing import tokenize as tokenize
from .rules import DESTROY_VERBS as DESTROY_VERBS
from .rules import FETCHERS as FETCHERS
from .rules import INTERPRETERS as INTERPRETERS
from .rules import READ_ONLY as READ_ONLY
from .rules import READ_VERBS as READ_VERBS
from .rules import RESOURCE_CLIS as RESOURCE_CLIS
from .rules import RULES as RULES
from .rules import SHELLS as SHELLS
from .rules import WRITE_VERBS as WRITE_VERBS
from .scales import BANDS as BANDS
from .scales import LEVELS as LEVELS
from .scales import REVERT as REVERT
from .scales import SCOPES as SCOPES
from .scales import TOP_BAND_BASE as TOP_BAND_BASE
from .scales import Definition as Definition
from .scales import Entry as Entry
from .scales import Factor as Factor
from .scales import FactorTuple as FactorTuple
from .scales import Override as Override
from .scales import Result as Result
from .scales import band as band
from .scales import harder as harder
from .scales import widest as widest
from .scoring import FACTOR_RULE_INDEX as FACTOR_RULE_INDEX
from .scoring import FORKBOMB as FORKBOMB
from .scoring import MAX_CARRIER_DEPTH as MAX_CARRIER_DEPTH
from .scoring import MAX_SCRIPT_BYTES as MAX_SCRIPT_BYTES
from .scoring import RUNNERS as RUNNERS
from .scoring import SCRIPT_EXT as SCRIPT_EXT
from .scoring import WRAPPER_NOTE as WRAPPER_NOTE
from .scoring import analyze as analyze
from .scoring import generic_clis as generic_clis
from .scoring import hidden_payload as hidden_payload
from .scoring import kube_rbac_factors as kube_rbac_factors
from .scoring import path_factors as path_factors
from .scoring import pick_rule as pick_rule
from .scoring import resolve_payload as resolve_payload
from .scoring import score_command as score_command
from .scoring import specific_clis as specific_clis
from .why import entry_by_id as entry_by_id
from .why import rule_ids as rule_ids
from .why import why_text as why_text

__all__ = [
    "ALIAS_DEF",
    "AMPS",
    "BANDS",
    "CARRIER_ALIAS",
    "CARRIER_FUNCTION",
    "COLORS",
    "CONFIG_NAMES",
    "CONTEXTS",
    "CORE_DIRS",
    "DAMPENERS",
    "DESTROY_VERBS",
    "DEVICE_TARGET_EXPECTED",
    "DOCKER_VALUE_FLAGS",
    "DRY_RUN_N_BINS",
    "ENTRYPOINT",
    "ENV_ASSIGN",
    "FACTOR_RULE_INDEX",
    "FETCHERS",
    "FORKBOMB",
    "FUNC_DEF",
    "FUNC_HEAD",
    "FUNC_HEAD_KW",
    "INCIDENTS",
    "INTERPRETERS",
    "KUBE_BINS",
    "KUBE_RESOURCE_ALIASES",
    "KUBE_TIMEOUT_DEFAULT",
    "KUBE_VALUE_FLAGS",
    "KUBE_VERB_ALIASES",
    "LEVELS",
    "MARKS",
    "MAX_CARRIER_DEPTH",
    "MAX_SCRIPT_BYTES",
    "OPS",
    "OVERRIDE_ACTIONS",
    "PATH_SENSITIVE",
    "PAYLOAD",
    "PEPPERS",
    "RBAC",
    "READ_ONLY",
    "READ_VERBS",
    "REGENERABLE",
    "RESOURCE_CLIS",
    "REVERT",
    "RULES",
    "RUNNERS",
    "SCALES",
    "SCOPES",
    "SCORE_FOR_LEVEL",
    "SCRIPT_EXT",
    "SHELLS",
    "SOFTENERS",
    "SSH_VALUE_FLAGS",
    "SUBSHELL",
    "SYSTEM_DIRS",
    "TOP_BAND_BASE",
    "UNKNOWN_DESTROY",
    "VAR_PATH",
    "WRAPPER",
    "WRAPPERS",
    "WRAPPER_NOTE",
    "WRAPPER_VALUE_FLAGS",
    "WRITE_VERBS",
    "A",
    "ConfigError",
    "Definition",
    "Entry",
    "Factor",
    "FactorTuple",
    "Override",
    "R",
    "Result",
    "analyze",
    "apply_overrides",
    "band",
    "carried_command",
    "collect_definitions",
    "definition_at",
    "entry_by_id",
    "find_config",
    "gated",
    "generic_clis",
    "harder",
    "hidden_payload",
    "introspect_target",
    "kube_can_i",
    "kube_context",
    "kube_rbac_factors",
    "kube_target",
    "label",
    "load_config",
    "main",
    "match_override",
    "overall",
    "paint",
    "path_factors",
    "pick_rule",
    "public",
    "render_text",
    "resolve_payload",
    "rule_ids",
    "score_command",
    "specific_clis",
    "split_commands",
    "strip_prefix",
    "subshell_commands",
    "tokenize",
    "why_text",
    "widest",
]
