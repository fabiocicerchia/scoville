# Specifications of scoville

What this code does, one atomic Gherkin scenario per behaviour, read from the code by code-atlas.
Tags: `@verified` a test asserts it · `@inferred` read from the code only · `@gap` an entry point no test covers · `@human` written or amended by a person, never rewritten.

## Command reading
How scoville takes in shell text and works out which commands it would actually run.

- **Command splitting**: [Splitting a command line into the commands it runs](command-reading/command-splitting/splitting-command-lines.feature) (6)
- **Functions and aliases**: [Resolving functions and aliases defined in the input](command-reading/functions-and-aliases/local-functions-and-aliases.feature) (5), [Scoring calls to functions and aliases defined in the script](command-reading/functions-and-aliases/script-defined-functions-and-aliases.feature) (6)
- **Input sources**: [Choosing what to score](command-reading/input-sources/input-sources.feature) (2)
- **Wrapped commands**: [Looking through sudo, env and other wrappers](command-reading/wrapped-commands/looking-through-wrappers.feature) (5), [Scoring the command a wrapper carries](command-reading/wrapped-commands/wrapped-command-payloads.feature) (8), [Scoring what a wrapper actually runs](command-reading/wrapped-commands/wrapped-commands.feature) (6)

## Developer tooling
Building, packaging and demonstrating scoville.

- **Container image**: [Running scoville from its container image](developer-tooling/container-image/container-image.feature) (2)

## Explanations
Helping users understand why a rule exists and what it covers.

- **Rule explanations**: [Explaining the incident a rule prevents](explanations/rule-explanations/incident-notes.feature) (3), [Explaining why a rule scores what it does](explanations/rule-explanations/rule-explanations.feature) (6), [Looking up why a rule fired](explanations/rule-explanations/rule-lookup.feature) (3)

## Gating and automation
Using scoville as a guard in hooks and CI pipelines.

- **Exit codes**: [Refusing runs that cannot be scored](gating/exit-codes/exit-status-and-refusals.feature) (4)
- **Fail thresholds**: [Gating a pipeline or hook on a command's risk](gating/fail-thresholds/gating-on-risk.feature) (3)
- **Library API**: [Scoring commands from Python](gating/library-api/library-api.feature) (1)
- **Version reporting**: [Reporting the installed version](gating/version-reporting/version-reporting.feature) (1)

## Live context
Optionally asking the local environment, read-only, what a command would really do.

- **Container introspection**: [Resolving what a container image actually runs](live-context/container-introspection/container-entrypoint-introspection.feature) (5)
- **Kubernetes context**: [Checking a kubectl command against the cluster's own permissions](live-context/kubernetes-context/kubernetes-rbac-check.feature) (5), [Weighing a kubectl command against what the current context may do](live-context/kubernetes-context/kubernetes-rbac-context.feature) (7)

## Repository policy
Letting a repository re-rate rules for its own context.

- **Config discovery**: [Finding the repository's override file](repo-policy/config-discovery/config-discovery.feature) (3), [Picking the repository policy for a run](repo-policy/config-discovery/policy-selection.feature) (3)
- **Rule overrides**: [Re-rating commands for a repository](repo-policy/rule-overrides/repo-rule-overrides.feature) (8)

## Reporting
Presenting the verdict to people and to downstream tools.

- **JSON output**: [Consuming results as JSON](reporting/json-output/json-output.feature) (1)
- **Pepper scale**: [Naming risk on the pepper scale](reporting/pepper-scale/pepper-scale.feature) (2)
- **Text report**: [Reading the result of a run](reporting/text-report/run-report.feature) (4), [Reading the risk report](reporting/text-report/text-report.feature) (5)

## Risk catalogue
The built-in knowledge of which commands are dangerous and why.

- **Catalogue integrity**: [Refusing malformed catalogue entries](risk-catalogue/catalogue-integrity/catalogue-integrity.feature) (5)
- **Data and services**: [Scoring database and data-service commands](risk-catalogue/data-and-services/database-and-data-service-commands.feature) (5), [Rating secret-store, backup and storage commands](risk-catalogue/data-and-services/secrets-backups-storage.feature) (6), [Scoring storage, boot, access and cluster commands](risk-catalogue/data-and-services/storage-boot-access-cluster-commands.feature) (7)
- **Host and files**: [Rating commands that change the local machine](risk-catalogue/host-and-files/host-command-ratings.feature) (7), [Catching downloaded code that is run unread](risk-catalogue/host-and-files/remote-code-execution.feature) (3)
- **Resource CLIs**: [Classifying resource CLIs by their verbs](risk-catalogue/resource-clis/resource-cli-verbs-verbs.feature) (6), [Classifying resource CLIs by their verbs](risk-catalogue/resource-clis/resource-cli-verbs.feature) (4), [Choosing the rule that describes a command](risk-catalogue/resource-clis/rule-precedence.feature) (1)
- **Source control and containers**: [Rating cloud and delivery CLI commands by the resource they touch](risk-catalogue/source-control-and-containers/cloud-delivery-cli-resources.feature) (6), [Rating source control, container, cluster and cloud commands](risk-catalogue/source-control-and-containers/platform-risk-ratings.feature) (8)

## Risk scoring
Turning a recognised command into a 0–100 score, a band, a blast radius and a reversibility verdict.

- **Amplifiers**: [Raising the score for the dangerous way of asking](risk-scoring/amplifiers/risk-amplifiers.feature) (7), [Raising the score for dangerous targets and remote code](risk-scoring/amplifiers/target-and-context-amplifiers.feature) (5)
- **Score and bands**: [Naming how risky, how far-reaching and how undoable a command is](risk-scoring/score-and-bands/risk-scales.feature) (3), [Scoring a command](risk-scoring/score-and-bands/scoring-a-command.feature) (5)
- **Softeners**: [Lowering the score for dry runs and regenerable targets](risk-scoring/softeners/dry-runs-and-throwaway-targets.feature) (3), [Lowering the score for the careful way of asking](risk-scoring/softeners/risk-softeners.feature) (5)
- **Unknown commands**: [Scoring commands no rule recognises](risk-scoring/unknown-commands/unknown-commands.feature) (2)
