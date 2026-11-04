#!/usr/bin/env bash
# Sample input for scoville — not meant to be run. Mixed on purpose: two
# harmless lines, one that will end your afternoon.
set -euo pipefail

kubectl config current-context
kubectl apply -f manifests/

# Unset BUILD_DIR and this is `rm -rf /`.
# The unguarded expansion is the hazard this example exists to show scoville catching.
# shellcheck disable=SC2115
rm -rf "$BUILD_DIR"/

kubectl delete ns staging
