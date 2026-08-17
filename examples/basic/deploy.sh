#!/usr/bin/env bash
# Sample input for scoville — not meant to be run. Mixed on purpose: two
# harmless lines, one that will end your afternoon.
set -euo pipefail

kubectl config current-context
kubectl apply -f manifests/

# Unset BUILD_DIR and this is `rm -rf /`.
rm -rf "$BUILD_DIR"/

kubectl delete ns staging
