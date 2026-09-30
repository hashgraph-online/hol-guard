#!/usr/bin/env bash
set -euo pipefail

if ! command -v hol-guard >/dev/null 2>&1; then
  echo "hol-guard is required. Install it with: pipx install hol-guard" >&2
  exit 1
fi

echo "HOL Guard Kubernetes classification demo"
echo "These commands are classified only. kubectl is not executed."
echo

commands=(
  "kubectl get pods -A"
  "kubectl get secret -A -o yaml"
  "kubectl delete namespace demo"
  "kubectl apply -f unreviewed.yaml"
)

for command_text in "${commands[@]}"; do
  printf '\n$ %s\n' "$command_text"
  hol-guard command test "$command_text"
done
