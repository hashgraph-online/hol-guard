#!/usr/bin/env bash
# Preserve the original source-build auto-discovery and resident contracts.
set -euo pipefail

case "${1:?expected prepare, origin, or retirement}" in
  prepare)
    test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
    test -z "$(git status --porcelain --untracked-files=no)"
    uv run --no-sync pytest -q tests/test_native_sensitive_policy_resident.py::test_sensitive_resident_fixture_uses_actual_loaded_origins tests/test_native_generic_policy_resident.py::test_generic_resident_fixture_preserves_all_actual_origin_projections tests/test_native_generic_sync_resident.py::test_generic_sync_source_is_signed_and_target_authority_is_unstaged
    uv run --no-sync pytest -q tests/test_native_installation_retirement_resident.py::test_rotation_probe_calls_actual_store_in_a_new_process
    proof_pure_dir="$(mktemp -d "$RUNNER_TEMP/native-auto-pure.XXXXXX")"
    proof_native_dir="$(mktemp -d "$RUNNER_TEMP/native-auto-bundle.XXXXXX")"
    proof_runtime="$GITHUB_WORKSPACE/rust/target/release/hol-guard-runtime"
    proof_version="$(uv run --no-sync python scripts/sync_repo_version.py --check)"
    proof_rule_digest="$("$proof_runtime" capabilities --json | python -c 'import json,sys; print(json.load(sys.stdin)["rule_digest"])')"
    proof_target="$(rustc +1.88.0 -vV | sed -n 's/^host: //p')"
    test "$proof_target" = "x86_64-unknown-linux-gnu"
    uv build --wheel --out-dir "$proof_pure_dir"
    proof_wheels=("$proof_pure_dir"/*.whl)
    test "${#proof_wheels[@]}" -eq 1
    test -f "${proof_wheels[0]}"
    uv run --no-sync python -m tests.native_source_bundle \
      --wheel "${proof_wheels[0]}" \
      --runtime "$proof_runtime" \
      --output-dir "$proof_native_dir" \
      --version "$proof_version" \
      --source-sha "$GITHUB_SHA" \
      --rule-digest "$proof_rule_digest" \
      --platform-tag linux_x86_64 \
      --target "$proof_target"
    ;;
  origin)
    export HOL_GUARD_NATIVE=auto
    export HOL_GUARD_NATIVE_BINARY="$GITHUB_WORKSPACE/rust/target/release/hol-guard-runtime"
    export PYTHONPATH=src
    mkdir -p artifacts/native-sensitive-resident
    uv run --no-sync pytest -q -m slow tests/test_native_sensitive_policy_resident.py tests/test_native_generic_policy_resident.py tests/test_native_generic_sync_resident.py --junitxml=artifacts/native-sensitive-resident/results.xml
    ;;
  retirement)
    export HOL_GUARD_NATIVE=auto
    export HOL_GUARD_NATIVE_BINARY="$GITHUB_WORKSPACE/rust/target/release/hol-guard-runtime"
    export PYTHONPATH=src
    mkdir -p artifacts/native-installation-retirement
    uv run --no-sync pytest -q -m slow tests/test_native_installation_retirement_resident.py --junitxml=artifacts/native-installation-retirement/results.xml
    ;;
  *)
    printf "%s\n" "Unknown resident contract group" >&2
    exit 2
    ;;
esac
