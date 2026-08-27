#!/usr/bin/env bash
set -euo pipefail

BASE_REF=${BASE_REF:-origin/main}
SEED_ROOT=${SEED_ROOT:-/tmp/batch2-seed}
REPORT=docs/guard/rust-posttool-authority-bootstrap-report.md

candidates=(
  "automation/rust-p1-p2-end-to-end:97a5180646158ec9a7c00d889556f5da01e94a07"
  "feat/rust-p1-p2-autonomous:450f4336b10481f6001c450ebf43ea34c0737716"
  "feat/rust-runtime-supervision-final:8bd311d815612c976c0b6f8df50e16591267b7ef"
  "feat/rust-runtime-supervision-reconciled-v2:2c9606359580dc35ff82374cb029f41f2a13ca8f"
  "feat/rust-runtime-supervision-release:baf6354f80cb5480ea2a9a354794c9771ee2e46e"
  "feat/rust-runtime-resilience-v2:ce325533bfd979a389c9c5edf84874585b02ca06"
  "feat/rust-safety-kernel-integration-final:152cddf4c07db198772a8df792bc2aaa54430895"
)

restore_seed() {
  mkdir -p scripts/ci docs/guard
  cp "$SEED_ROOT/scripts/ci/converge_rust_posttool_authority_v2.py" scripts/ci/
  cp "$SEED_ROOT/scripts/ci/harden_rust_policy_snapshot_v3.py" scripts/ci/
  cp "$SEED_ROOT/scripts/ci/rust_posttool_failclosed_integration_v2.py" scripts/ci/rust_posttool_failclosed_integration.py
  cp "$SEED_ROOT/docs/guard/rust-migration-batch-2-tasks.md" docs/guard/
}

source_gate() {
  python - <<'PY'
from pathlib import Path
hook=Path('src/codex_plugin_scanner/guard/daemon/hook_worker.py').read_text(encoding='utf-8')
native=Path('src/codex_plugin_scanner/guard/native_runtime.py').read_text(encoding='utf-8')
runtime=Path('rust/crates/guard-runtime/src/main.rs').read_text(encoding='utf-8')
cargo=Path('rust/crates/guard-runtime/Cargo.toml').read_text(encoding='utf-8')
if 'if response is None:\n                response = self.engine.review(request)' in hook:
    raise SystemExit('Python fallback remains')
if 'currently supported Python reference backend remains authoritative' in native:
    raise SystemExit('Python authority declaration remains')
if 'guard-policy-snapshot' not in cargo:
    raise SystemExit('policy snapshot dependency missing')
if 'policy-snapshot-v1' not in runtime or ('PolicySnapshot' not in runtime and 'policy_snapshot' not in runtime):
    raise SystemExit('policy snapshot runtime authority missing')
PY
}

validate_candidate() {
  local log_dir=$1
  cargo fmt --manifest-path rust/Cargo.toml --all >"$log_dir/fmt.log" 2>&1 || return 1
  cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings >"$log_dir/clippy.log" 2>&1 || return 1
  cargo test --manifest-path rust/Cargo.toml --locked --workspace --all-targets >"$log_dir/cargo-test.log" 2>&1 || return 1
  VERSION=$(uv run --no-sync python scripts/sync_repo_version.py --check) || return 1
  HOL_GUARD_BUILD_SHA=$(git rev-parse HEAD) HOL_GUARD_PACKAGE_VERSION="$VERSION" \
    cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime >"$log_dir/build.log" 2>&1 || return 1
  rust/target/release/hol-guard-runtime self-test --json >"$log_dir/self-test.json" 2>&1 || return 1
  uv run --no-sync python scripts/ci/rust_posttool_failclosed_integration.py \
    --runtime rust/target/release/hol-guard-runtime \
    --json "$log_dir/posttool.json" >"$log_dir/integration.log" 2>&1 || return 1
  HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY="$PWD/rust/target/release/hol-guard-runtime" \
    uv run --no-sync pytest -q \
      ci/native_runtime/test_guard_native_runtime_binary.py \
      ci/native_runtime/test_guard_native_runtime_differential.py \
      ci/native_runtime/test_guard_native_runtime_mutation_differential.py \
      --tb=short >"$log_dir/differential.log" 2>&1 || return 1
  HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY="$PWD/rust/target/release/hol-guard-runtime" \
    uv run --no-sync python scripts/bench_guard_native_release_gate.py \
      --runtime rust/target/release/hol-guard-runtime \
      --warm-iterations 30 --cold-iterations 2 \
      --json "$log_dir/performance.json" --enforce >"$log_dir/performance.log" 2>&1 || return 1
}

mkdir -p docs/guard
cat >"$REPORT" <<EOF
# Rust PostToolUse Authority Candidate Selection

Base: \`$(git rev-parse "$BASE_REF")\`

EOF

for entry in "${candidates[@]}"; do
  branch=${entry%%:*}
  sha=${entry##*:}
  safe=${branch//\//-}
  log_dir="/tmp/rust-posttool-candidate-$safe"
  rm -rf "$log_dir" && mkdir -p "$log_dir"
  git reset --hard "$BASE_REF" >/dev/null
  git clean -fdx -e .venv -e rust/target >/dev/null
  restore_seed
  git fetch --no-tags origin "$branch" >/dev/null 2>&1 || git fetch --no-tags origin "$sha" >/dev/null 2>&1 || true
  if ! git cat-file -e "$sha^{commit}" 2>/dev/null; then
    printf -- '- %s: unavailable\n' "$branch" >>"$REPORT"
    continue
  fi
  merge_base=$(git merge-base "$BASE_REF" "$sha")
  git diff --binary "$merge_base" "$sha" -- \
    rust \
    src/codex_plugin_scanner/guard \
    ci/native_runtime \
    scripts/bench_guard_native_release_gate.py \
    scripts/bench_guard_native_full_path.py \
    tests/test_guard_native_runtime.py \
    tests/test_guard_hook_worker.py \
    tests/test_hook_security_regressions.py \
    >"$log_dir/candidate.patch"
  if [[ ! -s "$log_dir/candidate.patch" ]]; then
    printf -- '- %s: no unique source changes\n' "$branch" >>"$REPORT"
    continue
  fi
  if ! git apply --3way --index "$log_dir/candidate.patch" >"$log_dir/apply.log" 2>&1; then
    printf -- '- %s: patch conflict\n' "$branch" >>"$REPORT"
    continue
  fi
  uv run --no-sync python scripts/ci/converge_rust_posttool_authority_v2.py
  uv run --no-sync python scripts/ci/harden_rust_policy_snapshot_v3.py
  if ! source_gate >"$log_dir/source-gate.log" 2>&1; then
    printf -- '- %s: source authority gate failed\n' "$branch" >>"$REPORT"
    continue
  fi
  if validate_candidate "$log_dir"; then
    printf -- '- %s@%s: accepted\n' "$branch" "$sha" >>"$REPORT"
    cat >>"$REPORT" <<EOF

## Accepted candidate

\`$branch@$sha\`

The candidate plus current canonical policy binding passed Rust workspace
checks, release build, runtime self-test, real-binary PostToolUse adversarial
integration, resident differential and mutation testing, and performance gates.
EOF
    git add -A
    exit 0
  fi
  printf -- '- %s: compiled integration failed\n' "$branch" >>"$REPORT"
done

git reset --hard "$BASE_REF" >/dev/null
git clean -fdx -e .venv -e rust/target >/dev/null
restore_seed
uv run --no-sync python scripts/ci/converge_rust_posttool_authority_v2.py
uv run --no-sync python scripts/ci/harden_rust_policy_snapshot_v3.py
cat >"$REPORT" <<'EOF'
# Rust PostToolUse Authority Candidate Selection

No historical candidate passed every current release gate. The deterministic
fail-closed Rust authority migration with canonical policy binding was applied.

## Accepted implementation

`scripts/ci/converge_rust_posttool_authority_v2.py`
`scripts/ci/harden_rust_policy_snapshot_v3.py`
EOF
git add -A
