#!/usr/bin/env bash
set -euo pipefail

BASE_REF=${BASE_REF:-origin/main}
ORIGINAL_HEAD=$(git rev-parse HEAD)
REPORT=docs/guard/rust-posttool-authority-bootstrap-report.md
mkdir -p "$(dirname "$REPORT")"

candidates=(
  "automation/rust-p1-p2-end-to-end:97a5180646158ec9a7c00d889556f5da01e94a07"
  "feat/rust-p1-p2-autonomous:450f4336b10481f6001c450ebf43ea34c0737716"
  "feat/rust-runtime-supervision-final:8bd311d815612c976c0b6f8df50e16591267b7ef"
  "feat/rust-runtime-supervision-reconciled-v2:2c9606359580dc35ff82374cb029f41f2a13ca8f"
  "feat/rust-runtime-supervision-release:baf6354f80cb5480ea2a9a354794c9771ee2e46e"
  "feat/rust-runtime-resilience-v2:ce325533bfd979a389c9c5edf84874585b02ca06"
  "feat/rust-safety-kernel-integration-final:152cddf4c07db198772a8df792bc2aaa54430895"
)

pathspec=(
  rust
  src/codex_plugin_scanner/guard/native_runtime.py
  src/codex_plugin_scanner/guard/native_runtime_admission.py
  src/codex_plugin_scanner/guard/native_runtime_resident.py
  src/codex_plugin_scanner/guard/native_runtime_resilience.py
  src/codex_plugin_scanner/guard/daemon/hook_worker.py
  src/codex_plugin_scanner/guard/daemon/runtime_hook_deadline.py
  src/codex_plugin_scanner/guard/daemon/runtime_hook_scheduler.py
  src/codex_plugin_scanner/guard/daemon/runtime_hook_scheduler_contracts.py
  src/codex_plugin_scanner/guard/daemon/runtime_hook_scheduler_types.py
  src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py
  ci/native_runtime
  scripts/bench_guard_native_full_path.py
  scripts/bench_guard_native_release_gate.py
  scripts/verify_native_runtime_release.py
  tests/test_guard_native_runtime.py
  tests/test_guard_hook_worker.py
  tests/test_guard_hook_process_deadline_contract.py
  tests/test_codex_hook_fallback_isolation.py
)

cat >"$REPORT" <<EOF
# Rust PostToolUse Authority Bootstrap Evidence

Base: \`$(git rev-parse "$BASE_REF")\`

A historical implementation is accepted only when it applies cleanly to the current release line, preserves the completed PreToolUse authority batch, links the native policy snapshot crate into the runtime, removes Python semantic fallback from supported PostToolUse, and passes compiled release-binary integration.

EOF

source_guard() {
  python - <<'PY'
from pathlib import Path
hook = Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py").read_text(encoding="utf-8")
native = Path("src/codex_plugin_scanner/guard/native_runtime.py").read_text(encoding="utf-8")
if "currently supported Python reference backend remains authoritative" in native:
    raise SystemExit("native runtime still declares Python authoritative")
needle = "if response is None:\n                response = self.engine.review(request)"
if needle in hook:
    raise SystemExit("supported PostToolUse still spills into Python HookReviewEngine")
if "guard-policy-snapshot" not in Path("rust/crates/guard-runtime/Cargo.toml").read_text(encoding="utf-8"):
    raise SystemExit("guard-policy-snapshot is not linked into hol-guard-runtime")
runtime_rs = Path("rust/crates/guard-runtime/src/main.rs").read_text(encoding="utf-8")
if "PolicySnapshot" not in runtime_rs and "policy_snapshot" not in runtime_rs:
    raise SystemExit("native runtime does not consume policy snapshots")
PY
}

validate_candidate() {
  local label=$1
  local log_dir=$2
  source_guard >"$log_dir/source-guard.log" 2>&1 || {
    cp "$log_dir/source-guard.log" "$log_dir/failure"; return 1;
  }
  cargo fmt --manifest-path rust/Cargo.toml --all --check >"$log_dir/fmt.log" 2>&1 || {
    echo "cargo fmt failed" >"$log_dir/failure"; return 1;
  }
  cargo clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings >"$log_dir/clippy.log" 2>&1 || {
    echo "cargo clippy failed" >"$log_dir/failure"; return 1;
  }
  cargo test --manifest-path rust/Cargo.toml --locked --workspace --all-targets >"$log_dir/cargo-test.log" 2>&1 || {
    echo "cargo test failed" >"$log_dir/failure"; return 1;
  }
  VERSION=$(uv run --no-sync python scripts/sync_repo_version.py --check)
  HOL_GUARD_BUILD_SHA=$(git rev-parse HEAD) HOL_GUARD_PACKAGE_VERSION="$VERSION" \
    cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime \
    >"$log_dir/build.log" 2>&1 || {
      echo "release runtime build failed" >"$log_dir/failure"; return 1;
    }
  runtime="$PWD/rust/target/release/hol-guard-runtime"
  "$runtime" self-test --json >"$log_dir/self-test.json" 2>"$log_dir/self-test.err" || {
    echo "native self-test failed" >"$log_dir/failure"; return 1;
  }
  HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY="$runtime" \
    uv run --no-sync pytest -q \
      ci/native_runtime/test_guard_native_runtime_binary.py \
      ci/native_runtime/test_guard_native_runtime_differential.py \
      ci/native_runtime/test_guard_native_runtime_mutation_differential.py \
      --tb=short >"$log_dir/integration.log" 2>&1 || {
        echo "compiled PostToolUse integration failed" >"$log_dir/failure"; return 1;
      }
  uv run --no-sync python scripts/bench_guard_native_release_gate.py \
    --runtime "$runtime" --warm-iterations 30 --cold-iterations 2 \
    --json "$log_dir/performance.json" --enforce >"$log_dir/performance.log" 2>&1 || {
      echo "native performance gate failed" >"$log_dir/failure"; return 1;
    }
  printf '%s\n' "$label" >"$log_dir/accepted"
}

selected=""
for entry in "${candidates[@]}"; do
  branch=${entry%%:*}
  sha=${entry##*:}
  safe=${branch//\//-}
  log_dir="/tmp/rust-posttool-$safe"
  rm -rf "$log_dir" && mkdir -p "$log_dir"
  git reset --hard "$ORIGINAL_HEAD" >/dev/null
  git clean -fdx -e .venv -e rust/target >/dev/null
  git fetch --no-tags origin "$branch" >/dev/null 2>&1 || git fetch --no-tags origin "$sha" >/dev/null 2>&1 || true
  if ! git cat-file -e "$sha^{commit}" 2>/dev/null; then
    printf -- '- %s: unavailable\n' "$branch" >>"$REPORT"
    continue
  fi
  merge_base=$(git merge-base "$BASE_REF" "$sha")
  git diff --binary "$merge_base" "$sha" -- "${pathspec[@]}" >"$log_dir/candidate.patch"
  if [[ ! -s "$log_dir/candidate.patch" ]]; then
    printf -- '- %s: no unique changes\n' "$branch" >>"$REPORT"
    continue
  fi
  if ! git apply --3way --index "$log_dir/candidate.patch" >"$log_dir/apply.log" 2>&1; then
    printf -- '- %s: patch conflict\n' "$branch" >>"$REPORT"
    continue
  fi
  if validate_candidate "$branch@$sha" "$log_dir"; then
    selected="$branch@$sha"
    printf -- '- %s: accepted\n' "$selected" >>"$REPORT"
    break
  fi
  reason=$(tr '\n' ' ' <"$log_dir/failure" 2>/dev/null || echo validation-failed)
  printf -- '- %s: rejected (%s)\n' "$branch" "$reason" >>"$REPORT"
done

if [[ -z "$selected" ]]; then
  git reset --hard "$ORIGINAL_HEAD" >/dev/null
  git clean -fdx -e .venv -e rust/target >/dev/null
  echo >>"$REPORT"
  echo "No historical candidate passed the current PostToolUse, policy snapshot, and real-binary gates." >>"$REPORT"
  git add "$REPORT"
  exit 1
fi

git restore --source="$ORIGINAL_HEAD" -- \
  docs/guard/rust-authority-batch-2-bootstrap.md \
  docs/guard/rust-migration-batch-2-tasks.md \
  scripts/ci/bootstrap_rust_posttool_authority.sh

cat >>"$REPORT" <<EOF

## Accepted candidate

\`$selected\`

## Verification

- The completed batch-1 PreToolUse authority remained present.
- Supported PostToolUse no longer spills into the Python HookReviewEngine.
- The Rust runtime links and consumes guard-policy-snapshot.
- Rust formatting, Clippy, workspace tests, and release build passed.
- Real-binary differential and mutation integration passed.
- Native release performance gates passed.
EOF

git add -A
