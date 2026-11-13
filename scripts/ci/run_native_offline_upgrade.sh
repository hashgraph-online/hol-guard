#!/usr/bin/env bash
# Runs CI's native-offline-upgrade job (tests/test_native_pack_offline_upgrade.py) on a
# developer machine, so a fix to the installed upgrade path can be proven before a push.
#
# It mirrors the native-offline-previous and native-offline-upgrade jobs in ci.yml:
#   1. The pinned prior client (NATIVE_OFFLINE_PREVIOUS_SHA in ci.yml) is checked out as a
#      detached worktree, and its native pair plus projections are built ONCE, then reused
#      from the cache directory on every later run.
#   2. The current checkout's native pair and projections are rebuilt (cargo is incremental).
#   3. The test runs with the same environment CI sets.
#
# Usage: scripts/ci/run_native_offline_upgrade.sh [extra pytest args]
# Environment:
#   PYTHON                       interpreter with the dev dependencies (default: .venv/bin/python)
#   HOL_GUARD_OFFLINE_CACHE_DIR  where the prior client lives
#                                (default: ${XDG_CACHE_HOME:-$HOME/.cache}/hol-guard/native-offline-previous)
#   SKIP_CURRENT_BUILD=1         reuse rust/target/release and the current projections as they are
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
python=${PYTHON:-$root/.venv/bin/python}
if [[ ! -x "$python" ]]; then
  echo "No interpreter at $python; set PYTHON to a venv with the dev dependencies" >&2
  exit 1
fi

previous_sha=$(sed -n 's/^  NATIVE_OFFLINE_PREVIOUS_SHA: *\([0-9a-f]\{40\}\) *$/\1/p' .github/workflows/ci.yml)
if [[ ! "$previous_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Could not read NATIVE_OFFLINE_PREVIOUS_SHA from .github/workflows/ci.yml" >&2
  exit 1
fi

# Same profile overrides as ci.yml, so local evaluators match CI's.
export CARGO_PROFILE_RELEASE_LTO=false
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16

cache_root=${HOL_GUARD_OFFLINE_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/hol-guard/native-offline-previous}
previous="$cache_root/$previous_sha/source"
previous_target="$cache_root/$previous_sha/target"
ready="$cache_root/$previous_sha/.ready"

if [[ ! -f "$ready" ]]; then
  echo "Building pinned prior client ${previous_sha} once into ${cache_root}/${previous_sha}"
  mkdir -p "$cache_root/$previous_sha"
  if [[ ! -e "$previous/.git" ]]; then
    git cat-file -e "${previous_sha}^{commit}" 2>/dev/null || git fetch --no-tags origin "$previous_sha"
    git worktree add --detach "$previous" "$previous_sha"
  fi
  test "$(git -C "$previous" rev-parse HEAD)" = "$previous_sha"
  (
    cd "$previous"
    "$python" scripts/refresh_extension_artifacts.py --trust-only
    CARGO_TARGET_DIR="$previous_target" cargo build --manifest-path rust/Cargo.toml --locked --release \
      -p guard-command -p hol-guard-runtime --bin guard-command-source --bin hol-guard-runtime
    "$python" scripts/build_native_command_program.py --compiler "$previous_target/release/guard-command-source"
  )
  touch "$ready"
fi
test "$(git -C "$previous" rev-parse HEAD)" = "$previous_sha"
test -x "$previous_target/release/hol-guard-runtime"

if [[ "${SKIP_CURRENT_BUILD:-}" != "1" ]]; then
  "$python" scripts/refresh_extension_artifacts.py --trust-only
  cargo build --manifest-path rust/Cargo.toml --locked --release \
    -p guard-command -p hol-guard-runtime --bin guard-command-source --bin hol-guard-runtime
  "$python" scripts/build_native_command_program.py --compiler rust/target/release/guard-command-source
fi
test -x rust/target/release/hol-guard-runtime
test -x rust/target/release/guard-command-source

HOL_GUARD_NATIVE_BINARY="$root/rust/target/release/hol-guard-runtime" \
HOL_GUARD_NATIVE_SOURCE_COMPILER="$root/rust/target/release/guard-command-source" \
HOL_GUARD_BUILD_SOURCE_COMPILER="$root/rust/target/release/guard-command-source" \
NATIVE_ACTIVATION_PREVIOUS_BINARY="$previous_target/release/hol-guard-runtime" \
NATIVE_ACTIVATION_PREVIOUS_SOURCE="$previous" \
HOL_GUARD_NATIVE_REGRESSION=1 \
  "$python" -m pytest -q --tb=short tests/test_native_pack_offline_upgrade.py "$@"
