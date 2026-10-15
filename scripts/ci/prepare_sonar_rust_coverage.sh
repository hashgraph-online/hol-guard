#!/usr/bin/env bash
# Generate Rust coverage from this checkout, independently of reused Python shards.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root/rust"
toolchain="$(python -c 'import tomllib; print(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]["channel"])')"
coverage_version="0.6.21"
source "$repo_root/scripts/ci/sonar_rust_profile.sh"
# LLVM locks and merges concurrent processes into bounded per-binary pools.
# PID-specific profiles make nextest subprocesses repeat large coverage maps.
export LLVM_PROFILE_FILE_NAME="guard-%8m.profraw"
rustup component add --toolchain "$toolchain" llvm-tools-preview
if [[ "$(cargo +"$toolchain" llvm-cov --version 2>/dev/null || true)" != "cargo-llvm-cov $coverage_version" ]]; then
    cargo +"$toolchain" install cargo-llvm-cov --version "=$coverage_version" --locked --force
fi
nextest_bin="$(python "$repo_root/scripts/ci/install_nextest.py")"

report="$repo_root/coverage-reports/rust-lcov.info"
mkdir -p "$(dirname "$report")"
# Neither a restored report nor profiles from another commit can qualify this run.
rm -f "$report"
cargo +"$toolchain" llvm-cov clean --workspace
PATH="$nextest_bin:$PATH" cargo +"$toolchain" llvm-cov nextest --locked --workspace --all-targets \
    --profile ci --test-threads 4 --retries 0 --no-fail-fast --lcov --output-path "$report"
test -s "$report"
grep -q '^SF:.*\.rs$' "$report"
grep -q '^DA:' "$report"
