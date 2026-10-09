#!/usr/bin/env bash
# One fresh instrumented execution supplies native validation and Sonar coverage.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
report="$repo_root/rust-coverage/rust-lcov.info"
mkdir -p "$(dirname "$report")"
# A restored report, including one left by failed setup/tests, never qualifies.
rm -f "$report" "$repo_root/rust-coverage/metadata.json"
toolchain="$(python -c 'from pathlib import Path; from scripts.ci.rust_coverage_report import toolchain_channel; print(toolchain_channel(Path.cwd()))')"
# Keep debug/overflow checks; symbol tables do not affect LLVM coverage mappings.
export CARGO_PROFILE_TEST_OPT_LEVEL=1
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true
export CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true
export CARGO_LLVM_COV_TARGET_DIR="$repo_root/rust/target/llvm-cov-target"
# Lock-protected two-file-per-binary pooling matches nextest's two workers.
# Avoid writing one complete raw profile for every individual test process.
export LLVM_PROFILE_FILE_NAME="hol-guard-%2m.profraw"
rustup component add --toolchain "$toolchain" llvm-tools-preview
coverage_bin="$(python -m scripts.ci.install_llvm_cov)"
nextest_bin="$(python -m scripts.ci.install_nextest)"
export PATH="$coverage_bin:$nextest_bin:$PATH"
cd "$repo_root/rust"
# The pinned tool clears workspace binaries/profiles itself, retaining only
# reusable instrumented dependencies. Never --no-clean a restored workspace.
cargo +"$toolchain" llvm-cov nextest --locked --workspace --all-targets --no-cfg-coverage \
    --test-threads 2 --retries 0 --no-fail-fast --lcov --output-path ../rust-coverage/rust-lcov.info
cd "$repo_root"
python -m scripts.ci.rust_coverage_report bind
