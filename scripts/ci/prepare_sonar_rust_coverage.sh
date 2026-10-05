#!/usr/bin/env bash
# Generate Rust coverage from this checkout, independently of reused Python shards.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root/rust"
toolchain="$(python -c 'import tomllib; print(tomllib.load(open("rust-toolchain.toml", "rb"))["toolchain"]["channel"])')"
coverage_version="0.6.21"
rustup component add --toolchain "$toolchain" llvm-tools-preview
if [[ "$(cargo +"$toolchain" llvm-cov --version 2>/dev/null || true)" != "cargo-llvm-cov $coverage_version" ]]; then
    cargo +"$toolchain" install cargo-llvm-cov --version "=$coverage_version" --locked --force
fi

report="$repo_root/coverage-reports/rust-lcov.info"
mkdir -p "$(dirname "$report")"
# Neither a restored report nor profiles from another commit can qualify this run.
rm -f "$report"
cargo +"$toolchain" llvm-cov clean --workspace
cargo +"$toolchain" llvm-cov --locked --workspace --all-targets --lcov --output-path "$report"
test -s "$report"
grep -q '^SF:.*\.rs$' "$report"
grep -q '^DA:' "$report"
