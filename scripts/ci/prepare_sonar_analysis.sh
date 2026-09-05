#!/usr/bin/env bash
# Prepare both language analyzers before Sonar receives its authentication token.
set -euo pipefail

shopt -s globstar nullglob
reports=(coverage-data/**/.coverage)
echo "Combining ${#reports[@]} shard coverage files"
test "${#reports[@]}" -eq 96
uv run --no-sync coverage combine "${reports[@]}"
uv run --no-sync coverage xml

toolchain="$(python -c 'import tomllib; print(tomllib.load(open("rust/rust-toolchain.toml", "rb"))["toolchain"]["channel"])')"
rustup toolchain install "$toolchain" --profile minimal --component clippy
rustup default "$toolchain"
cargo clippy --manifest-path rust/Cargo.toml --locked --workspace
