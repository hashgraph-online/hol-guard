#!/usr/bin/env bash
set -euo pipefail

toolchain="$(python -c 'import tomllib; print(tomllib.load(open("rust/rust-toolchain.toml", "rb"))["toolchain"]["channel"])')"
rustup toolchain install "$toolchain" --profile minimal --component clippy
rustup default "$toolchain"
