#!/usr/bin/env bash
set -euo pipefail

toolchain="$(python -c 'from pathlib import Path; from scripts.ci.rust_coverage_report import toolchain_channel; print(toolchain_channel(Path.cwd()))')"
rustup toolchain install "$toolchain" --profile minimal
rustup default "$toolchain"
