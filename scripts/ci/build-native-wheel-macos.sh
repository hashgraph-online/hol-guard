#!/usr/bin/env bash
# Build and assemble the native wheel using the workflow target and source identity.
set -eo pipefail

VERSION=$(python -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
export HOL_GUARD_PACKAGE_VERSION="$VERSION"
build_target=()
target_dir="rust/target"
if [[ "$TARGET" == "x86_64-apple-darwin" ]]; then
  build_target=(--target "$TARGET")
  target_dir="$target_dir/$TARGET"
fi
cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime "${build_target[@]}"
cargo build --manifest-path rust/Cargo.toml --locked --release -p guard-command --bin guard-command-source "${build_target[@]}"
runtime="$target_dir/release/hol-guard-runtime"
source_compiler="$target_dir/release/guard-command-source"
# The ARM image includes Rosetta for this build-time sanity check.
# Installed Intel performance is measured on macos-15-intel below.
"$runtime" self-test --json
RULE_DIGEST=$("$runtime" capabilities --json | python -c 'import json,sys; print(json.load(sys.stdin)["rule_digest"])')
python scripts/build_native_command_program.py --check --compiler "$source_compiler"
jq -n --slurpfile source rust/crates/guard-command/tests/fixtures/command-source-example.v1.json --slurpfile trust contracts/extensions/trust-class-map.v1.json \
  '{schema:"guard.command-extension-build.v1",sources:$source,mcp_sources:[],trust:$trust[0],base:"packaged"}' > source-build.json
"$source_compiler" compile < source-build.json > source-compiled.json
python scripts/build_native_hol_guard_wheel.py \
  --wheel "pure-dist/hol_guard-${VERSION}-py3-none-any.whl" \
  --runtime "$runtime" \
  --output-dir native-dist \
  --version "$VERSION" \
  --platform-tag "$PLATFORM_TAG" \
  --target "$TARGET" \
  --source-sha "$HOL_GUARD_BUILD_SHA" \
  --rule-digest "$RULE_DIGEST" \
  --source-compiler "$source_compiler" \
  --implementation-digest "$(jq -r '.implementation_digest' source-compiled.json)" \
  --base-program-digest "$(jq -r '.base_program_digest' source-compiled.json)"
