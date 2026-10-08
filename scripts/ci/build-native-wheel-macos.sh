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
cargo build --manifest-path rust/Cargo.toml --locked --release -p hol-guard-runtime -p guard-command --bin hol-guard-runtime --bin guard-command-source "${build_target[@]}"
runtime="$target_dir/release/hol-guard-runtime"
source_compiler="$target_dir/release/guard-command-source"
export HOL_GUARD_BUILD_SOURCE_COMPILER="$source_compiler"
# The ARM image includes Rosetta for this build-time sanity check.
# Installed Intel performance is measured on macos-15-intel below.
"$runtime" self-test --json
# Match Linux: prepare and verify the complete current source tree for every
# event. Source-only PRs never need to commit generated catalogs or fixtures.
verification_arguments=(--compiler "$source_compiler")
if [[ -n "${NATIVE_PR_BASE_SHA:-}" ]]; then
  if [[ ! "$NATIVE_PR_BASE_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
    echo "NATIVE_PR_BASE_SHA must be a full Git commit SHA" >&2
    exit 1
  fi
  verification_arguments+=(--changed-from "$NATIVE_PR_BASE_SHA")
fi
python scripts/ci/verify_native_command_program.py "${verification_arguments[@]}"
uv build --wheel --out-dir pure-dist
RULE_DIGEST=$("$runtime" capabilities --json | python -c 'import json,sys; print(json.load(sys.stdin)["rule_digest"])')
jq -n --slurpfile source rust/crates/guard-command/tests/fixtures/command-source-example.v1.json --slurpfile trust contracts/extensions/build-trust-class-map.v1.json \
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
python scripts/ci/check_wheel_size.py --dist-dir native-dist
