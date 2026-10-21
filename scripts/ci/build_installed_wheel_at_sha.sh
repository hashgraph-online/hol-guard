#!/usr/bin/env bash
# Build the static Linux native wheel for one checked-out revision and install it
# into that checkout's .venv, following the linux-build recipe of the nightly
# native workflow. Measurement support only; it changes no product behavior.
#
# usage: build_installed_wheel_at_sha.sh <source-dir> <full-sha>
# env:   CARGO_TARGET_DIR (optional) shares dependency builds between revisions.
set -euo pipefail

source_dir=${1:?source directory}
source_sha=${2:?full source sha}
target=x86_64-unknown-linux-musl

cd "$source_dir"
export HOL_GUARD_BUILD_SHA="$source_sha"

uv sync --frozen --no-dev --group ci-test --python 3.12
export HOL_GUARD_PACKAGE_VERSION
HOL_GUARD_PACKAGE_VERSION=$(.venv/bin/python scripts/sync_repo_version.py --check)
version=$HOL_GUARD_PACKAGE_VERSION
target_root=${CARGO_TARGET_DIR:-rust/target}
# Workspace crates must be rebuilt for this revision even in a shared target directory.
cargo clean --manifest-path rust/Cargo.toml --release --target "$target" -p hol-guard-runtime -p guard-command || true
cargo build --manifest-path rust/Cargo.toml --locked --release --target "$target" \
  -p hol-guard-runtime -p guard-command --bin hol-guard-runtime --bin guard-command-source
release_dir="$target_root/$target/release"
mkdir -p native-build
cp "$release_dir/hol-guard-runtime" "$release_dir/guard-command-source" native-build/
runtime=native-build/hol-guard-runtime
compiler=native-build/guard-command-source
# The wheel build compiles this revision's command pack. Without this the
# builder falls back to a debug binary in the shared target directory, which
# belongs to the workspace rather than the revision being measured.
export HOL_GUARD_BUILD_SOURCE_COMPILER="$PWD/$compiler"
"$runtime" self-test --json > /dev/null

# Derive the packaged command program the same way the container proof does, without the container.
# Older revisions have no export-trust command and ship the trust map as a tracked file.
trust=contracts/extensions/trust-class-map.v1.json
if "$compiler" export-trust > native-build/trust-class-map.json 2> /dev/null; then
  trust=native-build/trust-class-map.json
  cp "$trust" contracts/extensions/build-trust-class-map.v1.json
fi
# Revisions that reject packaged-base authoring without a global validation
# context need the catalog this binary embeds, with no installed packs; earlier
# ones reject the field outright, so only send it when the revision requires it
# and its compiler can export the embedded build.
validation_arguments=()
validation_filter='{}'
if grep -q 'command_source_global_validation_required' rust/crates/guard-command/src/native_command_source.rs \
  && "$compiler" export-built > native-build/exported-build.json 2> /dev/null; then
  validation_arguments=(--slurpfile built native-build/exported-build.json)
  validation_filter='{validation_base:{catalog:$built[0].catalog,programs:[]}}'
fi
jq -n --slurpfile source rust/crates/guard-command/tests/fixtures/command-source-example.v1.json \
  --slurpfile trust "$trust" \
  ${validation_arguments[@]+"${validation_arguments[@]}"} \
  '{schema:"guard.command-extension-build.v1",sources:$source,mcp_sources:[],trust:$trust[0],base:"packaged"} + '"$validation_filter" \
  > source-build.json
# Revisions whose wheel builder still embeds a standalone compiler predate the
# runtime-hosted compiler; their runtime cannot answer `compile`.
compiler_arguments=()
identity_binary=$runtime
if grep -q -- '--source-compiler' scripts/build_native_hol_guard_wheel.py; then
  compiler_arguments=(--source-compiler "$compiler")
  identity_binary=$compiler
fi
"$identity_binary" compile < source-build.json > source-compiled.json

uv build --wheel --out-dir pure-dist
rule_digest=$("$runtime" capabilities --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["rule_digest"])')
.venv/bin/python scripts/build_native_hol_guard_wheel.py \
  --wheel "pure-dist/hol_guard-${version}-py3-none-any.whl" \
  --runtime "$runtime" \
  --output-dir native-dist \
  --version "$version" \
  --platform-tag manylinux_2_17_x86_64 \
  --target "$target" \
  --source-sha "$source_sha" \
  --rule-digest "$rule_digest" \
  ${compiler_arguments[@]+"${compiler_arguments[@]}"} \
  --implementation-digest "$(jq -r '.implementation_digest' source-compiled.json)" \
  --base-program-digest "$(jq -r '.base_program_digest' source-compiled.json)"

uv pip uninstall --python .venv/bin/python hol-guard
uv pip install --python .venv/bin/python --no-deps --force-reinstall native-dist/*.whl
.venv/bin/python -c 'from codex_plugin_scanner.guard.native_runtime import native_runtime_status; status = native_runtime_status(); assert status.identity is not None, "installed wheel has no native runtime"; print("native runtime:", status.identity.path)'
echo "built and installed hol-guard ${version} at ${source_sha}"
