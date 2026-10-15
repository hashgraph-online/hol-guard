#!/usr/bin/env bash
# Prove the packaged native compiler and fixtures in a Python-free container.
set -euo pipefail

cargo test --manifest-path rust/Cargo.toml --locked --release --target x86_64-unknown-linux-musl -p guard-command --test native_command_source_cli
cargo build --manifest-path rust/Cargo.toml --locked --release --target x86_64-unknown-linux-musl -p guard-command --bin guard-command-source
mkdir source-compiler-context
cp rust/target/x86_64-unknown-linux-musl/release/guard-command-source source-compiler-context/
cp ci/native_runtime/source-compiler.Dockerfile source-compiler-context/Dockerfile
docker build --network none --tag guard-source-compiler:ci source-compiler-context
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges guard-source-compiler:ci export-trust > contracts/extensions/build-trust-class-map.v1.json
jq -n --slurpfile source rust/crates/guard-command/tests/fixtures/command-source-example.v1.json --slurpfile trust contracts/extensions/build-trust-class-map.v1.json \
  '{schema:"guard.command-extension-build.v1",sources:$source,mcp_sources:[],trust:$trust[0],base:"packaged"}' > source-build.json
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges -i guard-source-compiler:ci compile < source-build.json > source-compiled.json
jq --slurpfile build source-build.json '. + {build:$build[0]}' rust/crates/guard-command/tests/fixtures/command-source-behavior.v1.json > source-fixtures.json
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges -i guard-source-compiler:ci test < source-fixtures.json > source-fixture-results.json
