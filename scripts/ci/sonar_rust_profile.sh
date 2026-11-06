#!/usr/bin/env bash
# Keep compiler-cache inputs separate from test scheduling and report options.
export CARGO_PROFILE_TEST_OPT_LEVEL=1
export CARGO_PROFILE_TEST_DEBUG=line-tables-only
export CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true
export CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true
# The existing checked wrapper changes only --test codegen; runtime binaries
# and dependency libraries keep their optimization and checked behavior.
export RUSTC_WORKSPACE_WRAPPER="$repo_root/scripts/ci/rust_test_compiler.sh"
