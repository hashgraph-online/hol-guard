#!/usr/bin/env bash
# The warmer and required CI use identical, complete nextest build selections.
set -euo pipefail
case "${1:?test partition required}" in
    core|test-core) packages=(--locked --workspace --exclude guard-command --exclude hol-guard-runtime --all-targets) ;;
    command|test-command) packages=(--locked --package guard-command --all-targets) ;;
    runtime|test-runtime-1) packages=(--locked --package hol-guard-runtime --all-targets) ;;
    *) echo "Unsupported archive partition" >&2; exit 64 ;;
esac
archive="${RUNNER_TEMP:?}/runtime-test-archive.tar.zst"
# Keep this filename identical to consumers: Actions cache versions bind paths.
# A previous partition's restored/built file is not this partition's output.
if [[ -e "$archive" || -L "$archive" ]]; then
    if [[ ! -f "$archive" || -L "$archive" ]]; then
        echo "Test archive staging path must be a regular file" >&2
        exit 64
    fi
    rm -- "$archive"
fi
nextest_bin="$(python3 scripts/ci/install_nextest.py)"
PATH="$nextest_bin:$PATH" cargo nextest archive --manifest-path rust/Cargo.toml \
    "${packages[@]}" --archive-file "$archive" --zstd-level 1
