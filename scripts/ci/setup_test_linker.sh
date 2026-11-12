#!/usr/bin/env bash
# Use the pinned toolchain's linker without refreshing system package indexes.
set -euo pipefail

rust_sysroot="$(rustc --print sysroot)"
rust_details="$(rustc -vV)"
rust_host=""
while IFS= read -r line; do
    case "$line" in
        'host: '*) rust_host="${line#host: }" ;;
    esac
done <<< "$rust_details"
test -n "$rust_host"
linker_bin="$rust_sysroot/lib/rustlib/$rust_host/bin/gcc-ld"
if [[ -x "$linker_bin/ld.lld" ]]; then
    "$linker_bin/ld.lld" --version
    printf '%s\n' "$linker_bin" >> "${GITHUB_PATH:?}"
elif command -v ld.lld >/dev/null 2>&1; then
    ld.lld --version
else
    echo 'The pinned Rust toolchain and runner provide no test linker.' >&2
    exit 1
fi
