#!/usr/bin/env bash
# Keep production/dependency optimization unchanged. Only test harnesses pay
# cheaper codegen and linking; sccache still validates actual rustc args.
# Bash preserves Cargo variables containing hyphens (CARGO_BIN_EXE_<name>).
# POSIX sh drops those names before invoking rustc, breaking integration tests.
set -euo pipefail
for argument do
    if [ "$argument" = --test ]; then
        exec sccache "$@" -C opt-level=0 -C link-arg=-fuse-ld=lld
    fi
done
exec sccache "$@"
