#!/usr/bin/env bash
# Keep production/dependency optimization unchanged. Only test harnesses pay
# the cheaper code-generation cost; sccache still validates actual rustc args.
# Bash preserves Cargo variables containing hyphens (CARGO_BIN_EXE_<name>).
# POSIX sh drops those names before invoking rustc, breaking integration tests.
set -euo pipefail
for argument do
    if [ "$argument" = --test ]; then
        exec sccache "$@" -C opt-level=0
    fi
done
exec sccache "$@"
