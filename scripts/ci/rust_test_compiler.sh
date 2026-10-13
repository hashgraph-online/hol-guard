#!/bin/sh
# Keep production/dependency optimization unchanged. Only test harnesses pay
# the cheaper code-generation cost; sccache still validates actual rustc args.
set -eu
for argument do
    if [ "$argument" = --test ]; then
        exec sccache "$@" -C opt-level=0
    fi
done
exec sccache "$@"
