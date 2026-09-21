"""Detached daemon recovery worker for bounded harness hooks."""

from __future__ import annotations

import sys
from contextlib import suppress
from pathlib import Path
from typing import cast

from .manager import (
    _GUARD_DAEMON_RECOVERY_WORKER_TIMEOUT_SECONDS,
    GuardDaemonHookFailureKind,
    clear_guard_daemon_recovery_reservation,
    recover_guard_daemon_after_hook_failure,
)


def main() -> int:
    if len(sys.argv) != 5:
        return 2
    guard_home, home_dir, raw_failure_kind, recovery_token = sys.argv[1:]
    failure_kind: GuardDaemonHookFailureKind
    if raw_failure_kind not in {
        "authenticated-control-plane-failure",
        "overload",
        "transport-failure",
    }:
        return 2
    failure_kind = cast(GuardDaemonHookFailureKind, raw_failure_kind)
    guard_home_path = Path(guard_home)
    try:
        _ = recover_guard_daemon_after_hook_failure(
            guard_home_path,
            home_dir=Path(home_dir),
            failure_kind=failure_kind,
            recovery_lock_timeout_seconds=_GUARD_DAEMON_RECOVERY_WORKER_TIMEOUT_SECONDS,
        )
    finally:
        with suppress(OSError, RuntimeError, ValueError):
            _ = clear_guard_daemon_recovery_reservation(
                guard_home_path,
                token=recovery_token,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
