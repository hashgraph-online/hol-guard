"""Leaf command builders shared by frozen Guard harness adapters."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .stable_guard_cli import resolve_frozen_guard_cli

FROZEN_CODEX_BRIDGE_ARG = "--_hol-guard-codex-bridge"
FROZEN_DAEMON_RECOVER_ARG = "--_hol-guard-codex-daemon-recover"
FROZEN_DAEMON_RECOVERY_WORKER_ARG = "--_hol-guard-codex-daemon-recovery-worker"


def frozen_codex_bridge_tokens_are_live(tokens: Sequence[str]) -> bool:
    """Return whether argv matches the frozen Codex private-bridge contract."""

    try:
        flag_index = tokens.index(FROZEN_CODEX_BRIDGE_ARG)
    except ValueError:
        return False
    if flag_index + 1 >= len(tokens):
        return False
    try:
        payload = json.loads(tokens[flag_index + 1])
    except (json.JSONDecodeError, TypeError, ValueError):
        return False
    return isinstance(payload, dict)


def is_frozen_guard_runtime() -> bool:
    """Return whether this process is a PyInstaller-style frozen Guard binary."""

    return bool(getattr(sys, "frozen", False)) and Path(sys.executable).is_file()


def _recovery_executable(executable: str | None) -> str:
    if executable is not None:
        return executable
    if is_frozen_guard_runtime():
        return resolve_frozen_guard_cli()
    return sys.executable


def frozen_daemon_recovery_command(
    guard_home: Path,
    home_dir: Path,
    *,
    executable: str | None = None,
) -> tuple[str, ...]:
    """Build the authenticated frozen-Core daemon recovery command."""

    payload = json.dumps(
        {
            "guard_home": str(guard_home.resolve(strict=False)),
            "home_dir": str(home_dir.resolve(strict=False)),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return (_recovery_executable(executable), FROZEN_DAEMON_RECOVER_ARG, payload)


def frozen_daemon_recovery_worker_command(
    guard_home: Path,
    home_dir: Path,
    failure_kind: str,
    recovery_token: str,
    *,
    executable: str | None = None,
) -> tuple[str, ...]:
    """Build the detached frozen-Core recovery worker command."""

    payload = json.dumps(
        {
            "failure_kind": failure_kind,
            "guard_home": str(guard_home.resolve(strict=False)),
            "home_dir": str(home_dir.resolve(strict=False)),
            "recovery_token": recovery_token,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return (_recovery_executable(executable), FROZEN_DAEMON_RECOVERY_WORKER_ARG, payload)


__all__ = [
    "FROZEN_CODEX_BRIDGE_ARG",
    "FROZEN_DAEMON_RECOVERY_WORKER_ARG",
    "FROZEN_DAEMON_RECOVER_ARG",
    "frozen_codex_bridge_tokens_are_live",
    "frozen_daemon_recovery_command",
    "frozen_daemon_recovery_worker_command",
    "is_frozen_guard_runtime",
]
