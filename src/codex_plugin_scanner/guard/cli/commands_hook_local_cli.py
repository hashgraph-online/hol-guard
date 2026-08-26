"""Local CLI observation and grant helpers for hook evaluation."""

from __future__ import annotations

from pathlib import Path

from ..local_cli_hook import apply_local_cli_grant, observe_unlisted_cli
from ..models import GuardAction
from ..store import GuardStore


def local_cli_grant_action(
    *,
    store: GuardStore,
    command: str | None,
    cwd: Path,
    home_dir: Path,
    current_action: GuardAction,
    grant_allowed: bool,
) -> GuardAction:
    if command is None:
        return current_action
    observe_unlisted_cli(store=store, command=command, cwd=cwd, home_dir=home_dir)
    if not grant_allowed:
        return current_action
    return apply_local_cli_grant(
        store=store,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_action,
    )


__all__ = ["local_cli_grant_action"]
