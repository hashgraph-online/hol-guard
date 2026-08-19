"""Hook-time observation and grant application for unlisted CLIs."""

from __future__ import annotations

from pathlib import Path

from .local_cli_trust import matching_local_cli_grant, utc_now
from .models import GuardAction
from .runtime.custom_extension_suggestion import observation_path_class
from .runtime.local_cli_identity import identify_unlisted_cli


def observe_unlisted_cli(
    *,
    store: object,
    command: str,
    cwd: Path,
    home_dir: Path | None,
) -> None:
    identity = identify_unlisted_cli(command, cwd=cwd, home_dir=home_dir)
    if identity is None:
        return
    recorder = getattr(store, "record_local_cli_observation", None)
    if not callable(recorder):
        return
    recorder(identity, seen_at=utc_now(), source_path=observation_path_class(identity.source_path))


def apply_local_cli_grant(
    *,
    store: object,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
) -> GuardAction:
    matched = matching_local_cli_grant(
        store=store,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_action,
    )
    if matched is None:
        return current_action
    _identity, state = matched
    if state == "allowed":
        return "allow"
    return "block"
