"""Hook-time observation and grant application for unlisted CLIs."""

from __future__ import annotations

from pathlib import Path

from .local_cli_trust import matching_local_cli_grant, utc_now
from .models import GuardAction
from .runtime.custom_extension_suggestion import observation_path_class
from .runtime.local_cli_identity import identify_unlisted_cli
from .runtime.package_json_scripts import identify_package_json_scripts, recognize_package_json_scripts


def observe_unlisted_cli(
    *,
    store: object,
    command: str,
    cwd: Path,
    home_dir: Path | None,
) -> None:
    package_identity = identify_package_json_scripts(command, cwd=cwd, home_dir=home_dir)
    identity = package_identity or identify_unlisted_cli(command, cwd=cwd, home_dir=home_dir)
    if identity is None:
        return
    recorder = getattr(store, "record_local_cli_observation", None)
    if not callable(recorder):
        return
    recorder(
        identity,
        seen_at=utc_now(),
        source_path=observation_path_class(identity.source_path),
        surface="package-scripts" if package_identity is not None else "cli",
    )
    if package_identity is not None:
        discovery = recognize_package_json_scripts(command, cwd=cwd, home_dir=home_dir or cwd)
        replace_commands = getattr(store, "replace_local_cli_commands", None)
        if discovery is not None and callable(replace_commands):
            replace_commands(discovery.identity.cli_id, discovery.commands)


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
