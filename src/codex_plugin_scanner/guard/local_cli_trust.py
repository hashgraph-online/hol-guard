"""This-device allow and block grants for unlisted CLIs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .local_cli_grant_decision import GRANT_REFINABLE_ACTIONS, decide_local_cli_grant
from .models import GuardAction
from .native_local_cli_identity import LocalCliIdentityUnavailableError, track_local_cli_identity_failures
from .native_rich_command_model import NativeCommandModelError
from .runtime.local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli
from .runtime.package_json_scripts import identify_package_json_scripts

LocalCliGrantState = Literal["allowed", "blocked"]


def matching_local_cli_grant(
    *,
    store: object,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
) -> tuple[UnlistedCliIdentity, LocalCliGrantState] | None:
    """Return an enrolled grant when the command matches an unlisted CLI identity.

    Raises ``LocalCliIdentityUnavailableError`` when the identity could not be
    derived, so callers can fail closed instead of treating it as no grant.
    """

    if current_action not in GRANT_REFINABLE_ACTIONS:
        return None
    try:
        with track_local_cli_identity_failures() as failures:
            identity = identify_package_json_scripts(command, cwd=cwd, home_dir=home_dir)
            if identity is None:
                identity = identify_unlisted_cli(command, cwd=cwd, home_dir=home_dir)
    except NativeCommandModelError as error:
        raise LocalCliIdentityUnavailableError(str(error)) from error
    # A failed script derivation can fall through to the binary's identity.
    if failures:
        raise LocalCliIdentityUnavailableError(failures[0])
    if identity is None:
        return None
    # The resident reads the grant rows and decides; this raises
    # ``LocalCliIdentityUnavailableError`` when it gives no answer.
    outcome = decide_local_cli_grant(
        store=store,
        identity=identity,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_action,
    )
    return None if outcome is None else (identity, outcome)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
