"""Present the native local CLI grant decision.

The resident owns the decision. This module supplies only non-authoritative
inputs (the verified identity material and the command id resolved from the
command model) and maps the answer back to callers.

When the resident gives no answer, an existing block must not silently
vanish, and Python must not guess. The answer is the same
``LocalCliIdentityUnavailableError`` an identity failure raises: callers hold
an otherwise allowed command for review while block rules exist, and the
native allow path blocks. Python never reads grant rows to substitute.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from .models import GuardAction
from .native_local_cli_grant import NativeLocalCliGrantFailure, native_local_cli_grant
from .native_local_cli_identity import LocalCliIdentityUnavailableError
from .runtime.local_cli_commands import LocalCliCommand, resolve_command_id_for_text
from .runtime.local_cli_identity import UnlistedCliIdentity

_LOGGER = logging.getLogger(__name__)

GRANT_REFINABLE_ACTIONS = frozenset({"allow", "review", "require-reapproval", "warn"})
GrantOutcome = Literal["allowed", "blocked"]


def decide_local_cli_grant(
    *,
    store: object,
    identity: UnlistedCliIdentity,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
) -> GrantOutcome | None:
    """Return ``allowed``, ``blocked``, or ``None`` when no grant applies.

    Raises ``LocalCliIdentityUnavailableError`` when the resident cannot answer.
    """

    if current_action not in GRANT_REFINABLE_ACTIONS:
        return None
    try:
        command_id = _resolved_command_id(store, identity, command=command, cwd=cwd, home_dir=home_dir)
    except Exception as exc:
        # The resident checks a CLI-level block only after this read, so a
        # failed read must not look like "no grant" to callers.
        _LOGGER.warning("local CLI command catalog unavailable", exc_info=True)
        raise LocalCliIdentityUnavailableError("native_local_cli_grant_catalog_unavailable") from exc
    store_path = getattr(store, "path", None)
    guard_home = getattr(store, "guard_home", None)
    native = (
        native_local_cli_grant(
            store_path=store_path,
            guard_home=guard_home,
            current_action=current_action,
            source=identity.identity_source,
            command_id=command_id,
        )
        if isinstance(store_path, Path) and isinstance(guard_home, Path) and identity.identity_source is not None
        else None
    )
    if native is None:
        raise LocalCliIdentityUnavailableError("native_local_cli_grant_unavailable")
    if isinstance(native, NativeLocalCliGrantFailure):
        # Callers hold or block without an answer; record why so a grant that
        # stopped applying can be traced to its cause.
        _LOGGER.warning("local CLI grant decision unavailable: %s", native.code)
        raise LocalCliIdentityUnavailableError(native.code)
    if native.cli_id != identity.cli_id or native.identity_hash != identity.identity_hash:
        # The resident derived a different identity than the one Python holds.
        raise LocalCliIdentityUnavailableError("native_local_cli_grant_identity_mismatch")
    if native.state == "allowed":
        return "allowed"
    if native.state == "blocked":
        return "blocked"
    return None


def _resolved_command_id(
    store: object,
    identity: UnlistedCliIdentity,
    *,
    command: str,
    cwd: Path,
    home_dir: Path | None,
) -> str | None:
    """Resolve which catalog command the text invokes.

    The resident treats the id as a selector only. Whether a catalog exists,
    and what state the command holds, is read from the store natively.
    """

    catalog_lookup = getattr(store, "read_local_cli_command_catalog", None)
    if not callable(catalog_lookup):
        return None
    loaded = catalog_lookup(identity.cli_id)
    commands = [item for item in loaded if isinstance(item, LocalCliCommand)] if isinstance(loaded, list) else []
    if not commands:
        return None
    return resolve_command_id_for_text(
        command,
        cwd=cwd,
        home_dir=home_dir,
        identity=identity,
        commands=commands,
    )
