"""Reviewed extension-permission contracts for blocked-extension Gauntlet cases."""

from __future__ import annotations

import functools
import os
import secrets
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# An unreleased candidate's optional packs are not on GitHub yet. The wheel
# build exports them (HOL_GUARD_BUNDLE_ASSET_OUTPUT) and this names that
# directory, so enabling an optional extension prepares the candidate's own pack.
RELEASE_ASSETS_ENV = "GUARD_GAUNTLET_RELEASE_ASSETS"


@dataclass(frozen=True)
class ExtensionAdapter:
    """One executable whose disabled permission the runner signs and the oracle verifies."""

    executable: str
    extension_id: str
    rule_id: str
    permission_id: str
    label: str


# The oracle checks native evidence against this table, not against the
# installed catalog, so a catalog that remaps a rule cannot pass silently.
EXTENSION_ADAPTERS = {
    adapter.executable: adapter
    for adapter in (
        ExtensionAdapter(
            "ollama",
            "command.ollama",
            "command.ollama.rm",
            "command.ollama.permission.rm",
            "ollama remove",
        ),
        ExtensionAdapter(
            "gws",
            "command.google-workspace.gws",
            "command.google-workspace.gws.send",
            "command.google-workspace.gws.permission.send",
            "Google Workspace send",
        ),
        ExtensionAdapter(
            "sf",
            "command.salesforce.sf",
            "command.salesforce.sf.delete",
            "command.salesforce.sf.permission.delete",
            "Salesforce delete",
        ),
        ExtensionAdapter(
            "gh",
            "command.github",
            "command.github.delete",
            "command.github.permission.delete-remote",
            "GitHub delete",
        ),
    )
}


def extension_adapter(command: str) -> ExtensionAdapter:
    """Return the reviewed adapter for a single-command blocked-extension case."""
    try:
        words = shlex.split(command)
    except ValueError as error:
        raise ValueError("blocked-extension command is not valid shell syntax") from error
    adapter = EXTENSION_ADAPTERS.get(words[0]) if words else None
    if adapter is None:
        raise ValueError("blocked-extension command has no reviewed extension adapter")
    return adapter


@functools.cache
def _serve_candidate_release_assets() -> None:
    directory = os.environ.get(RELEASE_ASSETS_ENV)
    if not directory:
        return
    from ci.native_runtime.installed_extension_probe_support import serve_release_assets

    path = Path(directory)
    if not path.is_dir():
        raise RuntimeError(f"{RELEASE_ASSETS_ENV} is not a directory")
    serve_release_assets(path)


def _authorize_extension_controls(daemon: Any, guard_home: Path) -> str:
    """Enforce, set the approval-gate password and enroll the control authority."""
    from ci.native_runtime.probe_installed_native_extensions import provision
    from codex_plugin_scanner.guard.approval_gate import update_settings
    from codex_plugin_scanner.guard.config import update_guard_settings

    _serve_candidate_release_assets()
    password = secrets.token_urlsafe(32)
    update_guard_settings(guard_home, {"mode": "enforce"})
    update_settings(
        guard_home,
        {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
    )
    store = daemon._server.store
    provision(store)
    # The daemon started before enrollment, so run the installed-release
    # migration its startup would have run against an enrolled authority. That
    # records the pack floor an optional extension's enable is prepared from.
    # Enrollment stays at revision 0, so the control service only picks up the
    # protected authority on an explicit refresh.
    store.migrate_installed_command_pack_authority()
    daemon._server.extension_control_api.refresh()
    return password


def _commit_extension_controls(
    daemon: Any, password: str, extension_id: str, permissions: tuple[tuple[str, bool], ...]
) -> int:
    """Commit one signed local-admin layer enabling an extension and setting each permission.

    The commit goes through the daemon's control service, the path an installed
    enable takes, so it prepares the extension's optional pack first.
    """
    from ci.native_runtime.probe_installed_native_extensions import commit_controls, control
    from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState, ControlTargetKind

    controls = [control(ControlTargetKind.EXTENSION, extension_id, ControlState.ENABLED)]
    controls += [
        control(ControlTargetKind.PERMISSION, permission, ControlState.ENABLED if enabled else ControlState.DISABLED)
        for permission, enabled in permissions
    ]
    return commit_controls(daemon._server.extension_control_api, password, tuple(controls))


def configure_extension_controls(
    daemon: Any, guard_home: Path, extension_id: str, *, enabled_permissions: list[str]
) -> int:
    """Enable an extension with every listed permission explicitly allowed."""
    password = _authorize_extension_controls(daemon, guard_home)
    return _commit_extension_controls(
        daemon, password, extension_id, tuple((permission, True) for permission in enabled_permissions)
    )


def configure_extension_permission_denial(daemon: Any, guard_home: Path, adapter: ExtensionAdapter) -> dict[str, Any]:
    """Install a signed synthetic extension control for one denial case.

    An optional extension's permissions join the active catalog only once the
    extension is enabled, so enable it first and then look the permission up.
    """
    password = _authorize_extension_controls(daemon, guard_home)
    _commit_extension_controls(daemon, password, adapter.extension_id, ())
    registry = daemon._server.extension_control_api._registry
    permission = registry.permission_for_rule_id(adapter.rule_id)
    if permission is None or permission.permission_id != adapter.permission_id:
        raise RuntimeError(f"installed extension catalog lacks the reviewed {adapter.rule_id} permission")
    revision = _commit_extension_controls(daemon, password, adapter.extension_id, ((permission.permission_id, False),))
    return {
        "extension_id": adapter.extension_id,
        "rule_id": adapter.rule_id,
        "permission_id": permission.permission_id,
        "permission_state": "disabled",
        "control_revision": revision,
    }
