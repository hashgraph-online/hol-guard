"""Reviewed extension-permission contracts for blocked-extension Gauntlet cases."""

from __future__ import annotations

import secrets
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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


def configure_extension_permission_denial(daemon: Any, guard_home: Path, adapter: ExtensionAdapter) -> dict[str, Any]:
    """Install a signed synthetic extension control for one denial case."""
    from ci.native_runtime.probe_installed_native_extensions import commit_controls, control, provision
    from codex_plugin_scanner.guard.approval_gate import update_settings
    from codex_plugin_scanner.guard.config import update_guard_settings
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
    from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState, ControlTargetKind

    password = secrets.token_urlsafe(32)
    update_guard_settings(guard_home, {"mode": "enforce"})
    update_settings(
        guard_home,
        {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
    )
    store = daemon._server.store
    provision(store)
    permission = BUILT_IN_COMMAND_EXTENSION_REGISTRY.permission_for_rule_id(adapter.rule_id)
    if permission is None or permission.permission_id != adapter.permission_id:
        raise RuntimeError(f"installed extension catalog lacks the reviewed {adapter.rule_id} permission")
    enabled = control(ControlTargetKind.EXTENSION, adapter.extension_id, ControlState.ENABLED)
    revision = commit_controls(
        store,
        password,
        (enabled, control(ControlTargetKind.PERMISSION, permission.permission_id, ControlState.DISABLED)),
    )
    return {
        "extension_id": adapter.extension_id,
        "rule_id": adapter.rule_id,
        "permission_id": permission.permission_id,
        "permission_state": "disabled",
        "control_revision": revision,
    }
