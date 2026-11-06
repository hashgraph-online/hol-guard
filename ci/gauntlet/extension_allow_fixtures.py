"""A contributed extension set to ALLOW must settle its own action, alone and in a chain.

Guard ships the first-party extensions and a much larger set of contributed ones,
and a user who turns one on expects it to behave exactly like the built-ins they
already allowed. The catalog's only contributed-extension cases run the opposite
policy -- the extension enabled with one permission explicitly denied -- so they
prove the deny path and say nothing about the allow path. A contributed extension
whose permissions sit at ``baseline_floor: "review"`` could keep asking after the
user allowed it and no case would notice.

``command.ollama`` is the subject because the fixture already installs a recording
stand-in for its executable and its trust binding is the ordinary ``external``
class every contributed extension carries, so these cases measure the class rather
than one extension's wiring. The stand-in records that the chain physically ran,
which separates "Guard stayed silent" from "the command never happened".
"""

from __future__ import annotations

from pathlib import Path

EXTENSION_ALLOW_SOLO_CASE = "external-extension-allow-solo-action"
# The same allowed action carrying ordinary reads after it in one compound.
EXTENSION_ALLOW_COMPOUND_CASE = "external-extension-allow-action-in-compound"
EXTENSION_ALLOW_CASES = frozenset({EXTENSION_ALLOW_SOLO_CASE, EXTENSION_ALLOW_COMPOUND_CASE})
EXTENSION_ALLOW_ID = "command.ollama"


def extension_allow_checks(workspace: Path, scenario_id: str, executed_flag: str) -> dict[str, bool]:
    """The allowed action reached its executable instead of being stopped before it."""
    if scenario_id not in EXTENSION_ALLOW_CASES:
        return {}
    return {"external-extension-allow-executed": (workspace / executed_flag).is_file()}


def configure_extension_allow_controls(daemon: object, guard_home: Path) -> dict[str, object]:
    """Sign the contributed extension and every permission it declares as enabled.

    The ids come from the installed catalog, so a permission added to the
    extension is enabled here without this file changing -- and a case that
    silently stopped covering one of them would show up as a review instead.
    """
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    from .extension_adapters import configure_extension_controls

    permissions = [
        permission.permission_id
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.extension_id == EXTENSION_ALLOW_ID
        for permission in extension.permissions
    ]
    if not permissions:
        raise RuntimeError("external_extension_permissions_missing")
    revision = configure_extension_controls(daemon, guard_home, EXTENSION_ALLOW_ID, enabled_permissions=permissions)
    return {
        "extension_id": EXTENSION_ALLOW_ID,
        "enabled_permissions": permissions,
        "control_revision": revision,
    }
