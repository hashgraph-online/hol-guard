"""Single Codex install plan segments, for tests.

The runtime's ``install_plan`` op composes these segments; a test asks the
native op for one segment and compares the captured files against disk, as
the composed plan does.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.codex_config import _Wire
from codex_plugin_scanner.guard.codex_harness_client import _codex, _reply_text, _runtime_guard_home
from codex_plugin_scanner.guard.codex_hook_self_binding import install_fields, short_path_fields
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.mcp_server_client import ManagedMcpServer
from codex_plugin_scanner.guard.native_harness_steps import planned_files
from codex_plugin_scanner.guard.runtime_transition import TransitionFile
from tests.codex_install_flow_support import legacy_fields
from tests.codex_toml_support import _restore_native
from tests.mcp_proxy_launcher import python_proxy_launcher_entry


def _one_planned_file(answer: dict[str, Any]) -> TransitionFile:
    return planned_files({"files": [answer["file"]]})[0]


@dataclass(frozen=True, slots=True)
class PreparedCodexHookMigration:
    """Captured JSON migration segment; publication requires the complete install."""

    config_payload: dict[str, object]
    files: tuple[TransitionFile, ...]


def prepare_codex_hook_migration(
    context: HarnessContext,
    *,
    config_path: Path,
    hooks_path: Path,
    owned_bindings: Sequence[Mapping[str, object]] = (),
    require_owners: bool = False,
) -> PreparedCodexHookMigration:
    """Fold one ``hooks.json`` into its ``config.toml``, as the native
    ``hook_migration`` op plans it: the config rewrite, the retired JSON
    source and a backup of the config it replaces."""
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition

    request: dict[str, Any] = {
        "config": str(config_path),
        "hooks": str(hooks_path),
        "owned": json.dumps(list(owned_bindings), separators=(",", ":")),
        "require_owners": require_owners,
        **legacy_fields(context),
        **install_fields(_runtime_guard_home(context), None),
        **short_path_fields(),
    }
    answer = _codex("hook_migration", context, **request)
    tokens = answer.get("tokens")
    if not isinstance(tokens, dict):
        raise ValueError("Harness adapter answer is malformed")
    config = _restore_native(json.loads(_reply_text(answer, "config")), tokens)
    if not isinstance(config, dict):
        raise ValueError("Harness adapter answer is malformed")
    files = planned_files({"files": answer.get("files")})
    RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
    return PreparedCodexHookMigration(config, tuple(files))


def render_codex_managed_mcp(
    context: HarnessContext,
    payload: dict[str, object],
    *,
    managed_servers: tuple[ManagedMcpServer, ...],
    workspace_payload: dict[str, object],
) -> tuple[dict[str, object], tuple[str, ...]]:
    """Render proxy refresh and workspace precedence from captured payloads."""
    entries = [
        (server, python_proxy_launcher_entry(proxy_command="codex-mcp-proxy", context=context, server=server))
        for server in managed_servers
    ]
    wire = _Wire(payload, workspace_payload, *(entry for _server, entry in entries))
    fields: dict[str, object] = {
        "payload": wire.text(payload),
        "workspace_payload": None if context.workspace_dir is None else wire.text(workspace_payload),
        "servers": [
            {"name": server.name, "source_scope": server.source_scope, "entry": wire.text(entry)}
            for server, entry in entries
        ],
    }
    answer = _codex("managed_mcp", context, **fields)
    rendered = wire.decode(_reply_text(answer, "rendered"))
    return rendered, tuple(str(name) for name in answer["migrated"])


def prepare_codex_alternate_cleanup(
    context: HarnessContext,
    *,
    config_path: Path,
    remove_hooks: bool = True,
    managed_server_names: Sequence[str] = (),
) -> TransitionFile:
    """Capture one cleanup segment; this is not a complete Codex install plan."""
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition

    request: dict[str, Any] = {
        "config": str(config_path),
        "remove_hooks": remove_hooks,
        "managed_server_names": list(managed_server_names),
        **legacy_fields(context),
        **install_fields(_runtime_guard_home(context), None),
        **short_path_fields(),
    }
    answer = _codex("alternate_change", context, **request)
    change = _one_planned_file(answer)
    RuntimeTransition._compare({"files": [change.payload()]}, "before")
    return change


def prepare_codex_shell_cleanup(context: HarnessContext) -> tuple[TransitionFile, ...]:
    """Capture all legacy shell removals without reading through symlinks or publishing."""
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition

    files = tuple(planned_files(_codex("shell_cleanup", context)))
    RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
    return files
