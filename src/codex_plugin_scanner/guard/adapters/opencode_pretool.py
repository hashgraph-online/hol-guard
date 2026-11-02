"""OpenCode pretool plugin generation for HOL Guard runtime interception.

The native runtime owns the plugin template and renders it from the attested
Guard CLI this module resolves.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..codex_hook_windows_job import windows_system_executable_path
from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from .base import HarnessContext
from .bounded_cli_hook_bridge import bounded_cli_hook_command
from .guard_cli_attestation import executable_identity_payload, resolve_attested_guard_cli

PLUGIN_FILENAME = "hol-guard-pretool.ts"
_HOOK_TIMEOUT_SECONDS = 25


def managed_plugin_path(context: HarnessContext) -> Path:
    return context.guard_home / "opencode" / "plugins" / PLUGIN_FILENAME


def global_plugin_path(context: HarnessContext) -> Path:
    return context.home_dir / ".config" / "opencode" / "plugins" / PLUGIN_FILENAME


def pretool_plugin_source(context: HarnessContext) -> str:
    guard_cli = resolve_attested_guard_cli(context)
    identity = guard_cli.frozen_identity or (guard_cli.python.identity if guard_cli.python is not None else None)
    if identity is None:
        raise RuntimeError("Guard could not attest the OpenCode hook runtime.")
    native_bridge_argv: list[str] | None = None
    import_roots: list[str] = []
    if guard_cli.python is not None:
        # The plugin fills in the interpreter and the per-workspace CLI argv
        # when it runs a hook; the native kind keeps this argv only when it is
        # the bounded native bridge.
        native_bridge_argv = list(
            bounded_cli_hook_command(
                python_executable=str(guard_cli.python.executable),
                package_root=Path(__file__).resolve().parents[3],
                guard_home=context.guard_home,
                cli_args=[],
                harness="opencode",
                timeout_seconds=_HOOK_TIMEOUT_SECONDS,
            )
        )
        import_roots = [str(root) for root in guard_cli.python.import_roots]
    try:
        taskkill_path = windows_system_executable_path("taskkill.exe") if os.name == "nt" else None
    except (OSError, ValueError):
        taskkill_path = None
    args = {
        "guard_home": str(context.guard_home.resolve()),
        "python": executable_identity_payload(identity),
        "frozen": guard_cli.frozen,
        "native_bridge_argv": native_bridge_argv,
        "import_roots": import_roots,
        "taskkill_path": taskkill_path,
    }
    try:
        source = native_runner_authority("opencode_plugin_render", args, guard_home=context.guard_home).get("source")
    except NativeRunnerAuthorityError as error:
        raise RuntimeError(f"Guard could not render the OpenCode plugin: {error}") from error
    if not isinstance(source, str):
        raise RuntimeError("Guard could not render the OpenCode plugin.")
    return source


def install_pretool_plugin(context: HarnessContext) -> dict[str, object]:
    source = pretool_plugin_source(context)
    managed_path = managed_plugin_path(context)
    global_path = global_plugin_path(context)
    managed_path.parent.mkdir(parents=True, exist_ok=True)
    global_path.parent.mkdir(parents=True, exist_ok=True)
    managed_path.write_text(source, encoding="utf-8")
    global_path.write_text(source, encoding="utf-8")
    return {
        "managed_plugin_path": str(managed_path),
        "global_plugin_path": str(global_path),
    }


def remove_pretool_plugin(context: HarnessContext) -> dict[str, object]:
    managed_path = managed_plugin_path(context)
    global_path = global_plugin_path(context)
    removed_paths: list[str] = []
    for path in (global_path, managed_path):
        if path.is_file():
            path.unlink()
            removed_paths.append(str(path))
    return {"removed_plugin_paths": removed_paths}


def opencode_config_has_mcp_servers(config_path: Path) -> bool:
    from ...ecosystems.opencode import _load_json_or_jsonc

    if not config_path.is_file():
        return False
    payload, parse_error, _ = _load_json_or_jsonc(config_path)
    if parse_error or not isinstance(payload, dict):
        return False
    mcp = payload.get("mcp")
    return isinstance(mcp, dict) and bool(mcp)


def _mcp_command_uses_guard_proxy(command: object) -> bool:
    if isinstance(command, list):
        return any("opencode-mcp-proxy" in str(part) for part in command)
    if isinstance(command, str):
        return "opencode-mcp-proxy" in command
    return False


def opencode_config_uses_guard_proxy(config_path: Path) -> bool:
    from ...ecosystems.opencode import _load_json_or_jsonc

    if not config_path.is_file():
        return False
    payload, parse_error, _ = _load_json_or_jsonc(config_path)
    if parse_error or not isinstance(payload, dict):
        return False
    mcp = payload.get("mcp")
    if not isinstance(mcp, dict):
        return False
    native_servers: dict[str, dict[str, object]] = {}
    companions: dict[str, dict[str, object]] = {}
    for name, server in mcp.items():
        if not isinstance(name, str) or not isinstance(server, dict):
            continue
        if name.startswith("hol-guard::"):
            companions[name] = server
        else:
            native_servers[name] = server
    if not native_servers:
        return any(_mcp_command_uses_guard_proxy(server.get("command")) for server in companions.values())
    for name, server in native_servers.items():
        if _mcp_command_uses_guard_proxy(server.get("command")):
            continue
        companion = companions.get(f"hol-guard::{name}")
        if companion is None or not _mcp_command_uses_guard_proxy(companion.get("command")):
            return False
    return True


__all__ = [
    "PLUGIN_FILENAME",
    "global_plugin_path",
    "install_pretool_plugin",
    "managed_plugin_path",
    "opencode_config_has_mcp_servers",
    "opencode_config_uses_guard_proxy",
    "pretool_plugin_source",
    "remove_pretool_plugin",
]
