"""Shared managed MCP server helpers for harness adapters."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, cast

from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection
from ..runtime.mcp_protection import McpServerIdentity
from ..stable_guard_cli import guard_cli_launcher
from .base import HarnessContext
from .managed_mcp_upstream import PROXY_LAUNCHER_ENV_KEYS, proxy_argument_tail
from .mcp_relay_native import mcp_proxy_launch


@dataclass(frozen=True, slots=True)
class ManagedMcpServer:
    """A local stdio MCP server that Guard can wrap at runtime."""

    harness: str
    name: str
    source_scope: str
    config_path: str
    command: str
    args: tuple[str, ...]
    transport: str
    env: dict[str, str]
    enabled: bool
    identity: McpServerIdentity | None = None


GUARD_MCP_COMPANION_PREFIX = "hol-guard::"


def is_guard_mcp_companion_name(name: str) -> bool:
    return name.startswith(GUARD_MCP_COMPANION_PREFIX)


def is_verified_guard_mcp_companion(
    name: str,
    command: str | None,
    args: tuple[str, ...],
) -> bool:
    return is_guard_mcp_companion_name(name) and is_guard_proxy_command(command, args)


_GUARD_PROXY_COMMANDS = frozenset(
    {
        "cline-mcp-proxy",
        "codex-mcp-proxy",
        "opencode-mcp-proxy",
        "copilot-mcp-proxy",
        "cursor-mcp-proxy",
        "hermes-mcp-proxy",
        "mcp-proxy",
    }
)

_PROXY_ENV_BLOCKLIST = PROXY_LAUNCHER_ENV_KEYS


def managed_stdio_servers(detection: HarnessDetection) -> tuple[ManagedMcpServer, ...]:
    """Extract local stdio MCP servers from a harness detection payload."""

    return _kept(detection, include_guard_managed_proxy=False)


def observable_stdio_servers_with_proxy(detection: HarnessDetection) -> tuple[ManagedMcpServer, ...]:
    """Include original servers recovered from Guard's managed proxy config.

    Discovery only observes these connections; ``managed_stdio_servers`` must
    continue excluding them so install never wraps a Guard proxy again.
    """

    return _kept(detection, include_guard_managed_proxy=True)


def skipped_stdio_server_names(detection: HarnessDetection) -> tuple[str, ...]:
    """Return server names Guard cannot manage through the runtime proxy."""

    named = [
        artifact for artifact in detection.artifacts if artifact.artifact_type == "mcp_server" and artifact.name.strip()
    ]
    selected = _select(named, include_guard_managed_proxy=False)
    return tuple(artifact.name for artifact, server in zip(named, selected, strict=True) if server is None)


def proxy_cli_args(
    *,
    proxy_command: str,
    guard_home: str,
    server: ManagedMcpServer,
    home: str | None = None,
    workspace: str | None = None,
) -> list[str]:
    """Build common CLI args for a Guard-managed MCP proxy command."""

    args = [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        proxy_command,
        "--guard-home",
        guard_home,
        "--server-name",
        server.name,
        "--server-id",
        stable_mcp_server_identifier(server),
        "--source-scope",
        server.source_scope,
        "--config-path",
        server.config_path,
        "--transport",
        server.transport,
        "--command",
        server.command,
    ]
    if home is not None:
        args.extend(["--home", home])
    if workspace is not None:
        args.extend(["--workspace", workspace])
    for value in server.args:
        args.append(f"--arg={value}")
    for key in sorted(proxy_process_env(server.env)):
        if key.strip():
            args.append(f"--server-env-key={key.strip()}")
    return args


def stable_mcp_server_identifier(server: ManagedMcpServer) -> str:
    """Build a Cloud-stable MCP server ID without local config path material."""

    request: dict[str, object] = {
        "op": "server_id",
        "servers": [
            {
                "harness": server.harness,
                "name": server.name,
                "source_scope": server.source_scope,
                "command": server.command,
                "args": list(server.args),
                "transport": server.transport,
            }
        ],
    }
    ids = _native(request, "ids")
    if len(ids) != 1 or not isinstance(ids[0], str):
        raise ValueError("native_mcp_server_select_malformed")
    return ids[0]


def proxy_process_env(server_env: dict[str, str]) -> dict[str, str]:
    """Return untrusted server env entries that are safe to inject into the Guard proxy."""

    filtered: dict[str, str] = {}
    for key, value in server_env.items():
        normalized_key = key.strip()
        if not normalized_key or normalized_key.upper() in _PROXY_ENV_BLOCKLIST:
            continue
        filtered[normalized_key] = value
    return filtered


def proxy_launcher_entry(
    *,
    proxy_command: str,
    context: HarnessContext,
    server: ManagedMcpServer,
) -> dict[str, object]:
    """Build the shared command/args/env mapping that launches a Guard MCP proxy."""

    args = proxy_cli_args(
        proxy_command=proxy_command,
        guard_home=str(context.guard_home),
        server=server,
        home=str(context.home_dir) if context.home_dir.resolve() != Path.home().resolve() else None,
        workspace=str(context.workspace_dir) if context.workspace_dir is not None else None,
    )
    command, launch_args = mcp_proxy_launch(guard_cli_launcher(), args)
    entry: dict[str, object] = {
        "command": command,
        "args": launch_args,
    }
    env = merge_guard_launcher_env(proxy_process_env(getattr(server, "env", {})))
    if env:
        entry["env"] = env
    return entry


def _kept(detection: HarnessDetection, *, include_guard_managed_proxy: bool) -> tuple[ManagedMcpServer, ...]:
    servers = [artifact for artifact in detection.artifacts if artifact.artifact_type == "mcp_server"]
    selected = _select(servers, include_guard_managed_proxy=include_guard_managed_proxy)
    return tuple(server for server in selected if server is not None)


def _select(artifacts: list[GuardArtifact], *, include_guard_managed_proxy: bool) -> list[ManagedMcpServer | None]:
    """Ask the native ``select`` op which ``mcp_server`` artifacts Guard can run behind its proxy.

    One request carries every artifact. The answer names each one's server, or
    null; a server recovered from a Guard proxy is inventory, never permission.
    """

    selected: list[ManagedMcpServer | None] = [None] * len(artifacts)
    positions: list[int] = []
    requests: list[dict[str, object]] = []
    for index, artifact in enumerate(artifacts):
        request = _select_request(artifact)
        if request is not None:
            positions.append(index)
            requests.append(request)
    if not requests:
        return selected
    answer = _native(
        {"op": "select", "include_proxy": include_guard_managed_proxy, "artifacts": requests},
        "servers",
    )
    if len(answer) != len(requests):
        raise ValueError("native_mcp_server_select_malformed")
    for index, found in zip(positions, answer, strict=True):
        if found is not None:
            selected[index] = _selected_server(artifacts[index], found)
    return selected


def _select_request(artifact: GuardArtifact) -> dict[str, object] | None:
    private = artifact.runtime_private_metadata
    args: tuple[object, ...] = artifact.args
    private_args = private.get("mcp_args")
    if isinstance(private_args, tuple):
        args = cast(tuple[object, ...], private_args)
        if not all(isinstance(value, str) for value in args):
            return None
    env = private.get("mcp_env", artifact.metadata.get("env"))
    saved = private.get("managed_mcp_origin")
    saved_home = private.get("managed_guard_home")
    request: dict[str, object] = {
        "harness": artifact.harness,
        "name": artifact.name,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "args": list(args),
        "transport": artifact.transport,
        "env": _env_pairs(env),
        "guard_managed_proxy": artifact.metadata.get("guard_managed_proxy") is True,
        "enabled": artifact.metadata.get("enabled") is not False,
        "saved_origin": (
            list(cast(tuple[str, ...], saved))
            if isinstance(saved, tuple) and all(isinstance(value, str) for value in cast(tuple[object, ...], saved))
            else None
        ),
        "saved_guard_home": saved_home if isinstance(saved_home, str) else None,
    }
    # The resident refuses a whole request holding text it cannot encode, so
    # one such entry is left out rather than failing every other server.
    try:
        json.dumps(request, ensure_ascii=False).encode()
    except UnicodeEncodeError:
        return None
    return request


def _env_pairs(env: object) -> list[list[str]] | None:
    """The string pairs of a configured env mapping; None when it is not one."""

    if not isinstance(env, dict):
        return None
    return [
        [key, value]
        for key, value in cast(dict[object, object], env).items()
        if isinstance(key, str) and isinstance(value, str)
    ]


def _selected_server(artifact: GuardArtifact, found: object) -> ManagedMcpServer:
    try:
        server = cast(dict[str, Any], found)
        identity = cast(dict[str, Any], server["identity"])
        return ManagedMcpServer(
            harness=artifact.harness,
            name=artifact.name,
            source_scope=_text(server["source_scope"]),
            config_path=_text(server["config_path"]),
            command=_text(server["command"]),
            args=tuple(_text(value) for value in server["args"]),
            transport=_text(server["transport"]),
            env={_text(key): _text(value) for key, value in server["env"]},
            enabled=server["enabled"] is True,
            identity=McpServerIdentity(
                config_path=_text(identity["config_path"]),
                command=_text(identity["command"]),
                args_hash=_text(identity["args_hash"]),
                package_name=identity["package_name"],
                package_version=identity["package_version"],
                package_source=_text(identity["package_source"]),
                transport=_text(identity["transport"]),
                env_values_hash=_text(identity["env_values_hash"]),
                identity_hash=_text(identity["identity_hash"]),
                env_keys=tuple(_text(key) for key in identity["env_keys"]),
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("native_mcp_server_select_malformed") from error


def _native(request: dict[str, object], field: str) -> list[object]:
    """One ``harness_mcp_discovery`` call; a native failure aborts as identity unavailable."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority("harness_mcp_discovery", request)[field]
    except NativeRunnerAuthorityError as error:
        raise ValueError(f"native_mcp_server_identity_unavailable:{error}") from error
    except KeyError as error:
        raise ValueError("native_mcp_server_select_malformed") from error
    if not isinstance(answer, list):
        raise ValueError("native_mcp_server_select_malformed")
    return cast(list[object], answer)


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("harness_mcp_discovery select field is malformed")
    return value


def _hol_guard_command_name(command: str) -> str | None:
    cmd_name = PurePath(command.replace("\\", "/")).name.lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if cmd_name.endswith(suffix):
            cmd_name = cmd_name[: -len(suffix)]
            break
    return cmd_name if cmd_name in {"hol-guard", "current-hol-guard"} else None


def is_guard_proxy_command(command: str | None, args: tuple[str, ...]) -> bool:
    if not isinstance(command, str):
        return False
    if _hol_guard_command_name(command) is not None:
        # Packaged launchers also receive generated Python-module argv from
        # existing adapter installations. Recognize that exact prefix too.
        return proxy_argument_tail(args, _GUARD_PROXY_COMMANDS) is not None
    if "codex_plugin_scanner.cli" not in args or "guard" not in args:
        return False
    return any(value in _GUARD_PROXY_COMMANDS for value in args)


__all__ = [
    "GUARD_MCP_COMPANION_PREFIX",
    "ManagedMcpServer",
    "is_guard_mcp_companion_name",
    "is_guard_proxy_command",
    "is_verified_guard_mcp_companion",
    "managed_stdio_servers",
    "observable_stdio_servers_with_proxy",
    "proxy_cli_args",
    "proxy_launcher_entry",
    "proxy_process_env",
    "skipped_stdio_server_names",
    "stable_mcp_server_identifier",
]
