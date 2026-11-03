"""Bounded stdio MCP initialize + tools/list probe for custom extensions."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .command_model import parse_shell_command
from .local_cli_commands import OTHER_COMMAND_ID, LocalCliCommand
from .local_cli_identity import (
    UnlistedCliIdentity,
    identify_unlisted_cli,
    unlisted_cli_invocation_is_safe,
)
from .local_mcp_stdio import (
    MCP_PACKAGE_PROBE_TIMEOUT_SECONDS,
    MCP_PROBE_TIMEOUT_SECONDS,
    McpCatalogResult,
    probe_search_path,
    run_mcp_catalog,
)
from .mcp_protection import McpServerIdentity, build_mcp_server_identity

McpProbeStatus = Literal["ok", "empty", "failed"]
McpToolsRunner = Callable[[Sequence[str]], list[dict[str, object]] | None]


class McpProbeError(RuntimeError):
    """Finite diagnostic for an explicitly configured MCP connection."""

    def __init__(self, reason: str | None) -> None:
        self.code = {
            "invalid_launch": "mcp_launch_failed",
            "transport_failed": "mcp_transport_failed",
            "initialize_failed": "mcp_initialize_failed",
            "invalid_initialize": "mcp_initialize_failed",
            "invalid_discovery": "mcp_initialize_failed",
            "unsupported_protocol": "mcp_protocol_unsupported",
            "discovery_rejected": "mcp_capability_rejected",
        }.get(reason or "", "discovery_failed")
        super().__init__(self.code)


_PACKAGE_LAUNCHERS = frozenset({"bunx", "npx", "npm", "pnpm", "uvx", "yarn", "pipx"})
_STRICT_PACKAGE_LAUNCHERS = frozenset({"bunx", "npx", "pipx", "uvx"})


@dataclass(frozen=True, slots=True)
class McpProbeResult:
    identity: UnlistedCliIdentity
    server_identity: McpServerIdentity
    tools: tuple[LocalCliCommand, ...]
    status: McpProbeStatus
    argv: tuple[str, ...]
    catalog: McpCatalogResult | None = None


def mcp_launch_tokens(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> tuple[str, ...] | None:
    """Return launch tokens when the pasted text is one safe invocation."""

    try:
        model = parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    except ValueError:
        return None
    if not unlisted_cli_invocation_is_safe(model) or not model.segments:
        return None
    segment = model.segments[0]
    executable = segment.executable
    if executable is None or not executable.strip():
        return None
    return (executable, *segment.arguments)


def is_package_mcp_launcher(tokens: Sequence[str]) -> bool:
    if not tokens:
        return False
    name = _executable_basename(tokens[0])
    if name not in _PACKAGE_LAUNCHERS:
        return False
    identity = build_mcp_server_identity(
        config_path="",
        command=tokens[0],
        args=tuple(tokens[1:]),
        transport="stdio",
    )
    return bool(identity.package_name)


def is_strict_package_mcp_launcher(tokens: Sequence[str]) -> bool:
    return is_package_mcp_launcher(tokens) and _executable_basename(tokens[0]) in _STRICT_PACKAGE_LAUNCHERS


def looks_like_mcp_launch(
    tokens: Sequence[str],
    *,
    command_text: str,
    cwd: Path,
    home_dir: Path | None,
) -> bool:
    if is_package_mcp_launcher(tokens):
        return True
    return identify_unlisted_cli(command_text, cwd=cwd, home_dir=home_dir) is not None


def probe_stdio_mcp_server(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    runner: McpToolsRunner | None = None,
    timeout: float | None = None,
    extra_env: Mapping[str, str] | None = None,
    cancel: threading.Event | None = None,
    connection_identity_hash: str | None = None,
    report_failure: bool = False,
    guard_home: Path | None = None,
) -> McpProbeResult | None:
    """Launch a stdio MCP server and list tools, or return None when it is not MCP."""

    tokens = mcp_launch_tokens(command_text, cwd=cwd, home_dir=home_dir)
    if tokens is None:
        return None
    server_identity = build_mcp_server_identity(
        config_path="",
        command=tokens[0],
        args=tuple(tokens[1:]),
        transport="stdio",
    )
    argv = _resolve_launch_argv(tokens, cwd=cwd)
    if argv is None or (report_failure and not Path(argv[0]).is_file()):
        if report_failure:
            raise McpProbeError("invalid_launch")
        return None
    resolved_timeout = _timeout_for(tokens, timeout)
    if runner is not None:
        raw_tools = runner(argv)
        if raw_tools is None:
            return None
        catalog = McpCatalogResult(tuple(raw_tools), complete=True)
    else:
        catalog = run_mcp_catalog(
            argv,
            timeout=resolved_timeout,
            extra_env=extra_env,
            cancel=cancel,
            connection_identity_hash=connection_identity_hash or server_identity.identity_hash,
            guard_home=guard_home,
        )
        if catalog.protocol_version is None:
            if report_failure:
                raise McpProbeError(catalog.reason)
            return None
        raw_tools = list(catalog.tools)
    tools = _tools_from_payload(raw_tools, server_name=_display_name(server_identity, tokens))
    status: McpProbeStatus = "ok" if any(tool.command_id != OTHER_COMMAND_ID for tool in tools) else "empty"
    if not catalog.complete and not raw_tools:
        status = "failed"
    identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{server_identity.identity_hash[:8]}",
        name=_display_name(server_identity, tokens),
        kind="executable",
        identity_hash=server_identity.identity_hash,
        example_label=_example_label(tokens),
        interpreter_name=None,
    )
    return McpProbeResult(
        identity=identity,
        server_identity=server_identity,
        tools=tools,
        status=status,
        argv=argv,
        catalog=catalog,
    )


def _timeout_for(tokens: Sequence[str], timeout: float | None) -> float:
    if timeout is not None:
        return timeout
    return MCP_PACKAGE_PROBE_TIMEOUT_SECONDS if is_package_mcp_launcher(tokens) else MCP_PROBE_TIMEOUT_SECONDS


def _resolve_launch_argv(tokens: Sequence[str], *, cwd: Path) -> tuple[str, ...] | None:
    """The argv a probe launches, resolved by the native ``local_mcp_probe`` kind."""

    request = {"op": "launch", "tokens": list(tokens), "cwd": str(cwd), "search_path": probe_search_path()}
    argv = _ask(request).get("argv")
    if argv is None:
        return None
    if not isinstance(argv, list) or not argv or not all(isinstance(token, str) for token in argv):
        raise ValueError("MCP probe launch is unavailable")
    return tuple(argv)


def _ask(request: Mapping[str, object]) -> dict[str, object]:
    from ..native_runner_authority import native_runner_authority

    return native_runner_authority("local_mcp_probe", request)


def _display_name(identity: McpServerIdentity, tokens: Sequence[str]) -> str:
    if identity.package_name:
        return identity.package_name
    return Path(tokens[0]).name or "mcp-server"


def _example_label(tokens: Sequence[str]) -> str:
    return " ".join(tokens)[:160]


def _tools_from_payload(raw_tools: Sequence[dict[str, object]], *, server_name: str) -> tuple[LocalCliCommand, ...]:
    """Catalog rows for the listed tools, then Other tools, from the native kind."""

    listed = [
        {key: item[key] for key in ("name", "description") if isinstance(item.get(key), str)} for item in raw_tools
    ]
    rows = _ask({"op": "tools", "tools": listed, "server_name": server_name}).get("tools")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("MCP probe tools are unavailable")
    return tuple(
        LocalCliCommand(
            command_id=str(row["command_id"]),
            name=str(row["name"]),
            usage=str(row["usage"]),
            description=str(row["description"]),
        )
        for row in rows
    )


def _executable_basename(value: str) -> str:
    name = Path(value).name.lower()
    if name.endswith(".exe") or name.endswith(".cmd"):
        return name.rsplit(".", 1)[0]
    return name
