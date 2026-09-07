"""Bounded stdio MCP initialize + tools/list probe for custom extensions."""

from __future__ import annotations

import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .command_model import parse_shell_command
from .local_cli_commands import OTHER_COMMAND_ID, LocalCliCommand, slug_local_cli_command_id
from .local_cli_identity import (
    UnlistedCliIdentity,
    identify_unlisted_cli,
    unlisted_cli_invocation_is_safe,
)
from .local_mcp_stdio import (
    MAX_MCP_PROBE_TOOLS,
    MCP_PACKAGE_PROBE_TIMEOUT_SECONDS,
    MCP_PROBE_TIMEOUT_SECONDS,
    is_package_shim_executable,
    probe_search_path,
    run_mcp_tools_list,
)
from .mcp_protection import McpServerIdentity, build_mcp_server_identity

McpProbeStatus = Literal["ok", "empty", "failed"]
McpToolsRunner = Callable[[Sequence[str]], list[dict[str, object]] | None]

_PACKAGE_LAUNCHERS = frozenset({"bunx", "npx", "npm", "pnpm", "uvx", "yarn", "pipx"})
_STRICT_PACKAGE_LAUNCHERS = frozenset({"bunx", "npx", "pipx", "uvx"})


@dataclass(frozen=True, slots=True)
class McpProbeResult:
    identity: UnlistedCliIdentity
    server_identity: McpServerIdentity
    tools: tuple[LocalCliCommand, ...]
    status: McpProbeStatus
    argv: tuple[str, ...]


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
    if argv is None:
        return None
    resolved_timeout = _timeout_for(tokens, timeout)
    raw_tools = runner(argv) if runner is not None else run_mcp_tools_list(argv, timeout=resolved_timeout)
    if raw_tools is None:
        return None
    tools = _tools_from_payload(raw_tools, server_name=_display_name(server_identity, tokens))
    status: McpProbeStatus = "ok" if any(tool.command_id != OTHER_COMMAND_ID for tool in tools) else "empty"
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
    )


def _timeout_for(tokens: Sequence[str], timeout: float | None) -> float:
    if timeout is not None:
        return timeout
    return MCP_PACKAGE_PROBE_TIMEOUT_SECONDS if is_package_mcp_launcher(tokens) else MCP_PROBE_TIMEOUT_SECONDS


def _resolve_launch_argv(tokens: Sequence[str], *, cwd: Path) -> tuple[str, ...] | None:
    first = tokens[0]
    search_path = probe_search_path()
    if is_package_shim_executable(first):
        found = shutil.which(Path(first).name, path=search_path)
        if found is None:
            return None
        resolved = found
    elif Path(first).is_absolute():
        resolved = first
    else:
        found = shutil.which(first, path=search_path)
        if found is None:
            candidate = cwd / first
            if not candidate.is_file():
                return None
            resolved = str(candidate)
        else:
            resolved = found
    arguments = [_absolute_existing_path(token, cwd=cwd) for token in tokens[1:]]
    return (resolved, *arguments)


def _absolute_existing_path(token: str, *, cwd: Path) -> str:
    if token.startswith("-") or token.startswith("@") or "://" in token:
        return token
    path = Path(token)
    if path.is_absolute():
        return token
    candidate = cwd / token
    try:
        if candidate.exists():
            return str(candidate.resolve())
    except OSError:
        return token
    return token


def _display_name(identity: McpServerIdentity, tokens: Sequence[str]) -> str:
    if identity.package_name:
        return identity.package_name
    return Path(tokens[0]).name or "mcp-server"


def _example_label(tokens: Sequence[str]) -> str:
    return " ".join(tokens)[:160]


def _tools_from_payload(raw_tools: Sequence[dict[str, object]], *, server_name: str) -> tuple[LocalCliCommand, ...]:
    discovered: list[LocalCliCommand] = []
    seen = {OTHER_COMMAND_ID}
    for item in raw_tools:
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        command_id = slug_local_cli_command_id(name)
        if command_id in seen:
            continue
        seen.add(command_id)
        description = item.get("description")
        discovered.append(
            LocalCliCommand(
                command_id=command_id,
                name=name.strip()[:120],
                usage=name.strip()[:160],
                description=description.strip()[:240] if isinstance(description, str) else "",
            )
        )
        if len(discovered) >= MAX_MCP_PROBE_TOOLS - 1:
            break
    discovered.append(
        LocalCliCommand(
            command_id=OTHER_COMMAND_ID,
            name="Other tools",
            usage=f"{server_name} …",
            description="Any other tool this MCP server did not list.",
        )
    )
    return tuple(discovered)


def _executable_basename(value: str) -> str:
    name = Path(value).name.lower()
    if name.endswith(".exe") or name.endswith(".cmd"):
        return name.rsplit(".", 1)[0]
    return name
