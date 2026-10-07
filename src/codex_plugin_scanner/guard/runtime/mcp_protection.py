"""MCP identity primitives used by Guard runtime protections."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePath

from ..native_context import context_mcp_identity


@dataclass(frozen=True, slots=True)
class McpServerIdentity:
    """Stable identity for a local MCP server definition."""

    config_path: str
    command: str
    args_hash: str
    package_name: str | None
    package_version: str | None
    package_source: str
    transport: str
    env_keys: tuple[str, ...]
    env_values_hash: str
    identity_hash: str


@dataclass(frozen=True, slots=True)
class McpToolIdentity:
    """Stable identity for a tool exposed by an MCP server."""

    server_hash: str
    tool_name: str
    schema_hash: str
    description_hash: str
    identity_hash: str


def build_mcp_server_identity(
    *,
    config_path: str,
    command: str,
    args: tuple[str, ...],
    transport: str,
    env: dict[str, str] | None = None,
    env_keys: tuple[str, ...] = (),
) -> McpServerIdentity:
    """Project the native server identity; native failure cannot bind approval."""
    identity = context_mcp_identity(
        "mcp_server_identity",
        {
            "config_path": config_path,
            "command": command,
            "args": list(args),
            "transport": transport,
            "environment": list(env.items()) if env is not None else None,
            "env_keys": list(env_keys),
        },
    )
    if identity is None:
        raise ValueError("native_mcp_server_identity_unavailable")
    return McpServerIdentity(
        config_path=identity["config_path"],
        command=identity["command"],
        args_hash=identity["args_hash"],
        package_name=identity["package_name"],
        package_version=identity["package_version"],
        package_source=identity["package_source"],
        transport=identity["transport"],
        env_values_hash=identity["env_values_hash"],
        identity_hash=identity["identity_hash"],
        env_keys=tuple(identity["env_keys"]),
    )


def build_mcp_tool_identity(
    *,
    server_hash: str,
    tool_name: str,
    schema: object | None = None,
    description: str | None = None,
) -> McpToolIdentity:
    """Build a stable identity for one MCP tool definition."""

    identity = context_mcp_identity(
        "mcp_tool_identity",
        {
            "server_hash": server_hash,
            "tool_name": tool_name,
            "schema": schema,
            "description": description,
        },
    )
    if identity is None:
        raise ValueError("native_mcp_tool_identity_unavailable")
    return McpToolIdentity(**identity)


def _non_secret_mcp_server_command(command: str) -> str:
    """Return a serialization-safe MCP command without URL credentials."""

    if "://" not in command:
        return command
    return _sanitize_package_url(command)


def mcp_server_identity_metadata(identity: McpServerIdentity) -> dict[str, object]:
    """Serialize an MCP server identity into non-secret Guard metadata."""

    return {
        "config_path": identity.config_path,
        "command": _non_secret_mcp_server_command(identity.command),
        "args_hash": identity.args_hash,
        "package_name": identity.package_name,
        "package_version": identity.package_version,
        "package_source": identity.package_source,
        "transport": identity.transport,
        "env_keys": list(identity.env_keys),
        "env_values_hash": identity.env_values_hash,
        "identity_hash": identity.identity_hash,
    }


def mcp_tool_identity_metadata(identity: McpToolIdentity) -> dict[str, object]:
    """Serialize an MCP tool identity into Guard metadata."""

    return {
        "server_hash": identity.server_hash,
        "tool_name": identity.tool_name,
        "schema_hash": identity.schema_hash,
        "description_hash": identity.description_hash,
        "identity_hash": identity.identity_hash,
    }


_PACKAGE_LAUNCHERS = frozenset({"bunx", "npm", "npx", "pnpm", "uvx", "yarn", "pipx"})


def package_launcher_name(command: str) -> str | None:
    """Return the canonical package-launcher basename, if this command is one."""

    command_name = _command_name(command)
    return command_name if command_name in _PACKAGE_LAUNCHERS else None


def resolved_package_launcher_executable(command: str) -> Path | None:
    """Resolve a package launcher to a real executable, or None if unknown."""

    launcher = package_launcher_name(command)
    if launcher is None:
        return None
    candidate = Path(command).expanduser()
    if candidate.is_absolute():
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            return None
    else:
        found = _which_package_launcher(command) or _which_package_launcher(launcher)
        if found is None:
            return None
        try:
            resolved = Path(found).resolve(strict=True)
        except OSError:
            return None
    if not resolved.is_file():
        return None
    return resolved


def _which_package_launcher(launcher: str) -> str | None:
    """Resolve a launcher on PATH, skipping Guard package shims."""

    path_value = os.environ.get("PATH", "")
    parts = [part for part in path_value.split(os.pathsep) if part and not _is_guard_package_shim_dir(part)]
    if not parts:
        return None
    return shutil.which(launcher, path=os.pathsep.join(parts))


def _is_guard_package_shim_dir(part: str) -> bool:
    posix = Path(part).expanduser().as_posix().rstrip("/")
    return posix.endswith("/package-shims/bin") or "/.hol-guard/package-shims/" in posix


_PACKAGE_SOURCE_FLAGS = (
    "--registry",
    "--index-url",
    "--extra-index-url",
    "--index",
)


def package_source_token(command: str, args: tuple[str, ...]) -> str:
    """Return a canonical package-source token, or 'default' when none is set."""

    sources: list[str] = []
    index = 0
    while index < len(args):
        value = args[index].strip()
        matched = False
        for flag in _PACKAGE_SOURCE_FLAGS:
            equals = f"{flag}="
            if value == flag and index + 1 < len(args):
                sources.append(f"{flag}={args[index + 1].strip()}")
                index += 2
                matched = True
                break
            if value.startswith(equals):
                sources.append(f"{flag}={value.partition('=')[2].strip()}")
                index += 1
                matched = True
                break
        if not matched:
            index += 1
    return "|".join(sources) if sources else "default"


def _split_package_token(value: str) -> tuple[str | None, str | None]:
    pip_style_name, pip_style_version = _split_pip_style_specifier(value)
    if pip_style_name is not None:
        return pip_style_name, pip_style_version
    if value.startswith("@"):
        scope, slash, remainder = value.partition("/")
        if not slash or not remainder:
            return value, None
        name, at_sign, version = remainder.rpartition("@")
        if not at_sign or not name:
            return value, None
        return f"{scope}/{name}", version or None
    if "://" in value:
        return _sanitize_package_url(value), None
    name, at_sign, version = value.rpartition("@")
    if not at_sign or not name:
        return value, None
    return name, version or None


def _command_name(value: str) -> str:
    command_name = PurePath(value.replace("\\", "/")).name.lower()
    if command_name.endswith((".cmd", ".exe", ".bat", ".ps1")):
        command_name = PurePath(command_name).stem
    return command_name


def _split_pip_style_specifier(value: str) -> tuple[str | None, str | None]:
    if "://" in value:
        return None, None
    for separator in ("===", "==", "~=", "!=", "<=", ">=", "<", ">", "="):
        name, matched, version = value.partition(separator)
        if not matched:
            continue
        normalized_name = name.strip()
        normalized_version = version.strip()
        if not normalized_name or not normalized_version:
            continue
        if separator in {"=", "==", "==="}:
            return normalized_name, normalized_version
        return normalized_name, f"{separator}{normalized_version}"
    return None, None


def _url_authority_contains_userinfo(value: str) -> bool:
    authority_bounds = _url_authority_bounds(value)
    if authority_bounds is None:
        return False
    authority_start, authority_end = authority_bounds
    authority = value[authority_start:authority_end]
    return "@" in authority


def _sanitize_package_url(value: str) -> str:
    without_fragment = value.split("#", 1)[0]
    without_query = without_fragment.split("?", 1)[0]
    if _url_authority_contains_userinfo(without_query):
        return _redact_url_userinfo(without_query)
    return without_query


def _redact_url_userinfo(value: str) -> str:
    authority_bounds = _url_authority_bounds(value)
    if authority_bounds is None:
        return value
    authority_start, authority_end = authority_bounds
    authority = value[authority_start:authority_end]
    at_index = authority.rfind("@")
    if at_index < 0:
        return value
    redacted_authority = authority[at_index + 1 :]
    return f"{value[:authority_start]}{redacted_authority}{value[authority_end:]}"


def _url_authority_bounds(value: str) -> tuple[int, int] | None:
    scheme_index = value.find("://")
    if scheme_index < 0:
        return None
    authority_start = scheme_index + 3
    authority_end = len(value)
    for delimiter in ("/", "?", "#"):
        delimiter_index = value.find(delimiter, authority_start)
        if delimiter_index >= 0:
            authority_end = min(authority_end, delimiter_index)
    return authority_start, authority_end


__all__ = [
    "McpServerIdentity",
    "McpToolIdentity",
    "build_mcp_server_identity",
    "build_mcp_tool_identity",
    "mcp_server_identity_metadata",
    "mcp_tool_identity_metadata",
]
